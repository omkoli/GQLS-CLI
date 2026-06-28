package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
)

// extensionsLeakageCheck implements GQL-M03: it classifies and reports sensitive
// data leaked through the structured GraphQL `extensions` channel — Apollo
// tracing, exception stack traces, query-plan/cost details, and backend echoes
// (SQL text, file paths, internal hostnames). It complements GQL-005, which
// scans error *message* text; GQL-M03 keys on the structured `extensions`
// object specifically so the two do not double-report the same channel.
//
// Safety: read-only probes only. Leaked paths/hosts/SQL are redacted in the
// finding evidence via authz.MaskValue — the report names the leakage class and
// offending keys, never the raw secret.
type extensionsLeakageCheck struct{}

func init() {
	MustRegister(&extensionsLeakageCheck{})
}

func (c *extensionsLeakageCheck) ID() string { return "GQL-M03" }
func (c *extensionsLeakageCheck) Name() string {
	return "Sensitive Data in GraphQL extensions / Tracing"
}
func (c *extensionsLeakageCheck) Category() Category   { return InformationDisclosure }
func (c *extensionsLeakageCheck) Severity() Severity   { return MEDIUM }
func (c *extensionsLeakageCheck) RequiresSchema() bool { return false }

// extensionClass is one taxonomy category of sensitive data found in the
// `extensions` channel, with the severity its presence implies.
type extensionClass struct {
	id       string
	label    string
	severity Severity
}

var (
	classStacktrace  = extensionClass{"stacktrace", "stacktrace", MEDIUM}
	classBackendEcho = extensionClass{"backend-echo", "backend-echo", MEDIUM}
	classTracing     = extensionClass{"tracing", "tracing/timing", LOW}
	classQueryPlan   = extensionClass{"query-plan", "query-plan/cost", LOW}
)

// Taxonomy key sets (lowercased). A matching key consumes its subtree so that,
// e.g., file paths inside a stacktrace are reported once as "stacktrace" rather
// than re-flagged as a separate backend echo.
var (
	stacktraceKeys = map[string]bool{"stacktrace": true, "stack_trace": true, "stacktraces": true}
	tracingKeys    = map[string]bool{
		"tracing": true, "timing": true, "executiontime": true, "duration": true,
		"starttime": true, "endtime": true, "startoffset": true,
	}
	queryPlanKeys = map[string]bool{
		"queryplan": true, "cost": true, "complexity": true, "cachecontrol": true,
	}
)

// benignExtCodes are error `code` values that are normal client-facing
// validation/parse codes and never constitute a leak on their own.
var benignExtCodes = map[string]bool{
	"GRAPHQL_VALIDATION_FAILED":     true,
	"GRAPHQL_PARSE_FAILED":          true,
	"BAD_USER_INPUT":                true,
	"BAD_REQUEST":                   true,
	"PERSISTED_QUERY_NOT_FOUND":     true,
	"PERSISTED_QUERY_NOT_SUPPORTED": true,
	"INTROSPECTION_DISABLED":        true,
	"UNAUTHENTICATED":               true,
	"FORBIDDEN":                     true,
}

// echoPattern detects a backend echo in an extension string value. The label is
// a non-sensitive description of what leaked; the matched text itself is masked.
type echoPattern struct {
	re    *regexp.Regexp
	label string
}

var backendEchoPatterns = []echoPattern{
	{regexp.MustCompile(`(?i)/(?:var|home|usr|opt|app|srv|etc|root|tmp)/[a-z0-9_\-./]+\.(?:js|ts|go|py|rb|java|php|rs)`), "server file path"},
	{regexp.MustCompile(`[A-Za-z]:\\(?:[\w\-]+\\)+[\w\-]+\.(?:js|ts|go|py|rb|java|php|rs)`), "Windows file path"},
	{regexp.MustCompile(`(?i)syntax error at or near|you have an error in your sql syntax|ORA-\d{5}|SQLSTATE\[`), "SQL/database error"},
	{regexp.MustCompile(`(?i)\bselect\b.{1,200}\bfrom\b|\binsert\s+into\b|\bupdate\b.{1,200}\bset\b|\bdelete\s+from\b`), "SQL statement text"},
	{regexp.MustCompile(`(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+(?:internal|local|corp|svc)\b`), "internal hostname"},
	{regexp.MustCompile(`(?i)ECONNREFUSED\s+(?:\d{1,3}\.){3}\d{1,3}`), "internal IP / connection error"},
}

// internalCodeRe matches error `code` values that reveal an internal backend
// fault (vs. a benign client-facing validation code).
var internalCodeRe = regexp.MustCompile(`(?i)sql|database|timeout|econnrefused|nullpointer|exception|segfault|panic`)

// classHit accumulates the offending keys and redacted samples for one class.
type classHit struct {
	class      extensionClass
	keys       []string
	samples    []string
	seenKey    map[string]bool
	seenSample map[string]bool
}

// m03Probes elicit `extensions`: a benign query (which exposes tracing/cost on
// servers that leave it on) and a deliberately invalid query (which forces an
// error `extensions`, where exception stack traces appear).
var m03Probes = []struct{ label, query string }{
	{"valid", "{ __typename }"},
	{"type_error", "{ __typename { invalid } }"},
}

// Run executes the extensions-leakage check.
func (c *extensionsLeakageCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	hits := map[string]*classHit{}
	var reproReq *http.Request
	var reproBody []byte
	probeReqs := make([]PassProbe, 0, len(m03Probes))

	for _, p := range m03Probes {
		if ctx.Err() != nil {
			break
		}
		payload, err := json.Marshal(map[string]string{"query": p.query})
		if err != nil {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := cc.ProbeClient().Do(req)
		result.ProbeCount++
		if err != nil || resp == nil {
			continue
		}

		probeReqs = append(probeReqs, PassProbe{
			Label:   fmt.Sprintf("Probe %q — %s", p.label, p.query),
			Request: resp.Request,
			Body:    payload,
		})

		before := totalHits(hits)
		classifyResponseExtensions(resp.Body, hits)
		if reproReq == nil || totalHits(hits) > before {
			reproReq = resp.Request
			reproBody = payload
		}
	}

	if len(hits) == 0 {
		result.PassReason = "No sensitive data found in the GraphQL `extensions` channel: no exception stack " +
			"traces, Apollo tracing/timing, query-plan/cost metadata, or backend echoes (SQL, file paths, " +
			"internal hostnames) were present in the response extensions."
		result.PassProbes = probeReqs
		return result, nil
	}

	result.Findings = append(result.Findings, c.buildFinding(cc, hits, reproReq, reproBody))
	return result, nil
}

// buildFinding assembles the single aggregated finding from the classified hits.
func (c *extensionsLeakageCheck) buildFinding(
	cc *CheckContext, hits map[string]*classHit, reproReq *http.Request, reproBody []byte,
) Finding {
	ids := sortedMapKeys(hits) // deterministic class order
	severity := INFO
	labels := make([]string, 0, len(ids))
	keyParts := make([]string, 0, len(ids))
	var samples []string

	for _, id := range ids {
		h := hits[id]
		labels = append(labels, h.class.label)
		if h.class.severity > severity {
			severity = h.class.severity
		}
		keyParts = append(keyParts, fmt.Sprintf("%s [%s]", h.class.label, strings.Join(boundedList(h.keys, 6), ", ")))
		samples = append(samples, h.samples...)
	}

	sampleClause := ""
	if len(samples) > 0 {
		sampleClause = " Redacted samples: " + strings.Join(boundedList(samples, 5), "; ") + "."
	}

	description := fmt.Sprintf(
		"The GraphQL server at %s exposed internal data through the structured `extensions` channel. "+
			"Leaked class(es): %s. Offending keys — %s.%s "+
			"(GQL-005 covers stack traces in error message text; GQL-M03 covers the structured extensions channel.)",
		cc.Target, strings.Join(labels, ", "), strings.Join(keyParts, "; "), sampleClause)

	return Finding{
		CheckID:     c.ID(),
		CheckName:   c.Name(),
		Severity:    severity,
		Category:    c.Category(),
		Title:       "Sensitive Data Exposed in GraphQL extensions — " + strings.Join(labels, ", "),
		Description: description,
		Impact: "Internal stack traces, backend query text, internal hostnames, and resolver timing metadata " +
			"in the extensions channel aid targeted exploitation, timing attacks, and internal-topology " +
			"reconnaissance — turning a structured side-channel into a map of the server's internals.",
		Remediation: "Disable Apollo tracing and includeStacktraceInErrorResponses (set NODE_ENV=production) in " +
			"production; strip the extensions block of internal data at the gateway; return generic error codes " +
			"only and never propagate exception/stacktrace/SQL details to clients.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		ReproRequest: reproReq,
		ReproBody:    reproBody,
		Confidence:   "firm",
		CWE:          "CWE-200",
		OWASP:        "API8:2023",
		// Fingerprint is stable per (check, target, set-of-classes).
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "extensions:"+strings.Join(ids, ",")),
	}
}

// classifyResponseExtensions parses a GraphQL response body and classifies the
// top-level `extensions` object and every `errors[].extensions` object. It is
// panic-safe on missing or non-object extensions.
func classifyResponseExtensions(body []byte, hits map[string]*classHit) {
	var r struct {
		Errors []struct {
			Extensions json.RawMessage `json:"extensions"`
		} `json:"errors"`
		Extensions json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return
	}
	classifyExtensions(r.Extensions, "extensions", hits)
	for i, e := range r.Errors {
		classifyExtensions(e.Extensions, fmt.Sprintf("errors[%d].extensions", i), hits)
	}
}

// classifyExtensions decodes one raw extensions value and walks it. A missing,
// null, or non-object value yields no hits and never panics.
func classifyExtensions(raw json.RawMessage, prefix string, hits map[string]*classHit) {
	if len(raw) == 0 {
		return
	}
	var node interface{}
	if err := json.Unmarshal(raw, &node); err != nil {
		return
	}
	scanLeaf(node, prefix, hits)
	if isComposite(node) {
		walkExt(node, prefix, hits)
	}
}

// walkExt recursively classifies an extensions subtree. A key matching a
// taxonomy set consumes its subtree (no further descent) so nested values are
// attributed to the most specific class once.
func walkExt(node interface{}, path string, hits map[string]*classHit) {
	switch t := node.(type) {
	case map[string]interface{}:
		for _, k := range sortedMapKeys(t) {
			v := t[k]
			cp := joinPath(path, k)
			if classifyKey(strings.ToLower(k), v, cp, hits) {
				continue
			}
			scanLeaf(v, cp, hits)
			if isComposite(v) {
				walkExt(v, cp, hits)
			}
		}
	case []interface{}:
		for i, e := range t {
			cp := fmt.Sprintf("%s[%d]", path, i)
			scanLeaf(e, cp, hits)
			if isComposite(e) {
				walkExt(e, cp, hits)
			}
		}
	}
}

// classifyKey records a class hit when key names a known taxonomy category. It
// returns true when the key's subtree has been consumed (caller must not descend).
func classifyKey(lk string, v interface{}, path string, hits map[string]*classHit) bool {
	switch {
	case stacktraceKeys[lk] || (lk == "trace" && isArray(v)):
		addHit(hits, classStacktrace, path, maskedFramePreview(v))
		return true
	case tracingKeys[lk]:
		addHit(hits, classTracing, path, "")
		return true
	case queryPlanKeys[lk]:
		addHit(hits, classQueryPlan, path, "")
		return true
	case lk == "code":
		if s, ok := v.(string); ok {
			norm := strings.ToUpper(strings.TrimSpace(s))
			if !benignExtCodes[norm] && internalCodeRe.MatchString(s) {
				addHit(hits, classBackendEcho, path, "internal error code ("+authz.MaskValue(s)+")")
			}
		}
		return false
	}
	return false
}

// scanLeaf flags backend echoes found in a scalar string value.
func scanLeaf(v interface{}, path string, hits map[string]*classHit) {
	s, ok := v.(string)
	if !ok {
		return
	}
	for _, p := range backendEchoPatterns {
		if p.re.MatchString(s) {
			addHit(hits, classBackendEcho, path, p.label+" ("+authz.MaskValue(s)+")")
			return
		}
	}
}

// addHit records an offending key and a bounded set of redacted samples.
func addHit(hits map[string]*classHit, class extensionClass, keyPath, sample string) {
	h := hits[class.id]
	if h == nil {
		h = &classHit{class: class, seenKey: map[string]bool{}, seenSample: map[string]bool{}}
		hits[class.id] = h
	}
	if keyPath != "" && !h.seenKey[keyPath] {
		h.seenKey[keyPath] = true
		h.keys = append(h.keys, keyPath)
	}
	if sample != "" && !h.seenSample[sample] && len(h.samples) < 3 {
		h.seenSample[sample] = true
		h.samples = append(h.samples, sample)
	}
}

// maskedFramePreview renders a redacted, non-sensitive preview of a stacktrace
// value: a frame count plus a masked first frame.
func maskedFramePreview(v interface{}) string {
	switch t := v.(type) {
	case []interface{}:
		if len(t) == 0 {
			return "0 frames"
		}
		return fmt.Sprintf("%d frame(s); first: %s", len(t), authz.MaskValue(previewValue(t[0])))
	case string:
		return authz.MaskValue(t)
	default:
		return authz.MaskValue(previewValue(v))
	}
}

// previewValue produces a short string representation of a value for masking.
func previewValue(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []interface{}:
		if len(t) == 0 {
			return ""
		}
		return previewValue(t[0])
	case map[string]interface{}:
		for _, k := range []string{"file", "fileName", "function", "functionName", "message", "line"} {
			if val, ok := t[k]; ok {
				if s, ok := val.(string); ok && s != "" {
					return s
				}
			}
		}
		b, _ := json.Marshal(t)
		return string(b)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func totalHits(hits map[string]*classHit) int {
	n := 0
	for _, h := range hits {
		n += len(h.keys) + len(h.samples)
	}
	return n
}

func isComposite(v interface{}) bool {
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		return true
	}
	return false
}

func isArray(v interface{}) bool {
	_, ok := v.([]interface{})
	return ok
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func boundedList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	out := append([]string{}, items[:max]...)
	return append(out, fmt.Sprintf("… +%d more", len(items)-max))
}

// sortedMapKeys returns the keys of m in deterministic ascending order.
func sortedMapKeys[T any](m map[string]T) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
