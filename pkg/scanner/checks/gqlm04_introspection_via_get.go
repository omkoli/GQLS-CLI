package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// introspectionViaGetCheck implements GQL-M04: when canonical POST
// introspection is blocked, it retries the same introspection over alternative
// transports and introspection-defense bypasses (GET, text/plain, form-encoded,
// whitespace/comment after `__schema`, and batched). It fires only when a
// bypass succeeds while the POST baseline is denied — so it never duplicates
// GQL-001 (which already reports plainly-enabled introspection).
//
// Safety: read-only introspection over a bounded set of vectors. The finding
// confirms only that `__schema` is reachable; it does not dump schema content
// (the schema itself is what GQL-001 governs).
type introspectionViaGetCheck struct{}

func init() {
	MustRegister(&introspectionViaGetCheck{})
}

func (c *introspectionViaGetCheck) ID() string { return "GQL-M04" }
func (c *introspectionViaGetCheck) Name() string {
	return "Introspection Reachable via Alternative Transport"
}
func (c *introspectionViaGetCheck) Category() Category   { return InformationDisclosure }
func (c *introspectionViaGetCheck) Severity() Severity   { return MEDIUM }
func (c *introspectionViaGetCheck) RequiresSchema() bool { return false }

// Introspection documents reused across vectors. The canonical minimal probe is
// shared with GQL-001/002; the whitespace and comment variants insert a benign
// token after `__schema` to defeat naive string-match introspection gates.
const (
	m04IntroDoc           = "{ __schema { queryType { name } } }"
	m04IntroDocWhitespace = "{ __schema\n { queryType { name } } }"
	m04IntroDocComment    = "{ __schema #gqls\n { queryType { name } } }"
)

// m04Vector is one alternative-transport bypass attempt. build returns the
// request and the body bytes (nil for GET) for reproduction.
type m04Vector struct {
	name  string
	build func(ctx context.Context, target string) (*http.Request, []byte, error)
}

// m04Vectors are tried in this fixed order so findings list vectors deterministically.
var m04Vectors = []m04Vector{
	{"GET ?query=", buildGETIntrospection},
	{"POST text/plain", buildTextPlainIntrospection},
	{"POST form-encoded", buildFormIntrospection},
	{"whitespace bypass (newline after __schema)", buildWhitespaceIntrospection},
	{"comment bypass (# comment after __schema)", buildCommentIntrospection},
	{"batched introspection", buildBatchedIntrospection},
}

// Run executes the alternative-transport introspection check.
func (c *introspectionViaGetCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Baseline: canonical POST application/json introspection.
	baseBody, err := json.Marshal(map[string]string{"query": m04IntroDoc})
	if err != nil {
		result.Error = err
		return result, nil
	}
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(baseBody))
	if err != nil {
		result.Error = err
		return result, nil
	}
	baseReq.Header.Set("Content-Type", "application/json")

	baseResp, err := cc.ProbeClient().Do(baseReq)
	result.ProbeCount++
	if err != nil || baseResp == nil {
		result.Error = fmt.Errorf("baseline POST introspection probe failed: %w", err)
		return result, nil
	}

	if responseHasSchema(baseResp.Body) {
		// Introspection is plainly enabled over POST — GQL-001 owns this.
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "POST introspection is already enabled (covered by GQL-001); no alternative-transport bypass to report"
		return result, nil
	}

	// ── POST is blocked: retry over each alternative vector.
	var worked []string
	var reproReq *http.Request
	var reproBody []byte
	passProbes := []PassProbe{{
		Label:   "Baseline POST introspection (blocked) — " + m04IntroDoc,
		Request: baseResp.Request,
		Body:    baseBody,
	}}

	for _, v := range m04Vectors {
		if ctx.Err() != nil {
			break
		}
		req, body, berr := v.build(ctx, cc.Target)
		if berr != nil || req == nil {
			continue
		}
		resp, derr := cc.ProbeClient().Do(req)
		result.ProbeCount++
		if derr != nil || resp == nil {
			continue
		}
		if responseHasSchema(resp.Body) {
			worked = append(worked, v.name)
			if reproReq == nil {
				reproReq = resp.Request
				reproBody = body
			}
		} else {
			passProbes = append(passProbes, PassProbe{
				Label:   "Bypass vector (blocked) — " + v.name,
				Request: resp.Request,
				Body:    body,
			})
		}
	}

	if len(worked) == 0 {
		result.PassReason = "POST introspection is blocked and the schema stayed unreachable across all " +
			"alternative transports (GET, text/plain, form-encoded, whitespace/comment bypass, batched) — " +
			"the introspection policy is enforced consistently."
		result.PassProbes = passProbes
		return result, nil
	}

	vectors := strings.Join(worked, ", ")
	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  c.Severity(),
		Category:  c.Category(),
		Title:     "Introspection Bypass — schema reachable via " + vectors + " despite POST being blocked",
		Description: fmt.Sprintf(
			"The canonical POST application/json introspection probe (%s) was denied at %s, but the same "+
				"introspection succeeded over an alternative transport. Working vector(s): %s. The schema is "+
				"therefore still enumerable despite the apparent introspection lock-down.",
			m04IntroDoc, cc.Target, vectors),
		Impact: "The full schema (types, fields, arguments, deprecations) is exposed to attackers despite the " +
			"intended introspection lock-down, enabling targeted attack-surface mapping over a transport the " +
			"policy failed to cover.",
		Remediation: "Enforce the introspection policy across all transports and content-types; disable GET for " +
			"GraphQL; normalize/validate the operation before the introspection gate (to defeat whitespace and " +
			"comment bypasses); and apply the same rule to batched requests.",
		References: []string{
			"https://portswigger.net/web-security/graphql",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		},
		ReproRequest: reproReq,
		ReproBody:    reproBody,
		Confidence:   "confirmed",
		CWE:          "CWE-200",
		OWASP:        "API8:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "introspection_bypass"),
	})
	return result, nil
}

// ── vector builders ──────────────────────────────────────────────────────────

// buildGETIntrospection reuses the GQL-010 GET shape: introspection in ?query=.
func buildGETIntrospection(ctx context.Context, target string) (*http.Request, []byte, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()
	q.Set("query", m04IntroDoc)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	return req, nil, err
}

// buildTextPlainIntrospection POSTs the JSON body under a text/plain content type.
func buildTextPlainIntrospection(ctx context.Context, target string) (*http.Request, []byte, error) {
	body, err := json.Marshal(map[string]string{"query": m04IntroDoc})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	return req, body, nil
}

// buildFormIntrospection POSTs a form-encoded query= body.
func buildFormIntrospection(ctx context.Context, target string) (*http.Request, []byte, error) {
	body := []byte(url.Values{"query": {m04IntroDoc}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, body, nil
}

// buildWhitespaceIntrospection POSTs the newline-after-__schema variant.
func buildWhitespaceIntrospection(ctx context.Context, target string) (*http.Request, []byte, error) {
	return buildJSONIntrospection(ctx, target, m04IntroDocWhitespace)
}

// buildCommentIntrospection POSTs the comment-after-__schema variant.
func buildCommentIntrospection(ctx context.Context, target string) (*http.Request, []byte, error) {
	return buildJSONIntrospection(ctx, target, m04IntroDocComment)
}

func buildJSONIntrospection(ctx context.Context, target, doc string) (*http.Request, []byte, error) {
	body, err := json.Marshal(map[string]string{"query": doc})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, body, nil
}

// buildBatchedIntrospection POSTs a single-element batch array.
func buildBatchedIntrospection(ctx context.Context, target string) (*http.Request, []byte, error) {
	body, err := json.Marshal([]map[string]string{{"query": m04IntroDoc}})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, body, nil
}

// responseHasSchema reports whether a GraphQL response body carries a non-null
// `data.__schema`, handling both single responses and batched arrays.
func responseHasSchema(body []byte) bool {
	type schemaEnvelope struct {
		Data struct {
			Schema *json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	var single schemaEnvelope
	if err := json.Unmarshal(body, &single); err == nil && single.Data.Schema != nil {
		return true
	}
	var batch []schemaEnvelope
	if err := json.Unmarshal(body, &batch); err == nil {
		for _, e := range batch {
			if e.Data.Schema != nil {
				return true
			}
		}
	}
	return false
}
