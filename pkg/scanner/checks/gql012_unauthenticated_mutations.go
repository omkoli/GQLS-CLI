package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// unauthMutationsCheck implements GQL-012: Unauthenticated Access to Mutations.
type unauthMutationsCheck struct{}

func init() {
	MustRegister(&unauthMutationsCheck{})
}

func (c *unauthMutationsCheck) ID() string           { return "GQL-012" }
func (c *unauthMutationsCheck) Name() string         { return "Unauthenticated Access to Mutations" }
func (c *unauthMutationsCheck) Category() Category   { return Authentication }
func (c *unauthMutationsCheck) Severity() Severity   { return HIGH }
func (c *unauthMutationsCheck) RequiresSchema() bool { return false }

// mutAuthProbe describes a single mutation request to send without auth headers.
type mutAuthProbe struct {
	label  string
	body   []byte
	url    string
	method string
}

// mutAuthResult classifies a probe response with respect to auth enforcement.
type mutAuthResult int

const (
	mutAuthEnforced     mutAuthResult = iota // 401/403 or auth-related error message
	mutAuthNotEnforced                       // 200+data or schema validation/input error
	mutAuthInconclusive                      // cannot determine definitively
)

// mutAuthErrorPatterns matches error messages that signal auth enforcement.
var mutAuthErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bunauthorized\b`),
	regexp.MustCompile(`(?i)\bunauthenticated\b`),
	regexp.MustCompile(`(?i)\bnot authorized\b`),
	regexp.MustCompile(`(?i)\bforbidden\b`),
}

// mutValidationPatterns matches GraphQL schema-validation and input errors that
// indicate the server processed the request past the authentication layer.
// These patterns must not overlap with auth error messages.
var mutValidationPatterns = []*regexp.Regexp{
	// graphql-js / Apollo: "argument 'X' of type 'Y!' is required, but it was not provided."
	regexp.MustCompile(`(?i)argument .{1,80} of type .{1,80} is required`),
	// Generic "Field X is required" (various servers)
	regexp.MustCompile(`(?i)\bField .{1,80} is required\b`),
	// Shopify / graphql-ruby style: "Field 'X' is missing required arguments: Y"
	// Extensions code "missingRequiredArguments" is also checked in evalMutationAuth.
	regexp.MustCompile(`(?i)\bmissing required arguments?\b`),
	regexp.MustCompile(`(?i)expected type .{1,60}, found`),
	regexp.MustCompile(`(?i)\bgot invalid value\b`),
	regexp.MustCompile(`(?i)\bunknown argument\b`),
	regexp.MustCompile(`(?i)must not have a selection since type`),
	regexp.MustCompile(`(?i)\bcannot query field\b`),
	regexp.MustCompile(`(?i)is not defined on type`),
}

// mutValidationExtCodes is the set of extensions.code values that unambiguously
// identify GraphQL schema/input validation errors, confirming the request was
// processed past the authentication layer.
var mutValidationExtCodes = map[string]bool{
	"missingRequiredArguments":  true,
	"GRAPHQL_VALIDATION_FAILED": true,
	"argumentNotProvided":       true,
}

// mutKeywordRe matches the "mutation" keyword in a GraphQL operation document.
var mutKeywordRe = regexp.MustCompile(`(?i)\bmutation\b`)

// isMutationBody reports whether the JSON-encoded GraphQL request body in bodyStr
// contains a "mutation" keyword in its "query" field.
func isMutationBody(bodyStr string) bool {
	var payload struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(bodyStr), &payload); err != nil {
		return false
	}
	return mutKeywordRe.MatchString(payload.Query)
}

// evalMutationAuth classifies the auth enforcement signal from a probe response.
// It is conservative: only definitive signals are acted on; ambiguous responses
// return mutAuthInconclusive so they are never flagged.
func evalMutationAuth(resp *transport.Response) mutAuthResult {
	// 401/403 → auth enforced.
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return mutAuthEnforced
	}

	var parsed struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return mutAuthInconclusive
	}

	// Auth-related error messages take priority over all other signals.
	for _, e := range parsed.Errors {
		for _, re := range mutAuthErrorPatterns {
			if re.MatchString(e.Message) {
				return mutAuthEnforced
			}
		}
	}

	// 200 with non-null data → mutation executed without auth (not enforced).
	if resp.StatusCode == 200 && parsed.Data != nil && string(parsed.Data) != "null" {
		return mutAuthNotEnforced
	}

	// Schema validation / invalid input errors mean the server processed the
	// request past the auth layer (middleware-level auth would have rejected it
	// first with 401/403 or an auth-specific message).
	// Check both the error message text and the structured extensions.code field.
	for _, e := range parsed.Errors {
		if mutValidationExtCodes[e.Extensions.Code] {
			return mutAuthNotEnforced
		}
		for _, re := range mutValidationPatterns {
			if re.MatchString(e.Message) {
				return mutAuthNotEnforced
			}
		}
	}

	return mutAuthInconclusive
}

// mutSelectionSet returns the GraphQL selection set suffix for a mutation field's
// return type. Object, interface, and union types require " { __typename }";
// scalars and enums do not accept a sub-selection.
func mutSelectionSet(t *schema.TypeRef, s *schema.Schema) string {
	if t == nil {
		return " { __typename }"
	}
	unwrapped := t.Unwrap()
	if unwrapped == nil {
		return " { __typename }"
	}

	switch unwrapped.Kind {
	case schema.KindScalar, schema.KindEnum:
		return ""
	case schema.KindObject, schema.KindInterface, schema.KindUnion:
		return " { __typename }"
	}

	// Kind not set directly on the TypeRef — look up the type definition.
	if s != nil {
		if td := s.FindType(unwrapped.Name); td != nil {
			switch td.Kind {
			case schema.KindScalar, schema.KindEnum:
				return ""
			case schema.KindObject, schema.KindInterface, schema.KindUnion:
				return " { __typename }"
			}
		}
	}

	// Default: assume an object return type to maximise detection signal.
	// Worst case the server returns a "must not have a selection" validation
	// error, which still indicates auth was not enforced at the middleware level.
	return " { __typename }"
}

// buildSchemaProbes constructs one minimal mutation probe per field in the
// schema's mutation type. Probes contain no arguments so that missing-required-
// argument errors from the server confirm the request reached schema validation
// (i.e. was not rejected by auth middleware first).
//
// Returns the probes slice and the total number of mutation fields in the schema
// before any cap was applied (used for coverage disclosure in PassReason).
func buildSchemaProbes(s *schema.Schema, target string) ([]mutAuthProbe, int) {
	fields := s.MutationFields()
	total := len(fields)
	if total == 0 {
		return nil, 0
	}

	// Sort deterministically by field name so repeated runs always test the
	// same mutations in the same order, regardless of schema iteration order.
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name
	})

	// Cap to the first maxMutations fields (alphabetically).
	const maxMutations = 5
	if len(fields) > maxMutations {
		fields = fields[:maxMutations]
	}

	probes := make([]mutAuthProbe, 0, len(fields))
	for _, f := range fields {
		sel := mutSelectionSet(f.Type, s)
		gql := fmt.Sprintf("mutation GQL012Probe { %s%s }", f.Name, sel)
		body, err := json.Marshal(map[string]interface{}{"query": gql})
		if err != nil {
			continue
		}
		probes = append(probes, mutAuthProbe{
			label:  f.Name,
			body:   body,
			url:    target,
			method: http.MethodPost,
		})
	}
	return probes, total
}

// unauthClient returns cc.UnauthenticatedClient when set, or constructs a
// temporary bare client as a fallback for test environments that do not
// populate the field.
func unauthClient(cc *CheckContext) *transport.Client {
	if cc.UnauthenticatedClient != nil {
		return cc.UnauthenticatedClient
	}
	return transport.NewClient(30*time.Second, 10, nil)
}

// Run executes GQL-012 by sending mutation probes without auth headers and
// classifying each response according to the conservative auth-enforcement rules.
func (c *unauthMutationsCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: collect probes ────────────────────────────────────────────────
	//
	// Priority order:
	//   1. If curl input contains a mutation, use it directly.
	//   2. Else, enumerate mutations from the schema.
	//   3. If neither source is available, skip the check.
	var probes []mutAuthProbe
	var totalMutations int // total schema mutations before any cap; 0 for curl path

	if cc.ParsedCurl != nil && isMutationBody(cc.ParsedCurl.Body) {
		// Caller supplied a curl command that contains a mutation — use it as
		// the sole probe. Auth headers are stripped by the bare client below.
		probes = append(probes, mutAuthProbe{
			label:  "curl-provided mutation",
			body:   []byte(cc.ParsedCurl.Body),
			url:    cc.ParsedCurl.URL,
			method: cc.ParsedCurl.Method,
		})
	} else if cc.Schema != nil && cc.Schema.MutationType != nil {
		// Build minimal probes from the schema's mutation type.
		probes, totalMutations = buildSchemaProbes(cc.Schema, cc.Target)
	}

	if len(probes) == 0 {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no mutations to probe: the curl input did not contain a mutation " +
			"and no mutation type is available in the schema"
		return result, nil
	}

	// ── Step 2: send probes without auth headers ──────────────────────────────
	bareClient := unauthClient(cc)

	var (
		testedCount    int
		reachableCount int
		enforcedCount  int
		exampleProbe   *mutAuthProbe
		exampleReq     *http.Request
		exampleBody    []byte
		passProbes     []PassProbe
	)

	for i := range probes {
		p := &probes[i]

		req, err := http.NewRequestWithContext(ctx, p.method, p.url, bytes.NewReader(p.body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Del("Accept-Encoding")
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := bareClient.Do(req)
		result.ProbeCount++
		if err != nil {
			continue
		}
		testedCount++

		switch evalMutationAuth(resp) {
		case mutAuthEnforced:
			enforcedCount++
			passProbes = append(passProbes, PassProbe{
				Label:   fmt.Sprintf("auth enforced: mutation %q", p.label),
				Request: resp.Request,
				Body:    p.body,
			})
		case mutAuthNotEnforced:
			reachableCount++
			if exampleProbe == nil {
				exampleProbe = p
				exampleReq = resp.Request
				exampleBody = p.body
			}
			// mutAuthInconclusive: conservative — do not flag, do not count as enforced.
		}
	}

	// ── Step 3: classify overall result ──────────────────────────────────────

	// coverageNote is appended to PassReason / finding description when schema
	// sampling was applied (more mutations in schema than were tested).
	coverageNote := ""
	if totalMutations > len(probes) {
		coverageNote = fmt.Sprintf(
			" (schema has %d total mutations; first %d by name tested)",
			totalMutations, len(probes),
		)
	}

	if reachableCount > 0 {
		result.Findings = append(result.Findings, Finding{
			CheckID:   c.ID(),
			CheckName: c.Name(),
			Severity:  HIGH,
			Category:  Authentication,
			Title:     "Unauthenticated Access to Mutations",
			Description: fmt.Sprintf(
				"%d of %d tested mutation(s) are reachable without authentication%s. "+
					"Example reachable mutation: %q. "+
					"Probes were sent without Authorization, Cookie, or API-key headers.",
				reachableCount, testedCount, coverageNote, exampleProbe.label,
			),
			Impact: "Unauthenticated users can invoke write operations (create, update, delete) " +
				"against the GraphQL API without supplying any credentials. Depending on the " +
				"mutations exposed, this may allow account takeover, data corruption, " +
				"privilege escalation, or unauthorised resource creation.",
			Remediation: "Enforce authentication at the transport or middleware layer before " +
				"any GraphQL operation is parsed or executed. Require a valid bearer token, " +
				"session cookie, or equivalent credential for every mutation. " +
				"Do not rely solely on resolver-level checks — apply a global authentication " +
				"guard. Review all mutation resolvers for missing @auth directives or middleware.",
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
				"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
				"https://graphql.org/learn/authorization/",
			},
			ReproRequest: exampleReq,
			ReproBody:    exampleBody,
			// Fingerprint is stable across runs: keyed on check ID + target only.
			// The previously used exampleProbe.label was non-deterministic when
			// schema sampling shuffled the mutation list between runs.
			Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "unauthenticated_mutations"),
		})
		return result, nil
	}

	if testedCount == 0 {
		result.PassReason = fmt.Sprintf(
			"no mutation probes completed (%d attempted; all failed to connect)",
			result.ProbeCount,
		)
		return result, nil
	}

	if enforcedCount > 0 {
		result.PassReason = fmt.Sprintf(
			"auth enforced on %d of %d tested mutation(s)%s; remaining %d probe(s) were inconclusive",
			enforcedCount, testedCount, coverageNote, testedCount-enforcedCount,
		)
	} else {
		result.PassReason = fmt.Sprintf(
			"all %d tested mutation probe(s) returned inconclusive results%s "+
				"(no definitive auth enforcement or bypass signal observed)",
			testedCount, coverageNote,
		)
	}
	result.PassProbes = passProbes
	return result, nil
}
