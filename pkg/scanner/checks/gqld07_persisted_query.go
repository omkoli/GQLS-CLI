package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// APQ support states inferred from the persisted-query protocol probe.
const (
	apqSupported    = "supported"
	apqNotSupported = "not_supported"
	apqUnknown      = "unknown"
)

// arbitraryOperationQuery is a novel ad-hoc operation the server could not have
// pre-registered — its unusual alias keys make it impossible to be in any
// persisted-query allow-list.
const arbitraryOperationQuery = "query { z9q1: __typename z9q2: __typename }"

// apqExtensionBody is an Apollo APQ request carrying only the persisted-query
// extension (an all-zero hash) and no "query" field. A server that supports APQ
// answers PersistedQueryNotFound; one that does not answers
// PersistedQueryNotSupported (or a generic "must provide query string").
const apqExtensionBody = `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000000"}}}`

// persistedQueryCheck implements GQL-D07: Persisted Query / APQ Not Enforced.
//
// It detects whether the endpoint accepts arbitrary ad-hoc operations rather
// than restricting execution to an allow-list of persisted / Automatic Persisted
// Queries. Allow-listing is the strongest structural mitigation for the whole
// DoS class (D01–D06); its absence means any crafted query is executable
// (OWASP API4:2023).
type persistedQueryCheck struct{}

func init() {
	MustRegister(&persistedQueryCheck{})
}

func (c *persistedQueryCheck) ID() string           { return "GQL-D07" }
func (c *persistedQueryCheck) Name() string         { return "Persisted Query / APQ Not Enforced" }
func (c *persistedQueryCheck) Category() Category   { return DenialOfService }
func (c *persistedQueryCheck) Severity() Severity   { return MEDIUM }
func (c *persistedQueryCheck) RequiresSchema() bool { return false }

// apqProbeResult captures the outcome of a single GQL-D07 probe.
type apqProbeResult struct {
	status  int
	body    []byte
	req     *http.Request
	payload []byte
	err     error
}

// Run executes GQL-D07 against the target endpoint.
func (c *persistedQueryCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Arbitrary-operation probe ────────────────────────────────────────────
	arbPayload, err := json.Marshal(map[string]string{"query": arbitraryOperationQuery})
	if err != nil {
		result.Error = fmt.Errorf("marshalling arbitrary-operation probe: %w", err)
		return result, nil
	}
	arb := c.probe(ctx, cc, arbPayload)
	result.ProbeCount++

	if ctx.Err() != nil {
		result.Error = fmt.Errorf("persisted-query probe cancelled: %w", ctx.Err())
		return result, nil
	}

	// ── APQ-protocol probe ───────────────────────────────────────────────────
	apq := c.probe(ctx, cc, []byte(apqExtensionBody))
	result.ProbeCount++
	apqState := classifyAPQ(apq)

	arbitraryExecuted := arb.err == nil && arb.status == http.StatusOK && bytes.Contains(arb.body, []byte(`"data"`))
	if arbitraryExecuted {
		result.Findings = append(result.Findings, Finding{
			CheckID:      c.ID(),
			CheckName:    c.Name(),
			Severity:     MEDIUM,
			Category:     DenialOfService,
			Title:        "Arbitrary Operations Accepted (No Persisted-Query Allow-List)",
			Description:  persistedFindingDescription(apqState),
			Impact:       persistedImpact,
			Remediation:  persistedRemediation,
			References:   persistedReferences,
			ReproRequest: arb.req,
			ReproBody:    arb.payload,
			Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "apq_not_enforced"),
		})
		return result, nil
	}

	// ── PASS ─────────────────────────────────────────────────────────────────
	if arb.err != nil {
		result.PassReason = fmt.Sprintf(
			"endpoint did not respond to the arbitrary-operation probe (%v); persisted-query enforcement was not assessed",
			arb.err,
		)
	} else {
		result.PassReason = "Endpoint restricts execution to persisted/allow-listed operations (arbitrary query rejected)."
	}
	result.PassProbes = []PassProbe{
		{Label: "arbitrary-operation probe", Request: arb.req, Body: arb.payload},
		{Label: fmt.Sprintf("APQ-protocol probe (APQ %s)", apqState), Request: apq.req, Body: apq.payload},
	}
	return result, nil
}

// probe sends payload as a JSON POST via the probe client. The request and
// payload are populated even on a transport error so callers can still build
// repro / pass records.
func (c *persistedQueryCheck) probe(ctx context.Context, cc *CheckContext, payload []byte) apqProbeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return apqProbeResult{payload: payload, err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return apqProbeResult{req: req, payload: payload, err: err}
	}
	return apqProbeResult{status: resp.StatusCode, body: resp.Body, req: resp.Request, payload: payload}
}

// classifyAPQ infers the endpoint's APQ support state from the protocol probe.
func classifyAPQ(r apqProbeResult) string {
	if r.err != nil {
		return apqUnknown
	}
	low := bytes.ToLower(r.body)
	switch {
	case bytes.Contains(low, []byte("persistedquerynotfound")), bytes.Contains(low, []byte("persisted_query_not_found")):
		return apqSupported
	case bytes.Contains(low, []byte("persistedquerynotsupported")),
		bytes.Contains(low, []byte("persisted_query_not_supported")),
		bytes.Contains(low, []byte("must provide query string")),
		bytes.Contains(low, []byte("must provide a query")):
		return apqNotSupported
	default:
		return apqUnknown
	}
}

func persistedFindingDescription(apqState string) string {
	base := "A novel ad-hoc query the server could not have pre-registered " +
		"(`query { z9q1: __typename z9q2: __typename }`) executed successfully (HTTP 200 with data), " +
		"so execution is not restricted to a persisted-query allow-list. "
	switch apqState {
	case apqSupported:
		return base + "APQ supported but allow-listing not enforced: the persisted-query cache is enabled " +
			"(the server answered PersistedQueryNotFound), yet arbitrary ad-hoc operations still execute — a " +
			"common Apollo misconfiguration where the APQ cache is on but registered-only mode is off."
	case apqNotSupported:
		return base + "Automatic Persisted Queries are not supported by this endpoint; arbitrary ad-hoc " +
			"operations execute directly."
	default:
		return base + "APQ support could not be determined; arbitrary ad-hoc operations execute regardless."
	}
}

const persistedImpact = "Any attacker-crafted operation is executable — including the expensive/abusive " +
	"queries exercised by the other DoS checks (alias/depth/cost amplification) and injection probes. The " +
	"absence of a persisted-query allow-list removes a strong defense-in-depth layer and significantly widens " +
	"the attack surface."

const persistedRemediation = "Enforce a persisted-query allow-list (registered / safe-listed operations only) " +
	"in production: e.g. Apollo persistedQueries with mode \"only\" / operation safelisting, Relay persisted " +
	"queries, or Hive/Inigo persisted operations. Treat APQ caching as separate from allow-list enforcement — " +
	"enabling the APQ cache alone does not restrict which operations may run."

var persistedReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://www.apollographql.com/docs/apollo-server/performance/apq/",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
}
