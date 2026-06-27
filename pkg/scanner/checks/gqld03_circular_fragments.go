package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// fragmentCycleRejectionPattern matches the validation error a spec-compliant
// server returns when it detects a fragment-spread cycle. A match means the
// server correctly rejected the cycle (GraphQL spec §5.5.2.2), so no finding is
// produced.
var fragmentCycleRejectionPattern = regexp.MustCompile(
	`(?i)cannot spread fragment .* within itself|fragment .* cycle|circular|cannot spread fragment`,
)

// circularFragmentCheck implements GQL-D03: Circular Fragment Spread.
//
// The GraphQL spec (§5.5.2.2, "Fragment spreads must not form cycles") requires
// servers to reject documents whose fragments reference each other circularly.
// A non-compliant validator instead recurses/loops during validation or
// execution, turning one tiny request into a stack-overflow / hang / 5xx
// denial-of-service (OWASP API4:2023).
type circularFragmentCheck struct{}

func init() {
	MustRegister(&circularFragmentCheck{})
}

func (c *circularFragmentCheck) ID() string           { return "GQL-D03" }
func (c *circularFragmentCheck) Name() string         { return "Circular Fragment Spread" }
func (c *circularFragmentCheck) Category() Category   { return DenialOfService }
func (c *circularFragmentCheck) Severity() Severity   { return HIGH }
func (c *circularFragmentCheck) RequiresSchema() bool { return false }

// cycleProbeResult captures the outcome of a single fragment-cycle probe.
type cycleProbeResult struct {
	status    int
	body      []byte
	req       *http.Request
	payload   []byte
	latencyMS int64
	err       error
}

// Run executes GQL-D03 against the target endpoint.
//
// It sends exactly two probes: a benign control to establish a fast live
// baseline, then one circular-fragment document. A finding fires when the cycle
// probe times out, returns 5xx, or hangs (super-linear latency with no
// validation error) — all signs the validator did not detect the cycle. A clear
// cycle validation error is treated as spec-compliant (PASS); any other clean
// response is inconclusive but non-vulnerable.
func (c *circularFragmentCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Control probe (no fragments) ─────────────────────────────────────────
	ctl := c.probe(ctx, cc, "query { __typename }")
	result.ProbeCount++

	controlOK := ctl.err == nil && ctl.status == http.StatusOK && bytes.Contains(ctl.body, []byte(`"data"`))
	if !controlOK {
		result.PassReason = fmt.Sprintf(
			"endpoint did not respond to baseline probe (control query returned %s); "+
				"fragment-cycle handling was not assessed",
			describeControlFailure(ctl.status, ctl.err),
		)
		if ctl.req != nil {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   "cycle-control (no fragments)",
				Request: ctl.req,
				Body:    ctl.payload,
			})
		}
		return result, nil
	}

	// ── Cycle probe (circular fragments) ─────────────────────────────────────
	rootType := rootQueryTypeName(cc.Schema)
	doc := buildCircularFragmentDoc(rootType)
	cyc := c.probe(ctx, cc, doc)
	result.ProbeCount++

	// Vulnerable: timeout / network failure — but NOT a parent context
	// cancellation — means the validator did not detect the cycle and the
	// request hung past the per-request timeout.
	if cyc.err != nil {
		if ctx.Err() != nil {
			result.Error = fmt.Errorf("circular fragment probe cancelled: %w", cyc.err)
			return result, nil
		}
		result.Findings = append(result.Findings, c.finding(cc, cyc.req, cyc.payload,
			circularFindingDescription(doc,
				fmt.Sprintf("the cycle probe did not complete (%v); the validator did not reject the cycle", cyc.err),
				ctl.latencyMS, cyc.latencyMS, "timed out"),
		))
		return result, nil
	}

	// Vulnerable: 5xx on the cycle while the control was a fast 200.
	if cyc.status >= http.StatusInternalServerError {
		result.Findings = append(result.Findings, c.finding(cc, cyc.req, cyc.payload,
			circularFindingDescription(doc,
				fmt.Sprintf("the cycle probe returned HTTP %d; the validator did not reject the cycle", cyc.status),
				ctl.latencyMS, cyc.latencyMS, fmt.Sprintf("HTTP %d", cyc.status)),
		))
		return result, nil
	}

	// Compliant (PASS): a clear fragment-cycle validation error.
	if fragmentCycleRejectionPattern.Match(cyc.body) {
		result.PassReason = "Server correctly rejected the fragment cycle (spec-compliant validation)."
		result.PassProbes = cyclePassProbes(ctl, cyc)
		return result, nil
	}

	// Vulnerable: hang — super-linear latency versus the control with no
	// validation error.
	if cyc.latencyMS >= superLinearRatio*ctl.latencyMS && cyc.latencyMS >= superLinearFloorMS {
		result.Findings = append(result.Findings, c.finding(cc, cyc.req, cyc.payload,
			circularFindingDescription(doc,
				"the cycle probe latency was super-linear versus the control with no validation error (apparent validator hang)",
				ctl.latencyMS, cyc.latencyMS, fmt.Sprintf("HTTP %d", cyc.status)),
		))
		return result, nil
	}

	// Inconclusive but non-vulnerable: a clean response with no cycle error and
	// no hang — the server likely ignored the fragments.
	result.PassReason = "Server did not return a fragment-cycle validation error but also did not hang, " +
		"time out, or return 5xx (inconclusive but non-vulnerable); the cycle may have been silently ignored."
	result.PassProbes = cyclePassProbes(ctl, cyc)
	return result, nil
}

// probe marshals query into a GraphQL POST body, sends it via the probe client,
// and records the status, body, latency, request, and payload. The request and
// payload are populated even on a transport error so callers can still build
// repro / pass records (e.g. on a timeout).
func (c *circularFragmentCheck) probe(ctx context.Context, cc *CheckContext, query string) cycleProbeResult {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return cycleProbeResult{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return cycleProbeResult{payload: payload, err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return cycleProbeResult{req: req, payload: payload, err: err}
	}
	return cycleProbeResult{
		status:    resp.StatusCode,
		body:      resp.Body,
		req:       resp.Request,
		payload:   payload,
		latencyMS: resp.Latency.Milliseconds(),
	}
}

// finding builds a HIGH GQL-D03 finding with the shared metadata and the given
// description.
func (c *circularFragmentCheck) finding(cc *CheckContext, req *http.Request, body []byte, description string) Finding {
	return Finding{
		CheckID:      c.ID(),
		CheckName:    c.Name(),
		Severity:     HIGH,
		Category:     DenialOfService,
		Title:        "Fragment Cycle Not Rejected (Validator DoS)",
		Description:  description,
		Impact:       cycleImpact,
		Remediation:  cycleRemediation,
		References:   cycleReferences,
		ReproRequest: req,
		ReproBody:    body,
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "circular_fragment"),
	}
}

// cyclePassProbes returns the control + cycle probes for a clean (no-finding) run.
func cyclePassProbes(ctl, cyc cycleProbeResult) []PassProbe {
	return []PassProbe{
		{Label: "cycle-control (no fragments)", Request: ctl.req, Body: ctl.payload},
		{Label: "cycle-probe (circular fragments)", Request: cyc.req, Body: cyc.payload},
	}
}

// rootQueryTypeName returns the schema's query root type name, falling back to
// the literal "Query" when no schema (or no named query type) is available.
func rootQueryTypeName(s *schema.Schema) string {
	if s != nil && s.QueryType != nil && s.QueryType.Name != "" {
		return s.QueryType.Name
	}
	return "Query"
}

// buildCircularFragmentDoc builds a document whose two fragments spread each
// other, forming a cycle that a spec-compliant validator must reject:
//
//	query { ...A }
//	fragment A on <rootType> { __typename ...B }
//	fragment B on <rootType> { __typename ...A }
func buildCircularFragmentDoc(rootType string) string {
	return fmt.Sprintf(
		"query { ...A } fragment A on %s { __typename ...B } fragment B on %s { __typename ...A }",
		rootType, rootType,
	)
}

func circularFindingDescription(doc, signal string, controlMS, cycleMS int64, cycleStatusDesc string) string {
	return fmt.Sprintf(
		"The server did not reject a fragment-spread cycle with a clear validation error. The GraphQL "+
			"specification (§5.5.2.2, \"Fragment spreads must not form cycles\") requires servers to reject "+
			"documents whose fragments reference each other circularly; a server that instead recurses or "+
			"loops during validation/execution can be driven to exhaust CPU or stack from a single tiny "+
			"request.\n\n"+
			"Signal: %s.\n"+
			"Control: %dms (HTTP 200)    Cycle probe: %dms (%s)\n\n"+
			"Circular document sent:\n%s",
		signal, controlMS, cycleMS, cycleStatusDesc, doc,
	)
}

const cycleImpact = "A single small request can drive a non-compliant validator into unbounded recursion or " +
	"looping, exhausting CPU or stack and crashing the worker or hanging the request. The attacker cost is " +
	"negligible (one tiny document), making this a cheap and reliable denial-of-service primitive."

const cycleRemediation = "Upgrade to a spec-compliant GraphQL engine that enforces \"Fragment spreads must not " +
	"form cycles\" (GraphQL spec §5.5.2.2) and rejects circular fragments during validation, before execution. " +
	"Ensure validation runs ahead of execution, and add per-request timeouts and recursion/depth guards as " +
	"defence in depth."

var cycleReferences = []string{
	"https://spec.graphql.org/October2021/#sec-Fragment-spreads-must-not-form-cycles",
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
}
