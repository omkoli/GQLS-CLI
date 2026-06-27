package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Introspection amplification thresholds (constants; tuned via tests).
const (
	// introspectionByteFloor is the absolute amplified-response size (bytes,
	// ≈1 MB) above which the endpoint is flagged regardless of ratio.
	introspectionByteFloor = 1_000_000
	// introspectionSizeRatio is the amplified ÷ baseline size factor above which
	// the size signal fires.
	introspectionSizeRatio = 20
	// introspectionLatRatio and introspectionLatFloorMS gate the latency signal.
	introspectionLatRatio   = 10
	introspectionLatFloorMS = 1000
)

// introspectionDoSCheck implements GQL-D08: Unbounded Introspection Amplification.
//
// A single bounded-but-recursive introspection query (deeply nested ofType /
// fields chains) can force the server to serialize a very large schema response.
// When introspection is enabled in production and unbounded, attackers get a
// cheap, unauthenticated amplification + reconnaissance primitive (OWASP
// API4:2023).
type introspectionDoSCheck struct{}

func init() {
	MustRegister(&introspectionDoSCheck{})
}

func (c *introspectionDoSCheck) ID() string           { return "GQL-D08" }
func (c *introspectionDoSCheck) Name() string         { return "Unbounded Introspection Amplification" }
func (c *introspectionDoSCheck) Category() Category   { return DenialOfService }
func (c *introspectionDoSCheck) Severity() Severity   { return LOW }
func (c *introspectionDoSCheck) RequiresSchema() bool { return false }

// introspectionProbeResult captures one introspection probe's measured response.
type introspectionProbeResult struct {
	status    int
	respBytes int
	latencyMS int64
	hasData   bool
	req       *http.Request
	payload   []byte
	err       error
}

// Run executes GQL-D08 against the target endpoint.
func (c *introspectionDoSCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// Short-circuit when the schema metadata already proves introspection is off.
	if cc.Schema != nil && !cc.Schema.Metadata.IntrospectionEnabled {
		result.PassReason = "introspection disabled — not applicable"
		return result, nil
	}

	// ── Baseline introspection probe ─────────────────────────────────────────
	baseline := c.probe(ctx, cc, "query { __schema { queryType { name } } }")
	result.ProbeCount++
	baselineOK := baseline.err == nil && baseline.status == http.StatusOK && baseline.hasData
	if !baselineOK {
		result.PassReason = "introspection disabled — not applicable (baseline introspection probe was rejected)"
		if baseline.req != nil {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   "introspection-baseline",
				Request: baseline.req,
				Body:    baseline.payload,
			})
		}
		return result, nil
	}

	if ctx.Err() != nil {
		result.PassReason = "introspection amplification not assessed (cancelled before the amplified probe)"
		return result, nil
	}

	// ── Amplified introspection probe (bounded) ──────────────────────────────
	amplified := c.probe(ctx, cc, buildAmplifiedIntrospectionQuery())
	result.ProbeCount++

	amplifiedOK := amplified.err == nil && amplified.status == http.StatusOK && amplified.hasData
	sizeSignal := amplifiedOK &&
		(amplified.respBytes >= introspectionByteFloor || amplified.respBytes >= introspectionSizeRatio*baseline.respBytes)
	latSignal := amplifiedOK &&
		amplified.latencyMS >= introspectionLatRatio*baseline.latencyMS && amplified.latencyMS >= introspectionLatFloorMS

	if sizeSignal || latSignal {
		result.Findings = append(result.Findings, Finding{
			CheckID:      c.ID(),
			CheckName:    c.Name(),
			Severity:     LOW,
			Category:     DenialOfService,
			Title:        "Unbounded Introspection Response (Amplification + Recon)",
			Description:  introspectionFindingDescription(baseline, amplified),
			Impact:       introspectionImpact,
			Remediation:  introspectionRemediation,
			References:   introspectionReferences,
			ReproRequest: amplified.req,
			ReproBody:    amplified.payload,
			Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "introspection_dos"),
		})
		return result, nil
	}

	result.PassReason = "Introspection response size/latency stayed within safe bounds (introspection is either disabled or bounded)."
	result.PassProbes = []PassProbe{
		{Label: fmt.Sprintf("introspection-baseline (%dB, %dms)", baseline.respBytes, baseline.latencyMS),
			Request: baseline.req, Body: baseline.payload},
		{Label: fmt.Sprintf("introspection-amplified (%dB, %dms)", amplified.respBytes, amplified.latencyMS),
			Request: amplified.req, Body: amplified.payload},
	}
	return result, nil
}

// probe sends query as a JSON POST via the probe client and records the measured
// response. The request and payload are populated even on a transport error.
func (c *introspectionDoSCheck) probe(ctx context.Context, cc *CheckContext, query string) introspectionProbeResult {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return introspectionProbeResult{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return introspectionProbeResult{payload: payload, err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return introspectionProbeResult{req: req, payload: payload, err: err}
	}
	return introspectionProbeResult{
		status:    resp.StatusCode,
		respBytes: len(resp.Body),
		latencyMS: resp.Latency.Milliseconds(),
		hasData:   bytes.Contains(resp.Body, []byte(`"data"`)),
		req:       resp.Request,
		payload:   payload,
	}
}

// buildAmplifiedIntrospectionQuery returns a single bounded recursive
// introspection query: it walks every type's fields and arguments and expands
// the TypeRef ofType chain to a fixed 8-level depth. The nesting is capped (one
// request, depth ≤ 8) so the probe measures amplification without escalating.
func buildAmplifiedIntrospectionQuery() string {
	ofType := "kind name"
	for i := 0; i < 8; i++ {
		ofType = "kind name ofType { " + ofType + " }"
	}
	typeRef := "{ " + ofType + " }"
	return "query { __schema { types { name kind fields { name type " + typeRef +
		" args { name type " + typeRef + " } } inputFields { name type " + typeRef + " } } } }"
}

func introspectionFindingDescription(baseline, amplified introspectionProbeResult) string {
	var sb strings.Builder
	sb.WriteString("Introspection is enabled and unbounded: a single recursive introspection query produced a ")
	sb.WriteString("disproportionately large response, making the introspection system itself an amplification ")
	sb.WriteString("and reconnaissance primitive.\n\n")
	fmt.Fprintf(&sb, "Baseline  { __schema { queryType { name } } }: %d bytes, %dms\n",
		baseline.respBytes, baseline.latencyMS)
	fmt.Fprintf(&sb, "Amplified recursive introspection:            %d bytes, %dms\n",
		amplified.respBytes, amplified.latencyMS)
	if baseline.respBytes > 0 {
		fmt.Fprintf(&sb, "\nSize amplification: %.0f× baseline.", float64(amplified.respBytes)/float64(baseline.respBytes))
	}
	return sb.String()
}

const introspectionImpact = "A single unauthenticated request yields a large response — bandwidth and CPU " +
	"amplification plus full schema disclosure for attack planning. Repeated requests are a low-cost " +
	"availability and egress-cost attack, and the disclosed schema accelerates every other attack against the API."

const introspectionRemediation = "Disable introspection in production (the primary control). If it must remain " +
	"enabled, apply response-size / complexity limits to introspection queries and rate-limit them, and " +
	"restrict introspection to authenticated internal users."

var introspectionReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://spec.graphql.org/October2021/#sec-Introspection",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
}
