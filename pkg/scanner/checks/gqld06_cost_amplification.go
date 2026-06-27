package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Amplification thresholds (constants; tuned via tests).
const (
	// afSizeThreshold is the response-size amplification factor (max response
	// bytes ÷ its request bytes) above which the endpoint is flagged.
	afSizeThreshold = 50.0
	// afLatThreshold is the latency amplification factor (max ÷ min latency)
	// above which the latency signal contributes.
	afLatThreshold = 10.0
	// afLatFloorMS is the minimum baseline latency (ms) required before the
	// latency factor is meaningful; below it, latency is marked inconclusive.
	afLatFloorMS = 5
	// afLatMaxFloorMS is the minimum peak latency (ms) required for the latency
	// signal to fire (avoids flagging fast-but-variable endpoints).
	afLatMaxFloorMS = 750
)

// costRejectionPattern matches response bodies that indicate a gradient step was
// rejected by query-cost / complexity analysis. A match means cost limiting
// appears effective, so no finding is produced.
var costRejectionPattern = regexp.MustCompile(
	`(?i)complexity|too complex|exceeds maximum|cost limit|query cost|operation cost|maximum cost|over budget`,
)

// costGradient is the bounded series of (depth, alias-width) steps, ordered
// cheapest-first. Every step stays within the per-check caps (depth ≤ 6,
// aliases ≤ 16) so no single probe is itself an abusive payload (Safety).
var costGradient = []struct{ depth, width int }{
	{2, 1},
	{4, 8},
	{6, 16},
}

// costAmplificationCheck implements GQL-D06: Query Cost Amplification.
//
// It is an amplification oracle: it sends a graded series of bounded queries of
// increasing structural cost and computes how much server work (response bytes,
// latency) a small request produces. A high amplification factor with no
// cost-limit rejection demonstrates the absence of effective query-cost analysis
// (OWASP API4:2023).
type costAmplificationCheck struct{}

func init() {
	MustRegister(&costAmplificationCheck{})
}

func (c *costAmplificationCheck) ID() string           { return "GQL-D06" }
func (c *costAmplificationCheck) Name() string         { return "Query Cost Amplification" }
func (c *costAmplificationCheck) Category() Category   { return DenialOfService }
func (c *costAmplificationCheck) Severity() Severity   { return MEDIUM }
func (c *costAmplificationCheck) RequiresSchema() bool { return false }

// costStep captures one gradient step's request and the measured response.
type costStep struct {
	depth, width int
	reqBytes     int
	respBytes    int
	latencyMS    int64
	status       int
	hasData      bool
	rejected     bool
	err          error
	req          *http.Request
	payload      []byte
}

// Run executes GQL-D06 against the target endpoint.
func (c *costAmplificationCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	field := findBestNestableField(cc.Schema)

	// Send the bounded gradient, cheapest first.
	steps := make([]costStep, 0, len(costGradient))
	for _, g := range costGradient {
		if ctx.Err() != nil {
			break
		}
		step := c.probe(ctx, cc, buildCostQuery(field, g.depth, g.width))
		step.depth, step.width = g.depth, g.width
		result.ProbeCount++
		steps = append(steps, step)
	}

	// Evaluate cleanliness and rejection across all steps.
	allClean := len(steps) == len(costGradient)
	anyRejected := false
	for _, s := range steps {
		if s.err != nil || s.status != http.StatusOK || !s.hasData {
			allClean = false
		}
		if s.rejected {
			anyRejected = true
		}
	}

	afSize, best := computeAFSize(steps)
	afLat, maxLat, latOK := computeAFLat(steps)

	sizeSignal := afSize >= afSizeThreshold
	latSignal := latOK && afLat >= afLatThreshold && maxLat >= afLatMaxFloorMS

	if allClean && !anyRejected && (sizeSignal || latSignal) {
		result.Findings = append(result.Findings, Finding{
			CheckID:      c.ID(),
			CheckName:    c.Name(),
			Severity:     MEDIUM,
			Category:     DenialOfService,
			Title:        "High Query-Cost Amplification (No Effective Cost Limit)",
			Description:  costFindingDescription(steps, afSize, afLat, latOK, maxLat),
			Impact:       costImpact,
			Remediation:  costRemediation,
			References:   costReferences,
			ReproRequest: best.req,
			ReproBody:    best.payload,
			Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "cost_amplification"),
		})
		return result, nil
	}

	if anyRejected {
		result.PassReason = "Server rejected the cost gradient with a complexity/cost error (cost limiting appears effective)."
	} else {
		result.PassReason = "Measured amplification stayed within safe bounds or the server rejected the cost gradient (cost limiting appears effective)."
	}
	result.PassProbes = gradientPassProbes(steps)
	return result, nil
}

// probe marshals query into a GraphQL POST body, sends it via the probe client,
// and records the request/response metrics. The request and payload are
// populated even on a transport error so callers can still build pass records.
func (c *costAmplificationCheck) probe(ctx context.Context, cc *CheckContext, query string) costStep {
	step := costStep{}
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		step.err = err
		return step
	}
	step.payload = payload
	step.reqBytes = len(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		step.err = err
		return step
	}
	req.Header.Set("Content-Type", "application/json")
	step.req = req

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		step.err = err
		return step
	}
	step.status = resp.StatusCode
	step.respBytes = len(resp.Body)
	step.latencyMS = resp.Latency.Milliseconds()
	step.hasData = bytes.Contains(resp.Body, []byte(`"data"`))
	step.rejected = costRejectionPattern.Match(resp.Body)
	step.req = resp.Request
	return step
}

// computeAFSize returns the response-size amplification factor — the largest
// response divided by that step's request bytes — and the step that produced it.
func computeAFSize(steps []costStep) (float64, costStep) {
	var best costStep
	maxResp := -1
	for _, s := range steps {
		if s.respBytes > maxResp {
			maxResp = s.respBytes
			best = s
		}
	}
	if best.reqBytes <= 0 {
		return 0, best
	}
	return float64(best.respBytes) / float64(best.reqBytes), best
}

// computeAFLat returns the latency amplification factor (max ÷ min latency), the
// peak latency, and whether the measurement is conclusive. It is inconclusive
// when no step completed or the baseline latency is below the noise floor.
func computeAFLat(steps []costStep) (float64, int64, bool) {
	var minLat, maxLat int64
	have := false
	for _, s := range steps {
		if s.err != nil {
			continue
		}
		if !have {
			minLat, maxLat, have = s.latencyMS, s.latencyMS, true
			continue
		}
		if s.latencyMS < minLat {
			minLat = s.latencyMS
		}
		if s.latencyMS > maxLat {
			maxLat = s.latencyMS
		}
	}
	if !have || minLat < afLatFloorMS {
		return 0, maxLat, false
	}
	return float64(maxLat) / float64(minLat), maxLat, true
}

// buildCostQuery builds a query of width aliases, each a nested chain of field at
// the given depth. For the introspection fallback (field == "__schema") each
// alias is a depth-graded introspection body instead.
func buildCostQuery(field string, depth, width int) string {
	var sb strings.Builder
	sb.WriteString("query {")
	for i := 0; i < width; i++ {
		if field == "__schema" {
			fmt.Fprintf(&sb, " a%d: %s", i, introspectionBody(depth))
		} else {
			fmt.Fprintf(&sb, " a%d: %s", i, buildFieldChain(field, depth))
		}
	}
	sb.WriteString(" }")
	return sb.String()
}

// buildFieldChain nests field depth times, ending in a __typename leaf, e.g.
// depth 2 → "field { field { __typename } }".
func buildFieldChain(field string, depth int) string {
	inner := "{ __typename }"
	for i := 1; i < depth; i++ {
		inner = "{ " + field + " " + inner + " }"
	}
	return field + " " + inner
}

// introspectionBody returns an alias-able introspection selection that deepens
// with depth by cycling __schema → queryType → fields → type → fields → ...
func introspectionBody(depth int) string {
	inner := "kind"
	for i := 0; i < depth; i++ {
		inner = "fields { type { " + inner + " } }"
	}
	return "__schema { queryType { " + inner + " } }"
}

func gradientPassProbes(steps []costStep) []PassProbe {
	var pp []PassProbe
	for _, s := range steps {
		if s.req == nil {
			continue
		}
		var label string
		if s.err != nil {
			label = fmt.Sprintf("cost-step depth=%d width=%d — req %dB, error: %v", s.depth, s.width, s.reqBytes, s.err)
		} else {
			label = fmt.Sprintf("cost-step depth=%d width=%d — req %dB resp %dB %dms HTTP %d",
				s.depth, s.width, s.reqBytes, s.respBytes, s.latencyMS, s.status)
		}
		pp = append(pp, PassProbe{Label: label, Request: s.req, Body: s.payload})
	}
	return pp
}

func costFindingDescription(steps []costStep, afSize, afLat float64, latOK bool, maxLat int64) string {
	var sb strings.Builder
	sb.WriteString("The endpoint executed a graded series of bounded queries (depth ≤ 6, aliases ≤ 16) ")
	sb.WriteString("without any cost/complexity rejection, and the response size grew steeply with ")
	sb.WriteString("structural query cost — demonstrating the absence of effective query-cost analysis.\n\n")
	sb.WriteString("Gradient (cheapest first):\n")
	sb.WriteString("  depth  width   req(B)   resp(B)   latency\n")
	for _, s := range steps {
		if s.err != nil {
			fmt.Fprintf(&sb, "  %5d  %5d   %6d   error: %v\n", s.depth, s.width, s.reqBytes, s.err)
			continue
		}
		fmt.Fprintf(&sb, "  %5d  %5d   %6d   %7d   %dms (HTTP %d)\n",
			s.depth, s.width, s.reqBytes, s.respBytes, s.latencyMS, s.status)
	}
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "Size amplification (AF_size):   %.0f× (largest response ÷ its request bytes)\n", afSize)
	if latOK {
		fmt.Fprintf(&sb, "Latency amplification (AF_lat): %.1f× (max ÷ min latency; peak %dms)", afLat, maxLat)
	} else {
		sb.WriteString("Latency amplification (AF_lat): inconclusive (baseline latency below noise floor)")
	}
	return sb.String()
}

const costImpact = "An attacker can convert minimal request bandwidth into large server CPU, memory, IO, and " +
	"egress, enabling cost-efficient denial of service and inflated infrastructure billing (economic DoS). " +
	"Because each probe is individually small and well-formed, the amplification bypasses request-count rate " +
	"limiting."

const costRemediation = "Implement query-cost / complexity analysis with a hard ceiling computed before " +
	"execution (e.g. graphql-cost-analysis, Apollo operation cost limits, gqlgen complexity). Weight list " +
	"sizes and nesting depth in the cost, and reject over-budget operations with an HTTP 4xx before they run."

var costReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
	"https://www.howtographql.com/advanced/4-security/",
}
