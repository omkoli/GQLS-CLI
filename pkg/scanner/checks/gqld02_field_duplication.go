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

// dupCount is the fixed number of duplicated selections sent in the flood probe.
// It is a bounded constant (Safety): the check detects whether the server caps
// document size / duplicate selections, it must never attempt actual exhaustion.
const dupCount = 256

// superLinearRatio and superLinearFloorMS gate the secondary timing signal: a
// flood that takes at least superLinearRatio× the control AND at least
// superLinearFloorMS is treated as super-linear validation amplification.
const (
	superLinearRatio   = 10
	superLinearFloorMS = 1000
)

// documentSizeRejectionPattern matches response bodies that indicate the flood
// query was rejected or capped by a document-size / cost / complexity limiter
// rather than executed. A match means the protection appears to be enforced.
var documentSizeRejectionPattern = regexp.MustCompile(`(?i)too large|too many|complexity|cost|limit exceeded|maximum`)

// fieldDuplicationCheck implements GQL-D02: Field Duplication / __typename Flooding.
//
// Repeating the same selection many times in one document
// ({ __typename __typename ... }) stresses the parse → validate → field-merge
// pipeline before execution. Engines with quadratic validation cost (historic
// graphql-js advisories) amplify this into super-linear CPU from a small request
// (OWASP API4:2023).
type fieldDuplicationCheck struct{}

func init() {
	MustRegister(&fieldDuplicationCheck{})
}

func (c *fieldDuplicationCheck) ID() string           { return "GQL-D02" }
func (c *fieldDuplicationCheck) Name() string         { return "Field Duplication / __typename Flooding" }
func (c *fieldDuplicationCheck) Category() Category   { return DenialOfService }
func (c *fieldDuplicationCheck) Severity() Severity   { return HIGH }
func (c *fieldDuplicationCheck) RequiresSchema() bool { return false }

// dupProbeResult captures the outcome of a single duplication probe.
type dupProbeResult struct {
	status    int
	body      []byte
	req       *http.Request
	payload   []byte
	latencyMS int64
	err       error
}

// Run executes GQL-D02 against the target endpoint.
//
// It sends exactly two probes: a single-selection control to establish a fast
// live baseline, then one dupCount-duplicate flood. A finding fires when the
// flood is executed (HTTP 200 + data, no size/cost rejection), when it times out
// or returns 5xx after a fast control (CPU-amplification signal), or when flood
// latency is super-linear relative to the control.
func (c *fieldDuplicationCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Control probe (1 selection) ──────────────────────────────────────────
	ctl := c.probe(ctx, cc, "query { __typename }")
	result.ProbeCount++

	controlOK := ctl.err == nil && ctl.status == http.StatusOK && bytes.Contains(ctl.body, []byte(`"data"`))
	if !controlOK {
		result.PassReason = fmt.Sprintf(
			"endpoint did not respond to baseline probe (control query returned %s); "+
				"field duplication was not assessed",
			describeControlFailure(ctl.status, ctl.err),
		)
		if ctl.req != nil {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   "duplication-control (1 selection)",
				Request: ctl.req,
				Body:    ctl.payload,
			})
		}
		return result, nil
	}

	// ── Flood probe (dupCount duplicated selections) ─────────────────────────
	flood := c.probe(ctx, cc, buildDuplicatedQuery(dupCount))
	result.ProbeCount++

	// A timeout / network failure on the flood — but NOT a parent context
	// cancellation — is itself a positive CPU-amplification signal because the
	// control returned a fast 200.
	if flood.err != nil {
		if ctx.Err() != nil {
			result.Error = fmt.Errorf("field duplication probe cancelled: %w", flood.err)
			return result, nil
		}
		result.Findings = append(result.Findings, c.finding(cc, flood.req, flood.payload,
			floodUnresponsiveDescription(fmt.Sprintf("the request did not complete (%v)", flood.err), ctl.latencyMS),
		))
		return result, nil
	}

	// A 5xx under bounded duplication (control was fast 200) is likewise positive.
	if flood.status >= http.StatusInternalServerError {
		result.Findings = append(result.Findings, c.finding(cc, flood.req, flood.payload,
			floodUnresponsiveDescription(fmt.Sprintf("the server returned HTTP %d", flood.status), ctl.latencyMS),
		))
		return result, nil
	}

	hasData := bytes.Contains(flood.body, []byte(`"data"`))
	rejected := documentSizeRejectionPattern.Match(flood.body)
	structural := flood.status == http.StatusOK && hasData && !rejected
	superLinear := flood.latencyMS >= superLinearRatio*ctl.latencyMS && flood.latencyMS >= superLinearFloorMS

	if structural || superLinear {
		result.Findings = append(result.Findings, c.finding(cc, flood.req, flood.payload,
			floodAcceptedDescription(structural, superLinear, ctl.latencyMS, flood.latencyMS),
		))
		return result, nil
	}

	// ── Protected: size/cost rejection and no super-linear cost ──────────────
	result.PassReason = "Server limited or efficiently handled a 256-field duplicate query (document-size / cost limiting appears enforced)."
	result.PassProbes = []PassProbe{
		{Label: "duplication-control (1 selection)", Request: ctl.req, Body: ctl.payload},
		{Label: fmt.Sprintf("duplication-flood (%d selections)", dupCount), Request: flood.req, Body: flood.payload},
	}
	return result, nil
}

// probe marshals query into a GraphQL POST body, sends it via the probe client,
// and records the status, body, latency, request, and payload. The request and
// payload are populated even on a transport error so callers can still build
// repro / pass records (e.g. on a timeout).
func (c *fieldDuplicationCheck) probe(ctx context.Context, cc *CheckContext, query string) dupProbeResult {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return dupProbeResult{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return dupProbeResult{payload: payload, err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return dupProbeResult{req: req, payload: payload, err: err}
	}
	return dupProbeResult{
		status:    resp.StatusCode,
		body:      resp.Body,
		req:       resp.Request,
		payload:   payload,
		latencyMS: resp.Latency.Milliseconds(),
	}
}

// finding builds a HIGH GQL-D02 finding with the shared metadata and the given
// description.
func (c *fieldDuplicationCheck) finding(cc *CheckContext, req *http.Request, body []byte, description string) Finding {
	return Finding{
		CheckID:      c.ID(),
		CheckName:    c.Name(),
		Severity:     HIGH,
		Category:     DenialOfService,
		Title:        "No Document-Size / Field-Duplication Limit",
		Description:  description,
		Impact:       dupImpact,
		Remediation:  dupRemediation,
		References:   dupReferences,
		ReproRequest: req,
		ReproBody:    body,
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "field_duplication"),
	}
}

// buildDuplicatedQuery builds a GraphQL operation with the __typename meta-field
// repeated n times in a single selection set, e.g. n=3 →
// "query { __typename __typename __typename }".
func buildDuplicatedQuery(n int) string {
	var sb strings.Builder
	sb.WriteString("query {")
	for i := 0; i < n; i++ {
		sb.WriteString(" __typename")
	}
	sb.WriteString(" }")
	return sb.String()
}

func floodAcceptedDescription(structural, superLinear bool, controlMS, floodMS int64) string {
	var sb strings.Builder
	fmt.Fprintf(&sb,
		"The endpoint accepted a single GraphQL operation containing %d duplicated `__typename` "+
			"selections in one selection set. Duplicating identical selections forces the server "+
			"through its full parse → validate → field-merge pipeline for every repetition before "+
			"execution; engines with quadratic validation cost (e.g. historic graphql-js advisories) "+
			"amplify this into super-linear CPU.\n\n",
		dupCount,
	)
	fmt.Fprintf(&sb, "Control latency: %dms    Flood latency: %dms\n", controlMS, floodMS)

	var signals []string
	if structural {
		signals = append(signals, "structural acceptance (HTTP 200 with data, no size/cost rejection)")
	}
	if superLinear {
		signals = append(signals, fmt.Sprintf(
			"super-linear validation time (flood ≥ %d× control and ≥ %dms)",
			superLinearRatio, superLinearFloorMS,
		))
	}
	sb.WriteString("Signal(s) fired: ")
	sb.WriteString(strings.Join(signals, "; "))
	sb.WriteString(".")
	return sb.String()
}

func floodUnresponsiveDescription(outcome string, controlMS int64) string {
	return fmt.Sprintf(
		"A control query with a single `__typename` selection returned a fast HTTP 200 (%dms), but an "+
			"otherwise identical query carrying %d duplicated `__typename` selections did not complete "+
			"normally: %s. A bounded %d-duplicate document driving the server to time out or error is a "+
			"positive CPU-amplification signal — the server became unresponsive under field duplication "+
			"instead of enforcing a document-size / cost limit.",
		controlMS, dupCount, outcome, dupCount,
	)
}

const dupImpact = "An attacker can force super-linear parse and validation CPU with a small request body by " +
	"repeating identical selections. Because the cost is incurred before execution and the request looks " +
	"like a single ordinary query, sustained flooding can exhaust CPU and cause denial of service without " +
	"tripping per-request rate limits or per-resolver cost controls."

const dupRemediation = "Enforce a maximum document size / token count and a maximum selection-set width at the " +
	"validation layer, before execution. Add a request-body size cap at the gateway / reverse proxy, and " +
	"upgrade the GraphQL engine to a version with bounded (non-quadratic) validation. Combine with query " +
	"cost analysis so a large but shallow document is rejected before it is fully validated."

var dupReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
	"https://github.com/advisories?query=type%3Areviewed+graphql-js",
}
