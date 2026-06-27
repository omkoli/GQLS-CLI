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

// directiveCount is the fixed number of repeated directives sent in the overload
// probe. It is a bounded constant (Safety): the check detects whether the server
// caps repeated directives, it must never attempt actual exhaustion.
const directiveCount = 200

// directiveUniquenessRejectionPattern matches response bodies that indicate the
// overload query was rejected because directives must be unique per location, or
// because a directive-count / cost limiter capped it. A match means the
// protection appears to be enforced.
var directiveUniquenessRejectionPattern = regexp.MustCompile(
	`(?i)duplicate|can only be used once|repeated|too many directives|non-repeatable`,
)

// directiveOverloadingCheck implements GQL-D04: Directive Overloading.
//
// The GraphQL spec requires directives to be unique per location, but several
// engines (historically graphql-js — see GHSA directive-amplification advisories)
// accepted and processed thousands of repeated directives, causing super-linear
// validation/CPU cost from a small request
// ({ __typename @skip(if:false) @skip(if:false) ... }) — OWASP API4:2023.
type directiveOverloadingCheck struct{}

func init() {
	MustRegister(&directiveOverloadingCheck{})
}

func (c *directiveOverloadingCheck) ID() string           { return "GQL-D04" }
func (c *directiveOverloadingCheck) Name() string         { return "Directive Overloading" }
func (c *directiveOverloadingCheck) Category() Category   { return DenialOfService }
func (c *directiveOverloadingCheck) Severity() Severity   { return MEDIUM }
func (c *directiveOverloadingCheck) RequiresSchema() bool { return false }

// directiveProbeResult captures the outcome of a single directive probe.
type directiveProbeResult struct {
	status    int
	body      []byte
	req       *http.Request
	payload   []byte
	latencyMS int64
	err       error
}

// Run executes GQL-D04 against the target endpoint.
//
// It sends exactly two probes: a single-directive control to establish a fast
// live baseline, then one directiveCount-directive overload. A finding fires
// when the overload is executed (HTTP 200 + data, no uniqueness/cost rejection),
// when it times out or returns 5xx after a fast control, or when its latency is
// super-linear relative to the control.
func (c *directiveOverloadingCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Control probe (1 directive) ──────────────────────────────────────────
	ctl := c.probe(ctx, cc, "query { __typename @skip(if: false) }")
	result.ProbeCount++

	controlOK := ctl.err == nil && ctl.status == http.StatusOK && bytes.Contains(ctl.body, []byte(`"data"`))
	if !controlOK {
		result.PassReason = fmt.Sprintf(
			"endpoint did not respond to baseline probe (control query returned %s); "+
				"directive overloading was not assessed",
			describeControlFailure(ctl.status, ctl.err),
		)
		if ctl.req != nil {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   "directive-control (1 directive)",
				Request: ctl.req,
				Body:    ctl.payload,
			})
		}
		return result, nil
	}

	// ── Overload probe (directiveCount repeated directives) ──────────────────
	over := c.probe(ctx, cc, buildDirectiveOverloadQuery(directiveCount))
	result.ProbeCount++

	// A timeout / network failure on the overload — but NOT a parent context
	// cancellation — is itself a positive CPU-amplification signal because the
	// control returned a fast 200.
	if over.err != nil {
		if ctx.Err() != nil {
			result.Error = fmt.Errorf("directive overloading probe cancelled: %w", over.err)
			return result, nil
		}
		result.Findings = append(result.Findings, c.finding(cc, over.req, over.payload,
			overloadUnresponsiveDescription(fmt.Sprintf("the request did not complete (%v)", over.err), ctl.latencyMS),
		))
		return result, nil
	}

	// A 5xx under bounded directive repetition (control was fast 200) is positive.
	if over.status >= http.StatusInternalServerError {
		result.Findings = append(result.Findings, c.finding(cc, over.req, over.payload,
			overloadUnresponsiveDescription(fmt.Sprintf("the server returned HTTP %d", over.status), ctl.latencyMS),
		))
		return result, nil
	}

	hasData := bytes.Contains(over.body, []byte(`"data"`))
	rejected := directiveUniquenessRejectionPattern.Match(over.body)
	structural := over.status == http.StatusOK && hasData && !rejected
	superLinear := over.latencyMS >= superLinearRatio*ctl.latencyMS && over.latencyMS >= superLinearFloorMS

	if structural || superLinear {
		result.Findings = append(result.Findings, c.finding(cc, over.req, over.payload,
			overloadAcceptedDescription(structural, superLinear, ctl.latencyMS, over.latencyMS),
		))
		return result, nil
	}

	// ── Protected: uniqueness/cost rejection and no super-linear cost ────────
	result.PassReason = "Server rejected or efficiently handled 200 repeated directives (directive uniqueness / cost limiting appears enforced)."
	result.PassProbes = []PassProbe{
		{Label: "directive-control (1 directive)", Request: ctl.req, Body: ctl.payload},
		{Label: fmt.Sprintf("directive-overload (%d directives)", directiveCount), Request: over.req, Body: over.payload},
	}
	return result, nil
}

// probe marshals query into a GraphQL POST body, sends it via the probe client,
// and records the status, body, latency, request, and payload. The request and
// payload are populated even on a transport error so callers can still build
// repro / pass records (e.g. on a timeout).
func (c *directiveOverloadingCheck) probe(ctx context.Context, cc *CheckContext, query string) directiveProbeResult {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return directiveProbeResult{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return directiveProbeResult{payload: payload, err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return directiveProbeResult{req: req, payload: payload, err: err}
	}
	return directiveProbeResult{
		status:    resp.StatusCode,
		body:      resp.Body,
		req:       resp.Request,
		payload:   payload,
		latencyMS: resp.Latency.Milliseconds(),
	}
}

// finding builds a MEDIUM GQL-D04 finding with the shared metadata and the given
// description.
func (c *directiveOverloadingCheck) finding(cc *CheckContext, req *http.Request, body []byte, description string) Finding {
	return Finding{
		CheckID:      c.ID(),
		CheckName:    c.Name(),
		Severity:     MEDIUM,
		Category:     DenialOfService,
		Title:        "No Directive-Count Limit (Directive Overloading)",
		Description:  description,
		Impact:       directiveImpact,
		Remediation:  directiveRemediation,
		References:   directiveReferences,
		ReproRequest: req,
		ReproBody:    body,
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "directive_overloading"),
	}
}

// buildDirectiveOverloadQuery builds a GraphQL operation applying the built-in
// @skip(if: false) directive n times to a single __typename selection, e.g. n=2
// → "query { __typename @skip(if: false) @skip(if: false) }".
func buildDirectiveOverloadQuery(n int) string {
	var sb strings.Builder
	sb.WriteString("query { __typename")
	for i := 0; i < n; i++ {
		sb.WriteString(" @skip(if: false)")
	}
	sb.WriteString(" }")
	return sb.String()
}

func overloadAcceptedDescription(structural, superLinear bool, controlMS, overloadMS int64) string {
	var sb strings.Builder
	fmt.Fprintf(&sb,
		"The endpoint accepted a single GraphQL operation applying the built-in `@skip` directive %d "+
			"times at one location. The GraphQL spec requires directives to be unique per location; "+
			"engines that instead accept and process repeated directives incur super-linear validation "+
			"CPU (historic graphql-js directive-amplification advisories) from a small request.\n\n",
		directiveCount,
	)
	fmt.Fprintf(&sb, "Control latency: %dms    Overload latency: %dms\n", controlMS, overloadMS)

	var signals []string
	if structural {
		signals = append(signals, "structural acceptance (HTTP 200 with data, no uniqueness/cost rejection)")
	}
	if superLinear {
		signals = append(signals, fmt.Sprintf(
			"super-linear validation time (overload ≥ %d× control and ≥ %dms)",
			superLinearRatio, superLinearFloorMS,
		))
	}
	sb.WriteString("Signal(s) fired: ")
	sb.WriteString(strings.Join(signals, "; "))
	sb.WriteString(".")
	return sb.String()
}

func overloadUnresponsiveDescription(outcome string, controlMS int64) string {
	return fmt.Sprintf(
		"A control query applying `@skip` once returned a fast HTTP 200 (%dms), but an otherwise "+
			"identical query applying %d repeated `@skip` directives at the same location did not "+
			"complete normally: %s. A bounded %d-directive document driving the server to time out or "+
			"error is a positive CPU-amplification signal — the server became unresponsive under "+
			"directive repetition instead of enforcing directive-uniqueness / cost limiting.",
		controlMS, directiveCount, outcome, directiveCount,
	)
}

const directiveImpact = "An attacker can force super-linear validation CPU with a small request body by " +
	"repeating a directive many times at one location. Because the cost is incurred during validation and " +
	"the request looks like a single ordinary query, sustained abuse can exhaust CPU and cause denial of " +
	"service without tripping per-request rate limits or per-resolver cost controls."

const directiveRemediation = "Upgrade to a GraphQL engine that enforces directive-uniqueness validation per " +
	"the spec (\"Directives Are Unique Per Location\"). Add a maximum-directives-per-location limit and an " +
	"overall document-cost limit at the validation layer, before execution, and cap the request-body size at " +
	"the gateway."

var directiveReferences = []string{
	"https://spec.graphql.org/October2021/#sec-Directives-Are-Unique-Per-Location",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
	"https://github.com/advisories?query=type%3Areviewed+graphql-js+directive",
}
