package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// debugDevModeCheck implements GQL-M06: it detects production exposure of
// development tooling (GraphiQL, Playground, Apollo Sandbox, Altair, Voyager,
// Banana Cake Pop) and debug/development-mode behavior (framework debug pages,
// debug HTTP headers). It broadens GQL-004 (canonical /graphql Playground) to
// the full dev-tooling set served on dedicated paths plus a behavioral
// debug-mode signal, and coordinates with GQL-004 so the canonical-endpoint
// Playground is not double-reported.
//
// Safety: read-only GET probes over a bounded path set plus one erroring query.
type debugDevModeCheck struct{}

func init() {
	MustRegister(&debugDevModeCheck{})
}

func (c *debugDevModeCheck) ID() string           { return "GQL-M06" }
func (c *debugDevModeCheck) Name() string         { return "Debug Mode / Dev Tooling Exposed" }
func (c *debugDevModeCheck) Category() Category   { return InformationDisclosure }
func (c *debugDevModeCheck) Severity() Severity   { return LOW }
func (c *debugDevModeCheck) RequiresSchema() bool { return false }

// m06Sig is a (lowercase HTML/JS needle → short product label) signature.
type m06Sig struct {
	needle string
	label  string
}

// m06ToolPaths are the dedicated dev-tool paths probed in addition to the
// canonical endpoint. Together with the canonical probe this is 6 path probes.
var m06ToolPaths = []string{"/altair", "/voyager", "/graphiql", "/playground", "/sandbox"}

// m06ToolSignatures recognise the in-browser IDE/explorer shells.
var m06ToolSignatures = []m06Sig{
	{"altair", "Altair"},
	{"graphql-voyager", "Voyager"},
	{"voyager", "Voyager"},
	{"bananacakepop", "Banana Cake Pop"},
	{"banana cake pop", "Banana Cake Pop"},
	{"graphiql", "GraphiQL"},
	{"embeddable-sandbox", "Apollo Sandbox"},
	{"apollo-sandbox", "Apollo Sandbox"},
	{"graphql-playground", "GraphQL Playground"},
	{"graphql playground", "GraphQL Playground"},
}

// m06GQL004Tools are the tool labels GQL-004 already reports at the canonical
// endpoint; M06 suppresses these for the canonical path to avoid duplication.
var m06GQL004Tools = map[string]bool{
	"GraphiQL":           true,
	"GraphQL Playground": true,
	"Apollo Sandbox":     true,
}

// m06DebugBodySignatures recognise framework debug/development error pages.
// These are HTML debug consoles, distinct from the JSON error/extensions
// channels that GQL-005 / GQL-M03 cover.
var m06DebugBodySignatures = []m06Sig{
	{"werkzeug", "Werkzeug debugger"},
	{"whoops, looks like something went wrong", "Whoops error page"},
	{"action controller: exception caught", "Rails dev exception page"},
	{"sf-toolbar", "Symfony profiler"},
}

// m06Detection is one detected tool or debug-mode tell.
type m06Detection struct {
	label  string
	detail string
	isTool bool
}

// Run executes the debug / dev-tooling detection.
func (c *debugDevModeCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	var detections []m06Detection
	seen := map[string]bool{}
	var reproReq *http.Request
	var reproBody []byte
	var passProbes []PassProbe

	add := func(label, detail string, isTool bool) bool {
		if seen[label] {
			return false
		}
		seen[label] = true
		detections = append(detections, m06Detection{label: label, detail: detail, isTool: isTool})
		return true
	}

	// ── 1a. Canonical endpoint (Accept: text/html) — IDE shell. GQL-004 owns the
	// classic Playground here, so suppress the tools it already reports.
	if resp := m06GetHTML(ctx, cc, cc.Target); resp != nil {
		result.ProbeCount++
		passProbes = append(passProbes, PassProbe{Label: "Dev-tool probe (canonical, Accept: text/html)", Request: resp.Request})
		if resp.StatusCode == http.StatusOK {
			lower := m06LowerHead(resp.Body)
			for _, sig := range m06ToolSignatures {
				if strings.Contains(lower, sig.needle) && !m06GQL004Tools[sig.label] {
					if add(sig.label, fmt.Sprintf("%s dev IDE served at the canonical endpoint %s (matched %q).",
						sig.label, cc.Target, sig.needle), true) && reproReq == nil {
						reproReq = resp.Request
					}
				}
			}
		}
	}

	// ── 1b. Dedicated dev-tool paths.
	for _, p := range m06ToolPaths {
		if ctx.Err() != nil {
			break
		}
		pu, err := m06WithPath(cc.Target, p)
		if err != nil {
			continue
		}
		resp := m06GetHTML(ctx, cc, pu)
		if resp == nil {
			continue
		}
		result.ProbeCount++
		passProbes = append(passProbes, PassProbe{Label: "Dev-tool probe — " + p, Request: resp.Request})
		if resp.StatusCode != http.StatusOK {
			continue
		}
		lower := m06LowerHead(resp.Body)
		for _, sig := range m06ToolSignatures {
			if strings.Contains(lower, sig.needle) {
				if add(sig.label, fmt.Sprintf("%s dev IDE reachable at %s (matched %q).", sig.label, pu, sig.needle), true) &&
					reproReq == nil {
					reproReq = resp.Request
					reproBody = nil
				}
			}
		}
	}

	// ── 2. Debug-mode behavioral probe: one erroring query.
	if dbg := m06ErrorProbe(ctx, cc); dbg != nil {
		result.ProbeCount++
		passProbes = append(passProbes, PassProbe{Label: "Debug-mode probe — erroring query", Request: dbg.Request, Body: m06ErrBody})
		lower := m06LowerHead(dbg.Body)
		for _, sig := range m06DebugBodySignatures {
			if strings.Contains(lower, sig.needle) {
				if add(sig.label, fmt.Sprintf("%s observed in the error response — the server appears to run in "+
					"debug/development mode.", sig.label), false) && reproReq == nil {
					reproReq = dbg.Request
					reproBody = m06ErrBody
				}
			}
		}
		for k := range dbg.Headers {
			if strings.HasPrefix(strings.ToLower(k), "x-debug") {
				if add("debug HTTP header", fmt.Sprintf("Response carries a debug header (%s), indicating "+
					"debug/development mode.", k), false) && reproReq == nil {
					reproReq = dbg.Request
					reproBody = m06ErrBody
				}
				break
			}
		}
	}

	if len(detections) == 0 {
		result.PassReason = "No additional dev tooling (Altair, Voyager, GraphiQL, Playground, Sandbox, Banana " +
			"Cake Pop) was reachable on the probed paths, and no debug/development-mode behavior was observed."
		result.PassProbes = passProbes
		return result, nil
	}

	sort.Slice(detections, func(i, j int) bool { return detections[i].label < detections[j].label })
	labels := make([]string, 0, len(detections))
	details := make([]string, 0, len(detections))
	hasTool := false
	for _, d := range detections {
		labels = append(labels, d.label)
		details = append(details, d.detail)
		if d.isTool {
			hasTool = true
		}
	}

	confidence := "firm" // behavioral debug-mode tell
	if hasTool {
		confidence = "confirmed" // a tool fingerprint matched
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  c.Severity(),
		Category:  c.Category(),
		Title:     "Debug Mode / Dev Tooling Exposed — " + strings.Join(labels, ", "),
		Description: fmt.Sprintf(
			"Development tooling and/or debug-mode indicators are exposed at %s. %s "+
				"(GQL-004 covers the canonical-endpoint Playground; GQL-M06 reports the additional tools "+
				"and the debug-mode behavior.)",
			cc.Target, strings.Join(details, " ")),
		Impact: "Dev consoles and debug pages give attackers a browser query IDE, schema explorer, and verbose " +
			"server internals on production — accelerating reconnaissance and exploitation of every other weakness.",
		Remediation: "Disable GraphiQL/Playground/Altair/Voyager/Sandbox/Banana Cake Pop and any " +
			"debug/development mode in production; ensure framework debug pages (Werkzeug, Whoops, Rails, " +
			"Symfony) are off; return generic errors.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		ReproRequest: reproReq,
		ReproBody:    reproBody,
		Confidence:   confidence,
		CWE:          "CWE-489",
		OWASP:        "API8:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "debug_dev:"+strings.Join(labels, ",")),
	})
	return result, nil
}

// m06GetHTML issues a GET with an HTML Accept header, returning nil on error.
func m06GetHTML(ctx context.Context, cc *CheckContext, target string) *transport.Response {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return nil
	}
	return resp
}

// m06ErrBody is the deliberately-erroring query used for the debug-mode probe.
var m06ErrBody = []byte(`{"query":"{ __typename { gqls_m06_invalid } }"}`)

// m06ErrorProbe POSTs an erroring query to elicit debug-mode error pages.
func m06ErrorProbe(ctx context.Context, cc *CheckContext) *transport.Response {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(m06ErrBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return nil
	}
	return resp
}

// m06WithPath returns target with its path replaced by p and query cleared.
func m06WithPath(target, p string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	u.Path = p
	u.RawQuery = ""
	return u.String(), nil
}

// m06LowerHead lowercases up to the first 64 KiB of body for signature scanning.
func m06LowerHead(body []byte) string {
	const max = 64 * 1024
	if len(body) > max {
		body = body[:max]
	}
	return strings.ToLower(string(body))
}
