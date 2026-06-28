package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// corsMisconfigurationCheck implements GQL-M07: it detects dangerous CORS
// configuration on the GraphQL endpoint — origin reflection or wildcard ACAO
// combined with Access-Control-Allow-Credentials, plus null-origin acceptance —
// which lets a malicious website read authenticated GraphQL responses using the
// victim's cookies (CWE-942 / OWASP API8).
//
// Safety: read-only header probes with synthetic Origin values. No data is
// exfiltrated — the finding is the header configuration itself.
type corsMisconfigurationCheck struct{}

func init() {
	MustRegister(&corsMisconfigurationCheck{})
}

func (c *corsMisconfigurationCheck) ID() string           { return "GQL-M07" }
func (c *corsMisconfigurationCheck) Name() string         { return "CORS Misconfiguration" }
func (c *corsMisconfigurationCheck) Category() Category   { return InformationDisclosure }
func (c *corsMisconfigurationCheck) Severity() Severity   { return MEDIUM }
func (c *corsMisconfigurationCheck) RequiresSchema() bool { return false }

// m07AttackerOrigin is the synthetic, attacker-controlled origin used to test
// for reflection. It is a domain the operator does not own.
const m07AttackerOrigin = "https://gqls-evil.example"

// corsPattern classifies a CORS observation by danger.
type corsPattern struct {
	key      string // stable fingerprint key
	titleSeg string // short title segment
	label    string // human-readable description
	severity Severity
}

// Patterns ordered high → low so the most severe present one is chosen.
var (
	cpReflectCreds  = corsPattern{"reflect+credentials", "reflected origin + credentials", "arbitrary-origin reflection combined with Access-Control-Allow-Credentials: true", HIGH}
	cpWildcardCreds = corsPattern{"wildcard+credentials", "wildcard origin + credentials", "wildcard Access-Control-Allow-Origin (*) combined with credentials (spec-invalid, but emitted by some stacks)", MEDIUM}
	cpNullCreds     = corsPattern{"null+credentials", "null origin + credentials", "null-origin acceptance combined with credentials (exploitable from a sandboxed iframe)", MEDIUM}
	cpReflect       = corsPattern{"reflect", "reflected origin", "arbitrary-origin reflection (any site is echoed into Access-Control-Allow-Origin)", MEDIUM}
	cpWildcard      = corsPattern{"wildcard", "wildcard origin", "wildcard Access-Control-Allow-Origin (*) — cross-origin readable (unauthenticated)", LOW}
	cpNull          = corsPattern{"null", "null origin", "null-origin acceptance (unauthenticated)", LOW}
)

// corsPriority orders patterns for deterministic primary-pattern selection.
var corsPriority = []corsPattern{cpReflectCreds, cpWildcardCreds, cpNullCreds, cpReflect, cpWildcard, cpNull}

// corsObs records one probe's CORS-relevant response headers and its verdict.
type corsObs struct {
	probe   string
	origin  string
	acao    string
	acac    bool
	vary    string
	pattern *corsPattern
	req     *http.Request
}

// Run executes the CORS misconfiguration check.
func (c *corsMisconfigurationCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	host := m07TargetHost(cc.Target)
	suffixOrigin := "https://" + host + ".gqls-evil.example" // suffix-match bypass probe

	probes := []struct{ label, method, origin string }{
		{"preflight OPTIONS (attacker origin)", http.MethodOptions, m07AttackerOrigin},
		{"POST (attacker origin)", http.MethodPost, m07AttackerOrigin},
		{"POST (null origin)", http.MethodPost, "null"},
		{"POST (subdomain-suffix origin)", http.MethodPost, suffixOrigin},
	}

	var observations []corsObs
	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		resp := m07Send(ctx, cc, p.method, p.origin)
		result.ProbeCount++
		if resp == nil {
			continue
		}
		acao := strings.TrimSpace(resp.Headers.Get("Access-Control-Allow-Origin"))
		acac := strings.EqualFold(strings.TrimSpace(resp.Headers.Get("Access-Control-Allow-Credentials")), "true")
		vary := resp.Headers.Get("Vary")
		observations = append(observations, corsObs{
			probe:   p.label,
			origin:  p.origin,
			acao:    acao,
			acac:    acac,
			vary:    vary,
			pattern: classifyCORS(p.origin, acao, acac),
			req:     resp.Request,
		})
	}

	primary := pickPrimaryPattern(observations)
	if primary == nil {
		result.PassReason = "CORS is not dangerously configured: the endpoint did not reflect the attacker " +
			"origin, did not return a wildcard with credentials, and did not accept the null origin. " +
			m07ObservedSummary(observations)
		for _, o := range observations {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   fmt.Sprintf("%s — ACAO=%q ACAC=%t", o.probe, o.acao, o.acac),
				Request: o.req,
			})
		}
		return result, nil
	}

	// Find the representative observation that produced the primary pattern.
	var rep corsObs
	for _, o := range observations {
		if o.pattern != nil && o.pattern.key == primary.key {
			rep = o
			break
		}
	}

	varyNote := ""
	if !strings.Contains(strings.ToLower(rep.vary), "origin") {
		varyNote = " The response also omits `Vary: Origin`, which can let shared caches serve the permissive " +
			"ACAO to other clients."
	}

	description := fmt.Sprintf(
		"The GraphQL endpoint at %s is CORS-misconfigured: %s. With request `Origin: %s`, the server returned "+
			"`Access-Control-Allow-Origin: %s` and `Access-Control-Allow-Credentials: %t`.%s All probe results: %s",
		cc.Target, primary.label, rep.origin, rep.acao, rep.acac, varyNote, m07ObservedSummary(observations))

	result.Findings = append(result.Findings, Finding{
		CheckID:     c.ID(),
		CheckName:   c.Name(),
		Severity:    primary.severity,
		Category:    c.Category(),
		Title:       "CORS Misconfiguration — " + primary.titleSeg,
		Description: description,
		Impact: "A malicious website the victim visits can issue cross-origin GraphQL requests and read the " +
			"responses. When credentials are allowed, it does so with the victim's authenticated session — " +
			"exfiltrating their data directly from the API.",
		Remediation: "Do not reflect arbitrary origins; allow-list exact trusted origins. Never combine " +
			"`Access-Control-Allow-Origin: *` or origin reflection with `Access-Control-Allow-Credentials: true`. " +
			"Reject `Origin: null`. Set `Vary: Origin` whenever ACAO is computed from the request origin.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/942.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
			"https://portswigger.net/web-security/cors",
		},
		ReproRequest: rep.req,
		Confidence:   "confirmed",
		CWE:          "CWE-942",
		OWASP:        "API8:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "cors:"+primary.key),
	})
	return result, nil
}

// classifyCORS maps a probe's (origin, ACAO, ACAC) to a danger pattern, or nil
// when the configuration is safe (ACAO absent or a fixed/other origin).
func classifyCORS(origin, acao string, acac bool) *corsPattern {
	if acao == "" {
		return nil
	}
	switch {
	case acao == "*":
		if acac {
			return &cpWildcardCreds
		}
		return &cpWildcard
	case acao == "null":
		if acac {
			return &cpNullCreds
		}
		return &cpNull
	case acao == origin:
		// The server echoed the (attacker-controlled) origin back — reflection.
		if acac {
			return &cpReflectCreds
		}
		return &cpReflect
	}
	// ACAO is a fixed/trusted origin different from the one we sent → safe.
	return nil
}

// pickPrimaryPattern returns the highest-priority pattern present, or nil.
func pickPrimaryPattern(obs []corsObs) *corsPattern {
	present := map[string]bool{}
	for _, o := range obs {
		if o.pattern != nil {
			present[o.pattern.key] = true
		}
	}
	for i := range corsPriority {
		if present[corsPriority[i].key] {
			return &corsPriority[i]
		}
	}
	return nil
}

// m07ObservedSummary renders a compact, deterministic per-probe ACAO/ACAC summary.
func m07ObservedSummary(obs []corsObs) string {
	parts := make([]string, 0, len(obs))
	for _, o := range obs {
		acao := o.acao
		if acao == "" {
			acao = "(none)"
		}
		parts = append(parts, fmt.Sprintf("[%s: Origin=%s → ACAO=%s, ACAC=%t]", o.probe, o.origin, acao, o.acac))
	}
	return strings.Join(parts, " ")
}

// m07Send issues a CORS probe with the given method and Origin, returning nil on
// error. POST probes carry a benign `{ __typename }` body; OPTIONS probes carry
// the preflight request headers.
func m07Send(ctx context.Context, cc *CheckContext, method, origin string) *transport.Response {
	var body []byte
	if method == http.MethodPost {
		body = []byte(`{"query":"{ __typename }"}`)
	}
	req, err := http.NewRequestWithContext(ctx, method, cc.Target, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", origin)
	switch method {
	case http.MethodPost:
		req.Header.Set("Content-Type", "application/json")
	case http.MethodOptions:
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type")
	}
	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return nil
	}
	return resp
}

// m07TargetHost returns the hostname of target, or "target" if it cannot be parsed.
func m07TargetHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "target"
}
