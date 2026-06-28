package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// securityHeadersCheck implements GQL-M08: it inspects the GraphQL endpoint's
// HTTP response for missing/weak hardening headers (X-Content-Type-Options,
// Content-Security-Policy, Strict-Transport-Security) and information-disclosing
// headers that should be removed (Server with a version, X-Powered-By). It emits
// a single LOW finding listing the gaps.
//
// Safety: read-only single probe. The finding is the header configuration
// itself; no data is accessed. Deliberately LOW — these gaps are baseline
// hardening, not direct vulnerabilities.
type securityHeadersCheck struct{}

func init() {
	MustRegister(&securityHeadersCheck{})
}

func (c *securityHeadersCheck) ID() string           { return "GQL-M08" }
func (c *securityHeadersCheck) Name() string         { return "Missing Security Headers" }
func (c *securityHeadersCheck) Category() Category   { return InformationDisclosure }
func (c *securityHeadersCheck) Severity() Severity   { return LOW }
func (c *securityHeadersCheck) RequiresSchema() bool { return false }

// m08Gap is one missing or disclosing-header finding component.
type m08Gap struct {
	key    string // stable fingerprint key
	label  string // short title label
	detail string // human-readable detail with observed value
}

// m08VersionRe detects a version-like token (used to decide whether a Server
// header is disclosing).
var m08VersionRe = regexp.MustCompile(`\d`)

// Run executes the security-headers check.
func (c *securityHeadersCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	body := []byte(`{"query":"{ __typename }"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(body))
	if err != nil {
		result.Error = err
		return result, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	result.ProbeCount++
	if err != nil || resp == nil {
		result.Error = fmt.Errorf("security-headers probe failed: %w", err)
		return result, nil
	}

	gaps := m08Evaluate(cc.Target, resp.Headers)
	if len(gaps) == 0 {
		result.PassReason = "Security headers are in good shape: X-Content-Type-Options is set to nosniff, " +
			"transport/CSP headers are present where applicable, and no Server/X-Powered-By version disclosure " +
			"was observed."
		result.PassProbes = []PassProbe{{
			Label:   "Security-headers probe — POST { __typename }",
			Request: resp.Request,
			Body:    body,
		}}
		return result, nil
	}

	labels := make([]string, 0, len(gaps))
	keys := make([]string, 0, len(gaps))
	details := make([]string, 0, len(gaps))
	for _, g := range gaps {
		labels = append(labels, g.label)
		keys = append(keys, g.key)
		details = append(details, g.detail)
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  c.Severity(),
		Category:  c.Category(),
		Title:     "Missing/Weak Security Headers — " + strings.Join(labels, ", "),
		Description: fmt.Sprintf(
			"The GraphQL response at %s is missing hardening headers or discloses server details: %s. "+
				"(Content-Security-Policy is most relevant for HTML/IDE responses; for a pure JSON API it is "+
				"informational.)",
			cc.Target, strings.Join(details, "; ")),
		Impact: "MIME-sniffing of error/HTML responses, lack of transport-security enforcement on a credentialed " +
			"API, and Server/framework version disclosure that aids attackers in selecting targeted exploits.",
		Remediation: "Set `X-Content-Type-Options: nosniff`; set `Strict-Transport-Security` on HTTPS endpoints; " +
			"apply a restrictive `Content-Security-Policy` to any HTML (IDE) responses; and remove the `Server` " +
			"and `X-Powered-By` headers.",
		References: []string{
			"https://owasp.org/www-project-secure-headers/",
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		ReproRequest: resp.Request,
		ReproBody:    body,
		Confidence:   "confirmed",
		CWE:          "CWE-693",
		OWASP:        "API8:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "headers:"+strings.Join(keys, ",")),
	})
	return result, nil
}

// m08Evaluate inspects the response headers for the given target and returns the
// hardening gaps in deterministic (key-sorted) order. It is pure and nil-safe so
// the HTTPS/HSTS and disclosure logic can be unit-tested directly.
func m08Evaluate(target string, h http.Header) []m08Gap {
	var gaps []m08Gap

	if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		gaps = append(gaps, m08Gap{
			"x-content-type-options", "X-Content-Type-Options",
			"missing `X-Content-Type-Options: nosniff` (responses may be MIME-sniffed)"})
	}

	if m08IsHTTPS(target) && strings.TrimSpace(h.Get("Strict-Transport-Security")) == "" {
		gaps = append(gaps, m08Gap{
			"strict-transport-security", "HSTS",
			"missing `Strict-Transport-Security` on an HTTPS endpoint (transport security not enforced)"})
	}

	// CSP is meaningful for HTML responses (e.g. an IDE shell). For pure JSON it
	// is informational, so only flag it when the response is HTML.
	if strings.TrimSpace(h.Get("Content-Security-Policy")) == "" &&
		strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/html") {
		gaps = append(gaps, m08Gap{
			"content-security-policy", "Content-Security-Policy",
			"missing `Content-Security-Policy` on an HTML response (e.g. an IDE shell) — XSS/clickjacking exposure"})
	}

	if sv := strings.TrimSpace(h.Get("Server")); sv != "" && m08VersionRe.MatchString(sv) {
		gaps = append(gaps, m08Gap{
			"server-disclosure", "Server disclosure",
			fmt.Sprintf("`Server` header discloses software/version (%q)", sv)})
	}

	if xp := strings.TrimSpace(h.Get("X-Powered-By")); xp != "" {
		gaps = append(gaps, m08Gap{
			"x-powered-by", "X-Powered-By",
			fmt.Sprintf("`X-Powered-By` discloses the framework (%q)", xp)})
	}

	sort.Slice(gaps, func(i, j int) bool { return gaps[i].key < gaps[j].key })
	return gaps
}

// m08IsHTTPS reports whether target is an https URL.
func m08IsHTTPS(target string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(target)), "https://")
}
