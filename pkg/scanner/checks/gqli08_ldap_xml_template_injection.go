package checks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/gqls-cli/gqls/pkg/scanner/inject"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ldapXMLTemplateInjectionCheck implements GQL-I08: it detects LDAP injection
// (CWE-90), XML/XPath/XXE injection (CWE-91), and server-side template injection
// (SSTI, CWE-1336) behind GraphQL arguments, running three independent,
// name-gated sub-probes per relevant point with differential / arithmetic /
// parser-error oracles.
//
// Safety: SSTI uses arithmetic-only payloads (no RCE gadgets); the XXE canary is
// internal-entity-only (no external/system entity — no file or network fetch);
// LDAP payloads are read-only filter probes. Bounded; mutation points gated.
type ldapXMLTemplateInjectionCheck struct{}

func init() {
	MustRegister(&ldapXMLTemplateInjectionCheck{})
}

func (c *ldapXMLTemplateInjectionCheck) ID() string           { return "GQL-I08" }
func (c *ldapXMLTemplateInjectionCheck) Name() string         { return "LDAP / XML / Template Injection" }
func (c *ldapXMLTemplateInjectionCheck) Category() Category   { return Injection }
func (c *ldapXMLTemplateInjectionCheck) Severity() Severity   { return HIGH }
func (c *ldapXMLTemplateInjectionCheck) RequiresSchema() bool { return true }

const i08MaxPoints = 15

// Name gates: each class runs only on arguments whose name suggests its sink.
var (
	i08LDAPRe = regexp.MustCompile(`(?i)(user|uid|\bcn\b|\bdn\b|distinguishedname|search|group|member|\bou\b|directory|ldap|principal|account)`)
	i08XMLRe  = regexp.MustCompile(`(?i)(xml|xpath|xquery|soap|svg|markup|doc|document|feed|rss|saml|wsdl)`)
	i08SSTIRe = regexp.MustCompile(`(?i)(template|email|mail|subject|body|message|report|render|notif|greeting|content|title|label|format)`)
)

// Engine error signatures.
var (
	i08LDAPErrRe = regexp.MustCompile(`(?i)(LDAP: error code|Invalid DN syntax|Bad search filter|LDAPException|com\.sun\.jndi|javax\.naming)`)
	i08XMLErrRe  = regexp.MustCompile(`(?i)(xmlParseEntityRef|SAXParseException|Premature end of (file|data)|not well-formed|DOCTYPE is not allowed|error parsing XML|expected '>')`)
)

// i08LDAPBreak are read-only LDAP filter-break payloads.
var i08LDAPBreak = []string{`*)(uid=*))(|(uid=*`, `*)(|(objectClass=*)`, `)(cn=*`}

// i08XMLMalformed elicit XML parser errors (well-formedness only).
var i08XMLMalformed = []string{`gqls]]>`, `<gqls`, `<!--gqls`}

// i08SSTIFamilies are arithmetic-only template payloads (one %s for "a*b").
var i08SSTIFamilies = []string{"${%s}", "{{%s}}", "#{%s}", "<%%= %s %%>", "*{%s}"}

// Run executes the LDAP/XML/SSTI injection check.
func (c *ldapXMLTemplateInjectionCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "schema required to enumerate injection points"
		return result, nil
	}

	var targets []inject.Point
	mutationGated := false
	for _, p := range inject.Points(cc.Schema) {
		if !i01StringLike(p.ScalarType) {
			continue
		}
		if p.OpKind == "mutation" && !cc.AllowMutations {
			mutationGated = true
			continue
		}
		targets = append(targets, p)
	}
	targets = inject.Cap(targets, i08MaxPoints)

	if len(targets) == 0 {
		if mutationGated {
			result.PassReason = "only mutation injection points exist; they are write-gated and were skipped " +
				"(pass --authz-allow-mutations to test them)."
		} else {
			result.PassReason = "no injectable String/ID arguments were found in query or mutation fields"
		}
		return result, nil
	}

	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		name := tgt.RootField + "." + tgt.PathKey()
		if i08LDAPRe.MatchString(name) {
			c.probeLDAP(ctx, cc, tgt, &result)
		}
		if i08XMLRe.MatchString(name) {
			c.probeXML(ctx, cc, tgt, &result)
		}
		if i08SSTIRe.MatchString(name) {
			c.probeSSTI(ctx, cc, tgt, &result)
		}
	}

	if len(result.Findings) == 0 {
		reason := "no LDAP, XML/XXE, or template (SSTI) injection detected on the probed arguments"
		if mutationGated {
			reason += "; mutation points were skipped (write-gated)"
		}
		result.PassReason = reason
	}
	return result, nil
}

// probeLDAP runs the LDAP differential (wildcard superset) and error oracle.
func (c *ldapXMLTemplateInjectionCheck) probeLDAP(ctx context.Context, cc *CheckContext, tgt inject.Point, result *CheckResult) {
	control, _ := c.send(ctx, cc, tgt, "gqls-nonexistent-zzz-9f3a", result)
	wild, wildBody := c.send(ctx, cc, tgt, "*", result)
	if control != nil && wild != nil && i07Superset(control, wild) {
		w2, _ := c.send(ctx, cc, tgt, "*", result)
		if i07Superset(control, w2) {
			result.Findings = append(result.Findings, c.finding(cc, tgt, "LDAP", "ldap", "CWE-90", "confirmed",
				"a wildcard filter (*) returned a strict superset of a specific control search", wild.Request, wildBody))
			return
		}
	}
	for _, p := range i08LDAPBreak {
		resp, body := c.send(ctx, cc, tgt, p, result)
		if resp == nil {
			continue
		}
		if m, ok := inject.ErrorSignal(resp.Body, []*regexp.Regexp{i08LDAPErrRe}); ok {
			result.Findings = append(result.Findings, c.finding(cc, tgt, "LDAP", "ldap", "CWE-90", "firm",
				fmt.Sprintf("an LDAP filter-break payload elicited an LDAP error signal (%q)", m), resp.Request, body))
			return
		}
	}
}

// probeXML runs the internal-entity canary, XML parser-error, and XPath-break oracles.
func (c *ldapXMLTemplateInjectionCheck) probeXML(ctx context.Context, cc *CheckContext, tgt inject.Point, result *CheckResult) {
	// Internal-entity canary ONLY (never an external/system entity).
	marker := "INJ" + i08Nonce()
	canary := `<!DOCTYPE gqls [<!ENTITY e "` + marker + `">]><gqls>&e;</gqls>`
	if resp, body := c.send(ctx, cc, tgt, canary, result); resp != nil {
		// Entity was expanded if the marker is present but the raw reference is gone.
		if bytes.Contains(resp.Body, []byte(marker)) && !bytes.Contains(resp.Body, []byte("&e;")) {
			result.Findings = append(result.Findings, c.finding(cc, tgt, "XML/XXE", "xml", "CWE-91", "firm",
				"an internal XML entity was expanded in the response (internal-entity-only canary; no external "+
					"entity was sent), indicating unsafe XML parsing", resp.Request, body))
			return
		}
	}
	// Parser-error well-formedness probes.
	for _, p := range i08XMLMalformed {
		resp, body := c.send(ctx, cc, tgt, p, result)
		if resp == nil {
			continue
		}
		if m, ok := inject.ErrorSignal(resp.Body, []*regexp.Regexp{i08XMLErrRe}); ok {
			result.Findings = append(result.Findings, c.finding(cc, tgt, "XML/XXE", "xml", "CWE-91", "firm",
				fmt.Sprintf("a malformed-XML payload elicited an XML parser error (%q)", m), resp.Request, body))
			return
		}
	}
	// XPath-break differential.
	control, _ := c.send(ctx, cc, tgt, "gqls-nonexistent-zzz-9f3a", result)
	brk, brkBody := c.send(ctx, cc, tgt, "' or '1'='1", result)
	if control != nil && brk != nil && i07Superset(control, brk) {
		result.Findings = append(result.Findings, c.finding(cc, tgt, "XML/XXE", "xml", "CWE-91", "firm",
			"an XPath-break payload (' or '1'='1) returned a strict superset of a specific control", brk.Request, brkBody))
	}
}

// probeSSTI runs the arithmetic-evaluation oracle across template engines.
func (c *ldapXMLTemplateInjectionCheck) probeSSTI(ctx context.Context, cc *CheckContext, tgt inject.Point, result *CheckResult) {
	const a, b = 7919, 6841 // distinctive primes to avoid coincidental matches
	product := strconv.Itoa(a * b)
	literal := fmt.Sprintf("%d*%d", a, b)
	for _, fam := range i08SSTIFamilies {
		expr := fmt.Sprintf(fam, literal)
		resp, body := c.send(ctx, cc, tgt, expr, result)
		if resp == nil {
			continue
		}
		// Evaluated if the product appears and the literal expression does not.
		if bytes.Contains(resp.Body, []byte(product)) && !bytes.Contains(resp.Body, []byte(literal)) {
			result.Findings = append(result.Findings, c.finding(cc, tgt, "Template (SSTI)", "ssti", "CWE-1336", "confirmed",
				fmt.Sprintf("a template arithmetic payload %q evaluated to %s in the response", expr, product),
				resp.Request, body))
			return
		}
	}
}

func (c *ldapXMLTemplateInjectionCheck) send(ctx context.Context, cc *CheckContext, tgt inject.Point, value string, result *CheckResult) (*transport.Response, []byte) {
	doc, vars := tgt.Render(cc.Schema, value)
	resp, body, err := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
	result.ProbeCount++
	if err != nil || resp == nil {
		return nil, body
	}
	return resp, body
}

func (c *ldapXMLTemplateInjectionCheck) finding(cc *CheckContext, tgt inject.Point, class, classKey, cwe, confidence, evidence string, reproReq *http.Request, reproBody []byte) Finding {
	pathKey := tgt.PathKey()
	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  Injection,
		Title:     fmt.Sprintf("%s Injection — %s arg %s", class, tgt.RootField, pathKey),
		Description: fmt.Sprintf(
			"A %s injection probe at %s field %q (argument path %q) confirmed the sink: %s. Reflected data is "+
				"redacted; the XXE probe is internal-entity-only (no external/system entity is ever sent).",
			class, cc.Target, tgt.RootField, pathKey, evidence),
		Impact:      i08Impact(classKey),
		Remediation: i08Remediation(classKey),
		References: []string{
			"https://cwe.mitre.org/data/definitions/90.html",
			"https://cwe.mitre.org/data/definitions/91.html",
			"https://cwe.mitre.org/data/definitions/1336.html",
			"https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
		},
		ReproBody:   reproBody,
		Confidence:  confidence,
		CWE:         cwe,
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "i08:"+classKey+":"+tgt.RootField+"/"+pathKey),
	}
	if reproReq != nil {
		f.ReproRequest = reproReq
	}
	return f
}

func i08Impact(classKey string) string {
	switch classKey {
	case "ldap":
		return "LDAP injection enables authentication bypass and directory enumeration of users, groups, and " +
			"attributes outside the intended search scope."
	case "xml":
		return "XML/XPath injection can disclose document contents and, via XXE, read local files and reach " +
			"internal services (SSRF). Only an internal-entity canary is tested, but the sink implies XXE risk."
	default: // ssti
		return "Server-side template injection frequently escalates to remote code execution on the API server."
	}
}

func i08Remediation(classKey string) string {
	switch classKey {
	case "ldap":
		return "Escape LDAP filter meta-characters or use parameterized directory-search APIs; validate input " +
			"against an allow-list."
	case "xml":
		return "Disable DTD processing and external entities; use a hardened XML parser; validate and encode " +
			"input before building XML/XPath."
	default: // ssti
		return "Never render user input as a template. Use logic-less templates or a strict sandbox, and apply " +
			"context-aware output encoding."
	}
}

// i08Nonce returns a short random token for the XXE canary marker.
func i08Nonce() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
