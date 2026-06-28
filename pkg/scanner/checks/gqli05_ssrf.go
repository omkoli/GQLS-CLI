package checks

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/scanner/inject"
	"github.com/gqls-cli/gqls/pkg/scanner/oob"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ssrfCheck implements GQL-I05: Server-Side Request Forgery via URL-typed
// GraphQL arguments. Blind SSRF is confirmed via an out-of-band callback to an
// operator-supplied collaborator domain (opt-in, --oob-domain); without OOB it
// falls back to in-band signals (cloud-metadata-shaped responses, response
// differentials for internal targets) at lower confidence.
//
// Safety: OOB targets only the operator's own collaborator domain; in-band
// targets are loopback/metadata reads (never writes). OOB is opt-in. Bounded
// candidates; mutation points gated; internal data redacted.
type ssrfCheck struct{}

func init() {
	MustRegister(&ssrfCheck{})
}

func (c *ssrfCheck) ID() string           { return "GQL-I05" }
func (c *ssrfCheck) Name() string         { return "SSRF via GraphQL Arguments" }
func (c *ssrfCheck) Category() Category   { return Injection }
func (c *ssrfCheck) Severity() Severity   { return CRITICAL }
func (c *ssrfCheck) RequiresSchema() bool { return true }

const (
	i05MaxCandidates = 15
	i05OOBPollWait   = 5 * time.Second
)

// i05URLArgRe matches argument/field names that commonly take a URL/host and so
// may drive an outbound request.
var i05URLArgRe = regexp.MustCompile(`(?i)(url|uri|href|link|webhook|callback|redirect|avatar|image|src|endpoint|host|target|feed|proxy)`)

// i05MetadataRe matches cloud-metadata-shaped response content (a strong in-band
// SSRF signal that the server fetched the metadata endpoint).
var i05MetadataRe = regexp.MustCompile(`(?i)(ami-id|instance-id|instance-identity|security-credentials|/latest/meta-data|iam/info)`)

// In-band probe targets.
const (
	i05ControlURL  = "https://gqls-control.example/"
	i05MetadataURL = "http://169.254.169.254/latest/meta-data/"
	i05LoopbackURL = "http://127.0.0.1:80/"
)

// Run executes the SSRF check.
func (c *ssrfCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
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
		if !i05URLArgRe.MatchString(strings.ToLower(p.RootField + "." + p.PathKey())) {
			continue
		}
		if p.OpKind == "mutation" && !cc.AllowMutations {
			mutationGated = true
			continue
		}
		targets = append(targets, p)
	}
	targets = inject.Cap(targets, i05MaxCandidates)

	if len(targets) == 0 {
		if mutationGated {
			result.PassReason = "only mutation URL arguments exist; they are write-gated and were skipped " +
				"(pass --authz-allow-mutations to test them)."
		} else {
			result.PassReason = "no URL/host-like arguments were found to test for SSRF"
		}
		return result, nil
	}

	oobEnabled := cc.OOBDomain != "" && cc.OOBPoller != nil
	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		if oobEnabled {
			c.probeOOB(ctx, cc, tgt, &result)
		} else {
			c.probeInBand(ctx, cc, tgt, &result)
		}
	}

	if len(result.Findings) == 0 {
		reason := "no SSRF detected: injected URLs did not trigger a correlated out-of-band callback"
		if !oobEnabled {
			reason = "no in-band SSRF signal observed (no cloud-metadata-shaped response or internal-target " +
				"differential); supply --oob-domain for blind SSRF detection"
		}
		if mutationGated {
			reason += "; mutation points were skipped (write-gated)"
		}
		result.PassReason = reason
	}
	return result, nil
}

// probeOOB injects an OOB URL at the point and confirms on a correlated callback.
func (c *ssrfCheck) probeOOB(ctx context.Context, cc *CheckContext, tgt inject.Point, result *CheckResult) {
	host, fullURL := cc.OOBPoller.NewToken()
	var reproReq *http.Request
	var reproBody []byte

	for _, val := range []string{fullURL, "//" + host + "/"} {
		if ctx.Err() != nil {
			return
		}
		doc, vars := tgt.Render(cc.Schema, val)
		resp, body, _ := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
		result.ProbeCount++
		if resp != nil {
			reproReq, reproBody = resp.Request, body
		}
	}
	if hits, _ := cc.OOBPoller.Poll(ctx, host, i05OOBPollWait); len(hits) > 0 {
		result.Findings = append(result.Findings, c.finding(cc, tgt, "confirmed", CRITICAL,
			fmt.Sprintf("an out-of-band callback correlated to the injected URL %s (%s)", fullURL, oob.Summary(hits)),
			reproReq, reproBody))
	}
}

// probeInBand runs the no-OOB fallback: a cloud-metadata read (strong → firm)
// and an internal-target differential vs a control URL (weak → tentative).
func (c *ssrfCheck) probeInBand(ctx context.Context, cc *CheckContext, tgt inject.Point, result *CheckResult) {
	controlResp, _ := c.send(ctx, cc, tgt, i05ControlURL, result)
	metaResp, metaBody := c.send(ctx, cc, tgt, i05MetadataURL, result)

	// Strong signal: the server fetched cloud metadata and leaked its shape.
	if metaResp != nil && i05MetadataRe.Match(metaResp.Body) {
		result.Findings = append(result.Findings, c.finding(cc, tgt, "firm", CRITICAL,
			fmt.Sprintf("the server returned cloud-metadata-shaped content when the argument was set to %s, "+
				"indicating it fetched the instance metadata endpoint", i05MetadataURL),
			metaResp.Request, metaBody))
		return
	}

	// Weak signal: an internal target produces a materially different, non-erroring
	// response than a control URL — the server appears to make outbound requests.
	loopResp, loopBody := c.send(ctx, cc, tgt, i05LoopbackURL, result)
	if controlResp == nil {
		return
	}
	for _, probe := range []struct {
		resp *transport.Response
		body []byte
		url  string
	}{{metaResp, metaBody, i05MetadataURL}, {loopResp, loopBody, i05LoopbackURL}} {
		if i05InternalDifferential(controlResp, probe.resp) {
			result.Findings = append(result.Findings, c.finding(cc, tgt, "tentative", MEDIUM,
				fmt.Sprintf("the response to an internal target (%s) differed materially from a control URL, "+
					"suggesting the server makes outbound requests from this argument (unconfirmed without OOB)",
					probe.url),
				probe.resp.Request, probe.body))
			return
		}
	}
}

// i05InternalDifferential reports whether the internal-target response is a
// usable, non-erroring response that differs from the control response.
func i05InternalDifferential(control, internal *transport.Response) bool {
	if control == nil || internal == nil {
		return false
	}
	switch authz.Classify(internal) {
	case authz.ClassSuccess, authz.ClassEmpty, authz.ClassNotFound:
		return !inject.BodyEquivalent(control, internal)
	default:
		return false
	}
}

// send injects a URL string value at the point and returns the response + body.
func (c *ssrfCheck) send(ctx context.Context, cc *CheckContext, tgt inject.Point, url string, result *CheckResult) (*transport.Response, []byte) {
	doc, vars := tgt.Render(cc.Schema, url)
	resp, body, err := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
	result.ProbeCount++
	if err != nil {
		return nil, body
	}
	return resp, body
}

func (c *ssrfCheck) finding(cc *CheckContext, tgt inject.Point, confidence string, severity Severity, evidence string, reproReq *http.Request, reproBody []byte) Finding {
	pathKey := tgt.PathKey()
	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  severity,
		Category:  Injection,
		Title:     fmt.Sprintf("SSRF — %s arg %s triggers server-side outbound request", tgt.RootField, pathKey),
		Description: fmt.Sprintf(
			"The URL argument at %s field %q (argument path %q) causes a server-side outbound request: %s. "+
				"(Any internal data reached is not included in this report.)",
			cc.Target, tgt.RootField, pathKey, evidence),
		Impact: "SSRF grants access to internal services and cloud metadata (e.g. 169.254.169.254), enables " +
			"internal port scanning and credential theft, and provides a pivot into the internal network.",
		Remediation: "Validate and allow-list outbound destinations; resolve and re-check IPs to block RFC1918, " +
			"link-local, and metadata ranges; disable redirects; use a deny-by-default egress proxy; and never " +
			"fetch user-supplied URLs from privileged contexts.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/918.html",
		},
		ReproBody:   reproBody,
		Confidence:  confidence,
		CWE:         "CWE-918",
		OWASP:       "API7:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "ssrf:"+tgt.RootField+"/"+pathKey),
	}
	if reproReq != nil {
		f.ReproRequest = reproReq
	}
	return f
}
