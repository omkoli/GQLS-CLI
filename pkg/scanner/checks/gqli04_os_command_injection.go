package checks

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gqls-cli/gqls/pkg/scanner/inject"
)

// osCommandInjectionCheck implements GQL-I04: OS command injection. On arguments
// that may reach a shell it confirms injection primarily with a statistical
// time-based oracle (conditional sleep/ping across shell separators), optionally
// with an out-of-band DNS/HTTP callback (opt-in via --oob-domain), and
// corroborates with a shell error-signal table for verbose servers.
//
// Safety: only benign payloads (sleep/ping/timeout, or a DNS lookup of the
// operator's own OOB domain) — never destructive commands. OOB is opt-in.
// Bounded samples/points; mutation points gated; sampling is cancellable.
//
// sleep/floor/samples/maxPoints are zero in the registered instance (defaults
// applied at run time); tests set them to keep runs fast.
type osCommandInjectionCheck struct {
	sleep     time.Duration
	floor     time.Duration
	samples   int
	maxPoints int
}

func init() {
	MustRegister(&osCommandInjectionCheck{})
}

func (c *osCommandInjectionCheck) ID() string           { return "GQL-I04" }
func (c *osCommandInjectionCheck) Name() string         { return "OS Command Injection" }
func (c *osCommandInjectionCheck) Category() Category   { return Injection }
func (c *osCommandInjectionCheck) Severity() Severity   { return CRITICAL }
func (c *osCommandInjectionCheck) RequiresSchema() bool { return true }

func (c *osCommandInjectionCheck) sleepDur() time.Duration {
	if c.sleep > 0 {
		return c.sleep
	}
	return 5 * time.Second
}

func (c *osCommandInjectionCheck) floorDur() time.Duration {
	if c.floor > 0 {
		return c.floor
	}
	return c.sleepDur() / 2
}

func (c *osCommandInjectionCheck) sampleCount() int {
	if c.samples > 0 {
		return c.samples
	}
	return 7
}

func (c *osCommandInjectionCheck) pointCap() int {
	if c.maxPoints > 0 {
		return c.maxPoints
	}
	return 6
}

// i04ShellArgHints are argument-name substrings suggesting a shell-reaching param.
var i04ShellArgHints = []string{
	"host", "hostname", "domain", "url", "uri", "file", "filename", "path", "cmd",
	"command", "name", "format", "width", "height", "ip", "addr", "lookup", "ping", "exec",
}

// i04Family is a conditional-sleep payload across a shell separator. The %d is
// the sleep duration in seconds.
type i04Family struct {
	label  string
	suffix string
}

var i04Families = []i04Family{
	{"semicolon", "; sleep %d"},
	{"pipe", "| sleep %d"},
	{"backtick", "`sleep %d`"},
	{"subshell", "$(sleep %d)"},
	{"background-ping", "& ping -c %d 127.0.0.1"},
}

// i04OOBPayloads inject an OOB DNS/HTTP lookup of <token>.<oob-domain>. The %s is
// the unique subdomain.
var i04OOBPayloads = []string{
	"; curl http://%s",
	"; nslookup %s",
	"$(curl http://%s)",
}

// i04ShellErrorPatterns corroborate command execution on verbose servers.
var i04ShellErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)sh: \d+:`),
	regexp.MustCompile(`(?i)/bin/(?:ba)?sh`),
	regexp.MustCompile(`(?i)command not found`),
	regexp.MustCompile(`(?i)No such file or directory`),
	regexp.MustCompile(`(?i)not recognized as an internal or external command`),
}

// Run executes the OS command injection check.
func (c *osCommandInjectionCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
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
		if !i01StringLike(p.ScalarType) { // shell args are string-typed
			continue
		}
		if p.OpKind == "mutation" && !cc.AllowMutations {
			mutationGated = true
			continue
		}
		targets = append(targets, p)
	}
	// Prioritize points whose names suggest shell-reaching params (timing is costly).
	sort.SliceStable(targets, func(i, j int) bool {
		return i04ShellHint(targets[i]) && !i04ShellHint(targets[j])
	})
	targets = inject.Cap(targets, c.pointCap())

	if len(targets) == 0 {
		if mutationGated {
			result.PassReason = "only mutation injection points exist; they are write-gated and were skipped " +
				"(pass --authz-allow-mutations to test them)."
		} else {
			result.PassReason = "no injectable String/ID arguments were found in query or mutation fields"
		}
		return result, nil
	}

	base, _ := inject.ExampleValue("String").(string)
	if base == "" {
		base = "gqls"
	}
	secs := int(c.sleepDur() / time.Second)
	if secs < 1 {
		secs = 1
	}

	oobEnabled := cc.OOBDomain != "" && cc.OOBPoller != nil
	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		c.probePoint(ctx, cc, tgt, base, secs, oobEnabled, &result)
	}

	if len(result.Findings) == 0 {
		reason := "no OS command injection detected: no conditional-sleep payload produced a robust slowdown, " +
			"and no shell error signal was observed"
		if !oobEnabled {
			reason += "; out-of-band probing was skipped (no --oob-domain configured)"
		}
		if mutationGated {
			reason += "; mutation points were skipped (write-gated)"
		}
		result.PassReason = reason
	}
	return result, nil
}

// probePoint runs the timing oracle, then the optional OOB path, then the
// error-only fallback, appending at most one finding.
func (c *osCommandInjectionCheck) probePoint(ctx context.Context, cc *CheckContext, tgt inject.Point, base string, secs int, oobEnabled bool, result *CheckResult) {
	controlDoc, controlVars := tgt.Render(cc.Schema, base)
	var sawError string
	var lastReq *http.Request
	var lastBody []byte

	// ── Time-based oracle (primary).
	for _, fam := range i04Families {
		if ctx.Err() != nil {
			return
		}
		payloadDoc, payloadVars := tgt.Render(cc.Schema, base+fmt.Sprintf(fam.suffix, secs))

		control := func(ctx context.Context) (time.Duration, error) {
			resp, _, err := inject.Send(ctx, cc.HTTPClient, cc.Target, controlDoc, controlVars)
			result.ProbeCount++
			if err != nil || resp == nil {
				return 0, errProbe(err)
			}
			return resp.Latency, nil
		}
		payload := func(ctx context.Context) (time.Duration, error) {
			resp, body, err := inject.Send(ctx, cc.HTTPClient, cc.Target, payloadDoc, payloadVars)
			result.ProbeCount++
			if err != nil || resp == nil {
				return 0, errProbe(err)
			}
			lastReq, lastBody = resp.Request, body
			if m, ok := inject.ErrorSignal(resp.Body, i04ShellErrorPatterns); ok {
				sawError = m
			}
			return resp.Latency, nil
		}

		res := inject.TimingOracle(ctx, control, payload, c.sampleCount(), c.floorDur())
		if res.Effect {
			result.Findings = append(result.Findings, c.finding(cc, tgt,
				fmt.Sprintf("time-based (%s sleep): control median %s vs payload median %s (±MAD %s, %d samples)",
					fam.label, res.ControlMedian, res.PayloadMedian, res.MAD, res.Samples),
				"confirmed", sawError, lastReq, lastBody))
			return
		}
	}

	// ── Out-of-band (opt-in, blind).
	if oobEnabled {
		for _, tmpl := range i04OOBPayloads {
			if ctx.Err() != nil {
				return
			}
			token := cc.OOBPoller.NewToken()
			sub := token + "." + cc.OOBDomain
			doc, vars := tgt.Render(cc.Schema, base+fmt.Sprintf(tmpl, sub))
			resp, body, _ := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
			result.ProbeCount++
			if resp != nil {
				lastReq, lastBody = resp.Request, body
			}
			if cc.OOBPoller.Correlated(ctx, token) {
				result.Findings = append(result.Findings, c.finding(cc, tgt,
					fmt.Sprintf("out-of-band callback correlated to %s", sub),
					"confirmed", sawError, lastReq, lastBody))
				return
			}
		}
	}

	// ── Error-only corroboration (verbose servers) → firm.
	if sawError != "" {
		result.Findings = append(result.Findings, c.finding(cc, tgt,
			fmt.Sprintf("shell error signal observed (%q)", sawError),
			"firm", sawError, lastReq, lastBody))
	}
}

func (c *osCommandInjectionCheck) finding(cc *CheckContext, tgt inject.Point, evidence, confidence, sawError string, reproReq *http.Request, reproBody []byte) Finding {
	pathKey := tgt.PathKey()
	errNote := ""
	if sawError != "" && !strings.Contains(evidence, "shell error") {
		errNote = fmt.Sprintf(" A shell error signal (%q) corroborated the result.", sawError)
	}
	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Injection,
		Title:     fmt.Sprintf("OS Command Injection — %s arg %s", tgt.RootField, pathKey),
		Description: fmt.Sprintf(
			"A command-injection probe at %s field %q (argument path %q) confirmed that input reaches an OS "+
				"shell: %s. All payloads were benign probes (sleep/ping/DNS lookup only).%s",
			cc.Target, tgt.RootField, pathKey, evidence, errNote),
		Impact: "OS command injection is remote code execution on the API server: full host and data compromise " +
			"and a pivot for lateral movement.",
		Remediation: "Never pass user input to a shell; use exec APIs with argument arrays (no shell), strict " +
			"allow-lists, and input validation. Run workers with least privilege and restrict network egress.",
		References: []string{
			"https://owasp.org/www-community/attacks/Command_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/78.html",
		},
		ReproBody:   reproBody,
		Confidence:  confidence,
		CWE:         "CWE-78",
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "cmdi:"+tgt.RootField+"/"+pathKey),
	}
	if reproReq != nil {
		f.ReproRequest = reproReq
	}
	return f
}

// i04ShellHint reports whether the point's name suggests a shell-reaching param.
func i04ShellHint(p inject.Point) bool {
	hay := strings.ToLower(p.RootField + "." + p.PathKey())
	for _, h := range i04ShellArgHints {
		if strings.Contains(hay, h) {
			return true
		}
	}
	return false
}
