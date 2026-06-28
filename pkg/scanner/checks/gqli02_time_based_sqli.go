package checks

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gqls-cli/gqls/pkg/scanner/inject"
)

// timeBasedSQLiCheck implements GQL-I02: time-based blind SQL injection. For each
// injectable string leaf it injects a conditional database sleep and confirms,
// via the statistical timing oracle (median + MAD over repeated samples), that
// the payload response is robustly slower than a matched control — eliminating
// the false positives of single-sample latency heuristics.
//
// Safety: conditional sleep payloads only (read-only, no data change). Sample
// count, sleep duration, and point count are small bounded constants; mutation
// points are gated behind --authz-allow-mutations; sampling is cancellable.
//
// The sleep/floor/samples/maxPoints fields are zero in the registered instance
// (defaults applied at run time); tests set them to keep runs fast.
type timeBasedSQLiCheck struct {
	sleep     time.Duration // payload sleep duration (default 5s)
	floor     time.Duration // minimum robust delta for an effect (default sleep/2)
	samples   int           // timing samples per branch (default 7)
	maxPoints int           // max injection points probed (default 8)
}

func init() {
	MustRegister(&timeBasedSQLiCheck{})
}

func (c *timeBasedSQLiCheck) ID() string           { return "GQL-I02" }
func (c *timeBasedSQLiCheck) Name() string         { return "Time-Based Blind SQL Injection" }
func (c *timeBasedSQLiCheck) Category() Category   { return Injection }
func (c *timeBasedSQLiCheck) Severity() Severity   { return CRITICAL }
func (c *timeBasedSQLiCheck) RequiresSchema() bool { return true }

func (c *timeBasedSQLiCheck) sleepDur() time.Duration {
	if c.sleep > 0 {
		return c.sleep
	}
	return 5 * time.Second
}

func (c *timeBasedSQLiCheck) floorDur() time.Duration {
	if c.floor > 0 {
		return c.floor
	}
	return c.sleepDur() / 2
}

func (c *timeBasedSQLiCheck) sampleCount() int {
	if c.samples > 0 {
		return c.samples
	}
	return 7
}

func (c *timeBasedSQLiCheck) pointCap() int {
	if c.maxPoints > 0 {
		return c.maxPoints
	}
	return 8
}

// i02Family is a per-engine conditional-sleep payload suffix. The %d is the
// sleep duration in seconds; every suffix carries an engine-recognizable token.
type i02Family struct {
	engine string
	suffix string // Sprintf template with one %d (seconds)
}

var i02Families = []i02Family{
	{"MySQL", "' AND SLEEP(%d)-- -"},
	{"PostgreSQL", "' AND 1=(SELECT 1 FROM pg_sleep(%d))-- -"},
	{"MSSQL", "'; WAITFOR DELAY '0:0:%d'-- -"},
	{"Oracle", "' AND 1=dbms_pipe.receive_message('a',%d)-- -"},
}

// Run executes the time-based blind SQL injection check.
func (c *timeBasedSQLiCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
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
		if !i01StringLike(p.ScalarType) { // reuse I01's string-like leaf filter
			continue
		}
		if p.OpKind == "mutation" && !cc.AllowMutations {
			mutationGated = true
			continue
		}
		targets = append(targets, p)
	}
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

	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		c.probePoint(ctx, cc, tgt, base, secs, &result)
	}

	if len(result.Findings) == 0 && result.PassReason == "" {
		reason := "no time-based blind SQL injection detected: no injected sleep produced a statistically " +
			"robust slowdown (median + MAD over samples) at any injection point"
		if mutationGated {
			reason += "; mutation points were skipped (write-gated)"
		}
		result.PassReason = reason
	}
	return result, nil
}

// probePoint runs the timing oracle for each engine family at one point until an
// effect is found, appending a finding on the first robust slowdown.
func (c *timeBasedSQLiCheck) probePoint(ctx context.Context, cc *CheckContext, tgt inject.Point, base string, secs int, result *CheckResult) {
	controlDoc, controlVars := tgt.Render(cc.Schema, base)

	for _, fam := range i02Families {
		if ctx.Err() != nil {
			return
		}
		payloadValue := base + fmt.Sprintf(fam.suffix, secs)
		payloadDoc, payloadVars := tgt.Render(cc.Schema, payloadValue)

		var reproReq *http.Request
		var reproBody []byte

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
			reproReq = resp.Request
			reproBody = body
			return resp.Latency, nil
		}

		res := inject.TimingOracle(ctx, control, payload, c.sampleCount(), c.floorDur())

		if res.Effect {
			result.Findings = append(result.Findings, c.finding(cc, tgt, fam, res, reproReq, reproBody))
			return // one finding per point
		}

		result.PassProbes = append(result.PassProbes, PassProbe{
			Label: fmt.Sprintf("timing probe %s %s[%s]: control median %s, payload median %s (±MAD %s, %d samples) — no robust effect",
				fam.engine, tgt.RootField, tgt.PathKey(), res.ControlMedian, res.PayloadMedian, res.MAD, res.Samples),
			Request: reproReq,
			Body:    reproBody,
		})
	}
}

func (c *timeBasedSQLiCheck) finding(cc *CheckContext, tgt inject.Point, fam i02Family, res inject.TimingResult, reproReq *http.Request, reproBody []byte) Finding {
	pathKey := tgt.PathKey()
	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Injection,
		Title:     fmt.Sprintf("Time-Based Blind SQL Injection — %s arg %s", tgt.RootField, pathKey),
		Description: fmt.Sprintf(
			"A %s conditional-sleep payload injected at %s field %q (argument path %q) produced a statistically "+
				"robust slowdown: control median %s vs payload median %s (±MAD %s over %d samples). The payload "+
				"is a benign timing probe; the delay proves input reaches a SQL query that executes the sleep.",
			fam.engine, cc.Target, tgt.RootField, pathKey,
			res.ControlMedian, res.PayloadMedian, res.MAD, res.Samples),
		Impact: "Time-based blind SQL injection enables byte-by-byte extraction of arbitrary database contents " +
			"and full data compromise, even with no error leakage and no boolean-observable output.",
		Remediation: "Use parameterized queries / prepared statements; never concatenate GraphQL argument " +
			"values into SQL. Validate inputs and enforce database statement timeouts. A WAF is not sufficient.",
		References: []string{
			"https://owasp.org/www-community/attacks/Blind_SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/89.html",
		},
		ReproBody:   reproBody,
		Confidence:  "confirmed",
		CWE:         "CWE-89",
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "time_sqli:"+tgt.RootField+"/"+pathKey),
	}
	if reproReq != nil {
		f.ReproRequest = reproReq
	}
	return f
}

// errProbe normalizes a probe error so the timing oracle discards the sample.
func errProbe(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("nil response")
}
