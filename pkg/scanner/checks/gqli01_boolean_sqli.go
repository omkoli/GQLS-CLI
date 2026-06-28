package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/scanner/inject"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// booleanSQLiCheck implements GQL-I01: boolean-based (differential) SQL
// injection. For each injectable string leaf it sends a logically-true and a
// logically-false predicate and flags when the two responses diverge in a way
// that tracks the predicate — proving the input reaches a SQL WHERE clause. This
// is the confirmed oracle the error-based GQL-011 lacks.
//
// Safety: read-only boolean predicates only (no stacked statements, no writes).
// Bounded points/payloads; mutation points are gated behind --authz-allow-mutations;
// payloads are redacted in evidence.
type booleanSQLiCheck struct{}

func init() {
	MustRegister(&booleanSQLiCheck{})
}

func (c *booleanSQLiCheck) ID() string           { return "GQL-I01" }
func (c *booleanSQLiCheck) Name() string         { return "Boolean-Based SQL Injection" }
func (c *booleanSQLiCheck) Category() Category   { return Injection }
func (c *booleanSQLiCheck) Severity() Severity   { return CRITICAL }
func (c *booleanSQLiCheck) RequiresSchema() bool { return true }

// i01MaxPoints bounds how many injection points are probed.
const i01MaxPoints = 25

// i01Family is a syntactic boolean-SQLi payload family: a tautology suffix and a
// contradiction suffix appended to a benign base value.
type i01Family struct {
	label       string
	trueSuffix  string
	falseSuffix string
}

// i01Families are tried in order; the first that confirms wins for a point.
var i01Families = []i01Family{
	{"single-quote OR", "' OR '1'='1", "' OR '1'='2"},
	{"single-quote AND", "' AND '1'='1", "' AND '1'='2"},
	{"paren OR", "') OR ('1'='1", "') OR ('1'='2"},
}

// i01StringLike reports whether a scalar leaf is a string-typed injection target.
// Boolean SQLi payloads are strings; numeric/boolean leaves are rejected by the
// GraphQL type system and so are not injectable this way.
func i01StringLike(scalarType string) bool {
	switch scalarType {
	case "Int", "Float", "Boolean":
		return false
	default: // String, ID, custom scalars
		return true
	}
}

// Run executes the boolean-based SQL injection check.
func (c *booleanSQLiCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
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
	targets = inject.Cap(targets, i01MaxPoints)

	if len(targets) == 0 {
		if mutationGated {
			result.PassReason = "only mutation injection points exist; they are write-gated and were skipped " +
				"(pass --authz-allow-mutations to test them). No query injection points to probe."
		} else {
			result.PassReason = "no injectable String/ID arguments were found in query or mutation fields"
		}
		return result, nil
	}

	base, _ := inject.ExampleValue("String").(string)
	if base == "" {
		base = "gqls"
	}

	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		if c.probePoint(ctx, cc, tgt, base, &result) {
			// one finding per injection point
			continue
		}
	}

	if len(result.Findings) == 0 {
		reason := "no boolean-differential SQL injection detected: true/false predicates produced equivalent " +
			"responses at every injection point (input does not reach a SQL WHERE clause)"
		if mutationGated {
			reason += "; mutation points were skipped (write-gated)"
		}
		result.PassReason = reason
	}
	return result, nil
}

// probePoint runs the differential for one injection point. It returns true when
// a confirmed finding was appended.
func (c *booleanSQLiCheck) probePoint(ctx context.Context, cc *CheckContext, tgt inject.Point, base string, result *CheckResult) bool {
	controlResp := c.send(ctx, cc, tgt, base, result)
	if controlResp == nil {
		return false
	}
	if cls := authz.Classify(controlResp); cls == authz.ClassServerError || cls == authz.ClassRateLimited {
		return false // server unstable for this point — inconclusive
	}

	for _, fam := range i01Families {
		if ctx.Err() != nil {
			return false
		}
		trueResp, trueBody := c.sendWithBody(ctx, cc, tgt, base+fam.trueSuffix, result)
		falseResp, _ := c.sendWithBody(ctx, cc, tgt, base+fam.falseSuffix, result)
		if !booleanDivergence(controlResp, trueResp, falseResp) {
			continue
		}
		// Re-test once to rule out flakiness.
		trueResp2, _ := c.sendWithBody(ctx, cc, tgt, base+fam.trueSuffix, result)
		falseResp2, _ := c.sendWithBody(ctx, cc, tgt, base+fam.falseSuffix, result)
		if !booleanDivergence(controlResp, trueResp2, falseResp2) {
			continue
		}

		result.Findings = append(result.Findings, c.finding(cc, tgt, fam, trueResp, trueBody))
		return true
	}
	return false
}

func (c *booleanSQLiCheck) send(ctx context.Context, cc *CheckContext, tgt inject.Point, value string, result *CheckResult) *transport.Response {
	resp, _ := c.sendWithBody(ctx, cc, tgt, value, result)
	return resp
}

func (c *booleanSQLiCheck) sendWithBody(ctx context.Context, cc *CheckContext, tgt inject.Point, value string, result *CheckResult) (*transport.Response, []byte) {
	doc, vars := tgt.Render(cc.Schema, value)
	resp, body, err := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
	result.ProbeCount++
	if err != nil {
		return nil, body
	}
	return resp, body
}

// booleanDivergence reports whether the true/false responses diverge in a way
// that tracks a SQL predicate: the true predicate yields a data result, the
// false predicate yields strictly less data, and the two are not equivalent.
// Erroring (validation/auth/5xx/rate) true or false responses are inconclusive.
func booleanDivergence(control, trueResp, falseResp *transport.Response) bool {
	if trueResp == nil || falseResp == nil {
		return false
	}
	if !i01Usable(authz.Classify(trueResp)) || !i01Usable(authz.Classify(falseResp)) {
		return false
	}
	if authz.Classify(trueResp) != authz.ClassSuccess {
		return false // true predicate must return a data object
	}
	if inject.BodyEquivalent(trueResp, falseResp) {
		return false // predicate had no effect
	}
	// The hallmark: true yields more data than false. This rejects servers that
	// merely echo the (differing) payload back at equal magnitude.
	return i01DataLen(trueResp) > i01DataLen(falseResp)
}

// i01Usable reports whether a class is a definite, non-erroring data outcome.
func i01Usable(cls authz.Class) bool {
	switch cls {
	case authz.ClassSuccess, authz.ClassEmpty, authz.ClassNotFound:
		return true
	default:
		return false
	}
}

// i01DataLen returns the byte length of the canonical `data` object, or 0 when
// data is null/absent or the body is malformed.
func i01DataLen(resp *transport.Response) int {
	if resp == nil {
		return 0
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return 0
	}
	s := strings.TrimSpace(string(env.Data))
	if s == "" || s == "null" {
		return 0
	}
	return len(s)
}

func (c *booleanSQLiCheck) finding(cc *CheckContext, tgt inject.Point, fam i01Family, trueResp *transport.Response, trueBody []byte) Finding {
	pathKey := tgt.PathKey()
	maskedTrue := authz.MaskValue(fam.trueSuffix)
	maskedFalse := authz.MaskValue(fam.falseSuffix)

	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Injection,
		Title:     fmt.Sprintf("Boolean-Based SQL Injection — %s arg %s", tgt.RootField, pathKey),
		Description: fmt.Sprintf(
			"A boolean-differential probe at %s field %q (argument path %q) proved input reaches a SQL WHERE "+
				"clause: a logically-true predicate returned a data result while a logically-false predicate "+
				"changed the result set (fewer/zero rows). The divergence was consistent across a re-test. "+
				"Syntax family: %s (true≈%s, false≈%s, payloads redacted).",
			cc.Target, tgt.RootField, pathKey, fam.label, maskedTrue, maskedFalse),
		Impact: "Boolean-based SQL injection enables blind extraction of arbitrary database contents, " +
			"authentication bypass, and full data compromise — even when error messages are suppressed.",
		Remediation: "Use parameterized queries / prepared statements; never concatenate GraphQL argument " +
			"values into SQL. Validate and type-check inputs, and run database accounts with least privilege.",
		References: []string{
			"https://owasp.org/www-community/attacks/Blind_SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/89.html",
		},
		ReproBody:   trueBody,
		Confidence:  "confirmed",
		CWE:         "CWE-89",
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "bool_sqli:"+tgt.RootField+"/"+pathKey),
	}
	if trueResp != nil {
		f.ReproRequest = trueResp.Request
	}
	return f
}
