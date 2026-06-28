package checks

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/scanner/fingerprint"
	"github.com/gqls-cli/gqls/pkg/scanner/inject"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ormOperatorInjectionCheck implements GQL-I07: predicate/operator abuse in
// auto-generated ORM-backed GraphQL filter languages (Hasura/Postgraphile/Prisma
// where/_and/_or/_like/_eq). It injects attacker-controlled predicates into a
// filter input-object argument and flags when they widen the result set beyond a
// restrictive control (filter/authorization bypass), or surface privileged rows.
//
// It is engine-gated via the GQL-M01 fingerprint: the full predicate set runs
// only against Hasura/Postgraphile-style engines; an unknown engine gets a
// conservative widening-only subset; a known non-ORM engine is skipped.
//
// Safety: read-only predicate widening only (the generated filter language; no
// writes, no SQL meta-characters). Bounded filters; rows redacted.
type ormOperatorInjectionCheck struct{}

func init() {
	MustRegister(&ormOperatorInjectionCheck{})
}

func (c *ormOperatorInjectionCheck) ID() string           { return "GQL-I07" }
func (c *ormOperatorInjectionCheck) Name() string         { return "ORM/GraphQL Operator Injection" }
func (c *ormOperatorInjectionCheck) Category() Category   { return Injection }
func (c *ormOperatorInjectionCheck) Severity() Severity   { return HIGH }
func (c *ormOperatorInjectionCheck) RequiresSchema() bool { return true }

const i07MaxFilters = 10

// i07FilterArgRe matches argument names that denote a filter/where input.
var i07FilterArgRe = regexp.MustCompile(`(?i)(where|filter|condition)`)

// i07FilterTypeRe matches input-object type names that denote a filter/bool-exp.
var i07FilterTypeRe = regexp.MustCompile(`(?i)(bool_exp|boolexp|_filter|filter|where|condition)`)

// i07OperatorFieldRe matches boolean-combinator field names of a filter input.
var i07OperatorFieldRe = regexp.MustCompile(`(?i)^_?(and|or|not)$`)

// i07PrivilegedColRe matches column names that likely select privileged rows.
var i07PrivilegedColRe = regexp.MustCompile(`(?i)(role|admin|is_admin|isadmin|privilege|access|superuser)`)

// i07ormEngineRe matches engine names that use generated ORM filter languages.
var i07ormEngineRe = regexp.MustCompile(`(?i)(hasura|postgraphile|prisma)`)

// i07Filter describes one discovered filter argument and the columns to abuse.
type i07Filter struct {
	field      string
	arg        string
	typeName   string
	nonNull    bool
	controlCol string
	privCol    string
	privVal    any
}

// Run executes the ORM operator-injection check.
func (c *ormOperatorInjectionCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "schema required to enumerate filter arguments"
		return result, nil
	}

	filters := i07FindFilters(cc.Schema)
	if len(filters) > i07MaxFilters {
		filters = filters[:i07MaxFilters]
	}
	if len(filters) == 0 {
		result.PassReason = "no filter/where input-object arguments were found to test for predicate abuse"
		return result, nil
	}

	// Engine gating via the GQL-M01 fingerprint.
	engine, _, probes := fingerprint.Identify(ctx, cc.ProbeClient(), cc.Target)
	result.ProbeCount += probes
	ormMatch := i07ormEngineRe.MatchString(engine.Name)
	if engine.Identified() && !ormMatch {
		result.PassReason = fmt.Sprintf(
			"engine fingerprinted as %s; the Hasura/Postgraphile ORM predicate set is gated to ORM-backed "+
				"engines and was not run", engine.Name)
		return result, nil
	}
	conservative := !ormMatch // unknown engine → widening-only subset

	for _, f := range filters {
		if ctx.Err() != nil {
			break
		}
		c.probeFilter(ctx, cc, f, conservative, &result)
	}

	if len(result.Findings) == 0 {
		reason := "no ORM operator injection detected: injected filter predicates did not widen the result set " +
			"beyond a restrictive control (the filter appears scoped server-side or ignores client predicates)"
		if conservative {
			reason += "; engine fingerprint was unknown, so only the conservative widening subset was run"
		}
		result.PassReason = reason
	}
	return result, nil
}

// probeFilter runs the control/widen/target differential for one filter arg.
func (c *ormOperatorInjectionCheck) probeFilter(ctx context.Context, cc *CheckContext, f i07Filter, conservative bool, result *CheckResult) {
	point := inject.Point{OpKind: "query", RootField: f.field, Path: []string{f.arg}, ScalarType: f.typeName, NonNull: f.nonNull}

	control := map[string]any{f.controlCol: map[string]any{"_eq": "gqls-nonexistent-zzz-9f3a"}}
	widen := map[string]any{"_or": []any{map[string]any{}}} // [{}] → matches all

	controlResp, _ := c.send(ctx, cc, point, control, result)
	widenResp, widenBody := c.send(ctx, cc, point, widen, result)
	if controlResp == nil {
		return
	}

	// Target: a predicate selecting privileged rows (only in the full set).
	var targetResp *transport.Response
	var targetBody []byte
	if !conservative && f.privCol != "" {
		target := map[string]any{f.privCol: map[string]any{"_eq": f.privVal}}
		targetResp, targetBody = c.send(ctx, cc, point, target, result)
	}

	// Decide, then re-test once for consistency.
	if targetResp != nil && i07Surfaces(controlResp, targetResp) {
		t2, _ := c.send(ctx, cc, point, map[string]any{f.privCol: map[string]any{"_eq": f.privVal}}, result)
		if i07Surfaces(controlResp, t2) {
			result.Findings = append(result.Findings, c.finding(cc, f, "confirmed",
				fmt.Sprintf("a target predicate {%s: {_eq: %v}} surfaced rows the restrictive control filter excluded",
					f.privCol, f.privVal),
				targetResp.Request, targetBody))
			return
		}
	}
	if i07Superset(controlResp, widenResp) {
		w2, _ := c.send(ctx, cc, point, widen, result)
		if i07Superset(controlResp, w2) {
			result.Findings = append(result.Findings, c.finding(cc, f, "firm",
				"a widening predicate {_or: [{}]} returned a strict superset of the restrictive control filter",
				widenResp.Request, widenBody))
		}
	}
}

// i07Superset reports whether widen is a non-erroring data superset of control.
func i07Superset(control, widen *transport.Response) bool {
	if control == nil || widen == nil {
		return false
	}
	if !i01Usable(authz.Classify(control)) || authz.Classify(widen) != authz.ClassSuccess {
		return false
	}
	if inject.BodyEquivalent(control, widen) {
		return false
	}
	return i01DataLen(widen) > i01DataLen(control)
}

// i07Surfaces reports whether target returns success data exceeding control
// (privileged rows the control filter hid).
func i07Surfaces(control, target *transport.Response) bool {
	if control == nil || target == nil {
		return false
	}
	if authz.Classify(target) != authz.ClassSuccess {
		return false
	}
	return i01DataLen(target) > i01DataLen(control)
}

func (c *ormOperatorInjectionCheck) send(ctx context.Context, cc *CheckContext, point inject.Point, predicate map[string]any, result *CheckResult) (*transport.Response, []byte) {
	doc, vars := point.RenderValue(cc.Schema, predicate)
	resp, body, err := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
	result.ProbeCount++
	if err != nil {
		return nil, body
	}
	return resp, body
}

func (c *ormOperatorInjectionCheck) finding(cc *CheckContext, f i07Filter, confidence, evidence string, reproReq *http.Request, reproBody []byte) Finding {
	fnd := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  Injection,
		Title:     fmt.Sprintf("ORM Operator Injection — filter predicate abuse on %s", f.field),
		Description: fmt.Sprintf(
			"The %q argument (type %q) on %s field %q accepts attacker-controlled filter predicates that override "+
				"the intended scope: %s. Returned rows are not included; only the differential is reported.",
			f.arg, f.typeName, cc.Target, f.field, evidence),
		Impact: "Attacker-controlled filter predicates bypass the intended query scope, enabling authorization/" +
			"filter bypass and blind data exfiltration — access to rows outside the intended scope (other tenants, " +
			"admin records).",
		Remediation: "Restrict the exposed filter surface (allow-list permitted operators/fields per role) and " +
			"enforce row-level security / permission rules in the data layer (Hasura permissions, Postgraphile RLS) " +
			"so client predicates cannot widen access. Never rely on the client to scope queries.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/943.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		},
		ReproBody:   reproBody,
		Confidence:  confidence,
		CWE:         "CWE-943",
		OWASP:       "API1:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "ormi:"+f.field),
	}
	if reproReq != nil {
		fnd.ReproRequest = reproReq
	}
	return fnd
}

// i07FindFilters discovers query fields with a filter/where input-object arg.
func i07FindFilters(s *schema.Schema) []i07Filter {
	var out []i07Filter
	for _, fld := range s.QueryFields() {
		if fld == nil {
			continue
		}
		for _, a := range fld.Args {
			if a == nil || a.Type == nil {
				continue
			}
			u := a.Type.Unwrap()
			if u == nil || u.Kind != schema.KindInputObject {
				continue
			}
			td := s.FindType(u.Name)
			if td == nil || !i07IsFilterType(a.Name, td) {
				continue
			}
			controlCol, privCol, privVal := i07Columns(td)
			if controlCol == "" {
				continue // need a column to build a restrictive control
			}
			out = append(out, i07Filter{
				field: fld.Name, arg: a.Name, typeName: u.Name,
				nonNull:    a.Type.Kind == schema.KindNonNull,
				controlCol: controlCol, privCol: privCol, privVal: privVal,
			})
		}
	}
	return out
}

// i07IsFilterType reports whether arg/type looks like a generated filter input.
func i07IsFilterType(argName string, td *schema.TypeDef) bool {
	if i07FilterArgRe.MatchString(argName) || i07FilterTypeRe.MatchString(td.Name) {
		return true
	}
	for _, f := range td.InputFields {
		if f != nil && i07OperatorFieldRe.MatchString(f.Name) {
			return true
		}
	}
	return false
}

// i07Columns returns the first column field (for the control predicate) and a
// privileged column + value (for the target predicate), skipping operator fields.
func i07Columns(td *schema.TypeDef) (controlCol, privCol string, privVal any) {
	for _, f := range td.InputFields {
		if f == nil || i07OperatorFieldRe.MatchString(f.Name) {
			continue
		}
		if controlCol == "" {
			controlCol = f.Name
		}
		if privCol == "" && i07PrivilegedColRe.MatchString(f.Name) {
			privCol = f.Name
			if strings.Contains(strings.ToLower(f.Name), "role") {
				privVal = "admin"
			} else {
				privVal = true
			}
		}
	}
	return controlCol, privCol, privVal
}
