package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/scanner/inject"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// nosqlInjectionCheck implements GQL-I03: NoSQL (MongoDB) operator injection. It
// replaces an argument value with a Mongo operator object ({"$ne": …},
// {"$in": []}) — directly for custom JSON/Object scalar leaves, or string-encoded
// for plain String/ID leaves (body-parser quirks) — and flags when the result
// set tracks the operator semantics (a true operator returns a superset, a false
// one returns nothing), or when an operator logs in where a control was denied.
//
// Safety: read-only operator payloads only ($ne/$in matching; no writes, no
// side-effecting $where). Bounded points; mutation points gated; data redacted.
type nosqlInjectionCheck struct{}

func init() {
	MustRegister(&nosqlInjectionCheck{})
}

func (c *nosqlInjectionCheck) ID() string           { return "GQL-I03" }
func (c *nosqlInjectionCheck) Name() string         { return "NoSQL (MongoDB) Operator Injection" }
func (c *nosqlInjectionCheck) Category() Category   { return Injection }
func (c *nosqlInjectionCheck) Severity() Severity   { return CRITICAL }
func (c *nosqlInjectionCheck) RequiresSchema() bool { return true }

// i03MaxPoints bounds how many injection points are probed.
const i03MaxPoints = 25

// i03NonexistentMarker is an unlikely value used in $ne so the predicate matches
// (almost) every document.
const i03NonexistentMarker = "gqls-nonexistent-marker-9f3a"

// i03CredentialFields are substrings of a credential-like path/field name, used
// to enable the authentication-bypass variant.
var i03CredentialFields = []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "credential", "auth", "otp", "pin"}

// i03Mode classifies how a leaf can receive an operator object:
//   - "object": custom JSON/Object scalar — inject the operator object directly.
//   - "string": String/ID — inject the operator as a JSON-encoded string.
//   - "":       Int/Float/Boolean/enum — not operator-injectable.
func i03Mode(s *schema.Schema, scalarType string) string {
	switch scalarType {
	case "String", "ID":
		return "string"
	case "Int", "Float", "Boolean":
		return ""
	}
	if td := s.FindType(scalarType); td != nil && td.Kind == schema.KindEnum {
		return ""
	}
	return "object" // custom scalar (JSON/Object-like)
}

// Run executes the NoSQL operator-injection check.
func (c *nosqlInjectionCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "schema required to enumerate injection points"
		return result, nil
	}

	var objectPts, stringPts []inject.Point
	mutationGated := false
	for _, p := range inject.Points(cc.Schema) {
		mode := i03Mode(cc.Schema, p.ScalarType)
		if mode == "" {
			continue
		}
		if p.OpKind == "mutation" && !cc.AllowMutations {
			mutationGated = true
			continue
		}
		if mode == "object" {
			objectPts = append(objectPts, p)
		} else {
			stringPts = append(stringPts, p)
		}
	}
	// Object-injectable points are the most direct; probe them first.
	targets := inject.Cap(append(objectPts, stringPts...), i03MaxPoints)

	if len(targets) == 0 {
		if mutationGated {
			result.PassReason = "only mutation injection points exist; they are write-gated and were skipped " +
				"(pass --authz-allow-mutations to test them)."
		} else {
			result.PassReason = "no operator-injectable arguments (JSON/Object scalars or String/ID fields) were found"
		}
		return result, nil
	}

	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		c.probePoint(ctx, cc, tgt, &result)
	}

	if len(result.Findings) == 0 {
		reason := "no NoSQL operator injection detected: operator objects did not change the result set at any " +
			"injection point (inputs appear cast/validated before the database query)"
		if mutationGated {
			reason += "; mutation points were skipped (write-gated)"
		}
		result.PassReason = reason
	}
	return result, nil
}

// probePoint runs the operator differential (and auth-bypass variant) for one
// point, appending at most one finding.
func (c *nosqlInjectionCheck) probePoint(ctx context.Context, cc *CheckContext, tgt inject.Point, result *CheckResult) {
	mode := i03Mode(cc.Schema, tgt.ScalarType)

	controlResp := c.sendValue(ctx, cc, tgt, "gqls", result)
	if controlResp == nil {
		return
	}

	opTrue := map[string]any{"$ne": i03NonexistentMarker}
	opFalse := map[string]any{"$in": []any{}}

	trueResp, trueBody := c.sendOp(ctx, cc, tgt, mode, opTrue, result)
	falseResp, _ := c.sendOp(ctx, cc, tgt, mode, opFalse, result)

	if nosqlDivergence(trueResp, falseResp) {
		trueResp2, _ := c.sendOp(ctx, cc, tgt, mode, opTrue, result)
		falseResp2, _ := c.sendOp(ctx, cc, tgt, mode, opFalse, result)
		if nosqlDivergence(trueResp2, falseResp2) {
			authBypass := c.isCredentialPoint(tgt) && nosqlAuthBypass(controlResp, trueResp)
			result.Findings = append(result.Findings, c.finding(cc, tgt, "$ne / $in:[]", authBypass, trueResp, trueBody))
			return
		}
	}

	// Auth-bypass variant for credential-like fields: {"$ne": null}.
	if c.isCredentialPoint(tgt) {
		bypass := map[string]any{"$ne": nil}
		bypassResp, bypassBody := c.sendOp(ctx, cc, tgt, mode, bypass, result)
		if nosqlAuthBypass(controlResp, bypassResp) {
			bypassResp2, _ := c.sendOp(ctx, cc, tgt, mode, bypass, result)
			if nosqlAuthBypass(controlResp, bypassResp2) {
				result.Findings = append(result.Findings, c.finding(cc, tgt, "$ne:null", true, bypassResp, bypassBody))
			}
		}
	}
}

// sendValue injects a plain string value (the benign control).
func (c *nosqlInjectionCheck) sendValue(ctx context.Context, cc *CheckContext, tgt inject.Point, value string, result *CheckResult) *transport.Response {
	doc, vars := tgt.RenderValue(cc.Schema, value)
	resp, _, err := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
	result.ProbeCount++
	if err != nil {
		return nil
	}
	return resp
}

// sendOp injects an operator object (object mode) or its JSON-string encoding
// (string mode) at the point.
func (c *nosqlInjectionCheck) sendOp(ctx context.Context, cc *CheckContext, tgt inject.Point, mode string, op map[string]any, result *CheckResult) (*transport.Response, []byte) {
	var value any
	if mode == "object" {
		value = op
	} else {
		enc, _ := json.Marshal(op)
		value = string(enc)
	}
	doc, vars := tgt.RenderValue(cc.Schema, value)
	resp, body, err := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
	result.ProbeCount++
	if err != nil {
		return nil, body
	}
	return resp, body
}

func (c *nosqlInjectionCheck) isCredentialPoint(tgt inject.Point) bool {
	hay := strings.ToLower(tgt.RootField + "." + tgt.PathKey())
	for _, k := range i03CredentialFields {
		if strings.Contains(hay, k) {
			return true
		}
	}
	return false
}

// nosqlDivergence reports whether the operator-true response is a non-erroring
// data superset relative to the operator-false response (true returns more rows,
// they differ) — the hallmark of operator semantics reaching the query.
func nosqlDivergence(trueResp, falseResp *transport.Response) bool {
	if trueResp == nil || falseResp == nil {
		return false
	}
	if !i01Usable(authz.Classify(trueResp)) || !i01Usable(authz.Classify(falseResp)) {
		return false
	}
	if authz.Classify(trueResp) != authz.ClassSuccess {
		return false
	}
	if inject.BodyEquivalent(trueResp, falseResp) {
		return false
	}
	return i01DataLen(trueResp) > i01DataLen(falseResp)
}

// nosqlAuthBypass reports whether an operator turned a denied/empty control into
// a successful response — a confirmed authentication bypass.
func nosqlAuthBypass(control, op *transport.Response) bool {
	if control == nil || op == nil {
		return false
	}
	if authz.Classify(op) != authz.ClassSuccess {
		return false
	}
	switch authz.Classify(control) {
	case authz.ClassAuthDenied, authz.ClassNotFound, authz.ClassEmpty:
		return !inject.BodyEquivalent(control, op)
	default:
		return false
	}
}

func (c *nosqlInjectionCheck) finding(cc *CheckContext, tgt inject.Point, payloadDesc string, authBypass bool, repro *transport.Response, reproBody []byte) Finding {
	pathKey := tgt.PathKey()
	bypassNote := ""
	if authBypass {
		bypassNote = " An authentication-bypass variant succeeded: the operator returned a successful response " +
			"where the benign control was denied."
	}
	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Injection,
		Title:     fmt.Sprintf("NoSQL Operator Injection — %s arg %s", tgt.RootField, pathKey),
		Description: fmt.Sprintf(
			"A MongoDB operator object injected at %s field %q (argument path %q) changed the result set, "+
				"proving the input reaches a Mongo query unsanitized: a true operator (%s) returned a superset "+
				"while a false operator returned nothing, re-tested for consistency.%s (Returned data is not "+
				"included; only the differential is reported.)",
			cc.Target, tgt.RootField, pathKey, payloadDesc, bypassNote),
		Impact: "NoSQL operator injection enables authentication bypass (e.g. password: {$ne: null}), blind data " +
			"exfiltration via $regex, and — with $where — server-side JavaScript execution against the database.",
		Remediation: "Reject operator objects from user-controlled inputs; cast and validate inputs to the " +
			"expected scalar types before building queries; disable $where; use an ODM with strict schemas; and " +
			"never pass raw JSON arguments into Mongo query objects.",
		References: []string{
			"https://owasp.org/www-community/Injection_Flaws",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/943.html",
		},
		ReproBody:   reproBody,
		Confidence:  "confirmed",
		CWE:         "CWE-943",
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "nosqli:"+tgt.RootField+"/"+pathKey),
	}
	if repro != nil {
		f.ReproRequest = repro.Request
	}
	return f
}
