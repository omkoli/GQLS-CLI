package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// boplaCheck implements GQL-A03: Broken Object Property Level Authorization
// (field-level authz / excessive data exposure).
//
// Where GQL-A01 is "wrong object", GQL-A03 is "right object, wrong fields": even
// when object access is intended, sensitive fields (email, ssn, salary, …) are
// returned to a role that should not see them. It is differential — it requests
// the same sensitive selection as an owner and an under-privileged identity and
// flags when the under-privileged identity receives the owner's sensitive values.
type boplaCheck struct{}

func init() {
	MustRegister(&boplaCheck{})
}

func (c *boplaCheck) ID() string { return "GQL-A03" }
func (c *boplaCheck) Name() string {
	return "Field-Level Authorization (BOPLA / Excessive Data Exposure)"
}
func (c *boplaCheck) Category() Category   { return Authorization }
func (c *boplaCheck) Severity() Severity   { return HIGH }
func (c *boplaCheck) RequiresSchema() bool { return true }

const (
	maxBoplaTargets    = 5 // (fetcher, type) targets tested per run
	maxSensitiveFields = 6 // sensitive scalar fields requested per target
)

// boplaTarget is an object fetcher whose return type exposes sensitive fields.
type boplaTarget struct {
	fetcher   surface.ObjectFetcher
	selection string   // the GraphQL selection set "{ id ssn email }"
	idField   string   // the id field name within the selection (for SameObject)
	fields    []string // the sensitive field names requested
}

// Run executes the BOPLA / field-level authorization check.
func (c *boplaCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	if !cc.HasIdentities() {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "field-level authorization testing requires >=2 operator-supplied identities; " +
			"configure them via --identity / gqls.yaml"
		return result, nil
	}

	sensMap := surface.SensitiveFieldsByType(cc.Schema)
	fetchers := surface.Fetchers(cc.Schema)

	// Build targets: fetchers whose return type exposes sensitive scalar fields.
	var targets []boplaTarget
	for _, f := range fetchers {
		sel, idField, fields := buildSensitiveSelection(cc.Schema, f, sensMap)
		if len(fields) == 0 {
			continue
		}
		targets = append(targets, boplaTarget{fetcher: f, selection: sel, idField: idField, fields: fields})
		if len(targets) >= maxBoplaTargets {
			break
		}
	}
	if len(targets) == 0 {
		if len(sensMap) == 0 {
			result.PassReason = "no sensitive fields found in the reachable object graph (nothing to test for BOPLA)"
		} else {
			result.PassReason = "sensitive fields exist but no id-bearing object fetcher exposes them (nothing to test for BOPLA)"
		}
		return result, nil
	}

	pairs := cc.IdentityPairs()
	var (
		passProbes    []PassProbe
		ownerCache    = map[string]string{}
		comparisons   int
		objectDenied  int
		discoveredAny bool
	)

	for ti := range targets {
		if ctx.Err() != nil {
			break
		}
		tg := targets[ti]
		targetDone := false

		for pi := range pairs {
			if ctx.Err() != nil || targetDone {
				break
			}
			owner := pairs[pi][0]
			attacker := pairs[pi][1]

			cacheKey := owner.Name + "|" + tg.fetcher.RootField
			ownerObjID, cached := ownerCache[cacheKey]
			if !cached {
				ownerObjID = discoverOwnerObjectID(ctx, cc, owner, tg.fetcher, &result)
				ownerCache[cacheKey] = ownerObjID
			}
			if ownerObjID == "" {
				continue
			}
			discoveredAny = true

			idLit := formatIDLiteral(tg.fetcher.IDArgType, ownerObjID)
			query := fmt.Sprintf("query { %s(%s: %s) %s }",
				tg.fetcher.RootField, tg.fetcher.IDArg, idLit, tg.selection)

			ownerResp, _, oerr := gqlPost(ctx, owner.Client, cc.Target, query)
			result.ProbeCount++
			if oerr != nil || ownerResp == nil {
				continue
			}
			attackerResp, aBody, aerr := gqlPost(ctx, attacker.Client, cc.Target, query)
			result.ProbeCount++
			if aerr != nil || attackerResp == nil {
				continue
			}
			comparisons++

			ownerObj, ownerOK := objectNode(ownerResp, tg.fetcher.RootField)
			if !ownerOK {
				continue // owner cannot see the object → no baseline to compare against
			}
			attackerObj, attackerOK := objectNode(attackerResp, tg.fetcher.RootField)
			if !attackerOK {
				// Object itself denied to the attacker — an object-level (A01)
				// concern, not field-level. Skip; do not flag here.
				objectDenied++
				passProbes = append(passProbes, PassProbe{
					Label: fmt.Sprintf("BOPLA %s as %q: object access denied (defer to GQL-A01)",
						tg.fetcher.RootField, attacker.Name),
					Request: attackerResp.Request,
					Body:    aBody,
				})
				continue
			}

			// Compare each sensitive field: exposed when the attacker received the
			// SAME non-null value the owner did (i.e. the owner's data, not the
			// attacker's own object).
			var exposed []string
			for _, fld := range tg.fields {
				ov := jsonScalar(ownerObj[fld])
				av := jsonScalar(attackerObj[fld])
				if ov != "" && av != "" && ov == av {
					exposed = append(exposed, fld)
				}
			}
			if len(exposed) == 0 {
				passProbes = append(passProbes, PassProbe{
					Label: fmt.Sprintf("BOPLA %s as %q: no sensitive field exposed (field-level authz appears enforced)",
						tg.fetcher.RootField, attacker.Name),
					Request: attackerResp.Request,
					Body:    aBody,
				})
				continue
			}

			sameObject := tg.idField != "" &&
				jsonScalar(ownerObj[tg.idField]) != "" &&
				jsonScalar(ownerObj[tg.idField]) == jsonScalar(attackerObj[tg.idField])

			result.Findings = append(result.Findings,
				c.finding(cc, tg, owner, attacker, exposed, sameObject, attackerResp, aBody))
			targetDone = true
		}
	}

	if len(result.Findings) > 0 {
		return result, nil
	}

	result.PassProbes = passProbes
	switch {
	case !discoveredAny:
		result.PassReason = "could not establish any owner-owned object id to test for field exposure; " +
			"provide --authz-seed 'field=id' or ensure a viewer/list query exposes an id"
	default:
		note := ""
		if objectDenied > 0 {
			note = fmt.Sprintf(" (%d object(s) were denied to the under-privileged identity — see GQL-A01)", objectDenied)
		}
		result.PassReason = fmt.Sprintf(
			"performed %d field-exposure comparison(s) across %d target(s)%s; "+
				"field-level authorization appears enforced (no sensitive field leaked to an under-privileged role)",
			comparisons, len(targets), note)
	}
	return result, nil
}

// finding builds the HIGH BOPLA finding for a target with exposed fields.
func (c *boplaCheck) finding(cc *CheckContext, tg boplaTarget, owner, attacker Identity,
	exposed []string, sameObject bool, attackerResp *transport.Response, aBody []byte) Finding {

	sort.Strings(exposed)
	typeName := tg.fetcher.ReturnType
	paths := make([]string, len(exposed))
	for i, f := range exposed {
		paths[i] = typeName + "." + f
	}

	confidence := "firm"
	basis := "the same sensitive values were returned to both identities (object identity unverified)"
	if sameObject {
		confidence = "confirmed"
		basis = "the under-privileged identity received another principal's object and its sensitive fields"
	}

	redacted := authz.RedactLeak(exposed, attackerResp)
	if redacted == "" {
		redacted = "(values redacted)"
	}

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  Authorization,
		Title:     "Excessive Data Exposure — sensitive field(s) returned to under-privileged role",
		Description: fmt.Sprintf(
			"The under-privileged identity %q received sensitive field(s) [%s] via %s(%s) that the "+
				"privileged identity %q also sees; %s. Exposed values (redacted): %s.",
			attacker.Name, strings.Join(paths, ", "), tg.fetcher.RootField, tg.fetcher.IDArg,
			owner.Name, basis, redacted),
		Impact: "Disclosure of PII / financial / credential fields to roles that should not see them — " +
			"privacy and compliance violations (e.g. GDPR/PCI), credential leakage, and reconnaissance for " +
			"further attacks.",
		Remediation: "Apply authorization at the field/property level, not just the object level. Use field " +
			"middleware or @auth directives per sensitive field; return null or a field error for unauthorized " +
			"principals; never rely on clients to omit sensitive fields; minimize over-fetching in resolvers.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/213.html",
		},
		Confidence:   confidence,
		CWE:          "CWE-213",
		OWASP:        "API3:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "bopla:"+typeName+"."+strings.Join(exposed, ",")),
		ReproRequest: attackerResp.Request,
		ReproBody:    aBody,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// buildSensitiveSelection builds a selection set requesting an id field plus the
// fetcher return type's highest-scoring sensitive scalar fields (up to the cap),
// returning the selection, the id field name, and the sensitive field names.
func buildSensitiveSelection(s *schema.Schema, f surface.ObjectFetcher,
	sensMap map[string][]surface.SensitiveField) (selection, idField string, fields []string) {

	td := s.FindType(f.ReturnType)
	idField = idFieldOf(s, td)

	selFields := []string{idField}
	for _, sf := range sensMap[f.ReturnType] {
		if len(fields) >= maxSensitiveFields {
			break
		}
		if sf.Field == idField {
			continue
		}
		fd := fieldByName(td, sf.Field)
		if fd == nil || !isLeafField(s, fd) {
			continue // only scalar/enum sensitive fields are directly selectable
		}
		selFields = append(selFields, sf.Field)
		fields = append(fields, sf.Field)
	}
	if len(fields) == 0 {
		return "", idField, nil
	}
	return "{ " + strings.Join(selFields, " ") + " }", idField, fields
}

// objectNode parses resp and returns the object node at data.<rootField>, plus
// whether it is present as a non-null object.
func objectNode(resp *transport.Response, rootField string) (map[string]interface{}, bool) {
	if resp == nil {
		return nil, false
	}
	var env struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return nil, false
	}
	raw, ok := env.Data[rootField]
	if !ok {
		return nil, false
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// jsonScalar renders a decoded JSON scalar (string/number/bool) as a string,
// returning "" for null, objects, and arrays.
func jsonScalar(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return fmt.Sprintf("%v", t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	default:
		return ""
	}
}

// idFieldOf returns the id-like leaf field name of a type, or "id" as a fallback.
func idFieldOf(s *schema.Schema, td *schema.TypeDef) string {
	if td == nil {
		return "id"
	}
	for _, fd := range td.Fields {
		if fd != nil && idLikeFieldRe.MatchString(fd.Name) && isLeafField(s, fd) {
			return fd.Name
		}
	}
	return "id"
}

// fieldByName returns the named field of td, or nil.
func fieldByName(td *schema.TypeDef, name string) *schema.FieldDef {
	if td == nil {
		return nil
	}
	for _, fd := range td.Fields {
		if fd != nil && fd.Name == name {
			return fd
		}
	}
	return nil
}
