package checks

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// massAssignCheck implements GQL-B02: Mass Assignment via Input Objects. A
// mutation's input object accepts a privilege/state field the client should not
// be able to set (isAdmin, role, verified, owner, tenantId, …) and the server
// honors it — auto-binding client input to internal fields (OWASP API3:2023 /
// CWE-915), enabling privilege escalation.
//
// Like GQL-A05 it performs state-changing requests, so it is disabled by default
// and gated behind --authz-allow-mutations. It reuses the A05 discipline: it
// discovers an object the configured identity owns, runs a
// capture → inject → verify → restore cycle, never invokes destructive-named
// mutations, and always restores the original value. Injected values are
// non-real elevating sentinels (a bogus role, a boolean toggle) chosen so
// detection proves the input was honored without actually granting real admin.
type massAssignCheck struct{}

func init() {
	MustRegister(&massAssignCheck{})
}

func (c *massAssignCheck) ID() string           { return "GQL-B02" }
func (c *massAssignCheck) Name() string         { return "Mass Assignment via Input Objects" }
func (c *massAssignCheck) Category() Category   { return Authorization }
func (c *massAssignCheck) Severity() Severity   { return HIGH }
func (c *massAssignCheck) RequiresSchema() bool { return true }

const (
	maxMassAssignCandidates = 3
	// maxInputWalkDepth bounds the recursion through nested input objects when
	// searching for a privileged settable field.
	maxInputWalkDepth = 3
)

// privFieldRe matches privilege/state field names a client should not control.
var privFieldRe = regexp.MustCompile(`(?i)^(is_?admin|admin|role|roles|is_?superuser|verified|email_?verified|is_?active|enabled|balance|credit|owner|owner_?id|user_?id|tenant_?id|org_?id|permission|scope|status)$`)

// roleLikeRe matches privileged string fields where a role/label-style sentinel
// is the natural elevating value (as opposed to an id/owner reference).
var roleLikeRe = regexp.MustCompile(`(?i)(role|permission|scope|status)`)

// adminEnumRe matches enum values that would grant real elevated privilege; the
// enum sentinel deliberately avoids these so detection never grants admin.
var adminEnumRe = regexp.MustCompile(`(?i)(admin|root|super|owner|god|sudo|manager)`)

// massAssignCandidate is a mutation carrying a privileged settable field inside
// (or as) an input argument, paired with a read fetcher exposing the same field.
type massAssignCandidate struct {
	mutation    *schema.FieldDef
	idArg       string          // top-level id argument of the mutation
	idArgType   string          // its named scalar type
	targetArg   string          // the mutation argument carrying the privileged field
	argType     *schema.TypeRef // the target argument's type (for nested rendering)
	path        []string        // field path within the input object ([] ⇒ the arg itself is the field)
	privField   string          // the privileged field name
	privType    string          // the privileged field's named scalar/enum type
	isEnum      bool            // whether privType is an enum
	fetcher     surface.ObjectFetcher
	readIDField string
}

// inputPath renders the human-readable path to the privileged field.
func (cand massAssignCandidate) inputPath() string {
	if len(cand.path) == 0 {
		return cand.targetArg
	}
	return cand.targetArg + "." + strings.Join(cand.path, ".")
}

// Run executes the mass-assignment check.
func (c *massAssignCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: hard gate (writes) ────────────────────────────────────────────
	if !cc.AllowMutations {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "GQL-B02 performs state-changing requests and is disabled by default; " +
			"re-run with --authz-allow-mutations after confirming you are authorized to test writes against this target"
		return result, nil
	}

	// ── Step 2: find candidates ───────────────────────────────────────────────
	cands := findMassAssignCandidates(cc.Schema, cc.AllowedMutations)
	if len(cands) == 0 {
		result.PassReason = "no mutation input exposes a client-settable privileged field paired with a readable " +
			"verification field (a candidate needs an id argument, a privileged scalar/bool/enum field such as " +
			"isAdmin/role/verified reachable through its input, and a matching read query; destructive-named " +
			"mutations are excluded unless allow-listed via --authz-allow-mutation)"
		return result, nil
	}

	client := cc.HTTPClient
	if client == nil {
		client = cc.ProbeClient()
	}
	self := Identity{Name: "configured", Client: client}

	var (
		passProbes []PassProbe
		ownerCache = map[string]string{}
		tested     int
	)

	for ci := range cands {
		if ctx.Err() != nil {
			break
		}
		cand := cands[ci]

		cacheKey := cand.fetcher.RootField
		objID, cached := ownerCache[cacheKey]
		if !cached {
			objID = discoverOwnerObjectID(ctx, cc, self, cand.fetcher, &result)
			ownerCache[cacheKey] = objID
		}
		if objID == "" {
			continue
		}

		// ── Capture: read the field's current value (we must be able to revert) ─
		original, capOK := readPrivField(ctx, cc, client, cand, objID, &result)
		if !capOK {
			continue
		}
		tested++

		// ── Choose a non-real elevating sentinel distinct from the original ─────
		sentinel, sentOK := massAssignSentinel(cc.Schema, cand, original)
		if !sentOK {
			passProbes = append(passProbes, PassProbe{
				Label: fmt.Sprintf("mass-assign %s.%s: could not synthesize a safe elevating sentinel (skipped)",
					cand.mutation.Name, cand.privField),
			})
			continue
		}

		// ── Inject: set the privileged field via the client input ──────────────
		attackDoc := buildMassAssignDoc(cc.Schema, cand, objID, sentinel.literal)
		if attackDoc == "" {
			continue
		}
		aResp, aBody, aerr := gqlPost(ctx, client, cc.Target, attackDoc)
		result.ProbeCount++
		if aerr != nil || aResp == nil {
			continue
		}
		attackCls := authz.Classify(aResp)

		// ── Verify via read-back ───────────────────────────────────────────────
		after, verOK := readPrivField(ctx, cc, client, cand, objID, &result)

		switch {
		case verOK && after == sentinel.plain:
			// Confirmed: the client-supplied privileged value persisted.
			restored := restorePrivField(ctx, cc, client, cand, objID, original, &result)
			result.Findings = append(result.Findings,
				c.finding(cc, cand, sentinel, "confirmed", restored, aResp, aBody))
			return result, nil

		case !verOK && attackCls == authz.ClassSuccess:
			// Accepted but not verifiable — firm only.
			restored := restorePrivField(ctx, cc, client, cand, objID, original, &result)
			result.Findings = append(result.Findings,
				c.finding(cc, cand, sentinel, "firm", restored, aResp, aBody))
			return result, nil

		default:
			// Ignored/rejected. Restore only if something actually changed.
			if verOK && after != original {
				restorePrivField(ctx, cc, client, cand, objID, original, &result)
			}
			passProbes = append(passProbes, PassProbe{
				Label: fmt.Sprintf("mass-assign %s via %q: %s, %s unchanged (privileged input appears ignored)",
					cand.mutation.Name, cand.inputPath(), attackCls, cand.privField),
				Request: aResp.Request, Body: aBody,
			})
		}
	}

	if len(result.Findings) > 0 {
		return result, nil
	}
	result.PassProbes = passProbes
	if tested == 0 {
		result.PassReason = "could not capture any owned object's privileged field to test safely; " +
			"provide --authz-seed 'field=id' or ensure a viewer/list query exposes an id and the field"
	} else {
		result.PassReason = fmt.Sprintf(
			"tested %d privileged-field injection(s) across %d candidate mutation(s); the server ignored or "+
				"rejected the client-supplied privileged input (mass assignment appears prevented)",
			tested, len(cands))
	}
	return result, nil
}

// finding builds the HIGH mass-assignment finding.
func (c *massAssignCheck) finding(cc *CheckContext, cand massAssignCandidate, sentinel massSentinel,
	confidence, restored string, aResp *transport.Response, aBody []byte) Finding {

	proof := fmt.Sprintf("a read-back confirmed %s was set to the client-supplied value %s", cand.privField, sentinel.display)
	if confidence == "firm" {
		proof = fmt.Sprintf("the mutation accepted the client-supplied %s field (HTTP 200 with data) but the "+
			"change could not be re-read to confirm persistence", cand.privField)
	}

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  Authorization,
		Title:     fmt.Sprintf("Mass Assignment — client can set %s via %s input", cand.privField, cand.mutation.Name),
		Description: fmt.Sprintf(
			"The mutation %s auto-bound the client-controlled input path %q to the privileged field %q: %s. "+
				"A non-real elevating sentinel (%s) was used so detection proves the input was honored without "+
				"actually granting real privilege, and the original value was restored (%s). Data is redacted.",
			cand.mutation.Name, cand.inputPath(), cand.privField, proof, sentinel.display, restored),
		Impact: "A normal user can set privileged/internal fields (admin flags, roles, verification status, " +
			"ownership, balances) on their own or others' objects through an auto-bound input — leading to " +
			"privilege escalation, account takeover, and fraud.",
		Remediation: "Never auto-bind client input objects to internal/privileged fields; use explicit input DTOs " +
			"with an allow-list of client-settable fields; enforce server-side authorization for privileged state " +
			"changes; and ignore or reject unknown/forbidden input fields.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/915.html",
		},
		Confidence:   confidence,
		CWE:          "CWE-915",
		OWASP:        "API3:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "massassign:"+cand.mutation.Name+"."+cand.privField),
		ReproRequest: aResp.Request,
		ReproBody:    aBody,
	}
}

// ── read / restore ───────────────────────────────────────────────────────────

// readPrivField reads the candidate's privileged field on the owned object via
// the read fetcher, returning the scalar value and whether the read succeeded.
func readPrivField(ctx context.Context, cc *CheckContext, client *transport.Client,
	cand massAssignCandidate, objID string, result *CheckResult) (string, bool) {

	idLit := formatIDLiteral(cand.fetcher.IDArgType, objID)
	sel := cand.readIDField
	if cand.privField != cand.readIDField {
		sel += " " + cand.privField
	}
	q := fmt.Sprintf("query { %s(%s: %s) { %s } }", cand.fetcher.RootField, cand.fetcher.IDArg, idLit, sel)
	resp, _, err := gqlPost(ctx, client, cc.Target, q)
	result.ProbeCount++
	if err != nil || resp == nil {
		return "", false
	}
	obj, ok := objectNode(resp, cand.fetcher.RootField)
	if !ok {
		return "", false
	}
	v, present := obj[cand.privField]
	if !present {
		return "", false
	}
	s := jsonScalar(v)
	if s == "" {
		// null / composite value — we cannot safely set-and-revert it.
		return "", false
	}
	return s, true
}

// restorePrivField writes the captured original value back, returning a
// human-readable status. Best-effort; a failure is reported, never hidden.
func restorePrivField(ctx context.Context, cc *CheckContext, client *transport.Client,
	cand massAssignCandidate, objID, original string, result *CheckResult) string {

	doc := buildMassAssignDoc(cc.Schema, cand, objID, massAssignLiteral(cand, original))
	if doc == "" {
		return "restore FAILED: could not build a restore document — manual cleanup may be required"
	}
	resp, _, err := gqlPost(ctx, client, cc.Target, doc)
	result.ProbeCount++
	if err != nil || resp == nil {
		return "restore FAILED: " + errString(err)
	}
	if authz.Classify(resp) == authz.ClassSuccess {
		return "restored successfully"
	}
	return "restore FAILED: server did not accept the restore write — manual cleanup may be required"
}

// ── sentinel selection ───────────────────────────────────────────────────────

// massSentinel is an elevating-but-safe value: literal is the GraphQL literal to
// inject, plain is the JSON-scalar form for read-back comparison, and display is
// a human-readable rendering for the finding.
type massSentinel struct {
	literal string
	plain   string
	display string
}

// massAssignSentinel returns a non-real elevating sentinel for the candidate's
// privileged field, distinct from the captured original. It never yields a value
// that grants real privilege (booleans toggle, roles get a bogus label, enums
// pick a non-admin value, id-like fields get a bogus reference).
func massAssignSentinel(s *schema.Schema, cand massAssignCandidate, original string) (massSentinel, bool) {
	switch {
	case cand.isEnum:
		v := benignEnumValue(s, cand.privType, original)
		if v == "" {
			return massSentinel{}, false
		}
		return massSentinel{literal: v, plain: v, display: v}, true

	case cand.privType == "Boolean":
		v := "true"
		if strings.EqualFold(original, "true") {
			v = "false" // already elevated (unusual) — a toggle still proves control
		}
		return massSentinel{literal: v, plain: v, display: v}, true

	case cand.privType == "String" || cand.privType == "ID":
		plain := "gqls-probe-" + newBizProbeCode()
		if roleLikeRe.MatchString(cand.privField) {
			plain = "gqls-probe-role"
			if plain == original {
				plain = "gqls-probe-role-" + newBizProbeCode()
			}
		}
		return massSentinel{literal: strconv.Quote(plain), plain: plain, display: strconv.Quote(plain)}, true
	}
	return massSentinel{}, false
}

// benignEnumValue returns an enum value that is not admin-like and differs from
// original, preferring a non-privileged label so detection never grants admin.
func benignEnumValue(s *schema.Schema, enumType, original string) string {
	td := s.FindType(enumType)
	if td == nil {
		return ""
	}
	vals := append([]string(nil), td.EnumValues...)
	sort.Strings(vals)
	for _, v := range vals {
		if v != original && !adminEnumRe.MatchString(v) {
			return v
		}
	}
	for _, v := range vals {
		if v != original {
			return v
		}
	}
	return ""
}

// massAssignLiteral formats a captured scalar value as a GraphQL literal for the
// candidate's field type (booleans/enums unquoted, strings/ids quoted).
func massAssignLiteral(cand massAssignCandidate, value string) string {
	switch {
	case cand.isEnum, cand.privType == "Boolean":
		return value
	default:
		return strconv.Quote(value)
	}
}

// ── candidate discovery ──────────────────────────────────────────────────────

// findMassAssignCandidates returns up to maxMassAssignCandidates mutations that
// expose a client-settable privileged field paired with a read fetcher,
// deterministically ordered by mutation name.
func findMassAssignCandidates(s *schema.Schema, allowed []string) []massAssignCandidate {
	if s == nil {
		return nil
	}
	allowSet := map[string]bool{}
	for _, a := range allowed {
		allowSet[a] = true
	}
	fetchers := surface.Fetchers(s)

	muts := make([]*schema.FieldDef, len(s.MutationFields()))
	copy(muts, s.MutationFields())
	sort.Slice(muts, func(i, j int) bool { return muts[i].Name < muts[j].Name })

	var out []massAssignCandidate
	for _, m := range muts {
		if m == nil {
			continue
		}
		if a05DestructiveRe.MatchString(m.Name) && !allowSet[m.Name] {
			continue // destructive-named and not allow-listed → never test
		}
		idArg, idArgType := idArgOf(m)
		if idArg == "" {
			continue // need an id to target an owned object and read it back
		}
		cand, ok := privFieldCandidate(s, m, idArg, idArgType, fetchers)
		if !ok {
			continue
		}
		out = append(out, cand)
		if len(out) >= maxMassAssignCandidates {
			break
		}
	}
	return out
}

// privFieldCandidate finds the first privileged settable field reachable through
// one of the mutation's arguments (as a direct scalar arg, or within an input
// object), paired with a read fetcher exposing the same field.
func privFieldCandidate(s *schema.Schema, m *schema.FieldDef, idArg, idArgType string,
	fetchers []surface.ObjectFetcher) (massAssignCandidate, bool) {

	for _, a := range m.Args {
		if a == nil || a.Name == idArg || a.Type == nil {
			continue
		}
		u := a.Type.Unwrap()
		if u == nil {
			continue
		}

		// Direct scalar/enum argument that is itself a privileged field.
		if pt, isEnum, ok := verifiableScalar(s, u); ok && privFieldRe.MatchString(a.Name) {
			cand := massAssignCandidate{
				mutation: m, idArg: idArg, idArgType: idArgType,
				targetArg: a.Name, argType: a.Type, path: nil,
				privField: a.Name, privType: pt, isEnum: isEnum,
			}
			if f, rid, ok := matchReadFetcher(s, fetchers, a.Name); ok {
				cand.fetcher, cand.readIDField = f, rid
				return cand, true
			}
			continue
		}

		// Input-object argument: walk its fields for a privileged leaf.
		if resolvedKind(s, u) == schema.KindInputObject {
			td := s.FindType(u.Name)
			if td == nil {
				continue
			}
			path, pt, isEnum, ok := searchPrivPath(s, td, maxInputWalkDepth)
			if !ok {
				continue
			}
			privField := path[len(path)-1]
			f, rid, ok := matchReadFetcher(s, fetchers, privField)
			if !ok {
				continue
			}
			cand := massAssignCandidate{
				mutation: m, idArg: idArg, idArgType: idArgType,
				targetArg: a.Name, argType: a.Type, path: path,
				privField: privField, privType: pt, isEnum: isEnum,
				fetcher: f, readIDField: rid,
			}
			// Ensure the injection document is actually buildable.
			if buildMassAssignDoc(s, cand, "0", massSentinelPlaceholder(cand)) == "" {
				continue
			}
			return cand, true
		}
	}
	return massAssignCandidate{}, false
}

// resolvedKind returns a type reference's kind, falling back to the type
// definition's kind when the reference itself does not carry one.
func resolvedKind(s *schema.Schema, u *schema.TypeRef) schema.TypeKind {
	if u == nil {
		return ""
	}
	if u.Kind != "" && u.Kind != schema.KindNonNull && u.Kind != schema.KindList {
		return u.Kind
	}
	if s != nil {
		if td := s.FindType(u.Name); td != nil {
			return td.Kind
		}
	}
	return u.Kind
}

// searchPrivPath walks an input-object type (bounded by depth) for a privileged,
// verifiable settable field, returning the field-name path to it. Fields are
// examined in name order for deterministic candidate selection.
func searchPrivPath(s *schema.Schema, td *schema.TypeDef, depth int) (path []string, privType string, isEnum, ok bool) {
	if td == nil {
		return nil, "", false, false
	}
	fields := append([]*schema.FieldDef(nil), td.InputFields...)
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })

	// Prefer a direct privileged scalar/enum field at this level.
	for _, f := range fields {
		if f == nil || f.Type == nil {
			continue
		}
		u := f.Type.Unwrap()
		if u == nil {
			continue
		}
		if pt, en, isScalar := verifiableScalar(s, u); isScalar && privFieldRe.MatchString(f.Name) {
			return []string{f.Name}, pt, en, true
		}
	}
	if depth <= 0 {
		return nil, "", false, false
	}
	// Recurse into nested input objects.
	for _, f := range fields {
		if f == nil || f.Type == nil {
			continue
		}
		u := f.Type.Unwrap()
		if u == nil || u.Kind != schema.KindInputObject {
			continue
		}
		ntd := s.FindType(u.Name)
		if ntd == nil {
			continue
		}
		if sub, pt, en, found := searchPrivPath(s, ntd, depth-1); found {
			return append([]string{f.Name}, sub...), pt, en, true
		}
	}
	return nil, "", false, false
}

// verifiableScalar reports whether a type is a settable scalar whose value can
// be verified via read-back (Boolean/String/ID/enum). Numeric fields are
// excluded: the safe probe for them is a no-op (per the ticket's balance→original
// guidance), which cannot be verified, so they never produce a finding.
func verifiableScalar(s *schema.Schema, u *schema.TypeRef) (typeName string, isEnum, ok bool) {
	if u == nil {
		return "", false, false
	}
	switch u.Name {
	case "Boolean", "String", "ID":
		return u.Name, false, true
	case "Int", "Float":
		return "", false, false
	}
	kind := u.Kind
	if kind == "" && s != nil {
		if td := s.FindType(u.Name); td != nil {
			kind = td.Kind
		}
	}
	if kind == schema.KindEnum {
		return u.Name, true, true
	}
	return "", false, false
}

// ── document building ────────────────────────────────────────────────────────

// buildMassAssignDoc builds a mutation that targets the owned object by id and
// sets the privileged field to valueLiteral (nested inside its input object when
// applicable), synthesizing any other required arguments/input fields. Returns
// "" when a required composite argument/field cannot be synthesized.
func buildMassAssignDoc(s *schema.Schema, cand massAssignCandidate, objID, valueLiteral string) string {
	idLit := formatIDLiteral(cand.idArgType, objID)
	parts := []string{fmt.Sprintf("%s: %s", cand.idArg, idLit)}

	// The target argument carrying the privileged field.
	var targetVal string
	if len(cand.path) == 0 {
		targetVal = valueLiteral // the argument itself is the privileged field
	} else {
		v, ok := renderInputPath(s, cand.argType, cand.path, valueLiteral)
		if !ok {
			return ""
		}
		targetVal = v
	}
	parts = append(parts, fmt.Sprintf("%s: %s", cand.targetArg, targetVal))

	// Any other required top-level arguments.
	for _, a := range cand.mutation.Args {
		if a == nil || a.Name == cand.idArg || a.Name == cand.targetArg {
			continue
		}
		if argRequired(a) {
			ev := surface.ExampleValue(a.Type, s)
			if ev == "" {
				return ""
			}
			parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
		}
	}
	return fmt.Sprintf("mutation { %s(%s)%s }",
		cand.mutation.Name, strings.Join(parts, ", "), mutSelectionSet(cand.mutation.Type, s))
}

// renderInputPath renders the input-object literal for argType, setting the
// privileged leaf (reached via path) to valueLiteral and synthesizing sibling
// required scalar fields. Returns false when a required sibling cannot be built.
func renderInputPath(s *schema.Schema, argType *schema.TypeRef, path []string, valueLiteral string) (string, bool) {
	if len(path) == 0 || argType == nil {
		return "", false
	}
	u := argType.Unwrap()
	if u == nil {
		return "", false
	}
	td := s.FindType(u.Name)
	if td == nil {
		return "", false
	}

	head := path[0]
	var parts []string
	found := false
	for _, f := range td.InputFields {
		if f == nil {
			continue
		}
		if f.Name == head {
			found = true
			if len(path) == 1 {
				parts = append(parts, fmt.Sprintf("%s: %s", head, valueLiteral))
			} else {
				inner, ok := renderInputPath(s, f.Type, path[1:], valueLiteral)
				if !ok {
					return "", false
				}
				parts = append(parts, fmt.Sprintf("%s: %s", head, inner))
			}
			continue
		}
		if fieldRequired(f) {
			ev := surface.ExampleValue(f.Type, s)
			if ev == "" {
				return "", false
			}
			parts = append(parts, fmt.Sprintf("%s: %s", f.Name, ev))
		}
	}
	if !found {
		return "", false
	}
	return "{ " + strings.Join(parts, ", ") + " }", true
}

// massSentinelPlaceholder returns a type-appropriate placeholder literal for the
// buildability check during discovery (its concrete value is irrelevant — only
// whether the surrounding document can be assembled matters).
func massSentinelPlaceholder(cand massAssignCandidate) string {
	switch {
	case cand.isEnum:
		return "PLACEHOLDER" // a bare enum token; structure-only check
	case cand.privType == "Boolean":
		return "true"
	default:
		return strconv.Quote("placeholder")
	}
}

// fieldRequired reports whether an input field is required (NON_NULL). Input
// fields carry no default in the model, so NON_NULL is the required signal.
func fieldRequired(f *schema.FieldDef) bool {
	return f != nil && f.Type != nil && f.Type.Kind == schema.KindNonNull
}
