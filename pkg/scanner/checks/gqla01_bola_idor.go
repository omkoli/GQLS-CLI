package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// bolaCheck implements GQL-A01: Broken Object Level Authorization (BOLA/IDOR).
//
// It is differential: it fetches the same object by id as a higher-privilege
// "owner" identity and a lower-privilege "attacker" identity, and flags when the
// attacker receives the owner's object instead of an authorization denial.
type bolaCheck struct{}

func init() {
	MustRegister(&bolaCheck{})
}

func (c *bolaCheck) ID() string           { return "GQL-A01" }
func (c *bolaCheck) Name() string         { return "Broken Object Level Authorization (BOLA/IDOR)" }
func (c *bolaCheck) Category() Category   { return Authorization }
func (c *bolaCheck) Severity() Severity   { return CRITICAL }
func (c *bolaCheck) RequiresSchema() bool { return true }

// maxBolaFetchers caps how many object fetchers are tested per run (budget/safety).
const maxBolaFetchers = 5

// idLikeFieldRe matches identifier-like selection field names.
var idLikeFieldRe = regexp.MustCompile(`(?i)^(id|_id|.*id|nodeid|uuid|guid)$`)

// limitArgs are common pagination-limit argument names used to keep discovery
// list queries small.
var limitArgs = map[string]bool{"first": true, "limit": true, "top": true, "last": true, "count": true}

// Run executes the BOLA/IDOR differential check.
func (c *bolaCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: preconditions ────────────────────────────────────────────────
	if !cc.HasIdentities() {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "BOLA testing requires >=2 operator-supplied identities; " +
			"configure them via --identity / gqls.yaml"
		return result, nil
	}

	// ── Step 2: enumerate object fetchers ────────────────────────────────────
	fetchers := surface.Fetchers(cc.Schema)
	if len(fetchers) == 0 {
		result.PassReason = "no id-bearing object fetchers found in the schema (nothing to test for BOLA)"
		return result, nil
	}
	capped := false
	if len(fetchers) > maxBolaFetchers {
		fetchers = fetchers[:maxBolaFetchers]
		capped = true
	}

	pairs := cc.IdentityPairs()

	var (
		passProbes    []PassProbe
		ownerCache    = map[string]string{} // owner.Name|fetcher -> discovered id
		comparisons   int                   // differential comparisons performed
		discoveredAny bool
	)

	// ── Steps 3–5: per fetcher, per identity pair ────────────────────────────
	for fi := range fetchers {
		if ctx.Err() != nil {
			break
		}
		f := fetchers[fi]

		for pi := range pairs {
			if ctx.Err() != nil {
				break
			}
			owner := pairs[pi][0]
			attacker := pairs[pi][1]

			// Discover an owner-owned object id (seed → self-discovery), cached
			// per owner identity so repeated pairs don't re-probe.
			cacheKey := owner.Name + "|" + f.RootField
			ownerObjID, cached := ownerCache[cacheKey]
			if !cached {
				ownerObjID = discoverOwnerObjectID(ctx, cc, owner, f, &result)
				ownerCache[cacheKey] = ownerObjID
			}
			if ownerObjID == "" {
				continue // cannot establish an owner object for this (owner, fetcher)
			}
			discoveredAny = true

			idLit := formatIDLiteral(f.IDArgType, ownerObjID)
			query, idField := c.buildFetchQuery(cc.Schema, f, idLit)

			ownerResp, _, oerr := gqlPost(ctx, owner.Client, cc.Target, query)
			result.ProbeCount++
			if oerr != nil || ownerResp == nil {
				continue
			}
			attackerResp, attackerBody, aerr := gqlPost(ctx, attacker.Client, cc.Target, query)
			result.ProbeCount++
			if aerr != nil || attackerResp == nil {
				continue
			}
			comparisons++

			idPath := "data." + f.RootField + "." + idField
			diff := authz.Compare(ownerResp, attackerResp, idPath)

			// Positive: owner can read the object, attacker also reads it, and it
			// is the *same* object (same id) — a confirmed cross-identity leak.
			if diff.OwnerClass == authz.ClassSuccess &&
				diff.AttackerClass == authz.ClassSuccess && diff.SameObject {
				result.Findings = append(result.Findings,
					c.finding(cc, f, owner, attacker, ownerObjID, idLit, diff, attackerResp, attackerBody))
				break // first confirmed leak wins per fetcher
			}

			// Negative / inconclusive — record for transparency, never flag.
			passProbes = append(passProbes, PassProbe{
				Label: fmt.Sprintf("BOLA %s as %q vs %q: owner=%s attacker=%s sameObject=%v",
					f.RootField, owner.Name, attacker.Name,
					diff.OwnerClass, diff.AttackerClass, diff.SameObject),
				Request: attackerResp.Request,
				Body:    attackerBody,
			})
		}
	}

	if len(result.Findings) > 0 {
		return result, nil
	}

	// ── Clean run: explain the basis ─────────────────────────────────────────
	result.PassProbes = passProbes
	coverage := ""
	if capped {
		coverage = fmt.Sprintf(" (capped at the first %d fetchers by name)", maxBolaFetchers)
	}
	switch {
	case !discoveredAny:
		result.PassReason = "could not establish any owner-owned object id to test" + coverage +
			"; provide --authz-seed 'field=id' or ensure a viewer/list query exposes an id"
	default:
		result.PassReason = fmt.Sprintf(
			"performed %d cross-identity object comparison(s) across %d fetcher(s)%s; "+
				"object-level authorization appears enforced (no cross-identity object leak detected)",
			comparisons, len(fetchers), coverage)
	}
	return result, nil
}

// finding builds the CRITICAL BOLA finding.
func (c *bolaCheck) finding(cc *CheckContext, f surface.ObjectFetcher, owner, attacker Identity,
	ownerObjID, idLit string, diff authz.Diff, attackerResp *transport.Response, attackerBody []byte) Finding {

	redacted := authz.RedactLeak(diff.LeakedFields, attackerResp)
	if redacted == "" {
		redacted = "(no scalar fields returned)"
	}

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Authorization,
		Title: fmt.Sprintf("Broken Object Level Authorization — %s(%s) returns another principal's object",
			f.RootField, f.IDArg),
		Description: fmt.Sprintf(
			"Identity %q retrieved the object owned by %q via %s(%s: %s). "+
				"Both identities received the same object id, proving the lower-privilege identity "+
				"accessed an object it does not own. Leaked fields (redacted): %s.",
			attacker.Name, owner.Name, f.RootField, f.IDArg, idLit, redacted),
		Impact: "Any authenticated (or lower-privileged) user can read arbitrary objects belonging to " +
			"other users by manipulating the object identifier, enabling mass data exposure, privacy " +
			"breaches, and enumeration of other principals' records.",
		Remediation: "Enforce object-level authorization in the resolver/data layer for every object fetch: " +
			"verify the requesting principal owns or may access the object before returning it. Do not rely " +
			"on unguessable identifiers. Apply centralized policy (row-level security, an authorization " +
			"middleware, or @auth rules scoped to the current principal), and test the global-id/node " +
			"interface as well.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/639.html",
		},
		Confidence:   "confirmed",
		CWE:          "CWE-639",
		OWASP:        "API1:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "bola:"+f.RootField),
		ReproRequest: attackerResp.Request,
		ReproBody:    attackerBody,
	}
}

// discoverOwnerObjectID returns an object id the owner identity legitimately
// owns for fetcher f. Priority: operator seed → list-query discovery → viewer/me
// discovery. Returns "" when none can be established. It increments
// result.ProbeCount for each discovery request sent. Shared by the object-level
// authorization checks (GQL-A01, GQL-A03).
func discoverOwnerObjectID(ctx context.Context, cc *CheckContext, owner Identity,
	f surface.ObjectFetcher, result *CheckResult) string {

	if cc.AuthzSeeds != nil {
		if v := strings.TrimSpace(cc.AuthzSeeds[f.RootField]); v != "" {
			return v
		}
	}

	s := cc.Schema

	// List-query discovery: a root query returning [ReturnType].
	if lf := listFieldFor(s, f.ReturnType, f.RootField); lf != nil {
		q := buildListQuery(s, lf)
		resp, _, err := gqlPost(ctx, owner.Client, cc.Target, q)
		result.ProbeCount++
		if err == nil {
			if id := authz.FirstID(resp); id != "" {
				return id
			}
		}
	}

	// Viewer/me discovery: a root field returning the same object type.
	if mf := viewerFieldFor(s, f.ReturnType); mf != nil {
		q := fmt.Sprintf("query { %s { id } }", mf.Name)
		resp, _, err := gqlPost(ctx, owner.Client, cc.Target, q)
		result.ProbeCount++
		if err == nil {
			if id := authz.FirstID(resp); id != "" {
				return id
			}
		}
	}

	return ""
}

// buildFetchQuery constructs the single-object fetch query for fetcher f using
// idLit as the id argument value, returning the query and the id field name
// requested in the selection set (for the Compare id path).
func (c *bolaCheck) buildFetchQuery(s *schema.Schema, f surface.ObjectFetcher, idLit string) (query, idField string) {
	sel, idField := buildSelection(s, f.ReturnType)

	parts := []string{fmt.Sprintf("%s: %s", f.IDArg, idLit)}
	if fd := queryFieldByName(s, f.RootField); fd != nil {
		for _, a := range fd.Args {
			if a == nil || a.Name == f.IDArg {
				continue
			}
			if argRequired(a) {
				if ev := surface.ExampleValue(a.Type, s); ev != "" {
					parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
				}
			}
		}
	}
	query = fmt.Sprintf("query { %s(%s) %s }", f.RootField, strings.Join(parts, ", "), sel)
	return query, idField
}

// buildSelection returns a minimal, non-sensitive selection set for typeName
// (an id-like field plus up to two benign scalar fields) and the id field name
// used. Sensitive fields are deliberately excluded — a BOLA proof only needs an
// identifier, not the victim's PII.
func buildSelection(s *schema.Schema, typeName string) (sel, idField string) {
	td := s.FindType(typeName)
	if td == nil || len(td.Fields) == 0 {
		return "{ id }", "id"
	}

	idField = ""
	for _, fd := range td.Fields {
		if fd != nil && idLikeFieldRe.MatchString(fd.Name) && isLeafField(s, fd) {
			idField = fd.Name
			break
		}
	}
	parts := make([]string, 0, 3)
	if idField == "" {
		idField = "id"
	}
	parts = append(parts, idField)

	added := 0
	for _, fd := range td.Fields {
		if fd == nil || fd.Name == idField {
			continue
		}
		if fd.SensitivityScore > 0 || !isLeafField(s, fd) || hasRequiredArgs(fd) {
			continue
		}
		parts = append(parts, fd.Name)
		if added++; added >= 2 {
			break
		}
	}
	return "{ " + strings.Join(parts, " ") + " }", idField
}

// buildListQuery builds a small discovery query for a list field, requesting a
// single id and limiting pagination where possible.
func buildListQuery(s *schema.Schema, lf *schema.FieldDef) string {
	var parts []string
	for _, a := range lf.Args {
		if a == nil {
			continue
		}
		if argRequired(a) {
			if ev := surface.ExampleValue(a.Type, s); ev != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
			}
		} else if limitArgs[strings.ToLower(a.Name)] {
			parts = append(parts, fmt.Sprintf("%s: 1", a.Name))
		}
	}
	argStr := ""
	if len(parts) > 0 {
		argStr = "(" + strings.Join(parts, ", ") + ")"
	}
	return fmt.Sprintf("query { %s%s { id } }", lf.Name, argStr)
}

// ── schema helpers ───────────────────────────────────────────────────────────

// queryFieldByName returns the named query-root field, or nil.
func queryFieldByName(s *schema.Schema, name string) *schema.FieldDef {
	for _, fd := range s.QueryFields() {
		if fd != nil && fd.Name == name {
			return fd
		}
	}
	return nil
}

// listFieldFor returns a root query field (other than exclude) that returns a
// list of typeName, or nil.
func listFieldFor(s *schema.Schema, typeName, exclude string) *schema.FieldDef {
	for _, fd := range s.QueryFields() {
		if fd == nil || fd.Name == exclude {
			continue
		}
		named, isList := unwrapNamed(fd.Type)
		if isList && named != nil && named.Name == typeName {
			return fd
		}
	}
	return nil
}

// viewerFieldRe matches "current principal" root field names.
var viewerFieldRe = regexp.MustCompile(`(?i)^(me|viewer|currentuser|current_user|profile|myself)$`)

// viewerFieldFor returns a root query field that returns typeName and is named
// like a current-principal accessor, or nil.
func viewerFieldFor(s *schema.Schema, typeName string) *schema.FieldDef {
	for _, fd := range s.QueryFields() {
		if fd == nil || !viewerFieldRe.MatchString(fd.Name) {
			continue
		}
		named, isList := unwrapNamed(fd.Type)
		if !isList && named != nil && named.Name == typeName {
			return fd
		}
	}
	return nil
}

// unwrapNamed unwraps a TypeRef to its named type, reporting whether a LIST
// wrapper was present.
func unwrapNamed(t *schema.TypeRef) (named *schema.TypeRef, isList bool) {
	cur := t
	for cur != nil {
		if cur.Kind == schema.KindList {
			isList = true
		}
		if cur.OfType == nil {
			return cur, isList
		}
		cur = cur.OfType
	}
	return nil, isList
}

// isLeafField reports whether a field returns a scalar or enum.
func isLeafField(s *schema.Schema, fd *schema.FieldDef) bool {
	u := fd.Type.Unwrap()
	if u == nil {
		return false
	}
	k := u.Kind
	if k == "" {
		if td := s.FindType(u.Name); td != nil {
			k = td.Kind
		}
	}
	return k == schema.KindScalar || k == schema.KindEnum
}

// hasRequiredArgs reports whether fd has any required argument.
func hasRequiredArgs(fd *schema.FieldDef) bool {
	for _, a := range fd.Args {
		if argRequired(a) {
			return true
		}
	}
	return false
}

// argRequired reports whether an argument is required (NON_NULL with no default).
func argRequired(a *schema.ArgDef) bool {
	if a == nil || a.Type == nil {
		return false
	}
	return a.Type.Kind == schema.KindNonNull && a.DefaultValue == nil
}

// formatIDLiteral renders an id value as a GraphQL literal appropriate to the
// id argument's scalar type (numeric types unquoted, everything else quoted).
func formatIDLiteral(argType, value string) string {
	switch argType {
	case "Int", "Float":
		return value
	default:
		return strconv.Quote(value)
	}
}

// gqlPost sends a GraphQL POST query via the given client and returns the
// response and the request body bytes. A nil client yields an error.
func gqlPost(ctx context.Context, client *transport.Client, target, query string) (*transport.Response, []byte, error) {
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, body, fmt.Errorf("nil client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, body, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, body, err
	}
	return resp, body, nil
}
