package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// mutAuthzCheck implements GQL-A05: Mutation-Side Authorization (non-owner
// write/delete). It is the only check in the suite that performs state-changing
// requests, so it is disabled by default and gated behind --authz-allow-mutations.
//
// For each safe, reversible update-style mutation it runs a
// capture → attack → verify → restore cycle: it records the original field value
// as the owner, attempts the write as a non-owner identity targeting the owner's
// object, re-reads as the owner to confirm whether the unauthorized write
// persisted, and restores the original value.
type mutAuthzCheck struct{}

func init() {
	MustRegister(&mutAuthzCheck{})
}

func (c *mutAuthzCheck) ID() string           { return "GQL-A05" }
func (c *mutAuthzCheck) Name() string         { return "Mutation-Side Authorization (Non-Owner Write/Delete)" }
func (c *mutAuthzCheck) Category() Category   { return Authorization }
func (c *mutAuthzCheck) Severity() Severity   { return CRITICAL }
func (c *mutAuthzCheck) RequiresSchema() bool { return true }

const maxMutAuthzCandidates = 3

// a05DestructiveRe matches mutation names that may destroy or irreversibly
// change data; these are never invoked unless explicitly allow-listed.
var a05DestructiveRe = regexp.MustCompile(`(?i)(delete|remove|destroy|purge|wipe|drop|cancel|revoke)`)

// innocuousArgRe matches scalar String argument names that are safe to set to a
// reversible probe sentinel (labels/descriptions, not credentials or roles).
var innocuousArgRe = regexp.MustCompile(`(?i)^(name|display_?name|nickname|label|title|description|bio|about|comment|note|caption|summary|tagline)$`)

// mutCandidate is a safe, reversible update-style mutation paired with a read
// path (query fetcher) to capture and verify the mutated field.
type mutCandidate struct {
	mutation     *schema.FieldDef
	mutIDArg     string
	mutIDArgType string
	setArg       string // the innocuous String argument set to the sentinel
	fetcher      surface.ObjectFetcher
	readIDField  string // id field of the fetcher return type (for the read selection)
}

// Run executes the mutation-side authorization check.
func (c *mutAuthzCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: hard gates ────────────────────────────────────────────────────
	if !cc.AllowMutations {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "GQL-A05 performs state-changing requests and is disabled by default; " +
			"re-run with --authz-allow-mutations after confirming you are authorized to test writes against this target"
		return result, nil
	}
	if !cc.HasIdentities() {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "mutation-side authorization testing requires >=2 operator-supplied identities; " +
			"configure them via --identity / gqls.yaml"
		return result, nil
	}

	// ── Step 2: select safe, reversible mutations ─────────────────────────────
	cands := findMutCandidates(cc.Schema, cc.AllowedMutations)
	if len(cands) == 0 {
		result.PassReason = "no safe, reversible update-style mutations found to test " +
			"(a candidate needs an id argument, an innocuous String argument, and a matching read query; " +
			"destructive-named mutations are excluded unless allow-listed via --authz-allow-mutation)"
		return result, nil
	}

	pairs := cc.IdentityPairs()
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
		candDone := false

		for pi := range pairs {
			if ctx.Err() != nil || candDone {
				break
			}
			owner := pairs[pi][0]
			attacker := pairs[pi][1]

			cacheKey := owner.Name + "|" + cand.fetcher.RootField
			ownerObjID, cached := ownerCache[cacheKey]
			if !cached {
				ownerObjID = discoverOwnerObjectID(ctx, cc, owner, cand.fetcher, &result)
				ownerCache[cacheKey] = ownerObjID
			}
			if ownerObjID == "" {
				continue
			}

			// ── Capture: read the original value as the owner ──────────────
			// If we cannot capture the original, we must not write (we could not
			// revert), so skip this (owner, candidate) safely.
			original, capOK := c.readField(ctx, cc, owner, cand, ownerObjID, &result)
			if !capOK {
				continue
			}
			tested++

			// ── Attack: attempt the write as the non-owner identity ────────
			sentinel := newSentinel()
			attackDoc := buildMutationDoc(cc.Schema, cand, ownerObjID, sentinel)
			aResp, aBody, aerr := gqlPost(ctx, attacker.Client, cc.Target, attackDoc)
			result.ProbeCount++
			if aerr != nil || aResp == nil {
				continue
			}
			attackCls := authz.Classify(aResp)

			// ── Verify: re-read as the owner ───────────────────────────────
			after, verOK := c.readField(ctx, cc, owner, cand, ownerObjID, &result)

			switch {
			case verOK && after == sentinel:
				// Confirmed: the attacker's value persisted on the owner's object.
				restored := c.restore(ctx, cc, owner, cand, ownerObjID, original, &result)
				result.Findings = append(result.Findings,
					c.finding(cc, cand, owner, attacker, ownerObjID, "confirmed", restored, aResp, aBody))
				candDone = true

			case !verOK && attackCls == authz.ClassSuccess:
				// The write was accepted but could not be verified — firm only.
				restored := c.restore(ctx, cc, owner, cand, ownerObjID, original, &result)
				result.Findings = append(result.Findings,
					c.finding(cc, cand, owner, attacker, ownerObjID, "firm", restored, aResp, aBody))
				candDone = true

			default:
				// Protected or unchanged. Only restore if something actually changed.
				if verOK && after != original {
					c.restore(ctx, cc, owner, cand, ownerObjID, original, &result)
				}
				passProbes = append(passProbes, PassProbe{
					Label: fmt.Sprintf("mutation-authz %s as %q vs owner %q: %s, value unchanged (authz appears enforced)",
						cand.mutation.Name, attacker.Name, owner.Name, attackCls),
					Request: aResp.Request,
					Body:    aBody,
				})
			}
		}
	}

	if len(result.Findings) > 0 {
		return result, nil
	}
	result.PassProbes = passProbes
	if tested == 0 {
		result.PassReason = "could not establish/capture any owner-owned object to test safely; " +
			"provide --authz-seed 'field=id' or ensure a viewer/list query exposes an id"
	} else {
		result.PassReason = fmt.Sprintf(
			"tested %d non-owner write attempt(s) across %d candidate mutation(s); "+
				"mutation-side authorization appears enforced (no non-owner write persisted)",
			tested, len(cands))
	}
	return result, nil
}

// finding builds the CRITICAL mutation-authz finding.
func (c *mutAuthzCheck) finding(cc *CheckContext, cand mutCandidate, owner, attacker Identity,
	ownerObjID, confidence, restored string, aResp *transport.Response, aBody []byte) Finding {

	proof := "an owner re-read confirmed the attacker's value persisted"
	if confidence == "firm" {
		proof = "the write was accepted (HTTP 200 with data) but could not be re-read to confirm persistence"
	}

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Authorization,
		Title: fmt.Sprintf("Mutation-Side Authorization Bypass — %q modified %q's object via %s",
			attacker.Name, owner.Name, cand.mutation.Name),
		Description: fmt.Sprintf(
			"Identity %q used mutation %s to change field %q on an object (id %s) owned by %q; %s. "+
				"The change was made with a benign probe value and the original was restored (%s).",
			attacker.Name, cand.mutation.Name, cand.setArg, ownerObjID, owner.Name, proof, restored),
		Impact: "An unauthorized user can modify (or, where allow-listed, delete) objects they do not own — " +
			"data tampering, account takeover, fraud, and destruction of other users' data.",
		Remediation: "Enforce object-level authorization on write resolvers: verify the principal owns or may " +
			"mutate the target before applying changes. Never authorize writes by object existence alone; " +
			"centralize ownership checks; add mutation-authorization assertions to tests.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/285.html",
		},
		Confidence:   confidence,
		CWE:          "CWE-285",
		OWASP:        "API5:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "mutauthz:"+cand.mutation.Name),
		ReproRequest: aResp.Request,
		ReproBody:    aBody,
	}
}

// readField reads cand.setArg on the owner's object via the read fetcher,
// returning the scalar value and whether the read succeeded.
func (c *mutAuthzCheck) readField(ctx context.Context, cc *CheckContext, ident Identity,
	cand mutCandidate, objID string, result *CheckResult) (string, bool) {

	idLit := formatIDLiteral(cand.fetcher.IDArgType, objID)
	q := fmt.Sprintf("query { %s(%s: %s) { %s %s } }",
		cand.fetcher.RootField, cand.fetcher.IDArg, idLit, cand.readIDField, cand.setArg)
	resp, _, err := gqlPost(ctx, ident.Client, cc.Target, q)
	result.ProbeCount++
	if err != nil || resp == nil {
		return "", false
	}
	obj, ok := objectNode(resp, cand.fetcher.RootField)
	if !ok {
		return "", false
	}
	v, present := obj[cand.setArg]
	if !present {
		return "", false
	}
	return jsonScalar(v), true
}

// restore writes the captured original value back as the owner, returning a
// human-readable status. It is best-effort; a failure is reported, never hidden.
func (c *mutAuthzCheck) restore(ctx context.Context, cc *CheckContext, owner Identity,
	cand mutCandidate, objID, original string, result *CheckResult) string {

	doc := buildMutationDoc(cc.Schema, cand, objID, original)
	resp, _, err := gqlPost(ctx, owner.Client, cc.Target, doc)
	result.ProbeCount++
	if err != nil || resp == nil {
		return "restore FAILED: " + errString(err)
	}
	if authz.Classify(resp) == authz.ClassSuccess {
		return "restored successfully"
	}
	return "restore FAILED: server did not accept the restore write — manual cleanup may be required"
}

// ── candidate selection ──────────────────────────────────────────────────────

// findMutCandidates returns up to maxMutAuthzCandidates safe, reversible
// update-style mutations paired with a read fetcher, deterministically ordered.
func findMutCandidates(s *schema.Schema, allowed []string) []mutCandidate {
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

	var out []mutCandidate
	for _, m := range muts {
		if m == nil {
			continue
		}
		if a05DestructiveRe.MatchString(m.Name) && !allowSet[m.Name] {
			continue // destructive and not allow-listed → never test
		}
		idArg, idArgType := idArgOf(m)
		if idArg == "" {
			continue
		}
		setArg := innocuousStringArgOf(m, idArg)
		if setArg == "" {
			continue
		}
		fetcher, readIDField, ok := matchReadFetcher(s, fetchers, setArg)
		if !ok {
			continue
		}
		out = append(out, mutCandidate{
			mutation: m, mutIDArg: idArg, mutIDArgType: idArgType,
			setArg: setArg, fetcher: fetcher, readIDField: readIDField,
		})
		if len(out) >= maxMutAuthzCandidates {
			break
		}
	}
	return out
}

// idArgOf returns the first id-like scalar argument name and its type.
func idArgOf(m *schema.FieldDef) (name, typeName string) {
	for _, a := range m.Args {
		if a == nil {
			continue
		}
		if idLikeFieldRe.MatchString(a.Name) {
			t := ""
			if u := a.Type.Unwrap(); u != nil {
				t = u.Name
			}
			return a.Name, t
		}
	}
	return "", ""
}

// innocuousStringArgOf returns the first innocuous, non-sensitive String
// argument (other than idArg) that is safe to set to a probe sentinel.
func innocuousStringArgOf(m *schema.FieldDef, idArg string) string {
	for _, a := range m.Args {
		if a == nil || a.Name == idArg {
			continue
		}
		u := a.Type.Unwrap()
		if u == nil || u.Name != "String" {
			continue
		}
		if !innocuousArgRe.MatchString(a.Name) {
			continue
		}
		if score, _ := schema.SensitiveTagsFor(a.Name); score > 0 {
			continue // never write a sensitive-looking argument
		}
		return a.Name
	}
	return ""
}

// matchReadFetcher returns a query fetcher whose return type has a leaf field
// named fieldName, plus that type's id field, for capture/verify reads.
func matchReadFetcher(s *schema.Schema, fetchers []surface.ObjectFetcher, fieldName string) (surface.ObjectFetcher, string, bool) {
	for _, f := range fetchers {
		td := s.FindType(f.ReturnType)
		if td == nil {
			continue
		}
		if fd := fieldByName(td, fieldName); fd != nil && isLeafField(s, fd) {
			return f, idFieldOf(s, td), true
		}
	}
	return surface.ObjectFetcher{}, "", false
}

// buildMutationDoc builds a mutation document setting cand.setArg to value on
// the object identified by objID, synthesizing any other required arguments.
func buildMutationDoc(s *schema.Schema, cand mutCandidate, objID, value string) string {
	idLit := formatIDLiteral(cand.mutIDArgType, objID)
	parts := []string{
		fmt.Sprintf("%s: %s", cand.mutIDArg, idLit),
		fmt.Sprintf("%s: %s", cand.setArg, strconv.Quote(value)),
	}
	for _, a := range cand.mutation.Args {
		if a == nil || a.Name == cand.mutIDArg || a.Name == cand.setArg {
			continue
		}
		if argRequired(a) {
			if ev := surface.ExampleValue(a.Type, s); ev != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
			}
		}
	}
	return fmt.Sprintf("mutation { %s(%s)%s }", cand.mutation.Name, strings.Join(parts, ", "), mutSelectionSet(cand.mutation.Type, s))
}

// newSentinel returns a unique, benign probe value.
func newSentinel() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "gqls-a05-probe"
	}
	return "gqls-a05-" + hex.EncodeToString(b[:])
}

// errString renders an error for status messages, tolerating nil.
func errString(err error) string {
	if err == nil {
		return "no response"
	}
	return err.Error()
}
