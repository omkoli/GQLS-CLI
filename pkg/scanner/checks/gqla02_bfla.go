package checks

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// bflaCheck implements GQL-A02: Broken Function Level Authorization.
//
// It asks the sharper question that GQL-012 does not: can a *lower-privilege*
// identity reach a *privileged* operation? For each privileged op it first
// confirms the highest-privilege identity can call it (baseline), then sends the
// same operation as each lower-privilege identity and flags when the function
// executes for a role that should not reach it.
type bflaCheck struct{}

func init() {
	MustRegister(&bflaCheck{})
}

func (c *bflaCheck) ID() string           { return "GQL-A02" }
func (c *bflaCheck) Name() string         { return "Broken Function Level Authorization (BFLA)" }
func (c *bflaCheck) Category() Category   { return Authorization }
func (c *bflaCheck) Severity() Severity   { return CRITICAL }
func (c *bflaCheck) RequiresSchema() bool { return true }

// maxBflaOps caps how many privileged operations are tested per run.
const maxBflaOps = 8

// destructiveOpRe matches mutation names that may destroy data; these are never
// invoked by GQL-A02 (even when --authz-allow-mutations is set) to keep the
// check safe by construction.
var destructiveOpRe = regexp.MustCompile(`(?i)(delete|remove|destroy|purge|wipe|drop)`)

// Run executes the BFLA differential check.
func (c *bflaCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: preconditions ────────────────────────────────────────────────
	if !cc.HasIdentities() {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "BFLA testing requires >=2 operator-supplied identities of differing privilege; " +
			"configure them via --identity / gqls.yaml"
		return result, nil
	}
	baseline := highestPrivilege(cc.Identities)
	attackers := lowerPrivileged(cc.Identities, baseline.Privilege)
	if len(attackers) == 0 {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "BFLA testing requires identities of differing privilege; " +
			"all configured identities share the same privilege level"
		return result, nil
	}

	// ── Step 2: enumerate privileged operations ──────────────────────────────
	ops := surface.PrivilegedOps(cc.Schema)
	if len(ops) == 0 {
		result.PassReason = "no privileged operations identified in the schema (nothing to test for BFLA)"
		return result, nil
	}
	capped := false
	if len(ops) > maxBflaOps {
		ops = ops[:maxBflaOps]
		capped = true
	}

	var (
		passProbes         []PassProbe
		writeGated         []string
		destructiveSkipped []string
		notPrivileged      []string
		tested             int
	)

	for oi := range ops {
		if ctx.Err() != nil {
			break
		}
		op := ops[oi]

		fd := opFieldDef(cc.Schema, op)
		if fd == nil {
			continue
		}

		// Write-gating: privileged mutations are not probed unless the operator
		// explicitly opts in, and destructive mutations are never probed.
		if op.IsMutation {
			if !cc.AllowMutations {
				writeGated = append(writeGated, op.Field)
				continue
			}
			if destructiveOpRe.MatchString(op.Field) {
				destructiveSkipped = append(destructiveSkipped, op.Field)
				continue
			}
		}

		doc := buildOpDoc(cc.Schema, op, fd)

		// ── Step 3: baseline — confirm the privileged identity can call it ──
		baseResp, _, err := gqlPost(ctx, baseline.Client, cc.Target, doc)
		result.ProbeCount++
		if err != nil || baseResp == nil {
			continue
		}
		baseCls := authz.Classify(baseResp)
		if baseCls != authz.ClassSuccess && baseCls != authz.ClassValidation {
			// The privileged identity itself cannot call this op — not a
			// meaningful BFLA target (avoid false positives on ops nobody can call).
			notPrivileged = append(notPrivileged, op.Field)
			continue
		}
		tested++

		// ── Step 4–5: probe each lower-privilege identity ──────────────────
		leaked := false
		for ai := range attackers {
			if ctx.Err() != nil {
				break
			}
			attacker := attackers[ai]
			aResp, aBody, aerr := gqlPost(ctx, attacker.Client, cc.Target, doc)
			result.ProbeCount++
			if aerr != nil || aResp == nil {
				continue
			}
			switch authz.Classify(aResp) {
			case authz.ClassSuccess:
				// Confirmed: the privileged function executed for a role that
				// should not reach it.
				result.Findings = append(result.Findings,
					c.finding(cc, op, baseline, attacker, baseCls, aResp, aBody))
				leaked = true
			case authz.ClassValidation:
				// Reached the resolver past the auth layer but did not execute
				// (missing args) — suggestive only, never flagged.
				passProbes = append(passProbes, PassProbe{
					Label: fmt.Sprintf("BFLA %q as %q: validation reached past auth layer (tentative, not flagged)",
						op.Field, attacker.Name),
					Request: aResp.Request,
					Body:    aBody,
				})
			default:
				passProbes = append(passProbes, PassProbe{
					Label: fmt.Sprintf("BFLA %q as %q: %s (authz appears enforced)",
						op.Field, attacker.Name, authz.Classify(aResp)),
					Request: aResp.Request,
					Body:    aBody,
				})
			}
			if leaked {
				break // one finding per leaking op
			}
		}
	}

	if len(result.Findings) > 0 {
		return result, nil
	}

	// ── Clean run: explain the basis ─────────────────────────────────────────
	result.PassProbes = passProbes
	result.PassReason = c.passReason(tested, len(attackers), writeGated, notPrivileged, destructiveSkipped, capped)
	return result, nil
}

// finding builds the CRITICAL BFLA finding for a leaking operation.
func (c *bflaCheck) finding(cc *CheckContext, op surface.PrivilegedOp, baseline, attacker Identity,
	baseCls authz.Class, aResp *transport.Response, aBody []byte) Finding {

	opType := "query"
	if op.IsMutation {
		opType = "mutation"
	}
	redacted := authz.RedactLeak(nil, aResp)
	if redacted == "" {
		redacted = "(no scalar data returned)"
	}
	reasons := strings.Join(op.Reasons, "; ")

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Authorization,
		Title: fmt.Sprintf("Broken Function Level Authorization — %s %q callable by %q",
			opType, op.Field, attacker.Name),
		Description: fmt.Sprintf(
			"The privileged %s %q (flagged privileged: %s) executed successfully for the lower-privilege "+
				"identity %q. The privileged baseline identity %q could call it (response class: %s), and %q — "+
				"which should not reach this function — also received a successful response. "+
				"Returned data (redacted): %s.",
			opType, op.Field, reasons, attacker.Name, baseline.Name, baseCls, attacker.Name, redacted),
		Impact: "A lower-privileged (or non-admin) user can invoke privileged functionality, enabling " +
			"privilege escalation, administrative actions, access to admin-only data, and — depending on the " +
			"operation set — account takeover.",
		Remediation: "Enforce function-level authorization on every resolver (not only at the UI or gateway). " +
			"Centralize role/permission checks via middleware or schema directives (e.g. @auth(requires: ADMIN)); " +
			"deny by default and explicitly grant; audit every mutation and admin query for a guard.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/285.html",
		},
		Confidence:   "confirmed",
		CWE:          "CWE-285",
		OWASP:        "API5:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "bfla:"+op.Field),
		ReproRequest: aResp.Request,
		ReproBody:    aBody,
	}
}

// passReason composes the no-finding explanation, disclosing coverage and any
// operations that were write-gated, skipped as destructive, or not callable by
// the privileged baseline.
func (c *bflaCheck) passReason(tested, attackers int, writeGated, notPrivileged, destructiveSkipped []string, capped bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "tested %d privileged operation(s) against %d lower-privilege identit%s; "+
		"function-level authorization appears enforced",
		tested, attackers, plural(attackers, "y", "ies"))
	if capped {
		fmt.Fprintf(&b, " (capped at the first %d privileged operations)", maxBflaOps)
	}
	b.WriteString(".")
	if len(writeGated) > 0 {
		fmt.Fprintf(&b, " %d mutation(s) not tested (write-gated; pass --authz-allow-mutations to include them): %s.",
			len(writeGated), strings.Join(writeGated, ", "))
	}
	if len(destructiveSkipped) > 0 {
		fmt.Fprintf(&b, " %d destructive mutation(s) skipped for safety: %s.",
			len(destructiveSkipped), strings.Join(destructiveSkipped, ", "))
	}
	if len(notPrivileged) > 0 {
		fmt.Fprintf(&b, " %d operation(s) skipped (not callable by the privileged baseline identity): %s.",
			len(notPrivileged), strings.Join(notPrivileged, ", "))
	}
	return b.String()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// highestPrivilege returns the most privileged identity, breaking ties by name
// for determinism.
func highestPrivilege(ids []Identity) Identity {
	best := ids[0]
	for _, id := range ids[1:] {
		if id.Privilege > best.Privilege || (id.Privilege == best.Privilege && id.Name < best.Name) {
			best = id
		}
	}
	return best
}

// lowerPrivileged returns all identities strictly below maxPriv, sorted by
// privilege descending then name ascending for deterministic iteration.
func lowerPrivileged(ids []Identity, maxPriv int) []Identity {
	var out []Identity
	for _, id := range ids {
		if id.Privilege < maxPriv {
			out = append(out, id)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Privilege != out[j].Privilege {
			return out[i].Privilege > out[j].Privilege
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// opFieldDef resolves the FieldDef for a privileged operation (query or mutation).
func opFieldDef(s *schema.Schema, op surface.PrivilegedOp) *schema.FieldDef {
	if op.IsMutation {
		return mutationFieldByName(s, op.Field)
	}
	return queryFieldByName(s, op.Field)
}

// mutationFieldByName returns the named mutation-root field, or nil.
func mutationFieldByName(s *schema.Schema, name string) *schema.FieldDef {
	for _, fd := range s.MutationFields() {
		if fd != nil && fd.Name == name {
			return fd
		}
	}
	return nil
}

// buildOpDoc constructs the GraphQL document that invokes op, synthesizing
// required scalar/enum arguments and selecting __typename for object returns.
func buildOpDoc(s *schema.Schema, op surface.PrivilegedOp, fd *schema.FieldDef) string {
	opType := "query"
	if op.IsMutation {
		opType = "mutation"
	}
	return fmt.Sprintf("%s { %s%s%s }", opType, op.Field, opArgs(fd, s), mutSelectionSet(fd.Type, s))
}

// opArgs renders the required-argument list for fd using synthesized example
// values, returning "" when there are no synthesizable required args.
func opArgs(fd *schema.FieldDef, s *schema.Schema) string {
	var parts []string
	for _, a := range fd.Args {
		if !argRequired(a) {
			continue
		}
		if ev := surface.ExampleValue(a.Type, s); ev != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// plural returns singular or pluralSuffix-based forms for count.
func plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
