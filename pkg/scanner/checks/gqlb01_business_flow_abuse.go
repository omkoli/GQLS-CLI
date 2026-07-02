package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// businessFlowAbuseCheck implements GQL-B01: Unrestricted Access to Sensitive
// Business Flows (batch/alias abuse). Where GQL-A06 targets *authentication*
// throttling, B01 targets *business-flow* throttling: signup / coupon-redeem /
// transfer / invite / vote-style mutations that lack per-actor rate or quantity
// limits, so a single aliased request performs the flow N times (coupon
// stacking, mass signup, vote stuffing, referral farming).
//
// It is a state-changing check, so — like GQL-A05 — it is disabled by default
// and gated behind --authz-allow-mutations. It reuses the GQL-A06 single-request
// aliasing idea and the GQL-A05 safe-write discipline: the probe uses a
// non-existent / non-valuable identifier (a bogus coupon/key) so a "success"
// indicates missing server-side validation and rate/quantity limiting rather
// than real value transfer.
type businessFlowAbuseCheck struct{}

func init() {
	MustRegister(&businessFlowAbuseCheck{})
}

func (c *businessFlowAbuseCheck) ID() string { return "GQL-B01" }
func (c *businessFlowAbuseCheck) Name() string {
	return "Unrestricted Access to Sensitive Business Flows"
}
func (c *businessFlowAbuseCheck) Category() Category   { return BusinessLogic }
func (c *businessFlowAbuseCheck) Severity() Severity   { return HIGH }
func (c *businessFlowAbuseCheck) RequiresSchema() bool { return true }

// bizAliasCount is the bounded number of aliased executions sent in a single
// request. It is well below DoS levels — this is a business-flow throttling
// test, not a denial-of-service probe.
const bizAliasCount = 20

// maxBizFlowCandidates caps how many sensitive flows are probed (these write).
const maxBizFlowCandidates = 2

// bizFlowRe matches sensitive-flow mutation names (non-destructive,
// idempotency-relevant): coupon/promo redemption, signup/registration,
// invite/referral, vote/like/follow, claim/reward, transfer/withdraw,
// purchase/order/subscribe.
var bizFlowRe = regexp.MustCompile(`(?i)(redeem|coupon|promo|apply_?discount|signup|register|invite|refer|vote|like|follow|claim|reward|transfer|withdraw|purchase|order|subscribe)`)

// bizLimitRe matches errors that indicate the server limited, deduplicated, or
// rejected the repeated flow (the protected signal): duplicate/one-per-key
// rejection, rate/quota limiting, or validation of the (bogus) identifier.
var bizLimitRe = regexp.MustCompile(`(?i)(already|duplicate|dedup|too many|rate.?limit|throttl|\blimit(ed|s)?\b|exceeded|one per|only once|\bonce\b|reuse|redeemed|\bused\b|not found|does ?n.?t exist|no such|invalid|expired|forbidden|denied|unauthor|max(imum)?[ _-]?(uses|redemptions|attempts|operations|aliases)|abuse|quota|cooldown|conflict)`)

// bizEffectFieldRe matches numeric payload fields that reflect a cumulative
// business effect (a credited balance, a redemption count, remaining uses).
// A monotonic sequence of these across the aliased executions confirms the
// abusive effect actually persisted N×.
var bizEffectFieldRe = regexp.MustCompile(`(?i)^(balance|count|total|uses|used|redemptions|redeemed|quantity|remaining|points|credits|votes|referrals|invites|amount)$`)

// bizFlowCandidate is a sensitive-flow mutation prepared for aliasing: its
// arguments (identical across all aliases, so every alias performs the *same*
// logical action) plus a selection set that requests a cumulative-effect field
// when one is available for the confirmed read-back.
type bizFlowCandidate struct {
	mutation    *schema.FieldDef
	args        string // rendered argument list (same for every alias)
	selection   string // selection-set suffix (may request the effect field)
	effectField string // cumulative-effect field name, empty when none
}

// Run executes the business-flow abuse check.
func (c *businessFlowAbuseCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: hard gate (these flows are state-changing) ────────────────────
	if !cc.AllowMutations {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "GQL-B01 performs state-changing (business-flow) requests and is disabled by default; " +
			"re-run with --authz-allow-mutations after confirming you are authorized to test writes against this target"
		return result, nil
	}
	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "GQL-B01 requires a parsed schema to identify sensitive-flow mutations"
		return result, nil
	}

	// ── Step 2: identify sensitive-flow mutations (bounded, non-destructive) ──
	code := newBizProbeCode()
	cands := findBizFlowCandidates(cc.Schema, cc.AllowedMutations, code)
	if len(cands) == 0 {
		result.PassReason = "no sensitive business-flow mutation found to test (a candidate needs a name matching " +
			"signup/redeem/coupon/invite/vote/transfer/… and synthesizable scalar arguments; destructive-named flows " +
			"are excluded unless allow-listed via --authz-allow-mutation)"
		return result, nil
	}

	client := cc.HTTPClient
	if client == nil {
		client = cc.ProbeClient()
	}

	var passProbes []PassProbe
	for i := range cands {
		if ctx.Err() != nil {
			break
		}
		cand := cands[i]

		// ── Step 3: quantity-limit probe — one request, N aliased executions of
		//    the *same* logical action (same bogus code/key). A server enforcing a
		//    per-actor/per-key limit rejects all but the first; an unprotected one
		//    executes every alias.
		doc := buildBizAliasedDoc(cand, bizAliasCount)
		resp, body, err := gqlPost(ctx, client, cc.Target, doc)
		result.ProbeCount++
		if err != nil || resp == nil {
			passProbes = append(passProbes, PassProbe{
				Label: fmt.Sprintf("aliased %d× %s produced no usable response "+
					"(server may have dropped/limited the request)", bizAliasCount, cand.mutation.Name),
			})
			continue
		}

		executed, limited, confirmed := analyzeBizFlow(resp, bizAliasCount, cand.effectField)

		// ── Step 4: decide ────────────────────────────────────────────────────
		if executed == bizAliasCount && !limited {
			confidence := "firm"
			proof := fmt.Sprintf("single-request multiplicity was proven — all %d alias keys (a0..a%d) returned "+
				"success with no per-actor/per-key limit or duplicate rejection", bizAliasCount, bizAliasCount-1)
			if confirmed {
				confidence = "confirmed"
				proof = fmt.Sprintf("single-request multiplicity was proven — all %d alias keys (a0..a%d) returned "+
					"success — and a read-back of the %q field showed a cumulative effect across the aliased "+
					"executions, confirming the abusive effect persisted %d×",
					bizAliasCount, bizAliasCount-1, cand.effectField, bizAliasCount)
			}
			result.Findings = append(result.Findings, c.finding(cc, cand, confidence, proof, resp, body))
			return result, nil
		}

		// ── Clean / protected ──────────────────────────────────────────────────
		var why string
		switch {
		case limited:
			why = fmt.Sprintf("the server limited/deduplicated the repeated %s flow "+
				"(per-actor/per-key limits appear enforced)", cand.mutation.Name)
		default:
			why = fmt.Sprintf("only %d of %d aliased %s executions succeeded in one request",
				executed, bizAliasCount, cand.mutation.Name)
		}
		passProbes = append(passProbes, PassProbe{
			Label:   fmt.Sprintf("aliased %d× %s: %s", bizAliasCount, cand.mutation.Name, why),
			Request: resp.Request, Body: body,
		})
	}

	result.PassProbes = passProbes
	result.PassReason = fmt.Sprintf("probed %d sensitive business-flow mutation(s) with a bounded %d-alias "+
		"single-request test using a non-existent probe identifier; the server limited or deduplicated the repeated "+
		"flow (per-actor/per-key business limits appear enforced)", len(cands), bizAliasCount)
	return result, nil
}

// finding builds the HIGH business-flow abuse finding.
func (c *businessFlowAbuseCheck) finding(cc *CheckContext, cand bizFlowCandidate,
	confidence, proof string, resp *transport.Response, body []byte) Finding {

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  BusinessLogic,
		Title: fmt.Sprintf("Unrestricted Business Flow — %s executes %d× per request without limit",
			cand.mutation.Name, bizAliasCount),
		Description: fmt.Sprintf(
			"A single GraphQL request aliasing the sensitive-flow mutation %q %d times (alias keys a0..a%d) "+
				"executed the flow %d times: %s. The probe repeated the *same* logical action and used a "+
				"non-existent / non-valuable identifier (a bogus code/key), so a \"success\" indicates missing "+
				"server-side validation and per-actor/per-key rate/quantity limiting rather than real value "+
				"transfer. Any returned data is redacted. Cleanup: no automated revert is available for this flow, "+
				"but because a non-valuable probe identifier was used no real value or account of consequence was "+
				"created.",
			cand.mutation.Name, bizAliasCount, bizAliasCount-1, bizAliasCount, proof),
		Impact: "Abusers can stack one-per-user coupons/promos, mass-create accounts, stuff votes/likes, farm " +
			"referral rewards, and bypass per-actor quotas — one request performs the flow N times — causing " +
			"direct financial loss and integrity damage to business logic.",
		Remediation: "Enforce per-actor and per-key business limits at the resolver/data layer (idempotency keys, " +
			"unique constraints, atomic decrement of a quota); cap the operation/alias count per request; apply " +
			"cost/action-based rate limiting keyed on the business action itself; and validate one-time codes " +
			"server-side.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/799.html",
		},
		Confidence:   confidence,
		CWE:          "CWE-799",
		OWASP:        "API6:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "bizflow:"+cand.mutation.Name),
		ReproRequest: resp.Request,
		ReproBody:    body,
	}
}

// analyzeBizFlow inspects the aliased response: how many of the n aliases
// (a0..a{n-1}) executed (present and non-null in data), whether the server
// emitted a limit/duplicate/rejection error (or a non-200), and whether a
// cumulative-effect field shows monotonic change across the aliases (the
// confirmed read-back signal).
func analyzeBizFlow(resp *transport.Response, n int, effectField string) (executed int, limited, confirmed bool) {
	var env struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return 0, false, false
	}
	for _, e := range env.Errors {
		if bizLimitRe.MatchString(e.Message) {
			limited = true
		}
	}
	if resp.StatusCode != 200 {
		// A non-200 to a bounded aliased document is treated as a rejection.
		limited = true
	}

	var effects []float64
	for i := 0; i < n; i++ {
		raw, ok := env.Data[fmt.Sprintf("a%d", i)]
		if !ok {
			continue
		}
		if t := strings.TrimSpace(string(raw)); t == "" || t == "null" {
			continue // explicit null → this alias did not execute
		}
		executed++
		if effectField != "" {
			if v, ok := numericFieldValue(raw, effectField); ok {
				effects = append(effects, v)
			}
		}
	}
	confirmed = monotonicEffect(effects)
	return executed, limited, confirmed
}

// numericFieldValue extracts a numeric field from an alias payload object.
func numericFieldValue(raw json.RawMessage, field string) (float64, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return 0, false
	}
	v, ok := obj[field]
	if !ok {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(v, &f); err != nil {
		return 0, false
	}
	return f, true
}

// monotonicEffect reports whether the effect values (collected in alias order)
// are strictly monotonic — increasing (e.g. a credited balance 1,2,…,N) or
// decreasing (e.g. remaining uses N,…,1). Strict monotonicity over at least two
// executions proves each aliased execution mutated shared state.
func monotonicEffect(vals []float64) bool {
	if len(vals) < 2 {
		return false
	}
	inc, dec := true, true
	for i := 1; i < len(vals); i++ {
		if vals[i] <= vals[i-1] {
			inc = false
		}
		if vals[i] >= vals[i-1] {
			dec = false
		}
	}
	return inc || dec
}

// ── candidate selection & document building ──────────────────────────────────

// findBizFlowCandidates returns up to maxBizFlowCandidates sensitive-flow
// mutations, deterministically ordered, each with arguments synthesized to
// repeat the same logical action with a bogus probe identifier.
func findBizFlowCandidates(s *schema.Schema, allowed []string, code string) []bizFlowCandidate {
	if s == nil {
		return nil
	}
	allowSet := map[string]bool{}
	for _, a := range allowed {
		allowSet[a] = true
	}

	muts := make([]*schema.FieldDef, len(s.MutationFields()))
	copy(muts, s.MutationFields())
	sort.Slice(muts, func(i, j int) bool { return muts[i].Name < muts[j].Name })

	var out []bizFlowCandidate
	for _, m := range muts {
		if m == nil || !bizFlowRe.MatchString(m.Name) {
			continue
		}
		if a05DestructiveRe.MatchString(m.Name) && !allowSet[m.Name] {
			continue // destructive-named and not allow-listed → never invoke
		}
		args, ok := buildBizArgs(s, m, code)
		if !ok {
			continue // a required argument could not be safely synthesized
		}
		sel, effect := bizSelection(s, m.Type)
		out = append(out, bizFlowCandidate{mutation: m, args: args, selection: sel, effectField: effect})
		if len(out) >= maxBizFlowCandidates {
			break
		}
	}
	return out
}

// buildBizArgs renders a candidate's required arguments with fixed values (so
// every alias performs the same logical action). String/ID arguments carry a
// bogus, non-existent probe identifier; other scalars/enums use an example
// value. It reports false when a required argument is a composite type that
// cannot be synthesized as an inline literal.
func buildBizArgs(s *schema.Schema, m *schema.FieldDef, code string) (string, bool) {
	var parts []string
	for _, a := range m.Args {
		if a == nil || !argRequired(a) {
			continue
		}
		u := a.Type.Unwrap()
		if u == nil {
			return "", false
		}
		switch u.Name {
		case "String", "ID":
			parts = append(parts, fmt.Sprintf("%s: %s", a.Name, strconv.Quote(bizProbeValue(a.Name, code))))
		default:
			ev := surface.ExampleValue(a.Type, s)
			if ev == "" {
				return "", false // composite/unsynthesizable required argument
			}
			parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
		}
	}
	return strings.Join(parts, ", "), true
}

// bizProbeValue returns a bogus, non-existent probe identifier for an argument.
// Email/username-like arguments get an @invalid.example address so a "success"
// against them clearly reflects missing validation, not real value transfer.
// The "gqls-probe-" prefix is shared by the business-flow checks (B01/B03) so a
// "success" always traces back to a non-valuable synthetic identifier.
func bizProbeValue(argName, code string) string {
	if credEmailRe.MatchString(argName) {
		return "gqls-probe-" + code + "@invalid.example"
	}
	return "gqls-probe-" + code
}

// bizSelection returns the selection-set suffix for a mutation's return type and
// the cumulative-effect field name it requests (empty when none / scalar return).
func bizSelection(s *schema.Schema, t *schema.TypeRef) (selection, effectField string) {
	base := mutSelectionSet(t, s)
	if base == "" {
		return "", "" // scalar/enum return — no sub-selection possible
	}
	if ef := bizEffectField(s, t); ef != "" {
		return " { " + ef + " __typename }", ef
	}
	return base, ""
}

// bizEffectField returns the first numeric (Int/Float) leaf field on the return
// type whose name reflects a cumulative business effect, deterministically.
func bizEffectField(s *schema.Schema, t *schema.TypeRef) string {
	if s == nil || t == nil {
		return ""
	}
	u := t.Unwrap()
	if u == nil {
		return ""
	}
	td := s.FindType(u.Name)
	if td == nil {
		return ""
	}
	var names []string
	for _, f := range td.Fields {
		if f == nil || !bizEffectFieldRe.MatchString(f.Name) {
			continue
		}
		fu := f.Type.Unwrap()
		if fu != nil && (fu.Name == "Int" || fu.Name == "Float") {
			names = append(names, f.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}

// buildBizAliasedDoc builds a mutation aliasing the candidate count times
// (a0..a{count-1}), each performing the identical logical action.
func buildBizAliasedDoc(cand bizFlowCandidate, count int) string {
	var call string
	if cand.args != "" {
		call = fmt.Sprintf("%s(%s)%s", cand.mutation.Name, cand.args, cand.selection)
	} else {
		call = cand.mutation.Name + cand.selection
	}
	aliases := make([]string, 0, count)
	for i := 0; i < count; i++ {
		aliases = append(aliases, fmt.Sprintf("a%d: %s", i, call))
	}
	return "mutation { " + strings.Join(aliases, " ") + " }"
}

// newBizProbeCode returns a unique, bogus (non-existent) probe identifier.
func newBizProbeCode() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "probe"
	}
	return hex.EncodeToString(b[:])
}
