package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"sync"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// raceCheck implements GQL-B03: Race Conditions (Parallel Mutations). It detects
// TOCTOU races in limited-quantity, state-changing mutations: when the same
// one-time operation is fired as a tight parallel burst, a server without an
// atomic check-and-act lets multiple requests pass the "check then act"
// boundary — double-spend, coupon re-use beyond its limit, balance
// over-withdrawal, single-use token replay (CWE-362).
//
// Like GQL-A05 it performs state-changing requests, so it is disabled by default
// and gated behind --authz-allow-mutations. It targets a probe / non-valuable
// one-time action (a bogus code) so an over-application proves a missing atomic
// guard rather than moving real value. The burst is bounded (K=20, within the
// client's rate-limiter burst), its goroutines are released together and always
// awaited (no leak), and it is safe under the race detector.
type raceCheck struct{}

func init() {
	MustRegister(&raceCheck{})
}

func (c *raceCheck) ID() string           { return "GQL-B03" }
func (c *raceCheck) Name() string         { return "Race Condition (Parallel Mutation)" }
func (c *raceCheck) Category() Category   { return BusinessLogic }
func (c *raceCheck) Severity() Severity   { return HIGH }
func (c *raceCheck) RequiresSchema() bool { return true }

// raceBurstSize is the bounded number of parallel requests (K). It is small and
// within the transport client's rate-limiter burst so the release is genuinely
// simultaneous — this is a concurrency correctness test, not a DoS probe.
const raceBurstSize = 20

// raceFlowRe matches limited-quantity, idempotency-relevant mutation names whose
// business rule should permit the action at most once (per code/actor).
var raceFlowRe = regexp.MustCompile(`(?i)(redeem|claim|withdraw|transfer|spend|apply_?discount|apply_?coupon|coupon|promo|purchase|checkout|book|reserve|consume|cash_?out|payout|use_?coupon|use_?token)`)

// raceCandidate is the single limited-quantity mutation probed per run.
type raceCandidate struct {
	mutation    *schema.FieldDef
	call        string // rendered "name(args)selection" (same for every request)
	effectField string // numeric effect field for post-state over-application proof
}

// raceResult is one parallel request's outcome.
type raceResult struct {
	resp *transport.Response
	err  error
}

// Run executes the race-condition check.
func (c *raceCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: hard gate (writes) ────────────────────────────────────────────
	if !cc.AllowMutations {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "GQL-B03 fires a parallel burst of state-changing requests and is disabled by default; " +
			"re-run with --authz-allow-mutations after confirming you are authorized to test writes against this target"
		return result, nil
	}
	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "GQL-B03 requires a parsed schema to identify a limited-quantity mutation"
		return result, nil
	}

	// ── Step 2: pick one limited-quantity mutation (bounded, non-destructive) ─
	code := newBizProbeCode()
	cand, ok := findRaceCandidate(cc.Schema, cc.AllowedMutations, code)
	if !ok {
		result.PassReason = "no limited-quantity mutation found to test (a candidate needs a name matching " +
			"redeem/claim/withdraw/transfer/coupon/… with synthesizable scalar arguments; destructive-named " +
			"flows are excluded unless allow-listed via --authz-allow-mutation)"
		return result, nil
	}

	client := cc.HTTPClient
	if client == nil {
		client = cc.ProbeClient()
	}
	if client == nil {
		result.PassReason = "no HTTP client available to send the parallel burst"
		return result, nil
	}

	// ── Steps 3–4: fire K identical mutations concurrently, released together ─
	doc := "mutation { " + cand.call + " }"
	body, err := json.Marshal(map[string]string{"query": doc})
	if err != nil {
		result.PassReason = "could not encode the race probe document"
		return result, nil
	}
	results := raceBurst(ctx, client, cc.Target, body, raceBurstSize)
	result.ProbeCount += raceBurstSize

	successes, effects, reproReq := analyzeRace(results, cand.mutation.Name, cand.effectField)

	// ── Step 5: decide ────────────────────────────────────────────────────────
	if successes <= 1 {
		if reproReq != nil {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label: fmt.Sprintf("parallel burst of %d× %s yielded %d success(es) — an atomic check-and-act "+
					"guard appears present", raceBurstSize, cand.mutation.Name, successes),
				Request: reproReq, Body: body,
			})
		}
		result.PassReason = fmt.Sprintf("fired a bounded %d-request parallel burst of %s against a non-valuable "+
			"probe target; at most one execution succeeded (the check-and-act appears atomic)",
			raceBurstSize, cand.mutation.Name)
		return result, nil
	}

	confidence := "firm"
	proof := fmt.Sprintf("%d of %d parallel executions returned a success class where the business rule should "+
		"permit at most one, but the post-state could not be read to quantify the over-application",
		successes, raceBurstSize)
	if overApplied(effects) {
		confidence = "confirmed"
		proof = fmt.Sprintf("%d of %d parallel executions returned a success class where the business rule should "+
			"permit at most one, and the %q field proved the effect was applied more than once (the shared quota "+
			"was over-consumed under the race)", successes, raceBurstSize, cand.effectField)
	}
	result.Findings = append(result.Findings, c.finding(cc, cand, successes, confidence, proof, reproReq, body))
	return result, nil
}

// finding builds the HIGH race-condition finding.
func (c *raceCheck) finding(cc *CheckContext, cand raceCandidate, successes int,
	confidence, proof string, reproReq *http.Request, body []byte) Finding {

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  BusinessLogic,
		Title: fmt.Sprintf("Race Condition — %s applied %d× under parallel requests (limit was 1)",
			cand.mutation.Name, successes),
		Description: fmt.Sprintf(
			"A tight parallel burst of %d identical %q mutations beat the server's check-and-act boundary: %s. "+
				"The requests were released simultaneously and targeted a non-valuable probe identifier (a bogus "+
				"one-time code), so the over-application proves a missing atomic guard rather than real value "+
				"movement. No automated revert is applicable (the probe target was non-valuable, so nothing of "+
				"consequence was created); any returned data is redacted.",
			raceBurstSize, cand.mutation.Name, proof),
		Impact: "Attackers can double-spend, re-use one-time coupons/vouchers beyond their limit, over-withdraw a " +
			"balance, or replay single-use tokens by racing requests — direct financial loss and integrity " +
			"violations invisible to sequential testing.",
		Remediation: "Make the check-and-act atomic: use database transactions with appropriate isolation, " +
			"`SELECT … FOR UPDATE`, unique constraints, atomic decrement/compare-and-swap, idempotency keys, or " +
			"distributed locks; never rely on a read-then-write gap for a limited-quantity operation.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/362.html",
			"https://portswigger.net/web-security/race-conditions",
			"https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
		},
		Confidence:   confidence,
		CWE:          "CWE-362",
		OWASP:        "API6:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "race:"+cand.mutation.Name),
		ReproRequest: reproReq,
		ReproBody:    body,
	}
}

// raceBurst fires k identical POST requests, released as simultaneously as
// possible: every goroutine builds its own *http.Request up front, blocks on a
// shared start barrier, then issues its request the instant the barrier opens.
// All goroutines are awaited, so there is no leak; each writes only its own
// result slot, so it is safe under the race detector.
func raceBurst(ctx context.Context, client *transport.Client, target string, body []byte, k int) []raceResult {
	results := make([]raceResult, k)
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
			if err != nil {
				results[i] = raceResult{err: err}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "identity")
			<-start // release together
			resp, err := client.Do(req)
			results[i] = raceResult{resp: resp, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	return results
}

// analyzeRace counts success-class responses among the burst, collects the
// numeric effect values from successful responses (for the over-application
// proof), and returns a representative request for reproduction.
func analyzeRace(results []raceResult, mutationName, effectField string) (successes int, effects []float64, reproReq *http.Request) {
	for _, r := range results {
		if r.resp == nil {
			continue
		}
		if authz.Classify(r.resp) != authz.ClassSuccess {
			continue
		}
		successes++
		if reproReq == nil {
			reproReq = r.resp.Request
		}
		if effectField != "" {
			if v, ok := raceEffectValue(r.resp, mutationName, effectField); ok {
				effects = append(effects, v)
			}
		}
	}
	return successes, effects, reproReq
}

// raceEffectValue extracts the numeric effect field from a mutation response's
// payload (data.<mutationName>.<effectField>).
func raceEffectValue(resp *transport.Response, mutationName, effectField string) (float64, bool) {
	obj, ok := objectNode(resp, mutationName)
	if !ok {
		return 0, false
	}
	v, present := obj[effectField]
	if !present {
		return 0, false
	}
	f, ok := v.(float64)
	return f, ok
}

// overApplied reports whether the effect values from the successful responses
// prove the limited quantity was applied more than once: distinct values across
// requests, a counter that reached ≥2, or a balance driven negative.
func overApplied(vals []float64) bool {
	if len(vals) == 0 {
		return false
	}
	distinct := map[float64]bool{}
	maxV, minV := vals[0], vals[0]
	for _, v := range vals {
		distinct[v] = true
		if v > maxV {
			maxV = v
		}
		if v < minV {
			minV = v
		}
	}
	return len(distinct) >= 2 || maxV >= 2 || minV < 0
}

// findRaceCandidate returns the first limited-quantity mutation (deterministically
// by name) whose arguments can be synthesized to repeat the same logical action
// with a bogus probe identifier. Only one target is probed per run — concurrency
// is sensitive.
func findRaceCandidate(s *schema.Schema, allowed []string, code string) (raceCandidate, bool) {
	if s == nil {
		return raceCandidate{}, false
	}
	allowSet := map[string]bool{}
	for _, a := range allowed {
		allowSet[a] = true
	}

	muts := make([]*schema.FieldDef, len(s.MutationFields()))
	copy(muts, s.MutationFields())
	sort.Slice(muts, func(i, j int) bool { return muts[i].Name < muts[j].Name })

	for _, m := range muts {
		if m == nil || !raceFlowRe.MatchString(m.Name) {
			continue
		}
		if a05DestructiveRe.MatchString(m.Name) && !allowSet[m.Name] {
			continue // destructive-named and not allow-listed → never invoke
		}
		args, ok := buildBizArgs(s, m, code)
		if !ok {
			continue
		}
		sel, effect := bizSelection(s, m.Type)
		call := m.Name + sel
		if args != "" {
			call = fmt.Sprintf("%s(%s)%s", m.Name, args, sel)
		}
		return raceCandidate{mutation: m, call: call, effectField: effect}, true
	}
	return raceCandidate{}, false
}
