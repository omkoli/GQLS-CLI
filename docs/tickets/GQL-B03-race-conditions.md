# GQL-B03 — Race Conditions (Parallel Mutations)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-BIZLOGIC |
| **Priority** | P3 |
| **Severity (of finding)** | HIGH |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `business-logic`, `race-condition`, `toctou`, `cwe-362`, `concurrency`, `write-gated` |
| **Category** | `BusinessLogic` |
| **Depends on** | **GQL-A05** write-gate/cycle; a concurrency primitive |
| **Files** | `pkg/scanner/checks/gqlb03_race_conditions.go` (+ `_test.go`) |

## Summary
Detect **race conditions** (TOCTOU) in state-changing mutations: when the same limited-quantity operation is
fired **in parallel**, a server without atomic checks lets multiple requests pass a "check then act" boundary —
double-spend, coupon re-use beyond its limit, balance over-withdrawal, single-use token replay. The check
sends a tight parallel burst of the *same* operation and detects more successes than the business limit allows.

## Why it matters
- Race conditions (CWE-362) are high-impact and invisible to sequential testing — the classic "redeem a
  one-time coupon twice by sending both requests simultaneously". They cause direct financial loss and are a
  staple of bug-bounty payouts.

## Engineering Context
(See `EPIC-GQL-BIZLOGIC.md` shared context + safety. Add a `BusinessLogic` category to `domain` if not present
(mirror `Authorization`). Use a concurrency primitive: launch K goroutines, each with its **own**
`*http.Request`, released together (a `sync.WaitGroup` + a start barrier/`close(ch)`), through `cc.HTTPClient`
(its rate limiter's burst should permit the simultaneous release — set a small K within burst). Follow the
GQL-A05 capture/verify/restore discipline. **Write-gated** behind `cc.AllowMutations`.)

- `ID()="GQL-B03"`, `Name()="Race Condition (Parallel Mutation)"`, `Category()=BusinessLogic`,
  `Severity()=HIGH`, `RequiresSchema()=true`.

## Detection algorithm
1. **Hard gate:** `!cc.AllowMutations` → `Skip`. Else continue.
2. **Pick a limited-quantity mutation** (non-destructive, idempotency-relevant): redeem/claim/withdraw/
   transfer/apply-once style, against a **probe** target (a bogus one-time code / a self-owned object), so a
   double-success indicates a missing atomic guard rather than real value movement. Cap to 1 target per run
   (concurrency is sensitive).
3. **Baseline:** capture the pre-state via a read fetcher (e.g. remaining quota / balance / redeemed flag).
4. **Parallel burst:** fire **K=20** identical mutations concurrently, released as simultaneously as possible.
   Count how many returned a *success* class (`authz.Classify == Success`, or the app's success shape).
   Increment `ProbeCount` by K.
5. **Verify & decide:** read the post-state. **Flag HIGH when** the number of successful executions exceeds the
   business limit (e.g. a one-time coupon redeemed > 1×, a balance decremented more than once for a single
   allowance) — i.e. the parallel requests beat the check. Confidence `"confirmed"` when the post-state proves
   over-application (e.g. balance went negative / quota over-consumed); `"firm"` when multiple successes were
   returned but the post-state could not be read.
   - Negative: exactly one success (the rest rejected as "already done"/conflict) → atomic guard present → no
     finding.
6. **Cleanup:** best-effort revert (the A05 restore pattern) and report status.

## Finding content
- **Title:** `Race Condition — <mutation> applied N× under parallel requests (limit was 1)`
- **Description:** the operation, the burst size, the number of successes vs the expected limit, and the
  post-state proof (e.g. quota over-consumed). Note the probe target was non-valuable.
- **Impact:** double-spend, coupon/voucher re-use beyond limits, balance over-withdrawal, single-use token
  replay — direct financial loss and integrity violations.
- **Remediation:** make the check-and-act atomic (database transactions with appropriate isolation, `SELECT …
  FOR UPDATE`, unique constraints, atomic decrement/CAS, idempotency keys, distributed locks); never rely on a
  read-then-write gap.
- **References:** `https://cwe.mitre.org/data/definitions/362.html`,
  `https://portswigger.net/web-security/race-conditions`,
  `https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/`.
- **Confidence:** `"confirmed"`/`"firm"`. **CWE:** `"CWE-362"`. **OWASP:** `"API6:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-B03", cc.Target, "race:"+mutation)`.

## Acceptance criteria
- **Given** `--authz-allow-mutations` and a server with a non-atomic one-time redeem (sleeps between check and
  write), the parallel burst yields >1 success → HIGH finding (confirmed via post-state). 
- **Given** a server with an atomic guard (exactly one success under burst), no finding.
- **Given** `AllowMutations=false`, the check is `Skipped` and no write is sent (assert zero mutations).
- Burst size bounded (K≤20); cleanup attempted; no goroutine leak / panic; test uses `-race`.

## Tests (`gqlb03_race_conditions_test.go`)
- Stateful server with a non-atomic redeem (a `time.Sleep` between read and write, no lock) → multiple
  successes → finding. Atomic variant (mutex / single-use flag set under lock) → exactly one success → no
  finding. `AllowMutations=false` → Skipped, zero mutations. Run under `-race`.

## Safety
Write-gated. Targets a **probe/non-valuable** one-time action so over-application proves the bug without moving
real value; bounded burst (K≤20, within the rate limiter's burst); best-effort cleanup; destructive mutations
excluded; goroutines bounded and cancellable.
