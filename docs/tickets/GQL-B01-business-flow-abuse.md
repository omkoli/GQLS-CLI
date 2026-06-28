# GQL-B01 — Unrestricted Access to Sensitive Business Flows (Batch/Alias Abuse)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-BIZLOGIC |
| **Priority** | P2 |
| **Severity (of finding)** | HIGH |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `business-logic`, `abuse`, `owasp-api6`, `batch`, `aliases`, `write-gated` |
| **Category** | `BusinessLogic` |
| **Depends on** | **GQL-A06** alias builder, **GQL-A05** write-gate |
| **Files** | `pkg/scanner/checks/gqlb01_business_flow_abuse.go` (+ `_test.go`) |

## Summary
Detect **unrestricted access to sensitive business flows**: signup/coupon-redeem/transfer/invite/vote-style
mutations that lack per-actor rate/quantity limits, so a single request (via **aliasing/batching**) or a tight
burst performs the flow N times — coupon stacking, mass signup, vote stuffing, referral farming. Where GQL-A06
targets *authentication* throttling, B01 targets *business-flow* throttling.

## Why it matters
- OWASP **API6:2023** (unrestricted access to sensitive business flows) is pure profit for abusers: redeem a
  one-per-user coupon 100× in one request, create thousands of accounts, or stuff a poll. These flows rarely
  enforce per-actor limits at the resolver.

## Engineering Context
(See `EPIC-GQL-BIZLOGIC.md` shared context + safety. Add a `BusinessLogic` category to `domain` (mirror how
`Authorization` was added). Reuse the GQL-A06 single-request aliasing builder; follow the GQL-A05 safe-write
discipline. **Write-gated** behind `cc.AllowMutations`. Use `cc.HTTPClient`.)

- `ID()="GQL-B01"`, `Name()="Unrestricted Access to Sensitive Business Flows"`, `Category()=BusinessLogic`,
  `Severity()=HIGH`, `RequiresSchema()=true`.

## Detection algorithm
1. **Hard gate:** `!cc.AllowMutations` → `Skip` (these are state-changing flows). Else continue.
2. **Identify sensitive-flow mutations** (non-destructive, idempotency-relevant): names matching
   `(?i)(redeem|coupon|promo|apply_?discount|signup|register|invite|refer|vote|like|follow|claim|reward|
   transfer|withdraw|purchase|order|subscribe)`. Exclude obviously-destructive names. Cap ≤ 2 flows (these
   write).
3. **Quantity-limit probe (bounded, safe):** for a chosen flow that takes an idempotency-relevant input (e.g. a
   coupon code, a unique key), send **one request aliasing the mutation N times** (N=20, well below DoS) with
   the **same** logical action (e.g. the same coupon) — a server enforcing "one per user/code" should reject
   all but the first; an unprotected server executes all N. Observe how many alias keys returned success vs a
   limit/duplicate error. Increment `ProbeCount`.
4. **Decide — flag HIGH when** the server executes the sensitive flow **more times than the business rule
   should allow in one request** (e.g. all N coupon redemptions succeed, or N signups created) with no
   per-actor/per-key limit or duplicate rejection. Confidence `"firm"` (single-request multiplicity proven)
   / `"confirmed"` when a read-back shows the abusive effect persisted (e.g. balance credited N×).
   - Negative: the server rejects/limits the repeated flow (one success + N−1 "already redeemed"/limit) → no
     finding.
5. **Cleanup:** where the flow is reversible (e.g. unredeem, delete-created), best-effort revert via the A05
   pattern and report cleanup status; never use a real, valuable coupon — use a probe/non-existent code so
   "success" indicates missing validation, not real value transfer (see Safety).

## Finding content
- **Title:** `Unrestricted Business Flow — <mutation> executes N× per request without limit`
- **Description:** the flow, that N aliased executions succeeded in one request with no per-actor/per-key
  limit, and any persisted effect observed; note the probe used a non-valuable/probe input. Redact data.
- **Impact:** coupon/promo stacking, mass account/vote/referral abuse, and quota bypass — direct financial loss
  and integrity damage to business logic.
- **Remediation:** enforce per-actor and per-key business limits at the resolver/data layer (idempotency keys,
  unique constraints, atomic decrement of a quota); cap operation/alias count per request; apply
  cost/action-based rate limiting; validate one-time codes server-side.
- **References:** `https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/`,
  `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`.
- **Confidence:** `"firm"`/`"confirmed"`. **CWE:** `"CWE-799"` (improper control of interaction frequency).
  **OWASP:** `"API6:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-B01", cc.Target, "bizflow:"+mutation)`.

## Acceptance criteria
- **Given** `--authz-allow-mutations` and a server that lets one request redeem the same probe coupon 20×
  (all alias keys succeed), a HIGH finding fires; a read-back showing N× effect raises confidence to confirmed.
- **Given** a server that enforces one-per-key (1 success + 19 "already redeemed"), no finding.
- **Given** `AllowMutations=false`, the check is `Skipped` and no write is sent (assert zero mutations).
- Destructive-named flows never invoked; cleanup status reported.

## Tests (`gqlb01_business_flow_abuse_test.go`)
- Stateful server with a coupon that *should* be one-per-key; unprotected variant honors all 20 aliases →
  finding; protected variant rejects duplicates → no finding.
- `AllowMutations=false` → Skipped, zero mutations. Assert HIGH/API6/CWE-799, fingerprint.

## Safety
Write-gated. Uses **probe/non-existent** identifiers (a bogus coupon/key) so a "success" indicates missing
validation rather than real value transfer; bounded aliasing (N=20, below DoS); best-effort cleanup of any
reversible effect; destructive flows excluded; data redacted.
