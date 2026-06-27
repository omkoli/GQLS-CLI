# GQL-D06 — Query Cost / Response-Size Amplification Oracle

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P2 (Medium) |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `dos`, `amplification`, `owasp-api4`, `oracle`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld06_cost_amplification.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D06**, an **amplification oracle** that empirically measures how much server work a
small request can produce. It sends a graded series of bounded queries of increasing structural cost and
computes the **amplification factor** = (response bytes and/or latency) ÷ (request bytes). A high factor with
no cost-limit rejection demonstrates the absence of effective query-cost analysis — the root cause behind
GQL-007/008/D01/D05.

## Why it matters
- Turns the qualitative "no depth/complexity limit" findings into a **quantified** amplification metric that
  is compelling in reports and prioritization ("this endpoint amplifies 1 byte → 4,200 bytes / 38× latency").
- Engine-agnostic: it proves real exploitability without depending on a specific limiter being absent.
- Maps to **OWASP API4:2023** and is the empirical complement to GQL-008 (complexity).

## Engineering Context
(See `EPIC-GQL-DOS.md` shared context + safety. Implement `checks.Check`, register in `init()`, probe via
`cc.ProbeClient()`, fingerprint key `"cost_amplification"`. You may reuse the nestable-field selection idea
from `gql007_depth_limit.go` — `findBestNestableField`-style logic — to build realistic cost gradients.)

- `ID()="GQL-D06"`, `Name()="Query Cost Amplification"`, `Category()=DenialOfService`,
  `Severity()=MEDIUM`, `RequiresSchema()=false` (richer with a schema, but can fall back to introspection/`__type`).

## Detection algorithm
1. **Build a cost gradient (bounded).** Construct G = 3 queries of increasing cost using *combinations* of
   the already-bounded primitives — e.g. nesting depth ∈ {2, 4, 6} crossed with alias width ∈ {1, 8, 16} on a
   nestable field (schema-derived, else a `__type(name:"Query")`/`__schema` introspection chain). Keep every
   probe within the per-check caps (depth ≤ 6, aliases ≤ 16) so no single request is itself abusive.
2. **For each gradient step** record: request body bytes `Req_i`, response body bytes `Resp_i`, latency `Lat_i`,
   status. Increment `ProbeCount` each time. Always send the cheapest step first as the control.
3. **Compute amplification:**
   - size factor `AF_size = max_i(Resp_i) / Req_of_that_step`
   - latency factor `AF_lat = max_i(Lat_i) / min_i(Lat_i)` (only when min latency ≥ a small floor, e.g. 5ms,
     to avoid divide-by-noise; otherwise mark latency inconclusive).
4. **Decision — flag MEDIUM when** all steps returned HTTP 200 with `data` (no cost rejection) **and**
   (`AF_size >= 50` **or** (`AF_lat >= 10` and `max latency >= 750ms`)). The thresholds are constants; tune via
   tests. If any step is rejected with a cost/complexity error, treat the endpoint as protected.
5. Otherwise `PassReason = "Measured amplification stayed within safe bounds or the server rejected the cost
   gradient (cost limiting appears effective)."` Record the gradient as `PassProbes` with per-step metrics in
   the labels.

## Finding content (when fired)
- **Title:** `High Query-Cost Amplification (No Effective Cost Limit)`
- **Description:** present the gradient table (depth/alias, request bytes, response bytes, latency) and the
  computed `AF_size` / `AF_lat`. Make the numbers the headline.
- **Impact:** an attacker can convert minimal bandwidth into large server CPU/memory/IO and egress, enabling
  cost-efficient denial of service and inflated infrastructure billing (economic DoS).
- **Remediation:** implement query-cost/complexity analysis with a hard ceiling computed before execution
  (e.g. `graphql-cost-analysis`, Apollo operation cost limits, gqlgen complexity); weight list sizes and
  nesting; reject over-budget operations with HTTP 4xx.
- **References:**
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
  - `https://www.howtographql.com/advanced/4-security/`
- **Fingerprint:** `GenerateFingerprint("GQL-D06", cc.Target, "cost_amplification")`

## Acceptance criteria
- **Given** a server whose response size scales steeply with query cost and never rejects, **then** one MEDIUM
  finding fires carrying the computed factors and the gradient table.
- **Given** a server that rejects the higher gradient steps with a complexity/cost error, **then** no finding +
  PassReason with the gradient recorded.
- **Given** a flat server (response size constant regardless of cost), **then** no finding (low AF).
- `ProbeCount == G` (3), fingerprint non-empty, severity MEDIUM. Latency-inconclusive path does not panic.

## Tests (`gqld06_cost_amplification_test.go`)
- Handler that returns a body whose length grows with nesting/alias count parsed from the query → finding,
  assert `AF_size` reported ≥ threshold.
- Handler that returns a complexity error for the costliest step → no finding.
- Handler with constant small body → no finding.
- Deterministic gradient ordering (cheapest first) verified.

## Safety
Gradient is fully bounded (depth ≤ 6, aliases ≤ 16, 3 probes). No single probe is itself an abusive payload;
the check *measures* amplification rather than inducing exhaustion.
