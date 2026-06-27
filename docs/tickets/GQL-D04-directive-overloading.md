# GQL-D04 — Directive Overloading

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P1 (High) |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 2 |
| **Complexity** | Low |
| **Labels** | `dos`, `directives`, `owasp-api4`, `ghsa`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld04_directive_overloading.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D04** that detects whether the server caps the number of **directives** applied at a
single location. The GraphQL spec requires directives to be unique per location, but several engines
(historically graphql-js — see GHSA directive-amplification advisories) accepted and processed thousands of
repeated directives, causing super-linear validation/CPU cost: `query { __typename @skip(if:false) @skip(if:false) ... }`.

## Why it matters
- Another small-request → large-CPU amplification vector that bypasses request-count rate limiting.
- Acceptance of duplicate directives also signals a non-spec-compliant or outdated engine (useful fingerprint).
- Maps to **OWASP API4:2023**.

## Engineering Context
(See `EPIC-GQL-DOS.md` shared context + safety. Implement `checks.Check`, register in `init()`, probe via
`cc.ProbeClient()`, fingerprint key `"directive_overloading"`.)

- `ID()="GQL-D04"`, `Name()="Directive Overloading"`, `Category()=DenialOfService`,
  `Severity()=MEDIUM`, `RequiresSchema()=false`.

## Detection algorithm
1. **Control probe:** `query { __typename @skip(if: false) }` → expect fast HTTP 200 with `data`
   (`@skip`/`@include` are built-in directives guaranteed to exist). Record latency `Lc`. If it fails,
   set `PassReason` and return.
2. **Overload probe (bounded):** repeat `@skip(if: false) ` `K = 200` times (constant `directiveCount`) on
   `__typename`: `query { __typename @skip(if:false) @skip(if:false) ... }`. Send once. Record `Lo`.
3. **Decision — flag MEDIUM when:**
   - overload probe returns HTTP 200 with `data` and is **not** a validation rejection
     (`(?i)duplicate|can only be used once|repeated|too many directives|non-repeatable`); **OR**
   - overload probe **times out / 5xx** while the control was fast 200; **OR**
   - `Lo >= 10 * Lc && Lo >= 1000ms` (super-linear directive-validation signal).
4. Otherwise `PassReason = "Server rejected or efficiently handled 200 repeated directives (directive
   uniqueness / cost limiting appears enforced)."` with both probes in `PassProbes`.

## Finding content (when fired)
- **Title:** `No Directive-Count Limit (Directive Overloading)`
- **Description:** K repeated directives accepted at one location; include control vs overload
  latency/status and the firing signal.
- **Impact:** small-payload super-linear validation CPU cost; sustained abuse exhausts resources while each
  request looks individually cheap, bypassing per-request rate limits.
- **Remediation:** upgrade to a GraphQL engine that enforces directive-uniqueness validation (per spec);
  add a maximum-directives-per-location and overall document-cost limit at the validation layer.
- **References:**
  - `https://spec.graphql.org/October2021/#sec-Directives-Are-Unique-Per-Location`
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
  - `https://github.com/advisories` (graphql-js directive-overloading GHSA — cite the specific advisory after verification)
- **Fingerprint:** `GenerateFingerprint("GQL-D04", cc.Target, "directive_overloading")`

## Acceptance criteria
- **Given** a server that returns 200+`data` for 200 repeated `@skip` directives, **then** one MEDIUM finding.
- **Given** a server returning a "directive can only be used once" validation error, **then** no finding +
  PassReason.
- **Given** control fast 200 but overload timeout, **then** a MEDIUM finding (timeout path).
- `ProbeCount >= 2`, fingerprint non-empty, severity MEDIUM.

## Tests (`gqld04_directive_overloading_test.go`)
- Handler returning `{"data":{"__typename":"Query"}}` regardless of directive count → finding.
- Handler returning `{"errors":[{"message":"The directive \"@skip\" can only be used once at this location."}]}`
  on the overload body → no finding + PassReason.
- Handler sleeping past timeout on large bodies → finding.

## Safety
`directiveCount = 200` (constant). Two probes. Detect acceptance/amplification, not outage.
