# GQL-D02 — Field Duplication / `__typename` Flooding (Parser/Validator Amplification)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P0 (Highest) |
| **Severity (of finding)** | HIGH |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `dos`, `parser`, `owasp-api4`, `ghsa`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld02_field_duplication.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D02** that detects whether the server caps the **number of duplicated selections** in
a single document. Repeating the same field thousands of times (`{ __typename __typename __typename ... }`)
or duplicating a nested selection set has historically caused **quadratic parsing/validation cost** in
several engines (notably graphql-js — see GHSA advisories on response/validation amplification). Unlike
aliases (GQL-D01, distinct response keys → N resolver runs), duplicate identical selections stress the
**parse + validate + merge** pipeline before execution.

## Why it matters
- Cheap to send, expensive to validate: a small request can trigger super-linear server-side CPU.
- Complements GQL-D01 (aliases) and GQL-007 (depth): together they cover the three structural DoS primitives.
- Maps to **OWASP API4:2023** and GraphQL Cheat Sheet (limit query size/cost before execution).

## Engineering Context
(See `EPIC-GQL-DOS.md` shared context + safety. Implement `checks.Check`, register in `init()`, probe via
`cc.ProbeClient()`, fingerprint key `"field_duplication"`.)

- `ID()="GQL-D02"`, `Name()="Field Duplication / __typename Flooding"`, `Category()=DenialOfService`,
  `Severity()=HIGH`, `RequiresSchema()=false`.

## Detection algorithm
1. **Control probe:** `query { __typename }` → expect fast HTTP 200 with `data`. Record its latency `Lc`.
   If it fails, set `PassReason` and return.
2. **Flood probe (bounded):** build a document repeating `__typename ` `D` times where `D = 256`
   (constant `dupCount`): `query { __typename __typename ... }`. (Optional second variant: duplicate a
   nested selection on a schema object field if `cc.Schema` is available, e.g. `{ f { __typename __typename ... } }`.)
   Send once. Record latency `Lf`.
3. **Decision — flag HIGH when:**
   - flood probe returns HTTP 200 with `data` **and** the response is not a size/cost/validation rejection
     (`(?i)too large|too many|complexity|cost|limit exceeded|maximum`); **OR**
   - flood probe **times out or returns 5xx** while the control was a fast 200 (CPU-amplification signal); **OR**
   - `Lf >= 10 * Lc` and `Lf >= 1000ms` (super-linear validation-time signal — a clear amplification even if
     the server ultimately answered). Use a small constant ratio; this is a *secondary* timing signal, the
     primary is structural acceptance.
4. Otherwise `PassReason = "Server limited or efficiently handled a 256-field duplicate query (document-size
   / cost limiting appears enforced)."` with both probes in `PassProbes`.

## Finding content (when fired)
- **Title:** `No Document-Size / Field-Duplication Limit`
- **Description:** report D duplicated selections accepted, the control vs flood latency, and the signal that
  fired (structural acceptance, timeout, or super-linear validation time).
- **Impact:** attacker can force super-linear parse/validation CPU with a small payload; sustained requests
  cause resource exhaustion without tripping per-request rate limits.
- **Remediation:** enforce maximum document size / token count and a maximum selection-set width at the
  validation layer; upgrade the GraphQL engine to a version with bounded validation; add a request-body size
  cap at the gateway.
- **References:**
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
  - `https://github.com/advisories` (graphql-js validation/amplification advisories — cite the specific GHSA after verification)
- **Fingerprint:** `GenerateFingerprint("GQL-D02", cc.Target, "field_duplication")`

## Acceptance criteria
- **Given** a server that returns 200+`data` for a 256-duplicate query, **then** one HIGH finding fires.
- **Given** a server returning a "document too large"/cost error or non-200, **then** no finding + PassReason.
- **Given** a control that is fast 200 but a flood probe that times out, **then** a HIGH finding fires
  (timeout-as-signal) without panicking.
- `ProbeCount >= 2`, fingerprint non-empty, severity HIGH, category DenialOfService.

## Tests (`gqld02_field_duplication_test.go`)
- Handler returning `{"data":{"__typename":"Query"}}` for any body → expect finding.
- Handler returning `{"errors":[{"message":"Query document too large"}]}` for the flood body (detect by body
  length) but 200 for the control → expect no finding + PassReason.
- Handler that sleeps on large bodies past the timeout → expect finding (timeout path).
- Assert latency-ratio branch with a stubbed slow handler (Lf ≥ 10×Lc) → finding.

## Safety
`dupCount = 256` (constant). Two probes. Detect acceptance/amplification, never attempt actual exhaustion.
