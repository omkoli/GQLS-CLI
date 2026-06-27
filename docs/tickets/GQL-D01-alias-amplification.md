# GQL-D01 — Alias-Based Query Amplification (No Alias/Document Limit)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P0 (Highest) |
| **Severity (of finding)** | HIGH |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `dos`, `aliases`, `owasp-api4`, `portswigger`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld01_alias_amplification.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D01** that detects whether a GraphQL endpoint enforces a limit on the number of
**field aliases** in a single operation. GraphQL lets a client request the *same* field many times under
different alias keys; each alias forces a **separate resolver execution**. Without an alias/document-cost
limit, one HTTP request can multiply server work N× — the canonical GraphQL amplification and rate-limit /
brute-force bypass primitive (PortSwigger GraphQL Academy).

## Why it matters
- A single request `{ a0: login(...) a1: login(...) ... aN: login(...) }` bypasses per-request rate limits
  and brute-force protections, and multiplies expensive-resolver cost N×.
- Higher signal-to-noise than the existing latency-based depth heuristic (GQL-007): alias acceptance is a
  **structural** yes/no, not a timing guess.
- Maps to **OWASP API4:2023 (Unrestricted Resource Consumption)** and OWASP GraphQL Cheat Sheet ("Aliases").

## Engineering Context
(See `EPIC-GQL-DOS.md` → "Shared Engineering Context" and "Shared SAFETY Requirements". Key points:
implement the `checks.Check` interface, self-register in `init()` via `MustRegister`, probe with
`cc.ProbeClient()` against `cc.Target`, JSON body `{"query":...}`, increment `result.ProbeCount`,
set `Fingerprint` via `GenerateFingerprint("GQL-D01", cc.Target, "alias_amplification")`.)

- `ID()="GQL-D01"`, `Name()="Alias-Based Query Amplification"`, `Category()=DenialOfService`,
  `Severity()=HIGH`, `RequiresSchema()=false`.

## Detection algorithm
1. **Pick an amplifiable field.** If `cc.Schema != nil`, choose the first root `Query` field that takes no
   *required* arguments and returns a scalar/enum/object (so it executes a resolver). Otherwise fall back to
   the meta-field `__typename` (always valid, still exercises document parsing/validation per alias).
2. **Control probe (1 alias):** send `query { c0: <field> }` (or `{ c0: __typename }`). Confirm HTTP 200 with
   a `data` object. If the control fails, set `PassReason` ("endpoint did not respond to baseline probe") and
   return (do not flag).
3. **Amplified probe (N aliases):** with `N = 100` (bounded — see Safety), build
   `query { a0: <field> a1: <field> ... a99: <field> }`. Send once.
4. **Decision — flag HIGH when ALL hold:**
   - amplified response is HTTP 200 **and** body contains a `data` object **and** the response actually
     contains the N distinct alias keys (`a0`..`a99`) — proving the server executed every alias; **and**
   - the response is **not** a limit/validation rejection (no error message matching
     `(?i)alias|too many|complexity|cost|query .*too large|limit exceeded`).
   - *Also* flag (with note "server became unresponsive under aliasing") if the amplified probe **times out
     or returns 5xx** while the control returned fast 200 — a timeout under bounded aliasing is itself a
     positive DoS signal.
5. Otherwise: `PassReason = "Endpoint rejected or limited a 100-alias query (alias/document-cost limiting
   appears enforced)."` and record both probes as `PassProbes`.

## Finding content (when fired)
- **Title:** `No Alias Limit — Query Amplification Possible`
- **Description:** state N aliases were accepted in one request, that each alias triggers a separate
  resolver execution, include the field used and the observed alias-key count echoed back.
- **Impact:** single-request amplification of resolver/database work; bypass of per-request rate limiting and
  brute-force/OTP protections; potential resource exhaustion.
- **Remediation:** enforce a maximum alias count / maximum operation cost at the validation layer
  (e.g. `graphql-no-alias`, Apollo operation-cost limits, `graphql-query-complexity`); apply cost-based rate
  limiting rather than request-count rate limiting.
- **References:**
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://portswigger.net/web-security/graphql` (alias-based rate-limit bypass)
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
- **Fingerprint:** `GenerateFingerprint("GQL-D01", cc.Target, "alias_amplification")`
- **ReproRequest / ReproBody:** the amplified request and its JSON body.

## Acceptance criteria
- **Given** a server that executes a 100-alias query and echoes all alias keys, **when** GQL-D01 runs,
  **then** exactly one HIGH finding is produced with the fields above and `ProbeCount >= 2`.
- **Given** a server that returns a validation error (`"Too many aliases"`/cost error) or non-200 for the
  amplified query, **when** GQL-D01 runs, **then** no finding is produced and `PassReason` is set with both
  probes recorded in `PassProbes`.
- **Given** a server that returns fast 200 to the control but times out on the amplified probe, **then** a
  HIGH finding fires noting unresponsiveness, and the check returns without panicking.
- **Given** the control probe fails (endpoint down), **then** no finding and `PassReason` explains the
  baseline failure.

## Tests (`gqld01_alias_amplification_test.go`)
- `httptest.NewServer` handler that: counts `a0..a99` aliases in the query and returns a `data` object with
  those keys → expect finding.
- Handler returning `{"errors":[{"message":"Too many aliases"}]}` → expect no finding + PassReason.
- Handler that sleeps past the client timeout on large bodies → expect finding (unresponsiveness path).
- Assert `ProbeCount`, `Fingerprint` non-empty, `Severity == HIGH`, `Category == DenialOfService`.

## Safety
N is fixed at 100 (constant `aliasCount`). Two probes total. No retries. Detect acceptance, not outage.
