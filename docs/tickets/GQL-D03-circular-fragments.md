# GQL-D03 — Circular Fragment / Fragment-Spread Bomb

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P1 (High) |
| **Severity (of finding)** | HIGH |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `dos`, `fragments`, `owasp-api4`, `spec-violation`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld03_circular_fragments.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D03** that detects whether the server correctly rejects **fragment cycles**. The
GraphQL spec (§5.5.2.2 "Fragment spreads must not form cycles") requires servers to reject documents where
fragments reference each other circularly. A non-compliant server that does **not** detect the cycle will
recurse/loop during validation or execution — an instant single-request DoS (stack overflow / hang / 5xx).

## Why it matters
- A single tiny request can hang or crash a non-compliant server.
- Tests spec-conformance of the validator — a strong indicator of an outdated or custom GraphQL engine.
- Maps to **OWASP API4:2023** and GraphQL Cheat Sheet (validate before execute).

## Engineering Context
(See `EPIC-GQL-DOS.md` shared context + safety. Implement `checks.Check`, register in `init()`, probe via
`cc.ProbeClient()`, fingerprint key `"circular_fragment"`.)

- `ID()="GQL-D03"`, `Name()="Circular Fragment Spread"`, `Category()=DenialOfService`,
  `Severity()=HIGH`, `RequiresSchema()=false`.

## Detection algorithm
1. **Determine a valid fragment target type.** Fragments need a type condition that exists. Use the query
   root type name from `cc.Schema` if available; otherwise default to the literal `"Query"`. (Most servers
   name it `Query`; if the schema is present, prefer the real name to avoid a trivial "unknown type" error
   that would mask the cycle test.)
2. **Build a circular document:**
   ```graphql
   query { ...A }
   fragment A on <RootType> { __typename ...B }
   fragment B on <RootType> { __typename ...A }
   ```
3. **Control probe:** first confirm the endpoint answers a benign `query { __typename }` with fast 200.
4. **Cycle probe:** send the circular document once.
5. **Decision:**
   - **Compliant (PASS):** server returns a fast response (200 or 400) containing a validation error matching
     `(?i)cannot spread fragment .* within itself|fragment .* cycle|circular|cannot spread fragment`. → no finding,
     set `PassReason = "Server correctly rejected the fragment cycle (spec-compliant validation)."`
   - **Vulnerable (FLAG HIGH):** server **times out**, returns **5xx**, or hangs (latency ≫ control and no
     clean validation error). A cycle that is not rejected with a clear validation message is the positive signal.
   - **Inconclusive:** any other clean 200 with `data` and no cycle error (e.g. the server silently ignored
     the fragments) → do **not** flag; set `PassReason` noting an inconclusive but non-vulnerable result.
6. Record probes in `PassProbes` on PASS.

## Finding content (when fired)
- **Title:** `Fragment Cycle Not Rejected (Validator DoS)`
- **Description:** include the circular document sent, the control vs cycle latency/status, and the signal
  (timeout / 5xx / hang) indicating the validator did not detect the cycle.
- **Impact:** a single small request can exhaust CPU/stack via unbounded recursion during validation or
  execution, crashing the worker or hanging the request — a denial-of-service with negligible attacker cost.
- **Remediation:** upgrade to a spec-compliant GraphQL engine that enforces "Fragment spreads must not form
  cycles" (GraphQL spec §5.5.2.2); ensure validation runs before execution; add request timeouts and recursion
  guards.
- **References:**
  - `https://spec.graphql.org/October2021/#sec-Fragment-spreads-must-not-form-cycles`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
- **Fingerprint:** `GenerateFingerprint("GQL-D03", cc.Target, "circular_fragment")`

## Acceptance criteria
- **Given** a server returning a "Cannot spread fragment within itself" validation error, **then** no finding
  + PassReason (spec-compliant).
- **Given** a server that times out / returns 5xx on the circular document but answers the control fast,
  **then** one HIGH finding fires.
- **Given** a server returning a clean unrelated 200, **then** no finding (inconclusive, non-vulnerable).
- `ProbeCount >= 2`, fingerprint non-empty, severity HIGH.

## Tests (`gqld03_circular_fragments_test.go`)
- Handler returning `{"errors":[{"message":"Cannot spread fragment \"A\" within itself."}]}` → no finding.
- Handler that sleeps past the timeout when the body contains `fragment A on` → finding (timeout path).
- Handler returning 500 on the cycle body → finding.
- Verify schema-derived root type name is used when `cc.Schema` provides one; falls back to `"Query"` when nil.

## Safety
Exactly one cycle probe (plus one control). Rely on the configured per-request timeout to bound any hang.
Never send nested/expanding fragment bombs that could amplify beyond a single bounded request.
