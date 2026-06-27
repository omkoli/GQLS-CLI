# GQL-D07 — Persisted Query / APQ Not Enforced (Arbitrary Operations Accepted)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P2 (Medium) |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 3 |
| **Complexity** | Medium |
| **Labels** | `dos`, `apq`, `persisted-queries`, `hardening`, `owasp-api4`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld07_persisted_query.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D07** that detects whether the endpoint **accepts arbitrary ad-hoc operations** rather
than restricting execution to an **allow-list of persisted queries / Automatic Persisted Queries (APQ)**.
Persisted-query allow-listing is a strong defense-in-depth control against DoS, injection, and unexpected
operations; its absence means any crafted (and potentially expensive/abusive) query is executable.

## Why it matters
- A persisted-query allow-list is the most effective structural mitigation for the entire DoS class (D01–D06):
  if only pre-registered operations run, alias/depth/cost bombs are simply rejected.
- Detecting APQ support vs enforcement tells defenders whether they've enabled the *cache* (APQ) but not the
  *allow-list* (registered/persisted operations only) — a common misconfiguration (Apollo `persistedQueries`).
- Maps to **OWASP API4:2023** and GraphQL Cheat Sheet (allow-listing / persisted queries).

## Engineering Context
(See `EPIC-GQL-DOS.md` shared context + safety. Implement `checks.Check`, register in `init()`, probe via
`cc.ProbeClient()`, fingerprint key `"apq_not_enforced"`.)

- `ID()="GQL-D07"`, `Name()="Persisted Query / APQ Not Enforced"`, `Category()=DenialOfService`,
  `Severity()=MEDIUM`, `RequiresSchema()=false`.

## Detection algorithm
1. **Arbitrary-operation probe.** Send a *novel, non-trivial* ad-hoc query the server could not have
   pre-registered — e.g. an unusual alias combination `query { z9q1: __typename z9q2: __typename }`.
   - If it returns HTTP 200 with `data` → the server executes **arbitrary** operations (allow-list NOT
     enforced). This is the primary positive signal.
2. **APQ-protocol probe (Apollo APQ).** Send a request with only the persisted-query extension and **no**
   `query` field:
   ```json
   {"extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000000"}}}
   ```
   - Response error `PersistedQueryNotFound` (message or `extensions.code`) → **APQ is supported**.
   - Combined with step 1 succeeding → APQ cache is on but **allow-listing is not enforced** (registered-only
     mode disabled): report this nuance in the finding.
   - Error `PersistedQueryNotSupported` / generic "must provide query string" → APQ not supported; rely on
     step 1 alone.
3. **Decision — flag MEDIUM when** the arbitrary-operation probe (step 1) executed successfully (200 + `data`).
   Enrich the description with the APQ support state from step 2.
4. **PASS when** the arbitrary operation is rejected (e.g. `PersistedQueryNotFound` with no `query` accepted,
   or an explicit "operation not in allow-list" / 4xx for ad-hoc queries). Set `PassReason = "Endpoint
   restricts execution to persisted/allow-listed operations (arbitrary query rejected)."`

## Finding content (when fired)
- **Title:** `Arbitrary Operations Accepted (No Persisted-Query Allow-List)`
- **Description:** state that a novel ad-hoc query executed, and whether APQ is supported-but-not-enforced vs
  not supported at all.
- **Impact:** any attacker-crafted operation — including expensive/abusive queries from the other DoS checks
  and injection probes — is executable; removes a strong defense-in-depth layer and widens the attack surface.
- **Remediation:** enforce a persisted-query **allow-list** (registered/safe-listed operations only) in
  production (e.g. Apollo `persistedQueries: { mode: "only" }` / operation safelisting, Relay persisted
  queries, Hive/Inigo persisted operations); treat APQ caching as separate from allow-list enforcement.
- **References:**
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://www.apollographql.com/docs/apollo-server/performance/apq/`
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
- **Fingerprint:** `GenerateFingerprint("GQL-D07", cc.Target, "apq_not_enforced")`

## Acceptance criteria
- **Given** a server that executes the novel ad-hoc query, **then** one MEDIUM finding fires; if the APQ probe
  returns `PersistedQueryNotFound`, the description notes "APQ supported but allow-listing not enforced".
- **Given** a server that rejects ad-hoc queries (allow-list only), **then** no finding + PassReason.
- **Given** an APQ-unsupported server that still runs ad-hoc queries, **then** a MEDIUM finding without the
  APQ-nuance note.
- `ProbeCount >= 2`, fingerprint non-empty, severity MEDIUM.

## Tests (`gqld07_persisted_query_test.go`)
- Handler returning `data` for any `query` and `PersistedQueryNotFound` for the extension-only body → finding
  with APQ-nuance note.
- Handler returning 4xx / "operation not allow-listed" for ad-hoc queries → no finding + PassReason.
- Handler returning `data` for ad-hoc and `PersistedQueryNotSupported` for the APQ probe → finding without note.

## Safety
Two small benign probes; no abusive payloads. This is a hardening/inventory check, not a load generator.
