# GQL-A02 — BFLA (Broken Function Level Authorization)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P0 (Highest) |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `authz`, `bfla`, `owasp-api5`, `cwe-285`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | **GQL-A00** (identities, oracle, surface graph) |
| **Files** | `pkg/scanner/checks/gqla02_bfla.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A02** that detects **Broken Function Level Authorization**: a privileged
operation (an admin-only query, or a sensitive mutation) is reachable by a **lower-privilege** identity.
Where A01 is about *objects*, A02 is about *functions/operations* — "can a normal user call `adminUsers`,
`promoteToAdmin`, `deleteUser`, `setRole`?"

## Why it matters
- BFLA is OWASP **API5:2023** / **CWE-285** and one of the three "Critical" authz risks gqls currently misses
  entirely (`SECURITY_PLATFORM_ANALYSIS.md` §3.1). It is the privilege-escalation primitive behind most
  account-takeover chains.
- Distinct from GQL-012 (which only asks "can *anonymous* run *any* mutation"). A02 asks the sharper question:
  "can a **lower-privileged authenticated** role reach a **privileged** operation it should not?"

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + safety. Consume GQL-A00: `cc.IdentityPairs()`,
`surface.PrivilegedOps(cc.Schema)`, `surface.ExampleValue`, `authz.Classify`.)

- `ID()="GQL-A02"`, `Name()="Broken Function Level Authorization (BFLA)"`,
  `Category()=Authorization`, `Severity()=CRITICAL`, `RequiresSchema()=true`.
- **Default read-bias.** Privileged **queries** are probed freely. Privileged **mutations** are probed only
  when `cfg.AllowAuthzMutations` is true (GQL-A00 flag); otherwise A02 reports mutation candidates as an
  INFO-level "not tested (write-gated)" note in PassReason and tests only the read side. Never invoke
  destructive mutations (`delete*|purge*|wipe*|drop*`) even when writes are allowed, unless explicitly
  allow-listed by the operator.

## Detection algorithm
1. **Preconditions.** `!cc.HasIdentities()` → `Skip` ("BFLA testing requires ≥2 identities of differing
   privilege"). Need at least one **lower-privilege** identity (Privilege below the max).
2. **Enumerate privileged operations.** `ops := surface.PrivilegedOps(cc.Schema)` — fields flagged privileged
   by name heuristic (`admin|delete|grant|revoke|promote|impersonate|role|permission|ban|refund|payout|
   config|...`) or by returning/accepting a `privileged`/`credential`-tagged type. Cap to **N=8** by name
   (disclose cap). Split into `privQueries` and `privMutations`.
3. **Establish the expected baseline.** For each op, send it **as the most privileged identity** to learn the
   "authorized" response class (ideally `ClassSuccess` or `ClassValidation` — i.e. the op *exists* and the
   high-priv role may call it). If the privileged identity itself is denied, the op is not actually privileged
   for the configured roles → skip it (avoid false positives on ops nobody can call).
4. **Differential probe.** For each privileged **query** op and each lower-privilege identity:
   - Build `query { <field>(<required args via ExampleValue>) { __typename } }` (or scalar selection).
   - Send **as the lower-privilege identity**. `ProbeCount++`.
   - `cls := authz.Classify(resp)`.
5. **Decide.** **Flag CRITICAL when** the privileged identity could call the op (baseline Success/Validation)
   **and** the lower-privilege identity gets `ClassSuccess` (HTTP 200 + non-null `data` for the privileged
   field) — i.e. the function executed for a role that should not reach it. Confidence `"confirmed"`.
   - **Negative:** lower-priv identity gets `ClassAuthDenied` → function-level authz enforced for that op.
   - **Inconclusive:** `ClassValidation` only (reached the resolver but missing args — *suggestive* but not
     proof of execution) → record as `Confidence="tentative"` PassProbe, **do not** raise a CRITICAL; if you
     choose to surface it, surface at most a single HIGH "function-level authz possibly missing (validation
     reached past authz layer)" with tentative confidence. 5xx/rate-limit → inconclusive, never flag.
6. **One finding per leaking op.** Aggregate the full list of leaking ops into the finding description (they
   share a root cause) but fingerprint per-op so suppression is granular.

## Finding content (when fired)
- **Title:** `Broken Function Level Authorization — <op> callable by <attacker.Name>`
- **Description:** name the privileged operation(s), the privilege level that *should* be required vs the
  identity that successfully called it, and the response class observed for each. Redact any returned data.
- **Impact:** a lower-privileged (or non-admin) user can invoke privileged functionality — privilege
  escalation, administrative actions, access to admin-only data, and account takeover depending on the op set.
- **Remediation:** enforce function-level authorization on every resolver (not just at the UI/gateway);
  centralize role/permission checks via middleware or schema directives (`@auth(requires: ADMIN)`); deny by
  default and explicitly grant; audit every mutation and admin query for a guard.
- **References:**
  - `https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://cwe.mitre.org/data/definitions/285.html`
- **Confidence:** `"confirmed"` (execution) or `"tentative"` (validation-only). **CWE:** `"CWE-285"`.
  **OWASP:** `"API5:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A02", cc.Target, "bfla:"+op)`.
- **ReproRequest / ReproBody:** the lower-privilege request that reached the privileged op.

## Acceptance criteria
- **Given** a privileged identity that can call `adminUsers` and a low-priv identity for whom the server *also*
  returns `data.adminUsers`, **then** one CRITICAL finding fires (Confidence `"confirmed"`, CWE/OWASP set).
- **Given** the low-priv identity is denied (403 / `FORBIDDEN`), **then** no finding + PassReason.
- **Given** the privileged identity itself cannot call the op, **then** the op is skipped (no FP).
- **Given** `AllowAuthzMutations=false`, **then** privileged mutations are *not* invoked; PassReason notes
  they were write-gated.
- **Given** no identities, **then** `Skipped` with reason. Malformed responses never panic.

## Tests (`gqla02_bfla_test.go`)
- `httptest.NewServer` distinguishing identities by `Authorization`: admin token → `{"data":{"adminUsers":[…]}}`,
  low-priv token → same data → expect CRITICAL.
- Low-priv token → `{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}` → no finding.
- Admin token itself denied → op skipped.
- Mutation candidate present + `AllowAuthzMutations=false` → no write probe sent (assert the server never
  received the mutation), PassReason mentions write-gating.
- No identities → `Skipped`. Assert severity/category/fingerprint/ProbeCount and deterministic op ordering.

## Safety & Ethics
Read-biased: queries always; mutations only behind the explicit opt-in and never destructive ones. Bounded ≤8
ops × low-priv identities. Operator-supplied identities only. Returned data redacted in evidence.
