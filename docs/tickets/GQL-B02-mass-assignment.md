# GQL-B02 — Mass Assignment via Input Objects

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-BIZLOGIC |
| **Priority** | P1 (start here) |
| **Severity (of finding)** | HIGH |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `business-logic`, `mass-assignment`, `owasp-api3`, `cwe-915`, `write-gated` |
| **Category** | `Authorization` |
| **Depends on** | **GQL-A05** write-gate/cycle, `pkg/schema/surface` input-object walk |
| **Files** | `pkg/scanner/checks/gqlb02_mass_assignment.go` (+ `_test.go`) |

## Summary
Detect **mass assignment**: a mutation input object accepts privilege/state fields the client should not be
able to set (`isAdmin`, `role`, `verified`, `emailVerified`, `balance`, `isActive`, `owner`, `tenantId`), and
the server honors them. The check sends a benign-but-elevating value and verifies (via read-back) that the
field persisted.

## Why it matters
- Mass assignment (OWASP **API3:2023** / CWE-915) is a top GraphQL bug: auto-bound input objects let a normal
  user set `isAdmin: true` or `role: "admin"` on a self-service mutation, achieving privilege escalation.

## Engineering Context
(See `EPIC-GQL-BIZLOGIC.md` shared context + safety. Reuse the GQL-A05 capture→write→verify→restore cycle and
its destructive-name exclusion; reuse `surface` to walk **input-object fields** of mutation arguments. Gate
all writes behind `cc.AllowMutations`. Use `cc.HTTPClient` (the configured identity).)

- `ID()="GQL-B02"`, `Name()="Mass Assignment via Input Objects"`, `Category()=Authorization`,
  `Severity()=HIGH`, `RequiresSchema()=true`.

## Detection algorithm
1. **Hard gate:** `!cc.AllowMutations` → `Skip` (write-gated, like GQL-A05). Else continue.
2. **Find candidates:** mutations (non-destructive name) whose input object(s) contain a **privileged field**
   matching `(?i)^(is_?admin|admin|role|roles|is_?superuser|verified|email_?verified|is_?active|enabled|
   balance|credit|owner|owner_?id|user_?id|tenant_?id|org_?id|permission|scope|status)$` of a settable scalar
   type (Boolean/String/Int/enum). Pair with a read fetcher (GQL-A05 `matchReadFetcher`) that exposes the same
   field for verification. Cap ≤ 3 candidates.
3. **Capture→inject→verify→restore** (per candidate, against an object the configured identity owns):
   - **Capture** the field's current value (read fetcher).
   - **Inject**: call the mutation with the privileged field set to an *elevating-but-safe* sentinel —
     `isAdmin/verified/enabled → true`, `role → "gqls-probe-role"` (a non-existent role, not a real admin
     role, to avoid actually granting admin), `balance → original+0` (no-op numeric to avoid value change but
     still test acceptance) — chosen so detection does not actually escalate real privilege.
   - **Verify** via read-back: did the field change to the injected value (proving the input was honored)?
   - **Restore** the original value (best-effort; report status).
4. **Decide — flag HIGH when** the read-back confirms the privileged field was set by the client input.
   Confidence `"confirmed"` (verified) / `"firm"` (mutation accepted but unverifiable). Negative: the field is
   ignored/rejected (validation error "unknown field", or value unchanged) → no finding.

## Finding content
- **Title:** `Mass Assignment — client can set <field> via <mutation> input`
- **Description:** the mutation, the input path to the privileged field, the injected sentinel, and the
  read-back confirmation; note the original was restored. Use a non-real elevated value so the report does not
  describe actually granting admin.
- **Impact:** privilege escalation and state tampering — a normal user sets admin/role/verified/balance fields
  on themselves or others, leading to account takeover and fraud.
- **Remediation:** never auto-bind client input objects to internal/privileged fields; use explicit input DTOs
  with an allow-list of client-settable fields; enforce server-side authorization for privileged state
  changes; ignore unknown/forbidden input fields.
- **References:** `https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`,
  `https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/915.html`.
- **Confidence:** `"confirmed"`/`"firm"`. **CWE:** `"CWE-915"`. **OWASP:** `"API3:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-B02", cc.Target, "massassign:"+mutation+"."+field)`.

## Acceptance criteria
- **Given** `--authz-allow-mutations` and a server that honors `isAdmin`/`role` in a mutation input (read-back
  shows the change), one HIGH finding fires (confirmed) and the original value is restored.
- **Given** a server that rejects/ignores the privileged input field, no finding.
- **Given** `AllowMutations=false`, the check is `Skipped` and **no write is sent** (assert zero mutations).
- **Given** a destructive-named mutation, it is never invoked. No panic on malformed responses.

## Tests (`gqlb02_mass_assignment_test.go`)
- Stateful `httptest` server with an object whose `isAdmin` can be set via input → finding + restore observed.
- Server ignoring the privileged field → no finding.
- `AllowMutations=false` → Skipped, assert no mutation hit the server.
- Assert HIGH/CWE-915/API3:2023, fingerprint, deterministic ordering.

## Safety
Write-gated (opt-in). Uses **non-real** elevated sentinels (a bogus role, boolean toggles, no-op numerics) so
detection never actually grants admin or moves money; capture→restore reverts every change; destructive
mutations excluded; bounded candidates.
