# GQL-A05 — Mutation-Side Authorization (Non-Owner Write / Delete)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P1 (High) |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `authz`, `mutation-authz`, `owasp-api5`, `cwe-285`, `write-gated`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | **GQL-A00** (identities, oracle, surface graph, `AllowAuthzMutations` flag) |
| **Files** | `pkg/scanner/checks/gqla05_mutation_authz.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A05** that detects **mutation-side broken object authorization**: a **non-owner**
identity can *update* or *delete* an object belonging to another identity. Where A01 proves a *read* leak,
A05 proves a *write* — the higher-impact half of object authorization.

⚠️ This is the only check in the epic that performs **state-changing requests**, so it is **disabled by
default** and gated behind the explicit `--authz-allow-mutations` opt-in from GQL-A00.

## Why it matters
- Mutation authz bypass is OWASP **API5:2023** / **CWE-285** and the difference between "an attacker can read
  my data" and "an attacker can change/delete my data" — account takeover, data destruction, fraud
  (`SECURITY_PLATFORM_ANALYSIS.md` §2.1 GQL-A05, §3.4 "Mutation authz bypass").

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + **SAFETY & ETHICS** — this ticket leans hardest on them. Consume
GQL-A00: `cc.Identities`, `cc.IdentityPairs()`, `surface.PrivilegedOps`, `surface.ExampleValue`,
`authz.Classify`. Read `cfg.AllowAuthzMutations` through context — expose it on `CheckContext` in GQL-A00,
e.g. `cc.AllowMutations bool`.)

- `ID()="GQL-A05"`, `Name()="Mutation-Side Authorization (Non-Owner Write/Delete)"`,
  `Category()=Authorization`, `Severity()=CRITICAL`, `RequiresSchema()=true`.

## Detection algorithm
1. **Hard gate.** If `!cc.AllowMutations` → `Skip` with `SkipReason` ("GQL-A05 performs state-changing
   requests and is disabled by default; re-run with --authz-allow-mutations after confirming you have written
   authorization to test this target"). If `!cc.HasIdentities()` → `Skip`.
2. **Select safe, reversible mutations.** From `surface.PrivilegedOps(cc.Schema)` (mutation side), keep only
   **update-style** mutations that operate on an object by id and that are **non-destructive**:
   - **Exclude** any mutation whose name matches `(?i)delete|remove|destroy|purge|wipe|drop|cancel|revoke`
     unless the operator explicitly allow-lists it (GQL-A00 `--authz-allow-mutation <name>` repeatable).
   - Prefer mutations that set an **innocuous, self-reverting field** (e.g. a display name/label/description)
     and capture the original value first so the test can **restore** it (best-effort).
   Cap to **N=3** mutations (writes are expensive and risky). Disclose the cap.
3. **Establish ownership.** Identify an object owned by the **owner** identity (viewer/me or seeded id). The
   *attacker* is a different, lower/peer-privilege identity who should **not** be able to mutate it.
4. **Capture-modify-verify-restore (per mutation, owner-object, attacker identity):**
   - **Capture:** as the owner, read the current value of the field the mutation will change. `ProbeCount++`.
   - **Attempt write as attacker:** send the update mutation **as the attacker identity**, targeting the
     owner's object id, setting the field to a unique benign sentinel (e.g. `"gqls-authz-probe-<rand>"`).
     `ProbeCount++`. `cls := authz.Classify(resp)`.
   - **Verify:** as the **owner**, re-read the field. `ProbeCount++`. If it now equals the attacker's sentinel,
     the unauthorized write **succeeded** (definitive proof).
   - **Restore:** as the owner, write the captured original value back (best-effort; never leave the sentinel).
     `ProbeCount++`. Record restore success/failure in the finding (operator must know if cleanup failed).
5. **Decide.** **Flag CRITICAL when** the verify step confirms the attacker's sentinel persisted on the
   owner's object (Confidence `"confirmed"`). A 200/`data` on the write *without* verification is only
   `"firm"` (some servers echo success without applying) — prefer the verify-based confirmed signal.
   - **Negative:** attacker write returns `ClassAuthDenied`, or verify shows the value unchanged → protected.
   - **Inconclusive:** validation/5xx/rate-limit, or capture/verify could not run → never flag; record.

## Finding content (when fired)
- **Title:** `Mutation-Side Authorization Bypass — <attacker.Name> modified <owner.Name>'s object via <mutation>`
- **Description:** name the mutation, the owner object id, the field changed, that an owner re-read **confirmed**
  the attacker's value persisted, and whether automatic restore succeeded. Redact any sensitive values.
- **Impact:** an unauthorized user can modify (or, where allow-listed, delete) objects they do not own — data
  tampering, account takeover, fraud, and destruction of other users' data.
- **Remediation:** enforce object-level authorization on **write** resolvers (verify the principal owns/may
  mutate the target before applying changes); never authorize writes by object existence alone; centralize
  ownership checks; add mutation authz to tests.
- **References:**
  - `https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://cwe.mitre.org/data/definitions/285.html`
- **Confidence:** `"confirmed"` (verified persistence) or `"firm"` (write accepted, unverified). **CWE:**
  `"CWE-285"`. **OWASP:** `"API5:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A05", cc.Target, "mutauthz:"+mutation)`.
- **ReproRequest / ReproBody:** the attacker write request and body.

## Acceptance criteria
- **Given** `--authz-allow-mutations` and a server where an attacker token can `updateProfile(id: <owner>)`
  and an owner re-read shows the sentinel, **then** one CRITICAL finding fires (Confidence `"confirmed"`),
  and a restore attempt is made.
- **Given** the attacker write returns 403/`FORBIDDEN`, **then** no finding + PassReason.
- **Given** `AllowMutations=false` (default), **then** the check is `Skipped` and **no write request is sent**
  (assert the test server received zero mutations).
- **Given** a destructive-named mutation not on the allow-list, **then** it is never invoked.
- **Given** no identities, **then** `Skipped`. Restore failure is surfaced in the finding, never silently
  dropped. No panic on malformed responses.

## Tests (`gqla05_mutation_authz_test.go`)
- `httptest.NewServer` with in-memory object state keyed by id; attacker token mutates owner's object;
  owner re-read returns the sentinel → CRITICAL; assert restore call observed.
- Server that rejects the attacker mutation (403) → no finding.
- `AllowMutations=false` → `Skipped`, assert **no** mutation hit the server.
- Destructive-named mutation present, not allow-listed → never sent.
- No identities → `Skipped`. Assert severity/category/fingerprint/ProbeCount.

## Safety & Ethics
**Highest-risk check in the epic.** Mandatory guardrails: disabled by default (explicit opt-in only);
non-destructive mutations only (destructive names require per-name allow-list); capture-and-restore the
original value; unique benign sentinels; bounded to N=3 mutations; operator-supplied identities only;
restore-failure is reported so the operator can clean up manually. The check must **never** target
`delete/purge/wipe/drop` without explicit allow-listing, and must prefer reversible, idempotent writes.
