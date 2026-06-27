# GQL-A01 — BOLA / IDOR (Broken Object Level Authorization)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P0 (Highest) |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `authz`, `bola`, `idor`, `owasp-api1`, `cwe-639`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | **GQL-A00** (identities, oracle, surface graph) |
| **Files** | `pkg/scanner/checks/gqla01_bola_idor.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A01** that detects **Broken Object Level Authorization** (a.k.a. IDOR): an object that
belongs to identity A (the *owner*) is returned to identity B (a lower-privilege *attacker*) when B requests
it by ID. This is the #1 GraphQL bug class and the single most valuable check in the scanner.

The check is **differential**: it fetches the same object as two identities and flags when the under-privileged
identity receives the *owner's* object data instead of an authorization denial.

## Why it matters
- BOLA/IDOR is OWASP **API1:2023** and the most frequently exploited, highest-paying GraphQL bug-bounty class
  (`SECURITY_PLATFORM_ANALYSIS.md` §2.1, §3.4). Maps to **CWE-639**.
- It is structurally invisible to the current engine: you cannot detect it with one identity. GQL-A00 makes
  it possible; this check is the first payoff.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` → Shared Engineering Context + Shared SAFETY & ETHICS. Consume GQL-A00 primitives:
`cc.Identities`, `cc.IdentityPairs()`, `surface.Fetchers(cc.Schema)`, `surface.ExampleValue`,
`authz.Classify`, `authz.Compare`.)

- `ID()="GQL-A01"`, `Name()="Broken Object Level Authorization (BOLA/IDOR)"`,
  `Category()=Authorization`, `Severity()=CRITICAL`, `RequiresSchema()=true`.
- **Read-only.** This check sends **queries only**, never mutations.

## Detection algorithm
1. **Preconditions.** If `!cc.HasIdentities()` → `Skip` with `SkipReason` ("BOLA testing requires ≥2 operator-
   supplied identities; configure them via --identity / gqls.yaml"). If schema is nil → already skipped by
   `RequiresSchema()`.
2. **Enumerate object fetchers.** `fetchers := surface.Fetchers(cc.Schema)` — root query fields that take an
   id-like arg and return an object (e.g. `user(id:)`, `order(id:)`, `node(id:)`, `account(id:)`). Cap to the
   first **N=5** fetchers by name for budget (disclose the cap in PassReason).
3. **Discover an owner object id per fetcher (seed phase).** For the highest-privilege identity in a pair
   (the *owner*), the operator should ideally supply known object ids. Two id sources, in priority order:
   - **Operator-provided seeds** (GQL-A00 may allow `--authz-seed 'user.id=42'`); else
   - **Self-discovery:** issue a "me"/"viewer"/list query as the owner to learn an id the owner legitimately
     owns (e.g. `{ me { id } }`, or `{ <fetcher>s(first:1){ id } }`). If no id can be obtained for a fetcher,
     skip *that fetcher* and record why; do not fabricate ids.
4. **Differential probe (per fetcher, per identity pair).** For each `(owner, attacker)` from
   `cc.IdentityPairs()`:
   - Build the operation `query { <field>(<idArg>: <ownerObjId>) { id <one or two non-sensitive scalars> } }`
     using `surface.ExampleValue` only for any *other* required args.
   - Send it **as owner** (`owner.Client.Do`) → `ownerResp`; **as attacker** (`attacker.Client.Do`) →
     `attackerResp`. Increment `ProbeCount` for each.
5. **Decide via the oracle.** `diff := authz.Compare(ownerResp, attackerResp, "data."+field+".id")`.
   **Flag CRITICAL when** `diff.OwnerClass == ClassSuccess` **and** `diff.AttackerClass == ClassSuccess`
   **and** `diff.SameObject == true` (the attacker received the *owner's* object id, not their own and not a
   denial). Confidence = `"confirmed"`.
   - **Negative (protected):** `attacker` got `ClassAuthDenied`, or `ClassNotFound`, or a *different* id
     (their own object) → not vulnerable for this pair.
   - **Inconclusive:** validation error / 5xx / rate-limit / null-without-error → record, never flag.
6. **First confirmed leak wins per fetcher** (one finding per vulnerable fetcher; don't spam every pair).
   When no fetcher leaks, set `PassReason` summarizing pairs/fetchers tested and record `PassProbes`.

## Finding content (when fired)
- **Title:** `Broken Object Level Authorization — <field>(<idArg>) returns another user's object`
- **Description:** state that identity `<attacker.Name>` retrieved the object owned by `<owner.Name>` via
  `<field>(<idArg>: <id>)`, that both responses returned the **same object id**, and include a **redacted**
  preview of the leaked fields (`authz.RedactLeak`). Never embed raw PII/tokens.
- **Impact:** any authenticated (or lower-privileged) user can read arbitrary objects belonging to other users
  by manipulating the object ID — mass data exposure, privacy breach, account/data enumeration.
- **Remediation:** enforce object-level authorization in the resolver/data layer for *every* object fetch
  (verify the requesting principal owns or may access the object); do not rely on unguessable IDs; apply
  centralized policy (e.g. row-level security, an authorization middleware, `@auth` rules scoped to the
  current principal). Test with the global-id/`node` interface too.
- **References:**
  - `https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://cwe.mitre.org/data/definitions/639.html`
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-639"`. **OWASP:** `"API1:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A01", cc.Target, "bola:"+field)`.
- **ReproRequest / ReproBody:** the attacker-identity request and its JSON body (with the attacker's headers
  redacted by the reporter as usual).

## Acceptance criteria
- **Given** two identities and a server where `user(id:)` returns the same object regardless of caller, **when**
  GQL-A01 runs, **then** exactly one CRITICAL finding fires for `user`, with `SameObject` proven, redacted
  evidence, `Confidence="confirmed"`, `CWE`/`OWASP` set, and `ProbeCount >= 2`.
- **Given** a server that returns 403 / an `UNAUTHENTICATED` error to the attacker identity, **then** no
  finding and `PassReason` notes that object authz appears enforced (record both probes in `PassProbes`).
- **Given** a server that returns the attacker's *own* (different) object for the same query, **then** no
  finding (`SameObject == false`).
- **Given** no identities configured, **then** the check is `Skipped` with a clear `SkipReason` (not an error).
- **Given** a fetcher whose owner-id cannot be discovered, **then** that fetcher is skipped and the rest still
  run; no panic on malformed/empty responses.

## Tests (`gqla01_bola_idor_test.go`)
- `httptest.NewServer` keyed on the request's `Authorization` header to simulate identities: handler returns
  the **same** `{"data":{"user":{"id":"42","email":"..."}}}` for both an "owner" and an "attacker" token →
  expect CRITICAL finding; assert evidence is redacted (no raw email substring).
- Handler returning `{"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}` for the attacker
  token → expect no finding + PassReason.
- Handler returning a *different* id for the attacker token → no finding.
- No-identity context → `result.Skipped == true`.
- Assert `Fingerprint` non-empty, `Severity == CRITICAL`, `Category == Authorization`, deterministic fetcher
  ordering.

## Safety & Ethics
Queries only (no writes). Bounded: ≤ N=5 fetchers × pairs, ≤ ~8 probes total typically. Only operator-supplied
identities are used. Leaked values are **redacted** in evidence. The positive signal is a read-only comparison,
never a modification.
