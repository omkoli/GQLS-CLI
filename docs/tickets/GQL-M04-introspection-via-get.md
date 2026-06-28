# GQL-M04 — Introspection via GET / Alternative Content-Types

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P1 |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `misconfig`, `introspection`, `bypass`, `portswigger` |
| **Category** | `InformationDisclosure` |
| **Depends on** | — (extends GQL-001/002 introspection, GQL-010 GET) |
| **Files** | `pkg/scanner/checks/gqlm04_introspection_via_get.go` (+ `_test.go`) |

## Summary
When POST introspection is **blocked**, the schema is often still reachable via **alternative transports**:
`GET ?query=...`, `POST text/plain`, form-encoded bodies, or introspection-defense bypasses (whitespace/
newline/comment after `__schema`, batched introspection). GQL-M04 retries introspection over these vectors and
flags when any one succeeds where the canonical POST is denied.

## Why it matters
- A server that disables POST introspection but answers `GET ?query={__schema{...}}` has not actually
  protected its schema. PortSwigger's GraphQL Academy highlights both GET-introspection and whitespace bypass
  (`__schema` followed by `\n`) as standard recon moves.

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. Reuse the GET builder from `gql010_get.go` and the
introspection document from `gql001`/`gql002`. Use `cc.ProbeClient()`. Only fire when the canonical POST
introspection is **denied** — otherwise GQL-001 already reports it and this would be a duplicate.)

- `ID()="GQL-M04"`, `Name()="Introspection Reachable via Alternative Transport"`,
  `Category()=InformationDisclosure`, `Severity()=MEDIUM`, `RequiresSchema()=false`.

## Detection algorithm
1. **Baseline:** POST `application/json` minimal introspection (`{ __schema { queryType { name } } }`). If it
   **succeeds**, `Skip`/PassReason ("POST introspection already enabled — see GQL-001"). Only proceed when it
   is blocked (no `__schema` data / error).
2. Retry the same introspection over each bypass vector (increment `ProbeCount` each):
   - **GET** `?query=<introspection>` (reuse `gql010` builder).
   - **POST `text/plain`** with the JSON body.
   - **POST form-encoded** `query=<introspection>`.
   - **Whitespace/comment bypass**: `{ __schema\n { queryType { name } } }`, `{ __schema #x\n { … } }`.
   - **Batched introspection**: `[ {"query":"{__schema{queryType{name}}}"} ]`.
3. **Decide — flag MEDIUM when** any vector returns a valid `__schema` object while the POST baseline was
   denied. Confidence `"confirmed"`. List the vector(s) that worked.

## Finding content
- **Title:** `Introspection Bypass — schema reachable via <vector(s)> despite POST being blocked`
- **Description:** the baseline-denied result and which alternative vector(s) returned `__schema`; include the
  accepted request shape.
- **Impact:** the full schema (types, fields, args, deprecations) is exposed to attackers despite the intended
  introspection lock-down, enabling targeted attack-surface mapping.
- **Remediation:** enforce the introspection policy across **all** transports and content-types; disable GET
  for GraphQL; normalize/validate the operation before the introspection gate (defeat whitespace/comment
  bypass); apply the same rule to batched requests.
- **References:** `https://portswigger.net/web-security/graphql`,
  `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`.
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-200"`. **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M04", cc.Target, "introspection_bypass")`.

## Acceptance criteria
- **Given** a server that denies POST introspection but answers `GET ?query={__schema...}`, a MEDIUM finding
  fires naming the GET vector.
- **Given** a server that answers the whitespace-bypass document but not the canonical one, a finding fires.
- **Given** POST introspection already enabled, the check Skips/PassReasons (no duplicate of GQL-001).
- **Given** all vectors blocked, no finding + PassReason.

## Tests (`gqlm04_introspection_via_get_test.go`)
- Handler: POST json introspection → denied; GET introspection → `__schema` → finding (GET vector).
- Handler accepting whitespace-bypass only → finding. Handler enabling POST introspection → Skip.
  All-blocked handler → PassReason. Assert vectors listed, deterministic order.

## Safety
Read-only introspection over alternative transports. Bounded vectors; no schema content dumped raw beyond
confirming `__schema` is reachable (the schema itself is already what GQL-001 governs).
