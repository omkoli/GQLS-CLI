# GQL-M09 — Schema Description / Default-Value Secret & Deprecation Leakage

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P3 |
| **Severity (of finding)** | LOW |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `misconfig`, `info-disclosure`, `schema`, `secrets`, `deprecation` |
| **Category** | `InformationDisclosure` |
| **Depends on** | — (extends GQL-006 sensitive fields; reuses `pkg/schema/sensitivity.go`) |
| **Files** | `pkg/scanner/checks/gqlm09_description_secret_leakage.go` (+ `_test.go`) |

## Summary
Scan the schema's **descriptions**, **deprecation reasons**, and **argument default values** for leaked
secrets and internal hints — credentials/tokens/URLs embedded in `description` text, internal endpoints or
"TODO/remove in prod" notes in `deprecationReason`, and secret-looking literals in `ArgDef.DefaultValue`.
GQL-006 flags sensitive *field names*; M09 covers the free-text and default-value channels GQL-006 misses.

## Why it matters
- Developers routinely paste example tokens, internal URLs, and "do not expose" notes into GraphQL
  descriptions and default values. These ship to anyone who can read the schema (introspection or M05
  reconstruction) and are a quiet but real secret-disclosure channel.

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. `RequiresSchema()=true`. Walk `cc.Schema` types/fields/
args; inspect `TypeDef.Description`, `FieldDef.Description`, `FieldDef.DeprecationReason`,
`ArgDef.DefaultValue`, `ArgDef.Description`. Reuse `schema.SensitiveTagsFor(name)` for sensitivity scoring and
add secret-literal regexes. **Redact** any matched secret value in output.)

- `ID()="GQL-M09"`, `Name()="Secrets/Hints Leaked in Schema Descriptions & Defaults"`,
  `Category()=InformationDisclosure`, `Severity()=LOW`, `RequiresSchema()=true`.

## Detection algorithm
1. Walk all types/fields/args. For each `Description`/`DeprecationReason`/`DefaultValue` string, match against:
   - **secret literals**: high-entropy tokens, `AKIA[0-9A-Z]{16}` (AWS), `ghp_`/`xox[baprs]-` (GitHub/Slack),
     `Bearer <jwt>`, `password=`/`api_key=`/`secret=` assignments, private-key headers
     (`-----BEGIN … PRIVATE KEY-----`), and connection strings (`mongodb://user:pass@`, `postgres://…`).
   - **internal hints**: internal hostnames/IPs (RFC1918, `.internal`, `.local`), `TODO`/`FIXME`/`remove in
     prod`/`do not expose`/`internal only`.
2. Also flag **default values** that are secret-looking literals (`ArgDef.DefaultValue` containing a token/URL
   with credentials).
3. **Decide — flag LOW when** ≥1 secret/internal-hint match is found. (Raise to MEDIUM when a concrete
   credential/private-key/connection-string with credentials is matched.) List each location
   (`Type.field` / `Type.field(arg)` / `Type` description). Confidence `"firm"` (regex-based).
   - Negative: no matches → no finding.

## Finding content
- **Title:** `Secrets/Internal Hints in Schema Descriptions or Defaults — <N locations>`
- **Description:** each location and the **class** of match (credential / connection-string / internal-host /
  "remove in prod"), with the value **redacted** (`authz.MaskValue`) — report the location and class, never
  the raw secret.
- **Impact:** leaked credentials/connection strings enable direct compromise; internal hints and endpoints aid
  reconnaissance and pivoting; "remove in prod" notes reveal unfinished controls.
- **Remediation:** keep secrets and internal notes out of schema descriptions, deprecation reasons, and
  default values; lint the schema in CI for secret patterns; rotate any exposed credential immediately.
- **References:** `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`,
  `https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/`.
- **Confidence:** `"firm"`. **CWE:** `"CWE-200"`/`"CWE-540"`. **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M09", cc.Target, "schema_secrets:"+sortedLocations)`.

## Acceptance criteria
- **Given** a schema with a field whose description contains an AWS key or `mongodb://user:pass@host`, M09
  fires (MEDIUM for the concrete credential) with the value **redacted** in output.
- **Given** a `deprecationReason` like "internal only — remove before prod", a LOW finding fires.
- **Given** a clean schema, no finding. Raw secrets never appear in the rendered finding (asserted).

## Tests (`gqlm09_description_secret_leakage_test.go`)
- Fixture schema with a credential in a description and a "remove in prod" deprecation reason → finding;
  assert the raw secret substring is absent from the finding text (redaction). Clean schema → no finding.
- Default-value secret → finding. Assert locations + classes listed, severity mapping.

## Safety
Read-only schema analysis (no requests beyond extraction). Matched secrets are **redacted** in all output —
report the location and class only.
