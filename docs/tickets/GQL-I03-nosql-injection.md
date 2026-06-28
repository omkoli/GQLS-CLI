# GQL-I03 — NoSQL (MongoDB Operator) Injection

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P1 |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `injection`, `nosql`, `mongodb`, `cwe-943`, `differential` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (injection points + differential oracle) |
| **Files** | `pkg/scanner/checks/gqli03_nosql_injection.go` (+ `_test.go`) |

## Summary
Detect **NoSQL (MongoDB) operator injection**: when a GraphQL argument that maps to a document field is fed an
operator object (`{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`) or a `$where` JavaScript expression and
the result set changes, the input is reaching a Mongo query unsanitized.

## Why it matters
- Mongo operator injection (CWE-943) enables authentication bypass (`password: {$ne: null}`), blind data
  exfiltration via `$regex`, and (with `$where`) server-side JS execution. GraphQL APIs over Mongo are common
  and frequently vulnerable because operator objects pass through JSON inputs.

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. Consume `inject.Points`, `inject.Send`,
`inject.BodyEquivalent`, `authz.Classify`. The injection here is **structural** — replace a scalar arg's value
with an *operator object* via a variable typed as the input's JSON type, or via an input field that accepts an
object/`JSON` scalar. Gate mutation points behind `cc.AllowMutations`.)

- `ID()="GQL-I03"`, `Name()="NoSQL (MongoDB) Operator Injection"`, `Category()=Injection`,
  `Severity()=CRITICAL`, `RequiresSchema()=true`. Richer when GQL-M01 fingerprints a Mongo-backed engine.

## Detection algorithm
1. Enumerate injection points. Prioritize points whose scalar type is a custom `JSON`/`Object` scalar or whose
   input-object field accepts arbitrary objects (these accept operator injection directly). For plain String
   fields, also try string-encoded operators (`[$ne]=`, `{"$ne":null}` as a string) for body-parser quirks.
2. For each point send:
   - **control**: a benign value that returns a known (possibly empty) result.
   - **operator-true**: `{"$ne": "gqls-nonexistent-<rand>"}` (matches everything) — expect a *superset* result.
   - **operator-false**: `{"$gt": "￿"}` or `{"$in": []}` (matches nothing) — expect an *empty* result.
   - (optional, engine-gated) **`$where`** read-only probe: `{"$where":"return true"}` vs
     `{"$where":"return false"}` — never a `$where` with side effects.
   Increment `ProbeCount` each.
3. **Decide — flag CRITICAL when** the operator-true response returns *more/other* rows than control while
   operator-false returns *fewer/empty*, tracking the operator semantics (differential, re-tested once).
   Confidence `"confirmed"`. Auth-bypass variant: when the point is a credential-like field (`password`,
   `token`), an operator-true that yields `ClassSuccess` where control was denied is a confirmed bypass.
   - Negative/inconclusive: identical responses, validation errors → not flagged.

## Finding content
- **Title:** `NoSQL Operator Injection — <rootField> arg <path>`
- **Description:** the point, the operator payloads, the differential result (true=superset / false=empty),
  and whether an auth-bypass variant succeeded. Redact returned data.
- **Impact:** authentication bypass, blind data exfiltration, and (via `$where`) server-side JavaScript
  execution against the database.
- **Remediation:** reject operator objects from user-controlled inputs; cast/validate inputs to expected
  scalar types before building queries; disable `$where`; use an ODM with strict schemas; never pass raw JSON
  arguments into Mongo query objects.
- **References:** `https://owasp.org/www-community/Injection_Flaws`,
  `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/943.html`.
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-943"`. **OWASP:** injection / `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-I03", cc.Target, "nosqli:"+rootField+"/"+pathKey)`.

## Acceptance criteria
- **Given** a server that returns all rows for `{$ne:...}` and none for `{$in:[]}`, one CRITICAL finding fires.
- **Given** a server that treats inputs as plain strings (no operator effect), no finding.
- **Given** a credential field where `{$ne:null}` logs in while a wrong password is denied, a confirmed
  auth-bypass finding fires.
- Mutation points gated; malformed responses never panic.

## Tests (`gqli03_nosql_injection_test.go`)
- `httptest` handler that decodes the variable and applies `$ne`/`$in` semantics over a fixed dataset →
  finding. Handler that ignores operators → no finding. Credential-bypass handler → confirmed finding.
- Assert severity CRITICAL, category Injection, fingerprint, deterministic ordering.

## Safety
Read-only operator payloads only (`$ne`/`$gt`/`$in`/`$regex` matching, `$where:"return true/false"`); never
operators that write or run side-effecting JS. Bounded; mutation points gated; data redacted.
