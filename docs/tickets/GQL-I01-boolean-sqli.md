# GQL-I01 — Boolean-Based SQL Injection (Differential)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P1 |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `injection`, `sqli`, `boolean`, `cwe-89`, `differential` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (injection points + differential oracle) |
| **Files** | `pkg/scanner/checks/gqli01_boolean_sqli.go` (+ `_test.go`) |

## Summary
Detect **boolean-based SQL injection** by injecting a logically-true and a logically-false predicate at each
injection point and flagging when the two responses diverge in a way that tracks the predicate — proving the
input reaches a SQL `WHERE` clause. This is the "confirmed" oracle the naive error-based GQL-011 lacks.

## Why it matters
- Boolean SQLi (CWE-89) is exploitable even when error messages are suppressed. It is the highest-confidence
  in-band SQLi signal and the foundation of blind data exfiltration.

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. Consume `inject.Points(cc.Schema)`,
`inject.Send`, `inject.BodyEquivalent`, `authz.Classify`. Use `cc.HTTPClient`. Gate mutation points behind
`cc.AllowMutations`.)

- `ID()="GQL-I01"`, `Name()="Boolean-Based SQL Injection"`, `Category()=Injection`, `Severity()=CRITICAL`,
  `RequiresSchema()=true`.

## Detection algorithm
1. Enumerate injection points (cap ≤ 25; query points first, mutation points only if `cc.AllowMutations`).
   Restrict to String/ID/Int scalar leaves.
2. For each point, send three probes (all read-only, non-destructive):
   - **control**: the benign baseline value (e.g. `inject.ExampleValue`).
   - **true** payload: append a tautology, e.g. `' AND '1'='1` / `") OR (1=1`/`1 AND 1=1` (numeric variant).
   - **false** payload: append a contradiction, e.g. `' AND '1'='2` / `") OR (1=2`/`1 AND 1=2`.
   Increment `ProbeCount` each.
3. **Decide — flag CRITICAL when** `true` response is *equivalent to control* (or `ClassSuccess` with data)
   **and** `false` response *differs* (fewer/zero rows, different `data`, or NotFound/Empty) — i.e. the
   predicate changed the result set. Require the divergence to be **consistent** (re-test the pair once to
   rule out flakiness). Confidence `"confirmed"`.
   - Negative: true and false responses are identical (input did not reach SQL) → not vulnerable.
   - Inconclusive: validation errors / 5xx / rate-limit → record, never flag.

## Finding content
- **Title:** `Boolean-Based SQL Injection — <rootField> arg <path>`
- **Description:** the injection point path, that a true predicate matched the baseline while a false predicate
  changed the result set, with the (redacted) payloads. Note the syntax family that worked.
- **Impact:** blind extraction of arbitrary database contents; authentication bypass; full data compromise.
- **Remediation:** use parameterized queries / prepared statements; never concatenate GraphQL argument values
  into SQL; validate and type-check inputs; apply least-privilege DB accounts.
- **References:** `https://owasp.org/www-community/attacks/Blind_SQL_Injection`,
  `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/89.html`.
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-89"`. **OWASP:** `"API8:2023"` (or note as injection class).
- **Fingerprint:** `GenerateFingerprint("GQL-I01", cc.Target, "bool_sqli:"+rootField+"/"+pathKey)`.

## Acceptance criteria
- **Given** a server whose result set shrinks for the false predicate but matches control for the true one,
  one CRITICAL finding fires (confirmed) with `ProbeCount >= 3` and the payloads redacted.
- **Given** a server that returns identical responses regardless of the predicate, no finding.
- **Given** only mutation injection points and `AllowMutations=false`, those points are skipped (PassReason
  notes write-gating); no finding.
- **Given** no injectable points / no schema, the check is `Skipped` or PassReason set; malformed responses
  never panic.

## Tests (`gqli01_boolean_sqli_test.go`)
- `httptest` handler that parses the injected variable and returns N rows for `1=1` and 0 rows for `1=2`
  → CRITICAL finding.
- Handler insensitive to the predicate → no finding.
- Mutation-only schema + `AllowMutations=false` → no probe to mutation points; PassReason mentions write-gating.
- Assert severity CRITICAL, category Injection, fingerprint set, deterministic point ordering.

## Safety
Read-only boolean predicates only (no stacked statements, no writes). Bounded points/payloads. Mutation points
gated. Payloads redacted in evidence.
