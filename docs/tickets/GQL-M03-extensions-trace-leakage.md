# GQL-M03 — Trace / `extensions` Leakage Taxonomy

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P1 |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `misconfig`, `info-disclosure`, `extensions`, `tracing`, `owasp-api8` |
| **Category** | `InformationDisclosure` |
| **Depends on** | — (extends GQL-005 stack-trace; complements, does not duplicate) |
| **Files** | `pkg/scanner/checks/gqlm03_extensions_leakage.go` (+ `_test.go`) |

## Summary
Classify and report sensitive data leaked through the GraphQL **`extensions`** block and tracing metadata:
Apollo tracing (`extensions.tracing`), `extensions.exception.stacktrace`, query-plan/cost details, server
timing, SQL/query echoes, and internal codes/paths. GQL-005 flags stack traces in error *messages*; M03 covers
the structured `extensions` channel and builds a leakage **taxonomy** (what class of internal data is exposed).

## Why it matters
- `extensions` is a structured side-channel that production servers frequently leave on. It leaks stack
  traces, resolver timings (aiding timing attacks), backend query text, and internal service topology —
  reconnaissance gold and an OWASP **API8** misconfiguration.

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. Use `cc.ProbeClient()`. Send (a) a normal query and
(b) a deliberately-erroring query to elicit `extensions`. Parse the JSON `extensions` object and classify its
keys. Coordinate with GQL-005 so identical stack-trace-in-message findings are not double-reported — M03 keys
on the `extensions` channel specifically.)

- `ID()="GQL-M03"`, `Name()="Sensitive Data in GraphQL extensions / Tracing"`,
  `Category()=InformationDisclosure`, `Severity()=MEDIUM`, `RequiresSchema()=false`.

## Detection algorithm
1. Probe 1 — valid query (`{ __typename }`); Probe 2 — invalid query / type error to force an error
   `extensions`. Increment `ProbeCount`.
2. Parse `data.extensions` / `errors[].extensions` and classify present keys against a taxonomy:
   - **stacktrace**: `exception.stacktrace`, `stacktrace`, `trace` (array of frames).
   - **tracing/timing**: `tracing`, `executionTime`, `duration`, `startTime`, resolver timings.
   - **query-plan/cost**: `queryPlan`, `cost`, `complexity`, `cacheControl`.
   - **backend echo**: SQL text, internal hostnames, file paths, service names, `code` enums revealing stack.
3. **Decide — flag MEDIUM when** any sensitive class is present (stacktrace/backend-echo are MEDIUM; pure
   timing/cost metadata is LOW — set severity by the most sensitive class found). Confidence `"firm"`.
   - Negative: `extensions` absent or only benign (`code: "GRAPHQL_VALIDATION_FAILED"`) → no finding.

## Finding content
- **Title:** `Sensitive Data Exposed in GraphQL extensions — <classes>`
- **Description:** which extension classes leaked (stacktrace / tracing / query-plan / backend-echo), with a
  **redacted** sample (mask paths, hostnames, SQL values via `authz.MaskValue`). List the offending keys.
- **Impact:** internal stack traces, backend query text, and timing metadata aid targeted exploitation,
  timing attacks, and internal-topology reconnaissance.
- **Remediation:** disable Apollo tracing and `includeStacktraceInErrorResponses` in production; strip
  `extensions` of internal data at the gateway; return generic error codes only.
- **References:** `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`,
  `https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/`.
- **Confidence:** `"firm"`. **CWE:** `"CWE-200"`. **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M03", cc.Target, "extensions:"+sortedClasses)`.

## Acceptance criteria
- **Given** a server returning `errors[].extensions.exception.stacktrace`, a MEDIUM finding fires listing the
  stacktrace class with a redacted sample (no raw file paths in output).
- **Given** only `extensions.tracing` timing, a LOW finding fires (timing class).
- **Given** benign-only `extensions` (validation code), no finding.
- No panic on missing/non-object `extensions`.

## Tests (`gqlm03_extensions_leakage_test.go`)
- Handler returning a stacktrace in `extensions` → MEDIUM finding, assert redaction. Tracing-only → LOW.
  Benign → none. Assert classes listed, fingerprint stable.

## Safety
Read-only probes. Leaked paths/hosts/SQL are **redacted** in evidence — report the class and key names, not
raw secrets.
