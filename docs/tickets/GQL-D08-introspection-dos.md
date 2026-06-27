# GQL-D08 — Introspection-as-DoS (Recursive Type Size Amplification)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P3 (Low) |
| **Severity (of finding)** | LOW |
| **Story points** | 2 |
| **Complexity** | Low |
| **Labels** | `dos`, `introspection`, `owasp-api4`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld08_introspection_dos.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D08** that detects whether the **introspection system itself** can be used as an
amplification vector. A single bounded-but-recursive introspection query (deeply nested `ofType`/`fields`
chains, or repeated type fragments) can force the server to serialize a very large schema response. When
introspection is enabled in production *and* unbounded, attackers get a cheap, unauthenticated amplification
and reconnaissance primitive in one request.

## Why it matters
- Pairs with GQL-001 (introspection enabled): even where exposure is "accepted", an *unbounded* introspection
  response is a measurable amplification + bandwidth-exhaustion vector.
- Cheap to add — can partly reuse data already gathered by the schema extractor
  (`schema.ExtractionMetadata.RawResponseSize`, `ProbeCount`) in `pkg/schema/extractor.go`.
- Maps to **OWASP API4:2023** and GraphQL Cheat Sheet (disable/limit introspection in prod).

## Engineering Context
(See `EPIC-GQL-DOS.md` shared context + safety. Implement `checks.Check`, register in `init()`, probe via
`cc.ProbeClient()`, fingerprint key `"introspection_dos"`.)

- `ID()="GQL-D08"`, `Name()="Unbounded Introspection Amplification"`, `Category()=DenialOfService`,
  `Severity()=LOW`, `RequiresSchema()=false`.
- **Skip cleanly if introspection is disabled.** If `cc.Schema != nil` and
  `cc.Schema.Metadata.IntrospectionEnabled == false`, set `PassReason` ("introspection disabled — not
  applicable") and return. If schema is nil, do a quick `{ __schema { queryType { name } } }` liveness probe
  and bail to PassReason if it errors.

## Detection algorithm
1. **Baseline introspection probe:** send the minimal `{ __schema { queryType { name } } }`. Record response
   bytes `Sb` and latency `Lb`. If introspection is rejected → PassReason ("introspection disabled"), return.
2. **Amplified introspection probe (bounded):** send a recursive type-reference query that nests the
   `ofType { ... }` chain to a fixed bounded depth (e.g. the standard ~7-level `TypeRef` fragment used in
   `schema.FullIntrospectionQuery`) combined with `fields { type { ofType ... } }` cycles — but **capped**:
   total nesting ≤ 8 levels, single request. Record response bytes `Sa` and latency `La`.
3. **Decision — flag LOW when** introspection is enabled **and** the amplified response is large/amplifying:
   `Sa >= 1_000_000` bytes (≈1 MB) **or** `Sa >= 20 * Sb` **or** (`La >= 10 * Lb` and `La >= 1000ms`).
   The thresholds are constants; tune via tests.
4. Otherwise `PassReason = "Introspection response size/latency stayed within safe bounds (introspection is
   either disabled or bounded)."` with both probes recorded in `PassProbes`.

## Finding content (when fired)
- **Title:** `Unbounded Introspection Response (Amplification + Recon)`
- **Description:** report baseline vs amplified response sizes (`Sb` → `Sa`) and latency, and that
  introspection is enabled in this environment.
- **Impact:** a single unauthenticated request yields a large response — bandwidth/CPU amplification plus full
  schema disclosure for attack planning; repeated requests are a low-cost availability and egress-cost attack.
- **Remediation:** disable introspection in production (primary control); if it must stay enabled, apply
  response-size/complexity limits to introspection queries and rate-limit them; restrict introspection to
  authenticated internal users.
- **References:**
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://spec.graphql.org/October2021/#sec-Introspection`
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
- **Fingerprint:** `GenerateFingerprint("GQL-D08", cc.Target, "introspection_dos")`

## Acceptance criteria
- **Given** a server with introspection enabled returning a >1 MB (or ≥20× baseline) introspection response,
  **then** one LOW finding fires carrying both sizes.
- **Given** a server with introspection disabled, **then** no finding + PassReason ("not applicable").
- **Given** introspection enabled but a small bounded response, **then** no finding + PassReason.
- `ProbeCount >= 1`, fingerprint non-empty, severity LOW. Reuses `cc.Schema.Metadata` when available without
  re-deriving it incorrectly.

## Tests (`gqld08_introspection_dos_test.go`)
- Handler returning a large (>1 MB) body for the recursive introspection query and a small one for the
  baseline → finding.
- Handler returning an introspection-disabled error → no finding + PassReason.
- Handler with small bounded introspection responses → no finding.
- Verify the disabled-via-metadata short-circuit when `cc.Schema.Metadata.IntrospectionEnabled == false`.

## Safety
Single bounded amplified probe (nesting ≤ 8, one request) plus a tiny baseline. Detect amplification by
measuring response size/latency; never loop or escalate nesting.
