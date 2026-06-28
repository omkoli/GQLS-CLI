# GQL-M05 — Suggestion-Based Schema (SDL) Reconstruction

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P1 |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `misconfig`, `info-disclosure`, `clairvoyance`, `schema`, `artifact` |
| **Category** | `InformationDisclosure` |
| **Depends on** | — (consumes `pkg/schema/harvester.go`) |
| **Files** | `pkg/scanner/checks/gqlm05_sdl_reconstruction.go` (+ `_test.go`) |

## Summary
gqls already **harvests** schema fields from "Did you mean …" field suggestions when introspection is disabled
(`pkg/schema/harvester.go`) — but it does not *report the reconstructed schema as a finding/artifact*. GQL-M05
turns that harvested schema into an explicit MEDIUM finding with a **reconstructed SDL artifact**, proving that
disabling introspection did not actually hide the schema (the clairvoyance technique).

## Why it matters
- Teams disable introspection believing the schema is now secret. Field suggestions leak it anyway. Showing
  the operator the **reconstructed SDL** is a high-impact, concrete demonstration that the control is
  ineffective — and a genuine differentiator (few CLIs do this).

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. Reuse the existing harvester: when introspection is off
but suggestions are on, the extractor already builds a partial `schema.Schema`. M05 renders that
`schema.Schema` to SDL text and reports it. Only fire when introspection was **unavailable** but a non-trivial
schema was harvested — otherwise GQL-001/003 cover it.)

- `ID()="GQL-M05"`, `Name()="Schema Reconstructed via Field Suggestions"`,
  `Category()=InformationDisclosure`, `Severity()=MEDIUM`, `RequiresSchema()=false` (reads `cc.Schema` /
  extraction metadata directly).

## Detection algorithm
1. Read `cc.Schema` and its `Metadata` (`ExtractionMethod`, `IntrospectionEnabled`, `SuggestionsEnabled`).
   Proceed only when `IntrospectionEnabled == false` **and** the schema was obtained via
   `MethodFieldSuggestion`/`MethodPartial` with a non-trivial number of recovered types/fields (e.g. ≥ 5
   fields). Else `Skip`/PassReason.
2. Render the harvested `schema.Schema` to **SDL** (`renderSDL(s) string`): type/field/arg declarations for
   every recovered type, marking partially-recovered types/fields with a comment (`# partial`). Keep it
   bounded (cap types/fields rendered; note truncation).
3. Emit a MEDIUM finding whose Description includes the reconstruction stats (N types, M fields recovered) and
   the SDL artifact (bounded; for very large schemas, include a head + a note).

## Finding content
- **Title:** `Schema Reconstructed via Field Suggestions (introspection disabled but schema still exposed)`
- **Description:** that introspection is disabled yet the schema was reconstructed from suggestions; the
  recovery stats; and the reconstructed SDL (bounded). Note this is the clairvoyance technique.
- **Impact:** attackers can map the full attack surface (types, fields, arguments) despite introspection being
  disabled, enabling targeted authz/injection/business-logic attacks.
- **Remediation:** disable field/"Did you mean" suggestions in production (`graphql-js` validation rules /
  engine flag), in addition to introspection; treat schema confidentiality as defense-in-depth, not a control.
- **References:** `https://github.com/nikitastupin/clairvoyance`,
  `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`.
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-200"`. **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M05", cc.Target, "sdl_reconstruction")`.

## Acceptance criteria
- **Given** an extraction where introspection is off and the harvester recovered ≥5 fields, M05 fires a MEDIUM
  finding whose Description contains valid-looking SDL for the recovered types.
- **Given** introspection enabled (schema via introspection), M05 Skips (GQL-001 covers it).
- **Given** suggestions off and no harvested schema, M05 Skips/PassReason.
- The SDL renderer is bounded (does not dump an unbounded artifact) and never panics on partial types.

## Tests (`gqlm05_sdl_reconstruction_test.go`)
- Construct a `schema.Schema` with `Metadata{IntrospectionEnabled:false, ExtractionMethod:MethodFieldSuggestion}`
  and several recovered types → finding with SDL containing those types.
- Introspection-enabled metadata → Skip. Empty/trivial harvest → Skip.
- Assert MEDIUM severity, SDL present, truncation note when over the cap.

## Safety
Read-only (consumes already-extracted data). The SDL is the schema shape (not data); bounded to avoid
unbounded artifacts. No request beyond what extraction already performed.
