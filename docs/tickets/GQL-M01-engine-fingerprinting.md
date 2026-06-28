# GQL-M01 — Server Engine Fingerprinting (graphw00f-style)

| Field | Value |
|---|---|
| **Type** | Story (enabler / build first) |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P0 — multiplier for M02 and several injection/error checks |
| **Severity (of finding)** | INFO |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `misconfig`, `fingerprinting`, `graphw00f`, `info` |
| **Category** | `InformationDisclosure` |
| **Files** | **new** `pkg/scanner/fingerprint/fingerprint.go` (+ `_test.go`), `pkg/scanner/checks/gqlm01_engine_fingerprint.go` (+ `_test.go`) |

## Summary
Identify the backing GraphQL engine (Apollo, graphql-ruby, Hasura, HotChocolate, Graphene, gqlgen,
Lighthouse/Lighthouse-PHP, Yoga, Strawberry, Ariadne, Sangria, Dgraph, AWS AppSync, …) by sending a set of
**discriminator probes** and matching engine-specific error wording, feature support, and `__typename`/
introspection quirks — the graphw00f technique. Emits an INFO finding **and** exposes the result on the run so
downstream checks (M02 CVE mapping, I07 ORM injection, M03 error taxonomy) can tailor behavior.

## Why it matters
- Engine + version + CVE in a report reads as "real scanner". More importantly, it is a **multiplier**:
  error formats, batching semantics, introspection defenses, and known CVEs are engine-specific. Several
  checks waste requests or miss bugs without it.

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. Build the discriminator library in
`pkg/scanner/fingerprint` so other packages can import it; the check is a thin wrapper that records the
finding. Use `cc.ProbeClient()`.)

- `ID()="GQL-M01"`, `Name()="GraphQL Engine Fingerprint"`, `Category()=InformationDisclosure`,
  `Severity()=INFO`, `RequiresSchema()=false`.

### Fingerprint library
```go
type Engine struct{ Name, Vendor string; Confidence string }
type Discriminator struct {
    Query string // a small probe document (often deliberately malformed/edge-case)
    Match func(resp *transport.Response) (Engine, bool) // engine-specific signal
}
func Discriminators() []Discriminator
func Identify(ctx, client *transport.Client, target string) (Engine, []Evidence, int /*probes*/)
```
- Probes (examples): an invalid query to elicit the engine's distinctive parse-error wording
  (`Apollo`: `Cannot query field … Did you mean`; `graphql-ruby`: `Field '…' doesn't exist on type`;
  `Hasura`: `field "…" not found in type` + `x-hasura` hints; `HotChocolate`: `The field \`…\` does not
  exist`; `gqlgen`/`graphql-go` wording; `Yoga`/`envelop` headers); a directive/feature probe; an
  introspection-defense probe; response header signals (`Server`, `X-Powered-By`, `x-hasura-*`,
  `apollo`/`apq` headers). Match the **first high-confidence** discriminator; fall back to "unknown".
- Keep total probes ≤ 6; deterministic ordering.

## Detection algorithm
1. Call `fingerprint.Identify(...)`; record probe count.
2. Always emit an **INFO** finding stating the detected engine (or "unknown") and the evidence (the matched
   discriminator + wording). This is context, not a vulnerability.
3. Store the `Engine` so the run exposes it to other checks (e.g. add an optional `cc.Fingerprint *Engine`
   populated by the orchestrator after M01, or have downstream checks call `fingerprint.Identify` lazily and
   cache). Document the chosen wiring.

## Finding content
- **Title:** `GraphQL Engine Identified — <engine>` (or `GraphQL Engine Not Identified`)
- **Description:** the engine/vendor, confidence, and the discriminating evidence (matched error wording /
  header). For "unknown", list which probes were inconclusive.
- **Impact:** engine identification narrows an attacker's exploit selection (engine-specific CVEs, batching/
  introspection defenses, error oracles).
- **Remediation:** suppress engine-identifying error wording and headers in production; normalize error
  messages; remove `Server`/`X-Powered-By` disclosure.
- **References:** `https://github.com/dolevf/graphw00f`,
  `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`.
- **Confidence:** mirror the match confidence (`"firm"`/`"tentative"`). **CWE:** `"CWE-200"` (info exposure).
  **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M01", cc.Target, "engine:"+engineName)`.

## Acceptance criteria
- **Given** a server returning Apollo's distinctive `Did you mean` parse error, M01 reports engine "Apollo
  Server" with firm confidence and the matched evidence.
- **Given** a Hasura server (header `x-hasura-*` / its error wording), M01 reports "Hasura".
- **Given** a generic server with normalized errors and no signals, M01 reports "unknown" (still INFO, no
  false attribution).
- Deterministic probe ordering; ≤ 6 probes; no panic on malformed responses.

## Tests (`gqlm01_engine_fingerprint_test.go` + `fingerprint_test.go`)
- Handlers emulating Apollo / Hasura / HotChocolate error wording and headers → correct engine each.
- Normalized-error handler → "unknown" with no false positive.
- Assert INFO severity, evidence captured, probe-count bound, deterministic discriminator order.

## Safety
Benign probes only (malformed-but-harmless queries + header reads). INFO severity — do not inflate. No secrets
in output beyond the engine name and the matched (public) error wording.
