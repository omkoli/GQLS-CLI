# GQL-A00 — Authorization Testing Foundation (Identities · Differential Oracle · Surface Graph)

| Field | Value |
|---|---|
| **Type** | Story (enabler / spike+build) |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P0 (Highest) — gating dependency for A01–A05, A09 |
| **Severity (of finding)** | n/a (no finding; this ticket ships primitives) |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `authz`, `foundation`, `engine`, `identities`, `oracle`, `surface-graph` |
| **Category** | n/a |
| **Files** | `pkg/domain/domain.go`, `pkg/scanner/checks/base.go`, `pkg/config/config.go`, `cmd/gqls/scan.go`, **new** `pkg/scanner/authz/identity.go`, **new** `pkg/scanner/authz/oracle.go`, **new** `pkg/schema/surface/surface.go` (+ `_test.go` for each) |

## Summary
Build the three core primitives that every stateful authorization check (GQL-A01..A05, A09) depends on:
1. **Multi-identity sessions** — an `Identity` model + a `map[name]*transport.Client` so a check can send the
   *same* operation "as Alice" then "as Bob" then "as anonymous."
2. **Differential oracle** — a single `Classify(resp) → Class` taxonomy and `Compare(a, b) → Diff` so authz
   decisions are expressed as "two responses differ in an authorization-relevant way," replacing the regex
   tables duplicated across `gql011`/`gql012`.
3. **Schema surface graph** — walk `schema.Schema` into typed authz candidates (id-bearing object fetchers,
   privileged operations, sensitive fields) with example-argument synthesis.

This ticket produces **no security finding of its own.** Its DoD is: the primitives exist, are unit-tested,
and the existing 12+ checks still build and pass.

## Why it matters
The current engine has exactly three *fixed* client identities (full / base / unauthenticated), and
`transport.Client.Do` **hard-overrides the `Authorization` header** (`pkg/transport/client.go`). There is no
way to express "send as role A, then as role B" — which is the definition of every authorization test. Per
`docs/SECURITY_PLATFORM_ANALYSIS.md` Appendix A #4: *"Add `Identity` to the client model … This is the single
most important structural change."* Build it once here; A01–A09 then become small checks.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` → Shared Engineering Context + Shared SAFETY & ETHICS. Key existing types:
`checks.CheckContext` in `base.go`; `transport.NewClient(timeout, rps, headers)`; client wiring in
`cmd/gqls/scan.go` `runScan`; `config.ScanConfig` + `config.Load`.)

### Part 1 — Identity model & multi-identity sessions
- **New type** (`pkg/scanner/authz/identity.go`, or co-located in `checks` if you prefer to avoid an import
  cycle — `checks` already imports `transport`):
  ```go
  type Identity struct {
      Name      string             // operator-chosen label, e.g. "admin", "userA", "userB"
      Privilege int                // higher = more privileged; anonymous = 0. Used to order pairs.
      Tenant    string             // optional tenant id for A04 cross-tenant tests ("" if N/A)
      Client    *transport.Client  // a dedicated client carrying this identity's headers
  }
  ```
- **Add to `CheckContext`** (`base.go`): `Identities []Identity`. Keep the existing
  `UnauthenticatedClient` — represent anonymous as an `Identity{Name:"anonymous", Privilege:0,
  Client: UnauthenticatedClient}` appended automatically when ≥1 authenticated identity is configured.
- **Helpers on `CheckContext`** (so checks don't re-implement pairing):
  - `(cc) HasIdentities() bool` — true when ≥ 2 identities (incl. anonymous) are available.
  - `(cc) IdentityPairs() [][2]Identity` — ordered `(higher, lower)` privilege pairs, e.g.
    `(admin,userB)`, `(admin,anonymous)`, `(userA,anonymous)`. These are the (victim-owner, attacker) pairs
    the differential checks iterate. Deterministic ordering (sort by `Privilege` desc, then `Name`).
  - `(cc) IdentityByName(name string) (Identity, bool)`.
- **Config** (`pkg/config/config.go`): add to `ScanConfig`
  ```go
  Identities []IdentityConfig `mapstructure:"identities"`
  // IdentityConfig: { Name string; Privilege int; Tenant string; Headers map[string]string }
  AllowAuthzMutations bool `mapstructure:"allow_authz_mutations"` // gates GQL-A05 writes
  ```
  Support both config-file (`identities:` block in `gqls.yaml`) and a repeatable CLI flag
  `--identity 'name=userA;priv=10;header=Authorization: Bearer <A>;header=X-Tenant: t1'`
  (parse `key=value` pairs separated by `;`; `header=` is repeatable within one identity). Header values
  honor the existing `${ENV_VAR}` expansion via `ResolveHeaders`-style logic. Also add
  `--authz-allow-mutations` (bool) bound to `AllowAuthzMutations`.
- **Wiring** (`cmd/gqls/scan.go` `runScan`): after building the existing clients, construct one
  `transport.NewClient(cfg.Timeout, cfg.RateLimit, resolvedIdentityHeaders)` **per configured identity**,
  append the anonymous identity (reusing `unauthClient`), and set `checkCtx.Identities`. Reuse the existing
  per-request timeout and `RateLimit`. Do **not** change the behavior of checks that don't read `Identities`.

### Part 2 — Differential oracle
- **New package** `pkg/scanner/authz/oracle.go` (no import cycle: depends only on `transport` + stdlib):
  ```go
  type Class int
  const ( ClassSuccess Class = iota; ClassAuthDenied; ClassValidation; ClassNotFound;
          ClassRateLimited; ClassServerError; ClassEmpty; ClassUnknown )
  func Classify(resp *transport.Response) Class
  ```
  Rules (migrate & de-duplicate the regex tables from `gql012_unauthenticated_mutations.go` and
  `gql011_sqli_error_based.go`):
  - HTTP 401/403, or GraphQL error message matching `(?i)\b(unauthorized|unauthenticated|not authorized|forbidden|access denied|permission)\b`, or `extensions.code ∈ {UNAUTHENTICATED, FORBIDDEN, ACCESS_DENIED}` → `ClassAuthDenied`.
  - HTTP 200 with non-null `data` and no errors → `ClassSuccess`. (`data` present but all-null with an authz error already handled above.)
  - GraphQL validation errors (`missing required arguments`, `cannot query field`, `unknown argument`, …) → `ClassValidation`.
  - 429 / rate-limit message → `ClassRateLimited`; 5xx → `ClassServerError`; not-found message/`null` object with no error → `ClassNotFound`/`ClassEmpty`.
- **Comparison** for authz decisions:
  ```go
  type Diff struct {
      SameObject   bool   // both responses returned the *same* identifying data (see below)
      OwnerClass   Class  // class for the higher-privilege / owner identity
      AttackerClass Class // class for the lower-privilege / attacker identity
      LeakedFields []string // field paths present for attacker that should have been denied
  }
  func Compare(owner, attacker *transport.Response, idPath string) Diff
  ```
  `SameObject` is true when the attacker response is `ClassSuccess` **and** a stable identifier extracted at
  `idPath` (default the queried object's `id`) is **equal** to the owner's — i.e. the attacker got the
  victim's object, not their own. Provide a tolerant JSON path extractor (`data.<field>.id`, fall back to
  any `id`/`_id`/`nodeId` leaf). This `SameObject && attacker==Success` is the BOLA/cross-tenant positive
  signal; `attacker==AuthDenied` is the negative (protected) signal.
- **Refactor note (optional but encouraged):** have `gql011`/`gql012` consume `Classify` to delete their
  local regex tables. Keep their existing behavior identical (snapshot the current tests).

### Part 3 — Schema surface graph
- **New package** `pkg/schema/surface/surface.go` (depends on `pkg/schema` only):
  ```go
  type ObjectFetcher struct {        // BOLA / cross-tenant candidate
      RootField string               // e.g. "user", "order", "node"
      IsMutation bool                // usually false (queries) for read-fetchers
      IDArg     string               // the id-like arg name, e.g. "id"
      IDArgType string               // "ID"/"Int"/"String"/"UUID"
      ReturnType string              // object type name returned
  }
  type PrivilegedOp struct {         // BFLA candidate
      Field string; IsMutation bool; Reasons []string // why flagged privileged
  }
  type SensitiveField struct {       // BOPLA candidate
      ParentType, Field string; Score int; Tags []string; SelectionPath string
  }
  func Fetchers(s *schema.Schema) []ObjectFetcher
  func PrivilegedOps(s *schema.Schema) []PrivilegedOp
  func SensitiveFieldsByType(s *schema.Schema) map[string][]SensitiveField
  func ExampleValue(t *schema.TypeRef, s *schema.Schema) string // valid literal for a required scalar/enum arg
  ```
  Heuristics:
  - **Fetchers:** root `Query` fields whose args include exactly/primarily one id-like arg
    (`id|.*Id|.*_id|uuid|slug|key|number`) of scalar type and that return an OBJECT (unwrap LIST/NON_NULL).
  - **PrivilegedOps:** fields whose name matches `(?i)(admin|delete|remove|grant|revoke|promote|impersonate|
    role|permission|disable|ban|refund|payout|invite|approve|publish|config|setting)`, OR mutations that
    return/accept a type tagged `privileged`/`credential` by `pkg/schema/sensitivity.go`. Record the reason(s).
  - **SensitiveFields:** every field with `SensitivityScore > 0` grouped by parent type, with the selection
    path needed to request it. Reuse `schema.Schema.SensitiveFields()` and the `Tags`.
  - **ExampleValue:** synthesize a valid literal for required args so probes pass validation: `ID/String →
    "1"` (configurable), `Int → 1`, `Float → 1.0`, `Boolean → true`, enum → first `EnumValues[0]`. Used by
    A01/A02 to build executable operations.

### Part 4 — `domain.Finding` extension (recommended)
Add optional fields so authz findings carry triage metadata (Appendix A #5):
```go
// in pkg/domain/domain.go Finding{}
Confidence string   // "confirmed" | "firm" | "tentative"
CWE        string   // e.g. "CWE-639"
OWASP      string   // e.g. "API1:2023"
```
Re-export nothing new in `checks` (Finding is already aliased). Update the reporters (`pkg/reporter/*`,
SARIF `properties`) to render them when non-empty — **non-breaking**: empty values render as today.
Also add the **new category**: `Authorization Category = "Authorization"` in `domain.go` and re-export it in
`base.go` (`Authorization = domain.Authorization`). Keep the existing `Authentication` category for GQL-012.

## Detection algorithm
n/a — this ticket ships primitives, not a check. It self-tests via the unit tests below and by leaving the
existing suite green.

## Acceptance criteria
- **Given** a `gqls.yaml` with two `identities` (or two `--identity` flags), **when** `runScan` builds the
  context, **then** `cc.Identities` contains those identities plus an auto-appended `anonymous` (Privilege 0),
  each with its own `*transport.Client`, and `cc.IdentityPairs()` returns deterministic (higher,lower) pairs.
- **Given** no identities configured, **then** `cc.HasIdentities() == false` and `cc.Identities` contains at
  most the anonymous identity; authz checks consuming this must `Skip` (not error).
- **Given** representative responses, **then** `Classify` returns the documented `Class` for each
  (401→AuthDenied, 200+data→Success, validation→Validation, 429→RateLimited, 5xx→ServerError), and
  `Compare(owner, attacker, idPath)` sets `SameObject=true` only when the attacker successfully received the
  owner's identifier.
- **Given** a parsed schema, **then** `surface.Fetchers`, `PrivilegedOps`, and `SensitiveFieldsByType` return
  the expected candidates for a fixture schema, and `ExampleValue` yields a schema-valid literal per scalar/enum.
- **Regression:** `go build ./cmd/gqls`, `go vet ./...`, and the full existing test suite pass unchanged.
- **No behavior change** for any check that does not read `cc.Identities`.

## Tests
- `identity_test.go`: config parsing (flag + file), `${ENV}` expansion, anonymous auto-append, deterministic
  `IdentityPairs` ordering, per-identity client header isolation (assert each client injects only its own
  headers — exercise `transport.Client.Do`'s Authorization override semantics).
- `oracle_test.go`: table-driven `Classify` cases for every `Class`; `Compare` positive (same id leaked) and
  negative (attacker denied / attacker got own different object) cases; malformed JSON → `ClassUnknown`,
  never panics.
- `surface_test.go`: fixture `schema.Schema` exercising fetchers (id-bearing root fields), privileged-op name
  heuristics + sensitivity-tag path, sensitive-field grouping, and `ExampleValue` per scalar/enum.
- `scan` wiring covered by an integration-style test that builds a `CheckContext` from a config with two
  identities and asserts the clients are distinct.

## Safety & Ethics
This ticket adds **capability**, not probes. Guardrails it must enforce for downstream checks:
- Identities are **operator-supplied only**; never synthesized or brute-forced.
- `AllowAuthzMutations` defaults **false**; A05 must refuse to run write probes unless it is true.
- The oracle's `Compare` redaction helper must expose a `RedactLeak(fields, resp) string` that masks values
  (`email → "j***@***"`) so downstream findings never embed raw PII or tokens.

## Out of scope (future tickets)
Login/OAuth flow automation, token refresh, HAR/Postman identity import (`SECURITY_PLATFORM_ANALYSIS.md` §7),
and the statistical timing oracle (§6.2). This ticket only covers static, operator-supplied identities.
