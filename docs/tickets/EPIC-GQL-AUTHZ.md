# EPIC: GraphQL Authorization Testing Suite (GQL-A00 → GQL-A09)

**Epic key:** GQLS-AUTHZ
**Epic owner:** Scanner / Detection Engine
**Status:** To Do
**Labels:** `authz`, `authorization`, `owasp-api1`, `owasp-api3`, `owasp-api5`, `detection`, `checks`

## Goal
Give gqls a real **authorization-testing engine** — the BOLA / BFLA / BOPLA / cross-tenant / mutation-authz
class plus the cheap authz-adjacent wins (alias auth bypass, GraphQL CSRF, JWT weaknesses, subscription
authz). This closes the gap called the "missing 70%" in `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.1, and the
three "Critical" OWASP API risks (API1, API3, API5) the scanner currently misses entirely.

This is the inflection point in the roadmap (`SECURITY_PLATFORM_ANALYSIS.md` §13 "v2.0 — Authorization
engine"). Unlike the DoS suite (GQLS-DOS), these checks are **stateful and comparative**: they decide
"is this vulnerable?" by sending the *same* operation as **two different identities** and diffing the
responses. That requires new core primitives, which is why this epic begins with a foundation ticket
(GQL-A00) that the authz checks depend on.

## Tickets in this epic
| Ticket | Check | OWASP / CWE | Severity | Cx | Priority | Depends on |
|---|---|---|---|---|---|---|
| [GQL-A00](./GQL-A00-authorization-foundation.md) | **Authorization testing foundation** (multi-identity sessions, differential oracle, schema surface graph) | — | — | High | **P0** | — |
| [GQL-A01](./GQL-A01-bola-idor.md) | BOLA / IDOR — object access across IDs | API1 / CWE-639 | CRITICAL | High | **P0** | A00 |
| [GQL-A02](./GQL-A02-bfla.md) | BFLA — privileged operation reachable by low-privilege role | API5 / CWE-285 | CRITICAL | High | **P0** | A00 |
| [GQL-A03](./GQL-A03-bopla-field-authz.md) | BOPLA / field-level authz — sensitive fields leaked to under-privileged role | API3 / CWE-213 | HIGH | High | **P0** | A00 |
| [GQL-A04](./GQL-A04-cross-tenant-isolation.md) | Cross-tenant isolation — tenant A reaches tenant B data | API1 / CWE-639 | CRITICAL | High | P1 | A00 |
| [GQL-A05](./GQL-A05-mutation-authz.md) | Mutation-side authz — non-owner update/delete | API5 / CWE-285 | CRITICAL | High | P1 | A00 |
| [GQL-A06](./GQL-A06-alias-auth-bypass.md) | Auth via aliases / batching — rate-limit & brute-force bypass | API4 / CWE-307 | HIGH | Medium | **P0** | — |
| [GQL-A07](./GQL-A07-graphql-csrf.md) | GraphQL CSRF — state-change via GET / simple content-type | API8 / CWE-352 | HIGH | Low | **P0** | — |
| [GQL-A08](./GQL-A08-jwt-weaknesses.md) | JWT weaknesses — `alg:none`, weak secret, missing `exp`, `kid` injection | CWE-347 | HIGH | Medium | P1 | — |
| [GQL-A09](./GQL-A09-subscription-authz.md) | Subscription authz — WebSocket subscription bypasses query authz | API5 / CWE-285 | HIGH | High | P2 | A00 |

> **Build order:** A00 first (it is the gating dependency), then the P0 set (A01, A02, A03, A06, A07),
> then P1 (A04, A05, A08), then P2 (A09). A06/A07/A08 do **not** need the full identity model and can be
> built in parallel with A00.

---

## Shared Engineering Context (applies to every ticket)

> This block is duplicated into each ticket so tickets can be fed to an LLM independently.

- **Module:** `github.com/gqls-cli/gqls`. **Language:** Go 1.24+.
- **New files:** `pkg/scanner/checks/gqlANN_<slug>.go` + `pkg/scanner/checks/gqlANN_<slug>_test.go`.
- **A check** is a struct implementing the `checks.Check` interface (`pkg/scanner/checks/base.go`):
  ```go
  ID() string                 // e.g. "GQL-A01"
  Name() string               // human title
  Category() Category         // checks.Authorization (added by GQL-A00)
  Severity() Severity         // checks.CRITICAL / HIGH
  RequiresSchema() bool       // true for object/field-level authz checks
  Run(ctx context.Context, cc *CheckContext) (CheckResult, error)
  ```
- **Register** in `init()` via `MustRegister(&<name>Check{})`.
- **CheckContext** (`base.go`): `Target string`, `Schema *schema.Schema` (may be nil), `HTTPClient`,
  `BaseHTTPClient`, `UnauthenticatedClient *transport.Client`, `ParsedCurl *CurlRequest`, **plus the new
  `Identities []Identity` slice added by GQL-A00.**
- **Transport:** `client.Do(req) (*transport.Response, error)`. `Response{StatusCode int,
  Headers http.Header, Body []byte, Latency time.Duration, Request *http.Request}`.
  Build requests with `http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))`
  and set header `Content-Type: application/json`.
  ⚠️ `transport.Client.Do` **always injects the client's own `Authorization` header, overriding any value
  set on the request** (see `client.go`). This is why per-identity testing must use *separate clients*,
  one per identity — you cannot swap the token on a single shared client.
- **GraphQL body:** JSON `{"query":"<doc>","variables":{...}}`. Use `json.Marshal`.
- **Probe accounting:** increment `result.ProbeCount` for every request attempt (including network errors).
- **Finding** (`pkg/domain/domain.go`, aliased in `checks`): set `CheckID, CheckName, Severity, Category,
  Title, Description, Impact, Remediation, References []string, ReproRequest *http.Request, ReproBody []byte,
  Fingerprint`. Build fingerprint via `GenerateFingerprint(c.ID(), cc.Target, "<evidenceKey>")`.
  (GQL-A00 also adds optional `Confidence`, `CWE`, `OWASP` fields — populate them when available.)
- **Clean run:** set `result.PassReason` (why no finding) and append `result.PassProbes`
  (`[]PassProbe{Label string, Request *http.Request, Body []byte}`) for transparency.
- **Cancellation:** check `ctx.Done()` between probes; return collected work, never panic.
- **Schema model** (`pkg/schema/model.go`): `s.QueryFields() []*FieldDef`, `s.MutationFields()`,
  `s.SubscriptionFields()`, `s.FindType(name) *TypeDef`, `s.SensitiveFields() []*FieldDef`,
  `FieldDef{Name, Type *TypeRef, Args []*ArgDef, SensitivityScore int, Tags []string}`,
  `ArgDef{Name, Type *TypeRef, DefaultValue *string}` (`DefaultValue == nil` ⇒ required arg),
  `TypeRef.Unwrap() *TypeRef` (strips NON_NULL/LIST), `TypeRef.String()` (e.g. `User!`),
  `TypeDef{Kind, Name, Fields, InputFields, EnumValues}`, kinds `schema.KindObject`, `schema.KindScalar`,
  `schema.KindEnum`, `schema.KindInputObject`, etc. Sensitivity scoring lives in `pkg/schema/sensitivity.go`.

## ⚠️ Shared SAFETY & ETHICS Requirements (mandatory for all authz checks)
Authorization checks are **active, exploit-adjacent probes**: a positive finding *is* a successful (read-only)
cross-identity access. They must be safe by construction:

1. **Read-before-write, and prefer read.** A01/A03/A04 must use **queries only** (object reads). Mutation
   checks (A05) are gated behind an explicit opt-in flag (see GQL-A00 `--authz-allow-mutations`) and must
   prefer reversible/idempotent operations and **never** target obviously destructive mutations (delete*,
   purge*, wipe*, drop*) unless the operator explicitly allow-lists them.
2. **Only test what the operator authorized.** Cross-identity testing requires the operator to *supply* the
   identities (GQL-A00). The scanner never invents or brute-forces credentials. No identity ⇒ the check
   skips with a clear `SkipReason`, it does not guess.
3. **Bounded probe budget.** Each check sends a small, fixed number of requests (target ≤ 8). Respect the
   global rate limiter (enforced by `transport.Client`). No fuzzing loops in this epic.
4. **Differential, not destructive.** The positive signal is "identity B received data it should not have"
   (a *comparison* of two responses), never "we changed/deleted something." Evidence is the two responses,
   redacted.
5. **Redact secrets in evidence.** When echoing leaked data into a finding Description, **mask** the actual
   sensitive values (show field *names* and a redacted preview, e.g. `email: "j***@***"`), and never log raw
   `Authorization`/identity tokens (reuse the existing redaction discipline in the reporters).
6. **Conservative classification.** Only flag on a *definitive* differential signal (identical successful
   object returned to both a privileged and an under-privileged identity, or to an anonymous one). Ambiguous
   results (validation errors, partial nulls, rate-limit, 5xx) are **inconclusive** → never flagged; record
   them in `PassProbes` / `PassReason`.

## Definition of Done (every ticket)
- [ ] Check implemented, self-registered, passes `go vet ./...` and `go build ./cmd/gqls`.
- [ ] Unit tests with `httptest.NewServer` covering: vulnerable→finding, properly-authorized→PassReason,
      no-identities→Skipped, error-resilient (network failure / malformed JSON never panics).
- [ ] `ProbeCount`, `Fingerprint`, `References`, `Remediation`, `Impact` all populated.
- [ ] `Confidence` + `CWE` + `OWASP` set when GQL-A00's `Finding` extension is present.
- [ ] README "Checks" table updated with the new ID/Name/Severity/Category.
- [ ] `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.1 row updated from ❌ to "implemented".
- [ ] Safety & Ethics requirements satisfied (no writes without opt-in; secrets redacted in evidence).

---

## Why this epic needs a foundation ticket (read before estimating)
The DoS suite worked because every check was a stateless single-shot probe. Authorization is the opposite:
- **You need ≥ 2 identities.** "Can role B read role A's object?" is undefined with one set of headers. The
  current engine has exactly three *fixed* client identities (full / base / unauthenticated) and
  `transport.Client.Do` hard-overrides `Authorization` — so there is no way to say "send as Alice, then as
  Bob." **GQL-A00 adds an `Identity` model and `map[name]*transport.Client`.** Without it, A01/A02/A03/A04/
  A05/A09 cannot be written.
- **You need a differential oracle.** Every authz decision is "compare response X to response Y." Today the
  classification regexes are copy-pasted across `gql011`/`gql012`. **GQL-A00 centralizes `classify(Response)`
  and `compare(a,b)`** so the authz checks express findings as "control vs payload classification differs."
- **You need a surface graph.** BOLA needs every `(rootField, idArg) → Object` fetcher; BFLA needs every
  privileged operation; BOPLA needs every sensitive field reachable per type. **GQL-A00 promotes a `surface`
  helper** off `pkg/schema` so checks consume typed candidates instead of re-walking the schema ad hoc.

Build the three primitives once (A00); every authz check then becomes small.
