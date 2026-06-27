# EPIC: GraphQL Denial-of-Service Detection Suite (GQL-D01 → GQL-D08)

**Epic key:** GQLS-DOS
**Epic owner:** Scanner / Detection Engine
**Status:** To Do
**Labels:** `dos`, `detection`, `owasp-api4`, `checks`

## Goal
Extend the gqls scanner with eight Denial-of-Service / resource-exhaustion checks
(GQL-D01 → GQL-D08) that map to **OWASP API4:2023 — Unrestricted Resource Consumption**
and the **OWASP GraphQL Cheat Sheet** (depth/amount/alias/batching limiting). These close the
highest-signal, lowest-cost DoS gaps identified in `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.2.

## Tickets in this epic
| Ticket | Check | Severity | Complexity | Priority |
|---|---|---|---|---|
| [GQL-D01](./GQL-D01-alias-amplification.md) | Alias-based amplification | HIGH | Low | P0 |
| [GQL-D02](./GQL-D02-field-duplication.md) | Field duplication / `__typename` flooding | HIGH | Low | P0 |
| [GQL-D03](./GQL-D03-circular-fragments.md) | Circular fragment / fragment-spread bomb | HIGH | Low | P1 |
| [GQL-D04](./GQL-D04-directive-overloading.md) | Directive overloading | MEDIUM | Low | P1 |
| [GQL-D05](./GQL-D05-list-argument-abuse.md) | Array/list argument & pagination abuse | HIGH | Medium | P1 |
| [GQL-D06](./GQL-D06-cost-amplification-oracle.md) | Query cost / response-size amplification oracle | MEDIUM | Medium | P2 |
| [GQL-D07](./GQL-D07-persisted-query-enforcement.md) | Persisted-query / APQ not enforced | MEDIUM | Medium | P2 |
| [GQL-D08](./GQL-D08-introspection-dos.md) | Introspection-as-DoS (recursive size amplification) | LOW | Low | P3 |

---

## Shared Engineering Context (applies to every ticket)

> This block is duplicated into each ticket so tickets can be fed to an LLM independently.

- **Module:** `github.com/gqls-cli/gqls`. **Language:** Go 1.24+.
- **New files:** `pkg/scanner/checks/gqlDNN_<slug>.go` + `pkg/scanner/checks/gqlDNN_<slug>_test.go`.
- **A check** is a struct implementing the `checks.Check` interface (`pkg/scanner/checks/base.go`):
  ```go
  ID() string                 // e.g. "GQL-D01"
  Name() string               // human title
  Category() Category         // checks.DenialOfService
  Severity() Severity         // checks.HIGH / MEDIUM / LOW
  RequiresSchema() bool       // true only if the check cannot run without cc.Schema
  Run(ctx context.Context, cc *CheckContext) (CheckResult, error)
  ```
- **Register** in `init()` via `MustRegister(&<name>Check{})`.
- **CheckContext** (`base.go`): `Target string`, `Schema *schema.Schema` (may be nil),
  `HTTPClient`, `BaseHTTPClient`, `UnauthenticatedClient *transport.Client`, `ParsedCurl *CurlRequest`.
  Use `cc.ProbeClient()` for synthetic probes (returns `BaseHTTPClient`, CLI-headers-only).
- **Transport:** `client.Do(req) (*transport.Response, error)`. `Response{StatusCode int,
  Headers http.Header, Body []byte, Latency time.Duration, Request *http.Request}`.
  Build requests with `http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))`
  and set header `Content-Type: application/json`.
- **GraphQL body:** JSON `{"query":"<doc>","variables":{...}}`. Use `json.Marshal`.
- **Probe accounting:** increment `result.ProbeCount` for every request attempt (including network errors).
- **Finding** (`pkg/domain/domain.go`, aliased in `checks`): set `CheckID, CheckName, Severity, Category,
  Title, Description, Impact, Remediation, References []string, ReproRequest *http.Request,
  ReproBody []byte, Fingerprint`. Build fingerprint via `GenerateFingerprint(c.ID(), cc.Target, "<evidenceKey>")`.
- **Clean run:** set `result.PassReason` (why no finding) and append `result.PassProbes`
  (`[]PassProbe{Label string, Request *http.Request, Body []byte}`) for transparency.
- **Cancellation:** check `ctx.Done()` between probes; return collected work, never panic.
- **Schema model** (`pkg/schema/model.go`): `s.QueryFields() []*FieldDef`, `s.MutationFields()`,
  `s.FindType(name) *TypeDef`, `FieldDef{Name string, Type *TypeRef, Args []*ArgDef}`,
  `ArgDef{Name string, Type *TypeRef}`, `TypeRef.Unwrap() *TypeRef` (strips NON_NULL/LIST),
  `TypeDef{Kind, Name, Fields, InputFields}`, kinds `schema.KindObject`, `schema.KindScalar`, etc.
  The query root type name is available via the schema; fall back to literal `"Query"` if absent.

## ⚠️ Shared SAFETY Requirements (mandatory for all DoS checks)
These checks must **detect the absence of a limit, not actually take the target down**:
1. **Bounded payloads.** Never send millions of anything. Caps: aliases/duplications/directives ≤ a few
   hundred (default 100–256); pagination values ≤ 10,000; single circular-fragment request only.
2. **Detect *acceptance*, not *outage*.** The positive signal is "server executed/accepted the abusive
   shape" (HTTP 200 + `data`, or absence of a limit/validation rejection) — **not** that the server crashed.
3. **Send a benign control first** (1× of the abused construct) to establish a baseline and to confirm the
   endpoint is live before sending the amplified probe.
4. **Small, fixed probe count** per check (target ≤ 4 requests). Respect the global rate limiter (already
   enforced by `transport.Client`).
5. **Timeout-aware.** A hang/timeout/`5xx` on the abusive probe (vs a fast control) is itself a positive
   DoS signal — treat it as evidence, not as a tool error.

## Definition of Done (every ticket)
- [ ] Check implemented, self-registered, passes `go vet ./...` and `go build ./cmd/gqls`.
- [ ] Unit tests with `httptest.NewServer` covering: vulnerable→finding, protected→PassReason, error-resilient.
- [ ] `ProbeCount`, `Fingerprint`, `References`, `Remediation` all populated correctly.
- [ ] README "Checks" table updated with the new ID/Name/Severity/Category.
- [ ] `docs/SECURITY_PLATFORM_ANALYSIS.md` row updated to reflect "implemented".
- [ ] No real-outage risk (Safety Requirements satisfied).
