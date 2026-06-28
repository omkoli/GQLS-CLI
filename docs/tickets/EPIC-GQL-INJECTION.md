# EPIC: GraphQL Injection Engine (GQL-I01 → GQL-I09)

**Epic key:** GQLS-INJECTION
**Epic owner:** Scanner / Detection Engine
**Status:** To Do
**Labels:** `injection`, `detection`, `owasp-api7`, `cwe-89`, `cwe-943`, `cwe-918`, `checks`

## Goal
Turn gqls's injection coverage from "a rounding error" (one String arg of one query + one mutation,
error-only — `pkg/scanner/checks/gql011_sqli_error_based.go`) into a real injection engine that walks the
**whole reachable input graph** and applies **multiple oracle strategies** (error, boolean-differential,
statistical timing, out-of-band). Closes the gaps in `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.3.

## Tickets in this epic
| Ticket | Check | CWE / OWASP | Severity | Cx | Priority | Depends on |
|---|---|---|---|---|---|---|
| [GQL-I09](./GQL-I09-injection-surface-engine.md) | **Injection surface graph + multi-oracle engine** (every leaf scalar; variables, inline, nested input objects, list elements) | — | — | Medium | **P1 (build first)** | — |
| [GQL-I01](./GQL-I01-boolean-sqli.md) | Boolean-based SQLi (differential true/false) | CWE-89 | CRITICAL | Medium | P1 | I09 |
| [GQL-I02](./GQL-I02-time-based-sqli.md) | Time-based blind SQLi (statistical timing oracle) | CWE-89 | CRITICAL | Medium | P1 | I09 |
| [GQL-I03](./GQL-I03-nosql-injection.md) | NoSQL (Mongo operator) injection | CWE-943 | CRITICAL | Medium | P1 | I09 |
| [GQL-I04](./GQL-I04-os-command-injection.md) | OS command injection (error + time-based) | CWE-78 | CRITICAL | Medium | P2 | I09, I02 |
| [GQL-I05](./GQL-I05-ssrf.md) | SSRF via GraphQL args (blind via OOB) | API7 / CWE-918 | CRITICAL | Medium | **P1** | I09 |
| [GQL-I06](./GQL-I06-xss.md) | Stored/reflected XSS surfaced through GraphQL | CWE-79 | MEDIUM | Medium | P2 | I09 |
| [GQL-I07](./GQL-I07-orm-operator-injection.md) | ORM/GraphQL operator injection (Hasura/Postgraphile `where`/`_like`) | CWE-943 | HIGH | Medium | P2 | I09, M01 |
| [GQL-I08](./GQL-I08-ldap-xml-template-injection.md) | LDAP / XML / template injection | CWE-90/91/1336 | HIGH | Medium | P3 | I09 |

> **Build order:** **GQL-I09 first** — it is the surface walker + oracle plumbing every other ticket consumes.
> Then the P1 set (I01, I02, I03, I05), then P2 (I04, I06, I07), then P3 (I08). I04 reuses I02's timing oracle.

---

## Shared Engineering Context (applies to every ticket)

> Duplicated into each ticket so tickets can be fed to an LLM independently.

- **Module:** `github.com/gqls-cli/gqls`. **Language:** Go 1.24+.
- **New files:** `pkg/scanner/checks/gqlINN_<slug>.go` (+ `_test.go`). The surface walker + oracles live in
  a new `pkg/scanner/inject` package (built by GQL-I09).
- **A check** implements `checks.Check` (`pkg/scanner/checks/base.go`): `ID/Name/Category/Severity/
  RequiresSchema/Run(ctx, *CheckContext) (CheckResult, error)`; self-register in `init()` via `MustRegister`.
  Use `Category()=checks.Injection`.
- **CheckContext** (`base.go`): `Target`, `Schema *schema.Schema` (may be nil), `HTTPClient/BaseHTTPClient/
  UnauthenticatedClient *transport.Client`, `ParsedCurl *CurlRequest`, `Headers map[string]string`.
  Injection checks should use **`cc.HTTPClient`** (the full client carrying the original auth context) so
  injectable fields behind auth are reachable — this matches the existing GQL-011 behavior.
- **Transport:** `client.Do(req) (*transport.Response, error)`; `Response{StatusCode, Headers http.Header,
  Body []byte, Latency time.Duration, Request *http.Request}`. Build requests with
  `http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(body))`, `Content-Type:
  application/json`. GraphQL body: `{"query":"<doc>","variables":{...}}`.
- **Differential oracle (reuse, do not re-implement):** `pkg/scanner/authz` provides
  `authz.Classify(resp) → Class` (Success/AuthDenied/Validation/NotFound/RateLimited/ServerError/Empty/Unknown)
  and `authz.Compare(a, b, idPath) → Diff`. Boolean-based injection (I01) and enumeration collapse to
  "compare two responses". `authz.RedactLeak` / `authz.MaskValue` redact evidence.
- **Existing seed to extend:** `gql011_sqli_error_based.go` — `containsDBError(body) bool`, the
  `sqliPayloadEntry` table, `sqliCollectTargets(s)`, `sqliFirstStringArg(fields)`, `sqliProbeBody(...)`.
  GQL-I09 generalizes `sqliCollectTargets`/`sqliFirstStringArg` into the full injection-point enumerator;
  the error-based payload table and `containsDBError` are reused by I01.
- **Schema model** (`pkg/schema/model.go`): `s.QueryFields()`, `s.MutationFields()`, `s.FindType(name)`,
  `FieldDef{Name, Type *TypeRef, Args []*ArgDef}`, `ArgDef{Name, Type *TypeRef, DefaultValue *string}`
  (nil default ⇒ required), `TypeDef{Kind, Name, Fields, InputFields, EnumValues}`, `TypeRef.Unwrap()`,
  kinds `KindScalar/KindEnum/KindInputObject/KindList/KindNonNull/KindObject`. `surface.ExampleValue(t, s)`
  synthesizes a valid literal for a scalar/enum arg.
- **Finding** (`pkg/domain/domain.go`, aliased in `checks`): set `CheckID, CheckName, Severity, Category,
  Title, Description, Impact, Remediation, References, ReproRequest, ReproBody, Fingerprint`, and the triage
  fields `Confidence` ("confirmed"|"firm"|"tentative"), `CWE`, `OWASP`. Fingerprint via
  `GenerateFingerprint(c.ID(), cc.Target, "<evidenceKey>")`.
- **Clean run:** set `result.PassReason` and append `result.PassProbes`. Increment `result.ProbeCount` per
  request. Check `ctx.Done()` between probes; never panic on malformed responses.

## ⚠️ Shared SAFETY Requirements (mandatory for every injection check)
Injection probing is active and can be destructive if careless. Be safe by construction:
1. **Non-destructive payloads only.** Never send payloads that modify or destroy data: no
   `DROP/DELETE/UPDATE/INSERT/TRUNCATE/;--` stacked statements, no Mongo `$where` that mutates, no shell
   commands with side effects. Use **read-only / boolean / time-delay / OOB-callback** payloads exclusively.
2. **Prefer query context; gate mutation injection.** Injecting into a *mutation* argument executes a
   mutation. Probe **query** injection points freely; only probe mutation injection points when
   `cc.AllowMutations` is true (the existing GQL-A05 opt-in), and even then only with side-effect-free
   payloads (boolean/time/OOB), never error-payloads that could partially execute a write.
3. **Bounded budget.** Cap injection points per run (default ≤ 25 leaf points) and payloads per point
   (≤ ~8). Respect the global rate limiter. Time-based probes use a small, fixed sample count (see I02).
4. **Differential, statistically-grounded decisions.** Never flag on a single sample. Boolean SQLi requires a
   true-vs-false response divergence with a matching control; time-based requires a median+MAD effect size
   over ≥ 7 samples; OOB requires a correlated callback. Single-shot regex (today's GQL-011) is "tentative".
5. **Redact evidence.** Mask any reflected data and never echo the configured `Authorization`/tokens.
6. **OOB / SSRF requires explicit opt-in.** Out-of-band interaction (I05 blind SSRF, I04 blind command
   injection) only runs when the operator supplies a collaborator domain (`--oob-domain`); otherwise the
   check degrades to in-band (timing/error) signals or reports "requires --oob-domain" in PassReason.

## Definition of Done (every ticket)
- [ ] Check implemented, self-registered, `go vet ./...` + `go build ./cmd/gqls` clean.
- [ ] Unit tests (`httptest.NewServer`): vulnerable→finding, safe→PassReason, no-target→Skip/Pass,
      error-resilient (malformed JSON / network failure never panics).
- [ ] `ProbeCount`, `Fingerprint`, `References`, `Remediation`, `Impact`, `Confidence`, `CWE`, `OWASP` set.
- [ ] README "Checks" table + `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.3 row updated to "implemented".
- [ ] Safety requirements satisfied (no destructive payloads; mutation injection gated; bounded; redacted).

## Why this epic needs GQL-I09 first
GQL-011 finds only the most naive error-leaking endpoint because it tests **one** String arg of **one** query
and **one** mutation. Every real injection class needs the *same* primitive: a list of typed **injection
points** — every leaf scalar reachable through query/mutation arguments, **including nested input-object
fields and list elements**, addressable via inline literals **or** GraphQL variables. GQL-I09 builds that
enumerator plus the shared oracle plumbing (a `Probe`/`Differ` and a statistical timing sampler); I01–I08
each just supply a payload set + an oracle choice and consume the candidates. Build the engine once.
