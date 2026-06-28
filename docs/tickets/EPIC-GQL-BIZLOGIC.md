# EPIC: GraphQL Business-Logic & Abuse Suite (GQL-B01 → GQL-B04)

**Epic key:** GQLS-BIZLOGIC
**Epic owner:** Scanner / Detection Engine
**Status:** To Do
**Labels:** `business-logic`, `abuse`, `owasp-api6`, `owasp-api3`, `cwe-915`, `cwe-362`, `checks`

## Goal
Add the high-value, hard tier: business-flow abuse, mass assignment, race conditions, and user/identifier
enumeration. These map to OWASP **API6** (unrestricted access to sensitive business flows), **API3** (mass
assignment), and **API1** (enumeration), and close `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.5.

## Tickets in this epic
| Ticket | Check | OWASP / CWE | Severity | Cx | Priority | Depends on |
|---|---|---|---|---|---|---|
| [GQL-B02](./GQL-B02-mass-assignment.md) | Mass assignment via input objects (`isAdmin`/`role`/`verified`) | API3 / CWE-915 | HIGH | Medium | **P1 (start here)** | A05 write-gate, surface |
| [GQL-B04](./GQL-B04-user-enumeration.md) | Enumeration via differential errors/timing (valid vs invalid user/email) | API1 | MEDIUM | Medium | P2 | authz oracle |
| [GQL-B01](./GQL-B01-business-flow-abuse.md) | Unrestricted access to sensitive business flows (batch+alias abuse) | API6 | HIGH | High | P2 | A06 alias engine |
| [GQL-B03](./GQL-B03-race-conditions.md) | Race conditions (parallel mutations: double-spend, coupon reuse) | CWE-362 | HIGH | High | P3 | A05 write-gate, concurrency primitive |

> **Build order:** start with **B02** (mass assignment — medium complexity, high value, reuses the GQL-A05
> write-gate and the `surface` input-object walker) and **B04** (enumeration — pure differential oracle, no
> writes). **B01** and **B03** perform real abuse/state-change and are write-gated and higher complexity.

---

## Shared Engineering Context (applies to every ticket)

> Duplicated into each ticket so tickets can be fed to an LLM independently.

- **Module:** `github.com/gqls-cli/gqls`. **Language:** Go 1.24+.
- **New files:** `pkg/scanner/checks/gqlBNN_<slug>.go` (+ `_test.go`).
- **A check** implements `checks.Check` (`base.go`); self-register in `init()` via `MustRegister`.
  Category: `checks.Authorization` for B02/B04 (access/property control), `checks.DenialOfService` or a new
  `BusinessLogic` category for B01/B03 — prefer adding `BusinessLogic Category = "BusinessLogic"` to
  `pkg/domain/domain.go` and re-exporting it in `base.go` (mirror how `Authorization` was added).
- **CheckContext** (`base.go`): `Target`, `Schema`, `HTTPClient/BaseHTTPClient/UnauthenticatedClient`,
  `ParsedCurl`, `Headers`, **`Identities []Identity`**, **`AllowMutations bool`**, **`AllowedMutations
  []string`**, `AuthzSeeds map[string]string`. Helpers: `cc.HasIdentities()`, `cc.IdentityPairs()`,
  `cc.IdentityByName(name)`.
- **Reuse the authorization primitives (do not re-implement):**
  - `pkg/scanner/authz`: `Classify(resp) → Class`, `Compare(a, b, idPath) → Diff`, `RedactLeak`, `MaskValue`.
  - `pkg/schema/surface`: `Fetchers`, `PrivilegedOps`, `SensitiveFieldsByType`, `ExampleValue`.
  - The GQL-A05 write-cycle helpers in `gqla05_mutation_authz.go` (`buildMutationDoc`, candidate selection,
    `a05DestructiveRe`, the capture→write→verify→restore pattern) — B02/B03 follow the same safe-write
    discipline.
  - The GQL-A06 alias builder in `gqla06_alias_auth_bypass.go` — B01 reuses single-request aliasing.
- **Transport:** `client.Do(req) (*transport.Response, error)`; `Response{StatusCode, Headers, Body, Latency,
  Request}`. For concurrency (B03), launch N goroutines each with its own `*http.Request`; the rate limiter
  in `transport.Client` is shared and safe.
- **Finding** (`pkg/domain/domain.go`): set the usual fields plus `Confidence`, `CWE`, `OWASP`. Fingerprint
  via `GenerateFingerprint(c.ID(), cc.Target, "<evidenceKey>")`.
- **Clean run:** `result.PassReason` + `result.PassProbes`; increment `result.ProbeCount`; check `ctx.Done()`.

## ⚠️ Shared SAFETY Requirements
1. **Writes are opt-in and reversible.** B01/B02/B03 perform state-changing requests; they run **only** when
   `cc.AllowMutations` is true (the `--authz-allow-mutations` gate). Prefer the capture→write→verify→restore
   pattern from GQL-A05; never invoke destructive-named mutations
   (`delete/remove/destroy/purge/wipe/drop/cancel/revoke`) unless explicitly allow-listed via
   `cc.AllowedMutations`.
2. **B04 is read-only.** Enumeration uses queries / failed-auth attempts with **invalid, non-existent**
   identifiers only; never a real/configured credential, never a real account lockout.
3. **Bounded & polite.** Race-condition probes (B03) use a small parallel burst (≤ ~20) against a single
   target operation, once. Business-flow abuse (B01) uses bounded aliasing (≤ ~20, well below DoS). Respect
   the rate limiter where it does not defeat the test (B03 intentionally bursts within the limiter's burst).
4. **Differential & redacted.** Findings are based on response/state comparison, not a single sample;
   redact any returned PII or secrets in evidence.

## Definition of Done (every ticket)
- [ ] Check implemented, self-registered, `go vet ./...` + `go build ./cmd/gqls` clean.
- [ ] Unit tests (`httptest.NewServer`): vulnerable→finding, protected→PassReason, write-gated→Skip with no
      state change, error-resilient.
- [ ] `ProbeCount`, `Fingerprint`, `References`, `Remediation`, `Impact`, `Confidence`, `CWE`/`OWASP` set.
- [ ] README "Checks" table + `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.5 row updated to "implemented".
- [ ] Safety satisfied (writes opt-in + reversible; B04 read-only; bounded; redacted).
