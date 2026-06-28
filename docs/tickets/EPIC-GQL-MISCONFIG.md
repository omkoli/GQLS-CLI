# EPIC: GraphQL Misconfiguration & Information-Disclosure Suite (GQL-M01 → GQL-M09)

**Epic key:** GQLS-MISCONFIG
**Epic owner:** Scanner / Detection Engine
**Status:** To Do
**Labels:** `misconfig`, `info-disclosure`, `fingerprinting`, `owasp-api8`, `checks`

## Goal
Round out the cheap, high-credibility "easy class": GraphQL **engine fingerprinting** (graphw00f-style) and
the CVE map it unlocks, plus the misconfiguration checks that reviewers expect — `extensions`/trace leakage
taxonomy, introspection-via-GET, suggestion-based SDL reconstruction, debug/dev-mode detection, CORS, security
headers, and schema-description secret leakage. Closes `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.4.

## Tickets in this epic
| Ticket | Check | Reference | Severity | Cx | Priority | Depends on |
|---|---|---|---|---|---|---|
| [GQL-M01](./GQL-M01-engine-fingerprinting.md) | Server engine fingerprinting (graphw00f-style) | graphw00f | INFO | Medium | **P0 (build first)** | — |
| [GQL-M02](./GQL-M02-engine-cve-mapping.md) | Engine-specific known-CVE mapping | — | varies | Medium | P1 | M01 |
| [GQL-M03](./GQL-M03-extensions-trace-leakage.md) | Trace/`extensions` leakage taxonomy | OWASP CS | MEDIUM | Low | P1 | — (extends GQL-005) |
| [GQL-M04](./GQL-M04-introspection-via-get.md) | Introspection via GET / alternative content-types | PortSwigger | MEDIUM | Low | P1 | — (extends GQL-001/010) |
| [GQL-M05](./GQL-M05-sdl-reconstruction.md) | Suggestion-based full schema (SDL) reconstruction | clairvoyance | MEDIUM | Medium | P1 | — (uses harvester) |
| [GQL-M06](./GQL-M06-debug-dev-mode.md) | Debug/dev-mode + dev-tooling detection (GraphiQL/Altair/Voyager) | — | LOW | Low | P2 | — (extends GQL-004) |
| [GQL-M07](./GQL-M07-cors-misconfiguration.md) | CORS misconfiguration on the GraphQL endpoint | API8 / CWE-942 | MEDIUM | Low | P1 | — |
| [GQL-M08](./GQL-M08-security-headers.md) | Missing security headers on the GraphQL response | API8 | LOW | Low | P3 | — |
| [GQL-M09](./GQL-M09-description-secret-leakage.md) | Field-level deprecation/secret leakage via descriptions & defaults | — | LOW | Low | P3 | — (extends GQL-006) |

> **Build order:** **M01 first** (engine fingerprint unlocks M02 and tailors several other checks). The rest
> are independent, low-complexity wins (M03, M04, M07 are the highest-value of those). M02 gates on M01.

---

## Shared Engineering Context (applies to every ticket)

> Duplicated into each ticket so tickets can be fed to an LLM independently.

- **Module:** `github.com/gqls-cli/gqls`. **Language:** Go 1.24+.
- **New files:** `pkg/scanner/checks/gqlMNN_<slug>.go` (+ `_test.go`). The fingerprinter (M01) lives in a new
  `pkg/scanner/fingerprint` package that other checks may import.
- **A check** implements `checks.Check` (`base.go`); self-register in `init()` via `MustRegister`;
  `Category()=checks.InformationDisclosure`. Most of these checks are schema-independent
  (`RequiresSchema()=false`); M09 reads the schema.
- **CheckContext** (`base.go`): `Target`, `Schema`, `HTTPClient/BaseHTTPClient/UnauthenticatedClient`,
  `ParsedCurl`, `Headers`. Use `cc.ProbeClient()` for synthetic probes (CLI-headers only); use
  `cc.UnauthenticatedClient` for "what does an anonymous client see" checks.
- **Transport:** `client.Do(req) (*transport.Response, error)`; `Response{StatusCode, Headers http.Header,
  Body []byte, Latency, Request}`. Response **headers are first-class here** (CORS, security headers,
  engine signals). Build POST `application/json` GraphQL requests as in the existing checks; M04 also issues
  GET and alternative content-type requests (reuse the builders from `gql010_get.go`).
- **Existing checks to extend / coordinate with:** `gql001_introspection.go`, `gql002_introspection_bypass.go`,
  `gql004_playground.go`, `gql005_stack_trace.go`, `gql006_sensitive_fields.go`,
  `pkg/schema/harvester.go` (field-suggestion harvester), `pkg/schema/sensitivity.go`. New checks must not
  duplicate existing findings — they extend the taxonomy or report a distinct artifact.
- **Finding** (`pkg/domain/domain.go`): set the usual fields plus `Confidence`, `CWE`, `OWASP`. Fingerprint
  via `GenerateFingerprint(c.ID(), cc.Target, "<evidenceKey>")`. Several of these are INFO/LOW severity —
  set severity accurately (an INFO fingerprint is not a "finding to fail CI on", it is context).
- **Reporting:** for artifact-style output (M05 reconstructed SDL, M01 fingerprint), put the human summary in
  the Description and keep evidence bounded; large artifacts can be referenced rather than inlined.

## ⚠️ Shared SAFETY Requirements
1. **Passive-leaning, read-only.** These checks send benign reads (introspection, `__typename`, header
   probes, malformed-but-harmless queries to elicit errors). Never send mutations or injection payloads.
2. **Bounded probes.** A few requests per check (target ≤ 6). Respect the rate limiter.
3. **No secret exfiltration into output.** When a check surfaces leaked data (M03 stacktraces, M09 secrets in
   descriptions/defaults), **redact** concrete secret-looking values (reuse `authz.MaskValue`) — report the
   *location and class*, not the raw secret.
4. **Severity honesty.** Fingerprint (M01) is INFO; CORS-with-credentials (M07) is MEDIUM; missing HSTS
   (M08) is LOW. Don't inflate.

## Definition of Done (every ticket)
- [ ] Check implemented, self-registered, `go vet ./...` + `go build ./cmd/gqls` clean.
- [ ] Unit tests (`httptest.NewServer`): positive→finding, clean→PassReason, error-resilient.
- [ ] `ProbeCount`, `Fingerprint`, `References`, `Remediation`, `Confidence`, `CWE`/`OWASP` (where applicable) set.
- [ ] README "Checks" table + `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.4 row updated to "implemented".
- [ ] No duplication of an existing check's finding; secrets redacted; severity accurate.

## Why M01 first
Engine fingerprinting is a *multiplier*: Apollo vs graphql-ruby vs Hasura have different error formats,
batching semantics, introspection defenses, and CVEs. M02 (CVE mapping) is meaningless without it, and
several other checks (I07 ORM injection, error-taxonomy in M03) tailor their behavior to the detected engine.
Build the graphw00f-style discriminator once in `pkg/scanner/fingerprint`, expose the result on the run, and
let downstream checks read it.
