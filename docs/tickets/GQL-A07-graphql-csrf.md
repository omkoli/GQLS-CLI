# GQL-A07 — GraphQL CSRF (State Change via GET / Simple Content-Type)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P0 (Highest) |
| **Severity (of finding)** | HIGH |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `authz`, `csrf`, `owasp-api8`, `cwe-352`, `apollo`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | — (no GQL-A00 dependency) |
| **Files** | `pkg/scanner/checks/gqla07_graphql_csrf.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A07** that detects **GraphQL CSRF**: the endpoint accepts state-changing operations via
request shapes a browser can forge cross-site **without a preflight** — namely `GET` requests and
`POST` with a "simple" `Content-Type` (`text/plain`, `application/x-www-form-urlencoded`,
`multipart/form-data`) — and without requiring a CSRF token / `application/json` content-type. This is exactly
the class Apollo Server's `csrfPrevention` exists to stop (`SECURITY_PLATFORM_ANALYSIS.md` §3.4, Appendix B).

This extends GQL-010 (which only flags *GET queries* as info disclosure) into the **CSRF-on-mutations** finding.

## Why it matters
- If a mutation executes from a forged cross-site request with the victim's cookies, an attacker page can
  perform actions as the victim. OWASP **API8:2023** / **CWE-352**.
- P0, low-complexity, high-credibility. No identity model required — it tests *request acceptance*, not
  cross-identity data.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + safety. Probe with `cc.ProbeClient()`. No schema strictly required;
if a schema is present, pick a *non-destructive, no-required-arg* mutation to probe — otherwise use a
**read-only** mutation-shaped probe that does not change state, see Safety. Reuse the GET-query construction
idea from `gql010_get.go`.)

- `ID()="GQL-A07"`, `Name()="GraphQL CSRF (State Change via GET / Simple Content-Type)"`,
  `Category()=Authorization`, `Severity()=HIGH`, `RequiresSchema()=false`.

## Detection algorithm
For safety this check proves the **transport acceptance** of CSRF-able request shapes using an
**introspection / no-op query** as the canary (a query is non-mutating), and separately reports whether
*mutations* are reachable over those shapes when a safe, side-effect-free mutation is available. The positive
signal is "the server executes operations sent in a browser-forgeable shape," which is the CSRF precondition.

1. **Baseline.** Confirm the normal `POST application/json` path works (`{ __typename }`). `ProbeCount++`.
2. **Vector A — GET with query param.** Send `GET <target>?query={__typename}` (and, when a safe mutation is
   known, `?query=mutation...`). No `Content-Type`. `ProbeCount++`. Reuse `gql010`'s GET builder.
3. **Vector B — POST `text/plain`.** Send the JSON body but with header `Content-Type: text/plain`.
   `ProbeCount++`.
4. **Vector C — POST `application/x-www-form-urlencoded`.** Send `query=<urlencoded doc>` (form body) with
   that content-type. `ProbeCount++`.
5. **CSRF-token / same-origin enforcement probe.** Note whether responses require a CSRF token header
   (e.g. server rejects without `X-CSRF-Token`/`Apollo-Require-Preflight`) or reject non-preflightable
   content-types. Apollo's `csrfPrevention` returns an error like
   `(?i)this operation has been blocked as a potential csrf|preflight|non-preflighted`.
6. **Decide — flag HIGH when** any of Vectors A/B/C returns HTTP 200 with a valid `data` object **and** the
   server did **not** emit a CSRF/preflight rejection — i.e. operations execute over a browser-forgeable shape
   with no CSRF defense. Severity stays HIGH; **escalate the Description** (and confidence to `"confirmed"`)
   when a *mutation* is shown reachable over a CSRF-able vector; `"firm"` when only queries are demonstrated
   (query CSRF is lower impact but still proves the missing defense).
7. **Negative.** All CSRF-able vectors are rejected (non-200, or CSRF/preflight error, or only
   `application/json` accepted) → no finding; `PassReason` ("server enforces JSON content-type / CSRF
   preflight; browser-forgeable request shapes were rejected"). Record all vectors as `PassProbes`.

## Finding content (when fired)
- **Title:** `GraphQL CSRF — operations accepted over browser-forgeable request shapes`
- **Description:** list which vectors succeeded (GET / `text/plain` / form-encoded), whether a mutation or only
  a query was demonstrated, and that no CSRF token / preflight was required. Include the accepted request shape.
- **Impact:** a malicious web page can cause a victim's browser to submit authenticated GraphQL operations
  (including mutations) cross-site using the victim's cookies/session, performing actions as the victim
  (CSRF) — account changes, data modification, privilege actions.
- **Remediation:** enable CSRF prevention (Apollo `csrfPrevention: true`); require `application/json` and
  reject "simple" content-types for operations; require a custom header (e.g. `Apollo-Require-Preflight` /
  `X-CSRF-Token`) that forces a CORS preflight; never accept mutations over `GET`; use `SameSite` cookies and
  anti-CSRF tokens for cookie-authenticated GraphQL.
- **References:**
  - `https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/`
  - `https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html`
  - `https://www.apollographql.com/docs/apollo-server/security/cors#preventing-cross-site-request-forgery-csrf`
  - `https://cwe.mitre.org/data/definitions/352.html`
- **Confidence:** `"confirmed"` (mutation over CSRF vector) / `"firm"` (query only). **CWE:** `"CWE-352"`.
  **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A07", cc.Target, "graphql_csrf")`.
- **ReproRequest / ReproBody:** the accepted CSRF-able request (e.g. the GET URL or `text/plain` POST).

## Acceptance criteria
- **Given** a server that returns `data` for `GET ?query={__typename}` and for `text/plain` POSTs with no CSRF
  error, **then** one HIGH finding fires listing the accepted vectors, CWE/OWASP set.
- **Given** a server that returns an Apollo CSRF/preflight error for those vectors (and only accepts
  `application/json`), **then** no finding + PassReason with all vectors recorded.
- **Given** the JSON baseline itself fails, **then** no finding + PassReason (endpoint unreachable).
- No panic on non-JSON/HTML responses; deterministic vector ordering (baseline → A → B → C).

## Tests (`gqla07_graphql_csrf_test.go`)
- Handler accepting GET and `text/plain` with a `data` response → HIGH finding; assert accepted vectors listed.
- Handler returning `{"errors":[{"message":"This operation has been blocked as a potential CSRF"}]}` for those
  vectors → no finding.
- Handler that accepts only `application/json` (415/400 for others) → no finding.
- Assert severity/category/fingerprint/ProbeCount and vector ordering.

## Safety & Ethics
Uses **non-mutating** canary operations (`__typename`/introspection) to demonstrate transport acceptance by
default; a real mutation is only sent over a CSRF vector when a **safe, no-required-arg, non-destructive**
mutation is identifiable (reuse the destructive-name exclusion list from A05) — otherwise the finding is based
on query acceptance + the absence of CSRF/preflight enforcement. Bounded to ~4 probes. No state change beyond
what a safe mutation (if any) performs.
