# GQL-A04 — Cross-Tenant Isolation Failure

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P1 (High) |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `authz`, `multi-tenant`, `cross-tenant`, `owasp-api1`, `cwe-639`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | **GQL-A00** (identities with `Tenant`, oracle, surface graph), conceptually builds on **GQL-A01** |
| **Files** | `pkg/scanner/checks/gqla04_cross_tenant.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A04** that detects **cross-tenant isolation failures**: identity in tenant **A** can
reach data belonging to tenant **B**, either by requesting B's object IDs or by manipulating a tenant
selector (a `tenantId`/`orgId` argument, or a tenant header such as `X-Tenant-ID`). This is BOLA (A01)
specialized to the multi-tenant boundary — the highest-impact variant because it crosses an organizational
trust boundary.

## Why it matters
- Cross-tenant data access is OWASP **API1:2023** / **CWE-639** and a catastrophic SaaS failure mode
  (`SECURITY_PLATFORM_ANALYSIS.md` §2.1 GQL-A04). One tenant reading another's data is typically a
  contract-ending, headline incident.
- Distinct from A01: the attacker and victim are in *different tenants*, and the bypass vector includes
  **tenant selectors** (args/headers), not just raw object IDs.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + safety. Consume GQL-A00: `cc.Identities` (each may carry a
`Tenant` label), `surface.Fetchers`, `authz.Compare`, `authz.Classify`, `authz.RedactLeak`. Requires at
least **two identities in different tenants** — i.e. `Identity.Tenant` differs.)

- `ID()="GQL-A04"`, `Name()="Cross-Tenant Isolation Failure"`, `Category()=Authorization`,
  `Severity()=CRITICAL`, `RequiresSchema()=true`. Read-only (queries only).
- **Tenant header detection.** If identities supply tenant-scoping headers (e.g. `X-Tenant-ID`, `X-Org-Id`,
  `X-Account`), the check also tests *header manipulation*: send tenant A's token with tenant B's header value.

## Detection algorithm
1. **Preconditions.** Need ≥2 identities whose `Tenant` differs (`tenantA`, `tenantB`). If fewer than two
   distinct tenants are configured → `Skip` ("cross-tenant testing requires two identities in different
   tenants; set `tenant:` on each --identity").
2. **Discover a tenant-B object id.** As the `tenantB` identity, learn an id it legitimately owns (viewer/me
   or `<fetcher>s(first:1){ id }`). This is the *victim* object. If none can be obtained, skip that fetcher.
3. **Vector 1 — object-ID crossing.** As the `tenantA` identity, request tenant B's object by id via each
   `surface.Fetchers` candidate: `query { <field>(<idArg>: <tenantB_objId>){ id <scalar> } }`. `ProbeCount++`.
   - `diff := authz.Compare(tenantB_ownerResp, tenantA_resp, "data."+field+".id")`. **Flag CRITICAL when**
     `tenantA` gets `ClassSuccess` and `diff.SameObject == true` (tenant A received tenant B's object).
4. **Vector 2 — tenant-selector manipulation (when present).**
   - **Argument selector:** if a fetcher/root field accepts a `tenantId|orgId|accountId|workspaceId` arg,
     send it as tenant A but with tenant B's tenant value. Same `Compare` decision.
   - **Header selector:** if identities carry a tenant header, clone tenant A's request but set the tenant
     header to tenant B's value (build the request and send via tenant A's client; note the override—because
     `transport.Client.Do` only force-overrides `Authorization`, other headers set on the request are
     preserved). Flag when tenant B's data returns.
5. **Decision & confidence.** `SameObject` true + attacker Success → CRITICAL, `Confidence="confirmed"`.
   Attacker `ClassAuthDenied`/`ClassNotFound`/different-id → protected (negative). Validation/5xx/rate-limit →
   inconclusive. One finding per (vector, fetcher) that leaks; aggregate into a single finding with the list.

## Finding content (when fired)
- **Title:** `Cross-Tenant Isolation Failure — tenant <A> reached tenant <B> data via <vector>`
- **Description:** name the vector (object-id crossing / tenant-arg / tenant-header), the field used, that the
  same object id crossed the tenant boundary, and a **redacted** preview. State which tenant labels were used.
- **Impact:** a customer/tenant can read (and, if combined with A05, modify) another tenant's data — total
  multi-tenant isolation breach, mass data exfiltration across organizations, and severe compliance/contractual
  exposure.
- **Remediation:** scope **every** data access by the authenticated principal's tenant at the data layer
  (row-level security / mandatory tenant predicate); never trust a client-supplied tenant id or tenant header
  for authorization; validate that requested object ids belong to the caller's tenant; add tenant assertions
  to integration tests.
- **References:**
  - `https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://cwe.mitre.org/data/definitions/639.html`
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-639"`. **OWASP:** `"API1:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A04", cc.Target, "xtenant:"+vector+":"+field)`.
- **ReproRequest / ReproBody:** the tenant-A request that returned tenant-B data.

## Acceptance criteria
- **Given** two identities in tenants `t1`/`t2` and a server that returns `t2`'s object to a `t1` caller by id,
  **then** one CRITICAL finding fires (vector `object-id`, `SameObject` proven, redacted evidence).
- **Given** a `X-Tenant-ID` header and a server that honors the header over the token's real tenant, **then** a
  CRITICAL finding fires (vector `tenant-header`).
- **Given** the server returns 403/`FORBIDDEN` or only the caller's own tenant data, **then** no finding +
  PassReason.
- **Given** only one tenant configured, **then** `Skipped` with a clear reason.
- Malformed responses never panic; evidence redacted.

## Tests (`gqla04_cross_tenant_test.go`)
- Handler that ignores tenant scoping and returns the requested id regardless of token tenant → CRITICAL
  (object-id vector).
- Handler that trusts `X-Tenant-ID` header → CRITICAL (header vector); assert the manipulated header was sent.
- Handler that enforces tenant (returns 403 for cross-tenant id) → no finding.
- Single-tenant context → `Skipped`. Assert severity/category/fingerprint/ProbeCount, deterministic ordering.

## Safety & Ethics
Queries only. Bounded probe budget (fetchers × vectors, ≤ ~8). Uses only operator-supplied identities/tenants;
never fabricates tenant ids beyond values the operator's identities already legitimately hold. Cross-tenant
data in evidence is **redacted**.
