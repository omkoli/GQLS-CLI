# GQL-I07 — ORM / GraphQL Operator Injection (Hasura / Postgraphile)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P2 |
| **Severity (of finding)** | HIGH |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `injection`, `orm`, `hasura`, `postgraphile`, `cwe-943`, `predicate-abuse` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (points + differential oracle); **GQL-M01** (engine fingerprint) |
| **Files** | `pkg/scanner/checks/gqli07_orm_operator_injection.go` (+ `_test.go`) |

## Summary
Detect **predicate/operator abuse** in auto-generated ORM-backed GraphQL APIs (Hasura, Postgraphile, Prisma,
Postgraphile-style `where`/`_and`/`_or`/`_like`/`_ilike`/`_regex` filters). Even without classic SQLi, these
generated filter languages let an attacker bypass intended `where` constraints and read rows they should not,
by injecting additional predicates or wildcards into filter input objects.

## Why it matters
- Generated GraphQL filter languages (CWE-943) are powerful by design. A client that can extend the server's
  intended `where` (e.g. add `_or: {role: {_eq: "admin"}}`, or widen with `_like: "%"`) achieves
  authorization/filter bypass and blind data exfiltration — distinct from raw SQLi and very common on
  Hasura/Postgraphile deployments.

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. Consume `inject.Points`, `inject.BodyEquivalent`,
`authz.Classify`. Gate this check on the engine fingerprint from **GQL-M01** when available — only run the
Hasura/Postgraphile predicate set against matching engines to cut noise; if fingerprint is unknown, run a
conservative subset. Use `cc.HTTPClient`. This targets **filter/`where` input-object arguments**, identified
structurally from the schema.)

- `ID()="GQL-I07"`, `Name()="ORM/GraphQL Operator Injection"`, `Category()=Injection`, `Severity()=HIGH`,
  `RequiresSchema()=true`.

## Detection algorithm
1. Identify filter inputs: query fields with an input-object arg named/typed like a filter
   (`where`, `filter`, `*_bool_exp`, `condition`, fields containing `_eq/_neq/_gt/_lt/_like/_ilike/_in/_regex/
   _and/_or/_not`). Cap ≤ 10.
2. For each, send:
   - **control**: a benign, specific filter that returns a small known set (or the schema-default).
   - **widen**: inject a permissive predicate (`{_or: [{}, {<field>: {_is_null: false}}]}`,
     `{<text>: {_like: "%"}}`, `{_not: {<field>: {_eq: "<impossible>"}}}`) — expect a *superset*.
   - **target**: inject a predicate selecting privileged rows (`{role: {_eq: "admin"}}`,
     `{is_admin: {_eq: true}}`) — expect rows the control filter excluded.
   Increment `ProbeCount`.
3. **Decide — flag HIGH when** the widen/target predicate returns a *strict superset* of control (more/other
   rows) and the predicate was attacker-controlled (i.e. the filter language accepts arbitrary client
   predicates that override the intended scope). Confidence `"confirmed"` when a target predicate surfaces rows
   the control hid; `"firm"` for widening-only. Differential, re-tested once.
   - Negative: filter ignores injected predicates / identical result → no finding.

## Finding content
- **Title:** `ORM Operator Injection — filter predicate abuse on <rootField>`
- **Description:** the filter arg, the injected predicate, and the differential (superset / privileged rows
  surfaced). Name the engine if fingerprinted. Redact returned rows.
- **Impact:** authorization/filter bypass and blind data exfiltration via attacker-controlled predicates;
  access to rows outside the intended scope (other tenants, admin records).
- **Remediation:** restrict the exposed filter surface (allow-list permitted operators/fields per role);
  enforce row-level security / permission rules in the data layer (Hasura permissions, Postgraphile RLS) so
  predicates cannot widen access; never rely on the client to scope queries.
- **References:** `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/943.html`,
  `https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/`.
- **Confidence:** `"confirmed"`/`"firm"`. **CWE:** `"CWE-943"`. **OWASP:** `"API1:2023"`/`"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-I07", cc.Target, "ormi:"+rootField)`.

## Acceptance criteria
- **Given** a Hasura-style server that honors an injected `_or`/`_eq` predicate to return more rows, a HIGH
  finding fires; a target predicate surfacing admin rows raises confidence to confirmed.
- **Given** a server that ignores injected predicates, no finding.
- **Given** a non-matching engine fingerprint, the Hasura/Postgraphile predicate set is not run (PassReason
  notes engine gating); a conservative subset still runs when fingerprint is unknown.

## Tests (`gqli07_orm_operator_injection_test.go`)
- `httptest` handler implementing a tiny `_eq/_or/_like` filter over a fixed dataset → finding for widening +
  target predicates. Handler ignoring predicates → no finding. Engine-gating respected via a stubbed
  fingerprint on the context/run.

## Safety
Read-only predicate widening only (no writes, no SQL meta-characters beyond the generated filter language).
Bounded filters; rows redacted; engine-gated to reduce noise.
