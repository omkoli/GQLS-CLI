# GQL-D05 — Array/List Argument & Unbounded Pagination Abuse

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-DOS — GraphQL DoS Detection Suite |
| **Priority** | P1 (High) |
| **Severity (of finding)** | HIGH |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `dos`, `pagination`, `owasp-api4`, `schema-driven`, `checks` |
| **Category** | `DenialOfService` |
| **Files** | `pkg/scanner/checks/gqld05_list_argument_abuse.go` (+ `_test.go`) |

## Summary
Implement check **GQL-D05** that detects **missing amount/pagination limits**. GraphQL list fields that
accept `first`/`last`/`limit`/`count`/`take` (or large list-valued arguments) without an enforced maximum let
a client request enormous result sets in one query, exhausting memory/DB/serialization resources. This is the
OWASP GraphQL Cheat Sheet "Amount limiting" control.

## Why it matters
- Requesting `first: 100000` on an unbounded list field is a one-line, fully-legitimate-looking DoS.
- Schema-driven: it scales coverage across the whole API surface instead of one hard-coded field.
- Maps to **OWASP API4:2023** ("Unrestricted Resource Consumption") and GraphQL Cheat Sheet.

## Engineering Context
(See `EPIC-GQL-DOS.md` shared context + safety. Implement `checks.Check`, register in `init()`, probe via
`cc.ProbeClient()`, fingerprint key per field, e.g. `"pagination_"+fieldName`.)

- `ID()="GQL-D05"`, `Name()="Unbounded List/Pagination Argument"`, `Category()=DenialOfService`,
  `Severity()=HIGH`, **`RequiresSchema()=true`** (needs the schema to find paginated fields safely).

## Detection algorithm
1. **Find candidate fields from `cc.Schema`.** Walk `s.QueryFields()`; a candidate is any field whose return
   type unwraps to a `LIST` (connection or plain list) **and** that has an integer-typed argument named
   (case-insensitive) one of: `first`, `last`, `limit`, `count`, `take`, `pageSize`, `perPage`, `size`.
   Select up to **2** candidates (deterministic: first by schema order) to bound request volume.
2. For each candidate field+arg:
   - **Control probe:** request a *small* page (`<arg>: 1`), selecting only `{ __typename }` (or the
     connection's `edges { __typename }` / a single scalar leaf) so the response is tiny. Record body size `Sc`
     and status. Skip the field if the control errors (likely needs other required args).
   - **Abuse probe (bounded):** request `<arg>: 10000` (constant `maxPageProbe = 10000` — **not** millions;
     see Safety). Same minimal selection. Record body size `Sa`, latency, status.
   - **Decision — flag HIGH for that field when:**
     - abuse probe returns HTTP 200 with `data` and is **not** a limit error
       (`(?i)maximum|exceeds|too large|limit|must be (less|fewer)|cannot request more than`); **and**
     - evidence the large page was honored: `Sa >= 5 * Sc` (response grew with the requested amount) **or**
       the response reports a returned-count near 10000; **OR**
     - abuse probe times out / 5xx while the control was fast 200.
   - Otherwise record both probes as `PassProbes` for that field.
3. If no field fired, `PassReason = "All paginated fields enforced a maximum page size (or rejected
   first:10000)."` If `cc.Schema` exposed no paginated fields, `PassReason = "No list fields with a
   recognized pagination argument were found in the schema."`

## Finding content (per vulnerable field)
- **Title:** `Unbounded Pagination on "<field>" (arg "<arg>")`
- **Description:** report the field/arg, the small vs large response sizes (Sc vs Sa), and that `<arg>: 10000`
  was honored without a max-page rejection.
- **Impact:** a single request can force the server to load, serialize, and transfer a very large dataset —
  memory/DB/bandwidth exhaustion and slow-loris-style amplification; also enables bulk data scraping.
- **Remediation:** enforce a server-side maximum page size (e.g. cap `first`/`limit` ≤ 100) and reject or clamp
  larger values; prefer cursor pagination with a hard ceiling; add query-cost analysis that weights list sizes.
- **References:**
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html` (Amount Limiting)
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
  - `https://graphql.org/learn/pagination/`
- **Fingerprint:** `GenerateFingerprint("GQL-D05", cc.Target, "pagination_"+fieldName)` (one per field).

## Acceptance criteria
- **Given** a schema with a list field `users(first: Int)` and a server that returns a large `data` payload
  for `first: 10000`, **then** one HIGH finding for that field fires with distinct fingerprint.
- **Given** a server that returns `{"errors":[{"message":"first must be less than 100"}]}` for the abuse
  probe, **then** no finding for that field + PassProbe recorded.
- **Given** `cc.Schema == nil`, **then** the check is skipped by the runner (RequiresSchema=true) — verify the
  check does not panic if invoked with nil schema in a unit test (defensive guard).
- **Given** no paginated fields in schema, **then** no finding + descriptive PassReason.
- Each finding carries the field name in Title and a field-specific fingerprint.

## Tests (`gqld05_list_argument_abuse_test.go`)
- Build a small `*schema.Schema` fixture with a `users(first: Int): [User]` query field.
- Handler: echo a response whose size scales with the requested `first` value → expect finding.
- Handler: return a "first must be ≤ 100" error for large values, small page otherwise → expect no finding.
- Candidate selection bounded to ≤ 2 fields; verify only 2 fields probed when schema has many.

## Safety
`maxPageProbe = 10000` (constant — deliberately moderate, not millions). At most 2 candidate fields × 2 probes
= 4 requests. Minimal selection sets keep response sizes small unless the *server* chooses to honor the amount
(which is exactly the signal). Never escalate the requested amount on retry.
