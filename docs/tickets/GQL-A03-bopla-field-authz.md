# GQL-A03 — BOPLA / Field-Level Authorization (Excessive Data Exposure)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P0 (Highest) |
| **Severity (of finding)** | HIGH |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `authz`, `bopla`, `field-authz`, `owasp-api3`, `cwe-213`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | **GQL-A00** (identities, oracle, surface graph, sensitivity) |
| **Files** | `pkg/scanner/checks/gqla03_bopla_field_authz.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A03** for **Broken Object Property Level Authorization** (field-level authz / excessive
data exposure): even when access to the *object* is legitimate, **sensitive fields** (`email`, `ssn`,
`isAdmin`, `salary`, `phone`, internal tokens) are returned to a role that should not see them. Where A01
is "wrong object," A03 is "right object, wrong fields."

GQL-006 today only flags that sensitive fields *exist in the schema*. A03 proves they are *exposed to the
wrong identity* — the difference between a schema lint and a real finding (`SECURITY_PLATFORM_ANALYSIS.md`
§3.1 API3 row).

## Why it matters
- BOPLA is OWASP **API3:2023** / **CWE-213**. Excessive data exposure on nested edges
  (`user { paymentMethods { number } }`) is a top bug-bounty pattern (`§3.4`).
- Reuses the existing sensitivity engine (`pkg/schema/sensitivity.go`, `Schema.SensitiveFields()`) — the data
  is already classified; A03 weaponizes it into a differential test.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + safety. Consume GQL-A00: `cc.IdentityPairs()`,
`surface.SensitiveFieldsByType`, `surface.Fetchers`, `authz.Classify`, `authz.RedactLeak`.)

- `ID()="GQL-A03"`, `Name()="Field-Level Authorization (BOPLA / Excessive Data Exposure)"`,
  `Category()=Authorization`, `Severity()=HIGH`, `RequiresSchema()=true`. Read-only (queries only).

## Detection algorithm
1. **Preconditions.** `!cc.HasIdentities()` → `Skip`. Schema required (sensitivity scores come from it).
2. **Pick target objects + sensitive fields.** From `surface.Fetchers(cc.Schema)` choose object fetchers
   whose return type has ≥1 field with `SensitivityScore > 0` (via `surface.SensitiveFieldsByType`). Cap to
   **N=5** (type, fetcher) targets. For each, assemble a selection set that requests `id` + up to **K=6**
   sensitive fields (highest score first). Respect nesting: include one level of sensitive nested edges
   (e.g. `paymentMethods { number }`) when present and cheap.
3. **Obtain a legitimately-accessible object.** For the *lower-privilege* identity, first confirm it can
   access the object **at all** (object-level access is intended) — e.g. fetch its *own* object (`me`/viewer)
   or an id the operator seeded as shared. A03 is only meaningful when object access is allowed but a field
   should be hidden; if the object itself is denied, that's an A01 concern, not A03 → skip target.
4. **Differential probe per (target, identity pair).**
   - Send the sensitive selection **as the privileged/owner identity** → `ownerResp`.
   - Send the *same selection* **as the lower-privilege identity** → `attackerResp`. `ProbeCount++` each.
5. **Decide field-by-field.** For each requested sensitive field, classify how the lower-priv identity's
   response treats it:
   - **Exposed:** field present with a **non-null** value in `attackerResp` (and the response is
     `ClassSuccess`). → leak candidate.
   - **Protected:** field is `null`, omitted, or returns a field-level error
     (`(?i)not authorized|forbidden|cannot access field`) for the lower-priv identity while the owner sees it.
   **Flag HIGH when** ≥1 sensitive field is **Exposed** to a lower-privilege identity that should not see it
   (owner sees it, attacker also sees the same non-null value). Confidence `"firm"` (field exposure is strong
   but intent is heuristic — see Safety). Use `RedactLeak` for the evidence preview.
   - If the field is exposed **equally to everyone including the owner's own data only**, that may be intended;
     require the value to belong to *another* principal's object (combine with A01's `SameObject` where an id
     is available) to raise confidence to `"confirmed"`. Field exposure on the attacker's *own* object is not
     a finding.
6. **Inconclusive:** validation/5xx/rate-limit, or the field is null for everyone → record, never flag.

## Finding content (when fired)
- **Title:** `Excessive Data Exposure — sensitive field(s) returned to under-privileged role`
- **Description:** list the exposed sensitive field paths (e.g. `User.ssn`, `User.paymentMethods.number`),
  their sensitivity tags (`pii`/`financial`/`credential`), which identity received them, and a **redacted**
  preview. State whether the data belonged to another principal (confirmed) or exposure was role-differential
  on shared objects (firm).
- **Impact:** disclosure of PII / financial / credential fields to roles that should not see them — privacy
  and compliance violations (GDPR/PCI), credential leakage, and reconnaissance for further attacks.
- **Remediation:** apply authorization at the **field/property** level, not just the object level; use field
  middleware / `@auth` directives per sensitive field; return `null` or a field error for unauthorized
  principals; never rely on clients to omit sensitive fields; minimize over-fetching in resolvers.
- **References:**
  - `https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://cwe.mitre.org/data/definitions/213.html`
- **Confidence:** `"confirmed"` (another principal's data) or `"firm"` (role-differential exposure).
  **CWE:** `"CWE-213"`. **OWASP:** `"API3:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A03", cc.Target, "bopla:"+typeName+"."+strings.Join(fields,","))`.
- **ReproRequest / ReproBody:** the lower-privilege request and selection set that exposed the fields.

## Acceptance criteria
- **Given** two identities where the low-priv identity receives a non-null `ssn`/`email` that should be hidden,
  **then** one HIGH finding fires listing the exposed fields with redacted values, CWE/OWASP set, and
  appropriate Confidence.
- **Given** the low-priv identity receives `null` (or a field-level authz error) for those fields while the
  owner sees them, **then** no finding + PassReason ("field-level authz enforced for tested fields").
- **Given** the object itself is denied to the low-priv identity, **then** the target is skipped (defer to A01).
- **Given** no sensitive fields on any reachable type, **then** `PassReason` ("no sensitive fields in
  reachable object graph").
- **Given** no identities, **then** `Skipped`. Malformed/partial responses never panic; evidence is redacted.

## Tests (`gqla03_bopla_field_authz_test.go`)
- Handler that returns `{"data":{"user":{"id":"1","email":"a@b.c","ssn":"111-22-3333"}}}` for a low-priv token
  → HIGH finding; assert raw `111-22-3333` is **not** present in the finding text (redaction).
- Handler that nulls `ssn` for the low-priv token but returns it for the owner token → no finding.
- Handler returning a field error `{"errors":[{"message":"Not authorized to access field ssn"}]}` → no finding.
- Schema with no sensitive fields → PassReason, no finding.
- No identities → `Skipped`. Assert severity/category/fingerprint/ProbeCount.

## Safety & Ethics
Queries only. Bounded ≤ N×K selection, ≤ ~8 probes. **Redaction is mandatory** — sensitive values must be
masked in all finding output. Confidence is downgraded to `"firm"` when intent is heuristic (role-differential
exposure on shared objects) to avoid over-claiming; `"confirmed"` only when another principal's data is proven
leaked.
