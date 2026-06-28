# GQL-I08 — LDAP / XML / Template Injection

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P3 |
| **Severity (of finding)** | HIGH |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `injection`, `ldap`, `xml`, `ssti`, `cwe-90`, `cwe-91`, `cwe-1336` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (points + differential oracle); **GQL-I02** timing for blind SSTI |
| **Files** | `pkg/scanner/checks/gqli08_ldap_xml_template_injection.go` (+ `_test.go`) |

## Summary
Detect three less-common but high-impact injection classes behind GraphQL args: **LDAP injection** (CWE-90),
**XML/XPath/XXE injection** (CWE-91), and **server-side template injection** (SSTI, CWE-1336). Each uses a
small, targeted payload set with a differential or arithmetic-evaluation oracle.

## Why it matters
- Directory-search args (LDAP), XML-document/SOAP-bridging args (XML/XPath/XXE), and templated output args
  (email/report/render templates → SSTI → RCE) are real GraphQL sinks. SSTI in particular can reach RCE.

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. Consume `inject.Points`, `inject.BodyEquivalent`,
`inject.ErrorSignal`, and `inject.TimingOracle` (for blind SSTI). Use `cc.HTTPClient`; gate mutation points
behind `cc.AllowMutations`. This check runs three independent sub-probes per relevant point.)

- `ID()="GQL-I08"`, `Name()="LDAP / XML / Template Injection"`, `Category()=Injection`, `Severity()=HIGH`,
  `RequiresSchema()=true`.

## Detection algorithm
For each injection point (cap ≤ 15), run the applicable sub-probes:
1. **LDAP** (args like `user`, `cn`, `uid`, `search`, `group`): differential filter injection —
   `*` (wildcard, expect superset), `)(uid=*))(|(uid=*` (filter break), `*)(|(objectClass=*)`; flag when the
   wildcard/break payload returns a *superset* vs a specific control, or `inject.ErrorSignal` matches LDAP
   errors (`LDAP: error code`, `Invalid DN syntax`, `Bad search filter`). Confidence confirmed (differential)
   / firm (error-only).
2. **XML / XPath / XXE** (args feeding XML docs/queries): XPath break (`' or '1'='1`, `']|//*|//`) with
   differential; XML well-formedness probe (`<`/`]]>`) eliciting parser errors (`xmlParseEntityRef`,
   `SAXParseException`, `Premature end of file`); **safe XXE canary** — an *internal-entity* expansion only
   (`<!DOCTYPE x [<!ENTITY e "INJ">]><x>&e;</x>` reflected as `INJ`) — **never** an external/system entity
   (no file/SSRF fetch). Confidence firm.
3. **SSTI** (args reflected into templated output — email/notification/report/render): arithmetic-evaluation
   oracle across engines — `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`, `*{7*7}`; flag when the response
   contains `49` (the evaluated product) where the literal payload was sent. Blind variant: time-based via a
   template sleep where supported (use `inject.TimingOracle`). Confidence confirmed (`49` reflected) / firm
   (timing).

**Decide — flag HIGH** per class on its positive oracle. One finding per (class, point); name the class.

## Finding content
- **Title:** `<LDAP|XML/XXE|Template> Injection — <rootField> arg <path>`
- **Description:** the class, the payload family that fired, and the proof (superset diff / parser error /
  `49` evaluation / timing). Redact reflected data; mark the XXE probe as internal-entity-only.
- **Impact:** LDAP — auth bypass / directory enumeration; XML/XXE — file disclosure & SSRF (note: only
  internal-entity reflection is *tested*, but the class implies XXE risk); SSTI — often remote code execution.
- **Remediation:** LDAP — escape filter meta-characters / use parameterized search APIs; XML — disable DTDs
  and external entities, use safe parsers; SSTI — never render user input as a template; use logic-less
  templates / strict sandboxing and output encoding.
- **References:** `https://cwe.mitre.org/data/definitions/90.html`, `.../91.html`, `.../1336.html`,
  `https://owasp.org/www-community/attacks/Server-Side_Template_Injection`.
- **Confidence:** `"confirmed"`/`"firm"`. **CWE:** `"CWE-90"`/`"CWE-91"`/`"CWE-1336"` (per class).
  **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-I08", cc.Target, "i08:"+class+":"+rootField+"/"+pathKey)`.

## Acceptance criteria
- **Given** a server that evaluates `{{7*7}}`→`49`, a confirmed SSTI finding fires. Server reflecting it
  literally → no SSTI finding.
- **Given** an LDAP search that returns a superset for `*`, a confirmed LDAP finding fires.
- **Given** an XML endpoint reflecting an internal entity as `INJ`, a firm XML finding fires; the check never
  sends an external/system entity.
- Mutation points gated; no panic on malformed/non-JSON responses.

## Tests (`gqli08_ldap_xml_template_injection_test.go`)
- SSTI handler computing `7*7` → finding; literal-echo → none. LDAP wildcard-superset handler → finding.
  XML internal-entity reflection handler → finding; assert no external-entity payload is ever sent.

## Safety
SSTI uses **arithmetic-only** payloads (no RCE gadgets). XXE uses **internal-entity-only** canaries (no file
or network fetch). LDAP payloads are read-only filter probes. Bounded; mutation points gated; data redacted.
