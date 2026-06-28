# GQL-M07 — CORS Misconfiguration on the GraphQL Endpoint

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P1 |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `misconfig`, `cors`, `owasp-api8`, `cwe-942` |
| **Category** | `InformationDisclosure` |
| **Depends on** | — |
| **Files** | `pkg/scanner/checks/gqlm07_cors_misconfiguration.go` (+ `_test.go`) |

## Summary
Detect dangerous **CORS** configuration on the GraphQL endpoint: `Access-Control-Allow-Origin` reflecting an
arbitrary `Origin` (or `*`) **together with** `Access-Control-Allow-Credentials: true`, which lets any website
read authenticated GraphQL responses with the victim's cookies. Also flag overly-permissive origins and
`null`-origin acceptance.

## Why it matters
- ACAO-reflects-Origin + ACAC:true is a textbook cross-origin data-theft misconfiguration (CWE-942 / OWASP
  **API8**). For a cookie-authenticated GraphQL API it is equivalent to handing the schema's data to any
  malicious page the victim visits.

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. Use `cc.ProbeClient()`. Inspect **response headers**
(`Response.Headers`) under different `Origin` request headers. Send both a preflight `OPTIONS` and a simple
`POST` to capture ACAO/ACAC/ACAM/ACAH behavior.)

- `ID()="GQL-M07"`, `Name()="CORS Misconfiguration"`, `Category()=InformationDisclosure`,
  `Severity()=MEDIUM`, `RequiresSchema()=false`.

## Detection algorithm
1. Send requests with a crafted, attacker-controlled `Origin` (e.g. `https://gqls-evil.example`) — a preflight
   `OPTIONS` and a normal `POST { __typename }`. Also try `Origin: null` and a subdomain-suffix trick
   (`https://target.com.gqls-evil.example`). Increment `ProbeCount` (cap ≤ 5).
2. Read response headers: `Access-Control-Allow-Origin` (ACAO), `Access-Control-Allow-Credentials` (ACAC),
   `Vary: Origin`.
3. **Decide — severity by pattern:**
   - **MEDIUM/HIGH:** ACAO **reflects** the attacker Origin (or is `*` while ACAC is true is *invalid per spec
     but some stacks emit it*) **and** ACAC `true` → cross-origin credentialed data theft. (Flag MEDIUM; note
     HIGH if reflection + credentials confirmed.)
   - **LOW:** ACAO `*` without credentials (data is readable cross-origin but only unauthenticated), or
     `null` origin accepted.
   - **None:** ACAO absent or restricted to a fixed trusted origin → no finding.
   Confidence `"confirmed"` (headers observed).

## Finding content
- **Title:** `CORS Misconfiguration — <reflected origin | wildcard | null> [+ credentials]`
- **Description:** the request `Origin` sent and the ACAO/ACAC values returned; explain why it permits
  cross-origin (credentialed) reads. Include the exact header values.
- **Impact:** any malicious website the victim visits can read authenticated GraphQL responses using the
  victim's session, exfiltrating their data.
- **Remediation:** do not reflect arbitrary origins; allow-list exact trusted origins; never combine ACAO `*`
  or origin-reflection with `Access-Control-Allow-Credentials: true`; reject `Origin: null`; set `Vary:
  Origin`.
- **References:** `https://cwe.mitre.org/data/definitions/942.html`,
  `https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/`,
  `https://portswigger.net/web-security/cors`.
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-942"`. **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M07", cc.Target, "cors:"+pattern)`.

## Acceptance criteria
- **Given** a server that reflects the attacker `Origin` in ACAO and sets ACAC `true`, a MEDIUM (or HIGH)
  finding fires with the exact headers.
- **Given** ACAO `*` without credentials, a LOW finding fires.
- **Given** ACAO restricted to a fixed origin (or absent), no finding + PassReason.
- No panic when CORS headers are missing.

## Tests (`gqlm07_cors_misconfiguration_test.go`)
- Handler reflecting `Origin` + ACAC true → finding (credentialed). Handler with ACAO `*` only → LOW.
  Handler with fixed allow-list origin → no finding. Assert exact header capture and severity mapping.

## Safety
Read-only header probes with a synthetic Origin. No data exfiltration performed — the finding is the header
configuration itself. Bounded probes.
