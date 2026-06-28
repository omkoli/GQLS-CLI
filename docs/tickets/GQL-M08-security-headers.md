# GQL-M08 — Missing Security Headers on the GraphQL Response

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P3 |
| **Severity (of finding)** | LOW |
| **Story points** | 2 |
| **Complexity** | Low |
| **Labels** | `misconfig`, `security-headers`, `owasp-api8`, `hardening` |
| **Category** | `InformationDisclosure` |
| **Depends on** | — |
| **Files** | `pkg/scanner/checks/gqlm08_security_headers.go` (+ `_test.go`) |

## Summary
Check the GraphQL endpoint's HTTP response for missing/weak hardening headers: `X-Content-Type-Options:
nosniff`, `Content-Security-Policy`, `Strict-Transport-Security` (HTTPS targets), and information-disclosing
headers that should be removed (`Server`, `X-Powered-By`). A single LOW finding lists the gaps.

## Why it matters
- Missing security headers are individually low-severity but collectively widen the blast radius (MIME
  sniffing of error/HTML responses, no HSTS on a credentialed API, verbose server banners). Reviewers and
  compliance scans expect this baseline (OWASP **API8**).

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. Use `cc.ProbeClient()`. One `POST { __typename }`
suffices to read the response headers. For an IDE-serving endpoint, also note missing CSP on the HTML
response. Only flag HSTS for `https://` targets.)

- `ID()="GQL-M08"`, `Name()="Missing Security Headers"`, `Category()=InformationDisclosure`,
  `Severity()=LOW`, `RequiresSchema()=false`.

## Detection algorithm
1. Send `POST { __typename }`; read `Response.Headers`. Increment `ProbeCount`.
2. Evaluate:
   - **Missing** `X-Content-Type-Options: nosniff`.
   - **Missing** `Content-Security-Policy` (relevant when the endpoint can return HTML, e.g. an IDE; note as
     informational for pure JSON APIs).
   - **Missing** `Strict-Transport-Security` (only for `https://` targets).
   - **Disclosing** `Server` / `X-Powered-By` present with version info.
3. **Decide — flag LOW when** ≥1 expected header is missing or a disclosing header is present. List each gap.
   Confidence `"confirmed"` (headers observed). If all present and no disclosure → no finding + PassReason.

## Finding content
- **Title:** `Missing/Weak Security Headers — <list>`
- **Description:** the specific headers missing or disclosing, with the observed values. Distinguish API-JSON
  vs HTML-serving relevance for CSP.
- **Impact:** MIME sniffing of error/HTML responses, lack of transport security enforcement, and server/
  framework version disclosure that aids targeted attacks.
- **Remediation:** set `X-Content-Type-Options: nosniff`; set HSTS on HTTPS; set a restrictive CSP for any
  HTML (IDE) responses; remove `Server`/`X-Powered-By`.
- **References:** `https://owasp.org/www-project-secure-headers/`,
  `https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/`.
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-693"` (protection mechanism failure). **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M08", cc.Target, "headers:"+sortedGaps)`.

## Acceptance criteria
- **Given** a response missing `X-Content-Type-Options` and exposing `X-Powered-By`, a LOW finding lists both.
- **Given** an `https://` target without HSTS, the finding includes HSTS; an `http://` target does **not**
  flag HSTS.
- **Given** a fully-hardened response, no finding + PassReason. No panic when headers are absent.

## Tests (`gqlm08_security_headers_test.go`)
- Handler missing nosniff + exposing `X-Powered-By` → finding listing both. Hardened handler → PassReason.
  Assert HSTS only considered for https targets (use a target string check), deterministic gap ordering.

## Safety
Read-only single probe. The finding is the header configuration itself; no data accessed. LOW severity — do
not inflate.
