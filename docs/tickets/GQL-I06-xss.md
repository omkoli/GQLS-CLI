# GQL-I06 — Stored/Reflected XSS Surfaced Through GraphQL

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P2 |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 3 |
| **Complexity** | Medium |
| **Labels** | `injection`, `xss`, `cwe-79`, `reflection` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (injection points) |
| **Files** | `pkg/scanner/checks/gqli06_xss.go` (+ `_test.go`) |

## Summary
Detect where GraphQL **surfaces XSS payloads unencoded** — chiefly through **error reflection** (a payload
echoed verbatim in an error message) and through **HTML-typed / rich-text fields** that store and return markup
without sanitization. GraphQL itself is JSON, so the risk is the downstream HTML sink; the scanner flags
unescaped reflection that would execute in a browser context.

## Why it matters
- XSS (CWE-79) via GraphQL is common where error messages, search echoes, or rich-text fields (`bio`,
  `description`, `comment`, `content`) are rendered into HTML by a client without encoding. The GraphQL layer
  is where the unsanitized payload enters and re-emerges.

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. Consume `inject.Points`. Use `cc.HTTPClient`; gate
mutation (stored-XSS) points behind `cc.AllowMutations` and the A05 capture/restore discipline. This check
reasons about the **raw JSON response bytes** — whether the payload is reflected unescaped — not about browser
execution.)

- `ID()="GQL-I06"`, `Name()="Cross-Site Scripting (Reflected/Stored via GraphQL)"`, `Category()=Injection`,
  `Severity()=MEDIUM`, `RequiresSchema()=true`.

## Detection algorithm
1. Use a unique, inert marker payload, e.g. `gqls<svg/onload=alert(1)>x<"'` with a random nonce so reflections
   are unambiguous and self-attributable.
2. **Reflected (query / error path):** inject the marker at each query injection point; inspect the response
   body (data **and** error messages). Flag when the marker appears **unescaped** (raw `<`, `>`, `"` rather
   than `<`/`&lt;`) in a context that a client would render as HTML (error `message`, or a field typed as
   `String`/`HTML` echoed back). JSON-escaped (`<`) reflection is **not** a finding (correctly encoded).
3. **Stored (mutation path, opt-in):** when `cc.AllowMutations`, set an innocuous rich-text field to the
   marker via the A05 write-cycle (capture→write→read-back→restore); flag when a subsequent read returns the
   marker unescaped. Never target sensitive fields; always restore.
4. **Decide — flag MEDIUM when** the marker is reflected with HTML-significant characters unescaped in a
   renderable sink. Confidence `"firm"` (the scanner cannot prove the client renders it as HTML, only that the
   payload survives unencoded). Negative: marker absent or fully escaped → no finding.

## Finding content
- **Title:** `Potential XSS — unencoded reflection of <marker> via <rootField> arg <path>`
- **Description:** where the payload was reflected (error message / field), that HTML-significant characters
  were returned unescaped, and the (truncated) reflected snippet. Note this is exploitable only if a client
  renders the value as HTML.
- **Impact:** session theft, account takeover, and arbitrary actions in the victim's browser when the
  reflected value is rendered as HTML by a consuming client.
- **Remediation:** context-aware output encoding at the HTML sink; sanitize rich-text on input/output
  (allow-list HTML); set `Content-Type` correctly; apply CSP; do not echo raw input in error messages.
- **References:** `https://owasp.org/www-community/attacks/xss/`,
  `https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/79.html`.
- **Confidence:** `"firm"`. **CWE:** `"CWE-79"`. **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-I06", cc.Target, "xss:"+rootField+"/"+pathKey)`.

## Acceptance criteria
- **Given** a server that echoes the injected marker unescaped in an error message, one MEDIUM finding fires.
- **Given** a server that returns the marker JSON-escaped (`<svg…`), no finding (correct encoding).
- **Given** stored path with `AllowMutations=true`, a write→read-back round-trip that returns the marker
  unescaped fires; the original value is restored. Without `AllowMutations`, the stored path is skipped.
- No panic on non-JSON/binary responses.

## Tests (`gqli06_xss_test.go`)
- Handler echoing the marker raw in `errors[].message` → finding. Handler returning it `<`-escaped →
  no finding. Stored handler (in-memory field) returning the marker on read-back → finding + restore observed.
- Assert severity MEDIUM, confidence firm, fingerprint, deterministic ordering.

## Safety
Inert, self-attributing marker (no real script execution server-side). Stored path is write-gated and uses
capture→restore; only innocuous fields. Reflected snippets truncated/redacted in evidence.
