# GQL-A08 — JWT Authentication-Token Weaknesses

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P1 (High) |
| **Severity (of finding)** | HIGH |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `authz`, `authn`, `jwt`, `cwe-347`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | — (uses the configured `Authorization` bearer token; optionally a GQL-A00 identity) |
| **Files** | `pkg/scanner/checks/gqla08_jwt_weaknesses.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A08** that inspects and tamper-tests the **JWT bearer token** supplied to the scanner
(via `--header 'Authorization: Bearer …'`, a curl seed, or a GQL-A00 identity) for classic verification
weaknesses: **`alg:none` acceptance**, **weak/guessable HMAC secret**, **missing/oversized `exp`**, and
**`kid` header injection**. A server that accepts a forged token grants authentication bypass.

## Why it matters
- JWT verification flaws (**CWE-347**) are a direct authentication-bypass / privilege-escalation primitive: if
  the server accepts an `alg:none` or weak-secret-signed token, an attacker mints arbitrary identities
  (`SECURITY_PLATFORM_ANALYSIS.md` §2.1 GQL-A08).
- Cheap and self-contained: it operates on a token the operator already provides; it does not need the full
  identity model.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + safety. No new schema needs. Obtain the source token in priority
order: a GQL-A00 identity's `Authorization` header → `cc.HTTPClient`'s configured header / `cc.ParsedCurl`
headers → `--header`. Send probes with a **bare** client carrying *only* the forged token, so the genuine
token isn't auto-injected — note `transport.Client.Do` force-overrides `Authorization`, so build a dedicated
`transport.NewClient(timeout, rps, map[string]string{"Authorization": forged})` per probe, or reuse
`cc.UnauthenticatedClient` with the header set on the *request* but be aware the configured client would
override it — hence a purpose-built client is required.)

- `ID()="GQL-A08"`, `Name()="JWT Authentication-Token Weaknesses"`, `Category()=Authorization`,
  `Severity()=HIGH`, `RequiresSchema()=false`.

## Detection algorithm
1. **Extract & decode the token.** Find a bearer token in the configured headers. If none is a JWT
   (three base64url segments `h.p.s`) → `Skip` ("no JWT bearer token supplied; provide one via --header /
   --identity to run JWT checks"). Base64url-decode header + payload (no signature verification). Capture
   `alg`, `kid`, `exp`, claims. **Do not log the raw token** — redact in all output.
2. **Establish an authenticated baseline.** Send a benign authenticated query (`{ __typename }`, or `{ me {
   id } }` if available) with the **genuine** token; confirm it is accepted (`ClassSuccess`/non-401). This is
   the control proving the token works. `ProbeCount++`. If the genuine token is already rejected, record and
   continue (weaknesses are still testable but baseline is noted).
3. **Forge & test (each forged token sent once):**
   - **`alg:none`:** re-encode header with `{"alg":"none","typ":"JWT"}`, keep payload (optionally bump a role
     claim like `role:admin`/`isAdmin:true` if present — but keep it benign), empty signature. Send.
   - **`alg:none` casing variants:** also try `None`/`NONE`/`nOnE` (libraries that only string-match `"none"`).
   - **Weak HMAC secret:** if `alg` is `HS256/HS384/HS512`, re-sign the (optionally role-elevated) payload with
     a small **built-in wordlist** of common secrets (`secret`, `password`, `changeme`, `jwt`, `key`,
     `your-256-bit-secret`, `admin`, empty string — ≤ ~12 entries). Send each (bounded).
   - **`exp` analysis (passive):** flag if the genuine token has **no `exp`** claim, or an `exp` far in the
     future (e.g. > 1 year). This is analysis of the supplied token, not a forge — no extra request.
   - **`kid` injection (best-effort, low-confidence):** if a `kid` header exists, send one probe with a
     `kid` payload attempting path/SQL trickery (`../../dev/null`, `' OR '1'='1`) re-signed with empty/weak
     secret. Treat acceptance as evidence only if the response is `ClassSuccess`.
   `ProbeCount++` per forged request. Cap total forged requests to **≤ 16**.
4. **Decide.** For each forged token, classify the response with `authz.Classify` (or 401/403 check):
   **Flag HIGH when** a forged token (alg:none, or a weak-secret re-sign, or kid-injection) yields a
   **non-rejected** authenticated response (`ClassSuccess`, or any 200 with `data` and no auth error) — the
   server accepted a token the attacker could mint. Confidence `"confirmed"` for alg:none / recovered-secret
   acceptance; `"firm"` for kid-injection. The **missing/oversized `exp`** case is a separate
   `"firm"` finding (token-hygiene) even without a forged-acceptance.
5. **Negative / inconclusive.** All forged tokens rejected (401/403/auth error) → no forge finding; report
   only the `exp` hygiene observation if applicable, else `PassReason` ("supplied JWT rejected all tamper
   variants; signature verification appears correct"). Record probes (with **redacted** tokens) as `PassProbes`.

## Finding content (when fired)
- **Title:** `JWT Verification Weakness — <alg:none | weak HMAC secret | kid injection | missing exp>`
- **Description:** name the specific weakness, which forged variant was accepted (alg value / recovered secret
  name — **not** the full secret if it matters, or do disclose the wordlist hit since it's public), and the
  decoded header/claims with sensitive values **redacted**. Never print the genuine signature or full token.
- **Impact:** an attacker can forge valid authentication tokens for arbitrary users/roles (including admin),
  achieving full authentication bypass and privilege escalation against the GraphQL API.
- **Remediation:** reject `alg:none` and enforce an allow-list of strong algorithms; use a high-entropy secret
  / proper asymmetric keys (never a dictionary word); validate `exp`/`nbf`/`iat` and keep lifetimes short;
  validate/whitelist `kid` against known keys and never use it to load keys from untrusted paths; rotate keys.
- **References:**
  - `https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html`
  - `https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/`
  - `https://cwe.mitre.org/data/definitions/347.html`
- **Confidence:** `"confirmed"` / `"firm"`. **CWE:** `"CWE-347"`. **OWASP:** `"API2:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A08", cc.Target, "jwt:"+weakness)`.
- **ReproRequest / ReproBody:** the accepted forged-token request (token redacted by the reporter).

## Acceptance criteria
- **Given** a server that accepts an `alg:none` token (200 + data), **then** one HIGH finding fires
  (Confidence `"confirmed"`, CWE-347), with the genuine token redacted in all output.
- **Given** a server signed with the secret `"secret"` that accepts a wordlist re-sign, **then** a HIGH finding
  names the weak-secret weakness.
- **Given** a token with no `exp`, **then** a `"firm"` token-hygiene finding (even if forgery is rejected).
- **Given** a server that rejects all forged variants, **then** no forge finding + PassReason.
- **Given** no JWT supplied, **then** `Skipped`. No raw token ever appears in findings/logs (assert in tests).

## Tests (`gqla08_jwt_weaknesses_test.go`)
- Build a genuine HS256 token (test secret), stand up a handler that *naively* accepts `alg:none` → expect
  alg:none finding; assert the genuine token string is absent from the rendered finding.
- Handler that verifies HS256 against `"secret"` → wordlist re-sign accepted → weak-secret finding.
- Token without `exp` → hygiene finding.
- Handler that correctly verifies (rejects all forgeries) → no finding + PassReason.
- Non-JWT `Authorization` header → `Skipped`. Assert ProbeCount cap (≤16), severity/category/fingerprint.

## Safety & Ethics
Operates only on the **operator-supplied** token (the operator already holds it). Forged tokens carry only
benign role bumps and are sent a **bounded** number of times (≤16). Genuine token and signatures are
**redacted** everywhere. No credential brute-force against accounts — only signature/secret tampering on a
token the operator provided. Wordlist is tiny and for *detection*, not exhaustive cracking.
