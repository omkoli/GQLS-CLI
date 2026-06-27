# GQL-A06 — Auth Bypass via Aliases / Batching (Rate-Limit & Brute-Force Bypass)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P0 (Highest) |
| **Severity (of finding)** | HIGH |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `authz`, `aliases`, `batching`, `brute-force`, `owasp-api4`, `cwe-307`, `portswigger`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | — (does **not** require GQL-A00; optionally uses `surface` to find a login op) |
| **Files** | `pkg/scanner/checks/gqla06_alias_auth_bypass.go` (+ `_test.go`) |

## Summary
Implement check **GQL-A06** that detects whether per-request rate limiting / brute-force protection on an
authentication-style operation (`login`, `verifyOtp`, `resetPassword`, `redeemCode`) can be **bypassed by
aliasing the operation N times in a single request** — the single most-cited PortSwigger GraphQL attack
(`SECURITY_PLATFORM_ANALYSIS.md` §3.3). One HTTP request = N login attempts.

This differs from GQL-009 (generic batch) and GQL-D01 (alias *amplification* DoS): A06 specifically targets
**authentication throttling**, proving N credential attempts execute in one request.

## Why it matters
- Aliasing `login` ×100 in one document bypasses request-count rate limits and OTP/MFA lockouts → credential
  stuffing, OTP brute-force, coupon/code brute-force. OWASP **API4:2023** / **CWE-307**.
- P0, low-complexity, high-credibility: a reviewer's first "does it miss the basics?" check.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + safety. This check needs no identities; it probes the auth endpoint
directly with `cc.ProbeClient()` / `cc.UnauthenticatedClient`. Optionally use `surface.PrivilegedOps` or a
schema scan to locate an auth-style mutation; otherwise accept an operator-provided op name.)

- `ID()="GQL-A06"`, `Name()="Auth Bypass via Aliases (Rate-Limit/Brute-Force Bypass)"`,
  `Category()=Authorization`, `Severity()=HIGH`, `RequiresSchema()=false` (richer with schema).

## Detection algorithm
1. **Locate an auth-style operation.** Priority: (a) operator-provided via flag (e.g.
   `--authz-login-op 'login(email:$e, password:$p)'`); (b) schema mutation whose name matches
   `(?i)login|signin|authenticate|verify.?otp|verify.?code|reset.?password|redeem|token|mfa|2fa`; (c) if
   none and no curl seed → `Skip` ("no authentication-style operation found to test alias brute-force; supply
   one with --authz-login-op"). Use **deliberately wrong credentials** (a benign non-existent user / obviously
   invalid OTP) so no real account is affected.
2. **Control probe (1×).** Send the operation **once** with wrong creds. Confirm the endpoint is live and learn
   the "single-attempt" response shape/class (expect an auth-failure error, NOT a lockout). `ProbeCount++`.
   If the single attempt is already rate-limited/blocked, record and continue cautiously.
3. **Aliased probe (N×, bounded).** With **N=20** (bounded — see Safety; far below DoS levels), build one
   document aliasing the operation N times, each with a *distinct wrong* credential value:
   `mutation { a0: login(...wrong0) { __typename } a1: login(...wrong1) ... a19: login(...wrong19) { ... } }`.
   Send **once**. `ProbeCount++`.
4. **Decide — flag HIGH when ALL hold:**
   - the aliased response is HTTP 200 with a `data` object containing **all N alias keys** (`a0..a19`),
     proving the server *executed every aliased attempt* in one request; **and**
   - the server did **not** reject/limit the multi-alias auth document (no error matching
     `(?i)too many|rate.?limit|throttl|locked|alias|complexity|cost|attempts`); **and**
   - none of the aliased results indicate a global lockout triggered *before* executing all N (i.e. the
     protection is per-request, not per-attempt).
   Confidence `"firm"` (execution of N attempts is proven; whether real throttling exists is inferred from the
   absence of a limit response). Raise to `"confirmed"` if the control showed throttling kicks in across
   *separate* requests but the aliased single request still executed all N.
5. **Negative / inconclusive.** Aliased request rejected, limited, or only partially executed (missing alias
   keys) → no finding; `PassReason` ("server limited or rejected the N-alias auth document — alias/operation
   limiting appears enforced"). Record both probes as `PassProbes`.

## Finding content (when fired)
- **Title:** `Authentication Rate-Limit Bypass via Aliases`
- **Description:** state that N aliased `<op>` attempts executed in a single request (all alias keys echoed),
  bypassing per-request throttling; name the op and the observed alias-key count. Use clearly-invalid
  credentials in the repro.
- **Impact:** attackers can perform brute-force / credential-stuffing / OTP-guessing at N× the intended rate
  per request, defeating rate limits and account-lockout protections; enables account takeover and code/coupon
  brute-forcing.
- **Remediation:** enforce a maximum alias/operation count per document at the validation layer
  (`graphql-no-alias`, operation-cost limits); apply **attempt-based** (not request-based) rate limiting and
  lockouts keyed on the authentication action itself; deduplicate repeated operations per request.
- **References:**
  - `https://portswigger.net/web-security/graphql/what-is-graphql#bypassing-rate-limiting-using-aliases`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/`
  - `https://cwe.mitre.org/data/definitions/307.html`
- **Confidence:** `"firm"` / `"confirmed"`. **CWE:** `"CWE-307"`. **OWASP:** `"API4:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A06", cc.Target, "alias_auth_bypass:"+op)`.
- **ReproRequest / ReproBody:** the aliased request and body (invalid creds).

## Acceptance criteria
- **Given** a server that executes all 20 aliased `login` attempts and echoes `a0..a19`, **then** one HIGH
  finding fires with `ProbeCount >= 2`, CWE/OWASP set.
- **Given** a server that returns `{"errors":[{"message":"Too many operations"}]}` or limits the document,
  **then** no finding + PassReason.
- **Given** no auth-style op can be located and none supplied, **then** `Skipped` with reason.
- **Given** the control probe shows the endpoint down, **then** no finding + PassReason.
- Invalid credentials are always used (assert the probe never sends a real/configured credential).

## Tests (`gqla06_alias_auth_bypass_test.go`)
- Handler that counts `a0..a19` and returns a `data` object with all keys → finding.
- Handler returning a rate-limit/too-many error for the aliased doc → no finding.
- Schema-only path: a `login` mutation discovered from schema → op selected; no schema + no flag → `Skipped`.
- Assert severity/category/fingerprint/ProbeCount, and that credentials used are clearly invalid sentinels.

## Safety & Ethics
N fixed at **20** (well below DoS thresholds; this is an authz/throttling test, not a DoS). Two requests total.
**Always uses invalid, non-existent credentials** — never a real or operator-configured credential, and never
targets a real username. Detects *execution of N attempts*, not actual account compromise.
