# GQL-B04 — User/Identifier Enumeration via Differential Errors & Timing

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-BIZLOGIC |
| **Priority** | P2 |
| **Severity (of finding)** | MEDIUM |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `business-logic`, `enumeration`, `owasp-api1`, `differential`, `timing` |
| **Category** | `Authorization` |
| **Depends on** | `pkg/scanner/authz` oracle; (optional) `inject.TimingOracle` from GQL-I09 |
| **Files** | `pkg/scanner/checks/gqlb04_user_enumeration.go` (+ `_test.go`) |

## Summary
Detect **user/identifier enumeration**: operations (login, password-reset, signup, `userExists`) that reveal
whether an account exists through **differential responses** — distinct error messages/codes, distinct success
shapes, or a **timing** difference (e.g. password hashing only runs for existing users) between a valid-looking
and an invalid identifier.

## Why it matters
- Enumeration (OWASP **API1** / privacy) lets attackers build target lists for credential-stuffing and
  phishing, and is a prerequisite for many account-takeover chains. GraphQL error verbosity makes it common.

## Engineering Context
(See `EPIC-GQL-BIZLOGIC.md` shared context + safety. **Read-only** — uses queries / deliberately-failed
operations with **invalid, non-existent** identifiers; never real credentials, never triggers real lockouts.
Reuse `authz.Classify`/`authz.BodyEquivalent` for response differential and `inject.TimingOracle` for the
timing channel. Auto-discover an enumeration-prone operation, or accept the GQL-A06 `--authz-login-op`.)

- `ID()="GQL-B04"`, `Name()="User/Identifier Enumeration"`, `Category()=Authorization`,
  `Severity()=MEDIUM`, `RequiresSchema()=false` (richer with schema).

## Detection algorithm
1. **Locate an enumeration-prone op:** a mutation/query whose name matches
   `(?i)(login|signin|reset_?password|forgot_?password|signup|register|user_?exists|check_?email|
   account)`; or operator-supplied via `--authz-login-op`. If none → `Skip`.
2. **Pick two probe identifiers, both clearly non-existent** so no real account is touched: a *well-formed*
   one (`gqls-nouser-<rand>@invalid.example`) and a *malformed* one (`gqls-not-an-email-<rand>`). For
   `userExists`-style ops, use a value that should resolve to "absent" vs an obviously-invalid one. (The point
   is to compare two negatives that should be *indistinguishable* if the API is safe.)
3. **Differential probes:** send each identifier (a few times for timing). Compare:
   - **message/code**: do the two yield different error messages or `extensions.code` ("user not found" vs
     "invalid password")? Any operation that distinguishes *existing vs not* leaks — but since we use two
     non-existent ids, detect leakage by also sending a value the server *might* treat as existing only if the
     responses for "definitely absent" differ in a way that encodes existence (message templates that echo
     "no account for X"). Prefer the message/shape differential.
   - **timing**: `inject.TimingOracle` between the two — a robust latency gap (e.g. bcrypt runs only for
     existing users) indicates an enumeration oracle.
4. **Decide — flag MEDIUM when** responses differ in an existence-revealing way (distinct message/code/shape)
   **or** a robust timing differential exists. Confidence `"firm"` (message/shape) / `"confirmed"` (robust
   timing oracle). Negative: identical responses and equal timing → no finding (the safe design).

## Finding content
- **Title:** `User Enumeration — <operation> reveals account existence via <message|timing>`
- **Description:** the operation, the differential channel (distinct error text/code, response shape, or timing
  medians), with the probe identifiers shown as the clearly-invalid sentinels they are. Redact any echoed data.
- **Impact:** attackers can confirm which emails/usernames have accounts, enabling targeted credential
  stuffing, phishing, and account-takeover, plus a privacy disclosure.
- **Remediation:** return generic, identical responses for existing and non-existing accounts (same message,
  code, and shape); use constant-time handling (always perform a dummy password hash); apply rate limiting and
  CAPTCHA on auth/reset flows.
- **References:** `https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages`,
  `https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/`.
- **Confidence:** `"firm"`/`"confirmed"`. **CWE:** `"CWE-204"` (observable response discrepancy). **OWASP:**
  `"API1:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-B04", cc.Target, "enum:"+operation+":"+channel)`.

## Acceptance criteria
- **Given** a server that returns "user not found" vs "invalid password" for the two probes, a MEDIUM finding
  fires (message channel, firm).
- **Given** a server that hashes (sleeps) only for the "existing" branch, a confirmed timing finding fires.
- **Given** a server returning identical generic responses with equal timing, no finding.
- Only invalid/non-existent identifiers are ever sent (asserted); no real lockout triggered.

## Tests (`gqlb04_user_enumeration_test.go`)
- Handler returning distinct messages per identifier → finding (message channel). Timing handler (sleep on one
  branch) → confirmed timing finding. Identical-generic handler → no finding.
- Assert MEDIUM/CWE-204/API1, the probe identifiers are clearly-invalid sentinels, deterministic ordering.

## Safety
Read-only; uses only **invalid, non-existent** identifiers (never a real/configured credential); bounded
samples; never triggers account lockout. Echoed data redacted.
