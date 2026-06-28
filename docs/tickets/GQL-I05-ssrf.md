# GQL-I05 — SSRF via GraphQL Arguments (with OOB)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P1 |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `injection`, `ssrf`, `oob`, `owasp-api7`, `cwe-918` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (points); ships the reusable **OOB interaction client** |
| **Files** | `pkg/scanner/checks/gqli05_ssrf.go` (+ `_test.go`), **new** `pkg/scanner/oob/oob.go` |

## Summary
Detect **Server-Side Request Forgery**: GraphQL arguments that take a URL/host/webhook/avatar/callback cause
the server to make an outbound request. Blind SSRF is confirmed via an **out-of-band (OOB) callback** to an
operator-supplied collaborator domain; in-band signals (response differences, timing, redirect/error leakage)
provide a lower-confidence fallback.

## Why it matters
- SSRF (OWASP **API7:2023** / CWE-918) lets an attacker pivot to internal services, cloud metadata
  (`169.254.169.254`), and internal admin panels. URL-typed GraphQL args (`url`, `webhook`, `avatar`,
  `callback`, `image`, `redirect`) are a classic vector. `pkg/schema/model.go` already enumerates URL-like
  args (`URLArgFields`).

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. This ticket also builds `pkg/scanner/oob`, a minimal
interaction client reused by GQL-I04. Add `cc.OOBDomain string` to `CheckContext` (operator flag
`--oob-domain`, e.g. an interactsh/Burp-Collaborator-style domain). Use `cc.HTTPClient`; gate mutation points
behind `cc.AllowMutations`. Reuse `schema.URLArgFields(s)` and `inject.Points`.)

- `ID()="GQL-I05"`, `Name()="SSRF via GraphQL Arguments"`, `Category()=Injection`, `Severity()=CRITICAL`,
  `RequiresSchema()=true`.

### OOB client (`pkg/scanner/oob/oob.go`)
```go
type Client struct{ Domain string }                 // operator-supplied collaborator domain
func (c *Client) NewToken() (subdomain, fullURL string) // unique per probe
func (c *Client) Poll(ctx, token string, wait time.Duration) (hits []Interaction, err error)
```
Implement against an interactsh-compatible endpoint or a pluggable poller; the test suite stubs `Poll`.

## Detection algorithm
1. Candidate args: `schema.URLArgFields(cc.Schema)` ∪ injection points whose arg name matches
   `(?i)(url|uri|href|link|webhook|callback|redirect|avatar|image|src|endpoint|host|target|feed|proxy)`.
   Cap ≤ 15.
2. **OOB probe (primary, opt-in):** if `cc.OOBDomain != ""`, for each candidate inject
   `http://<token>.<oob-domain>/` (also try `//<token>...`, `http://<token>...@trusted`), execute the op,
   then `oob.Poll(token)`. A correlated DNS/HTTP hit ⇒ **confirmed** SSRF.
3. **In-band fallback (no OOB):** inject a control URL vs an internal target
   (`http://127.0.0.1:80`, `http://169.254.169.254/latest/meta-data/`) and compare responses/timing — a
   difference (connection-refused vs timeout, metadata-shaped body, latency delta via the timing oracle) is
   `"firm"`/`"tentative"`. Never assert confirmed without OOB.
4. **Decide — flag CRITICAL when** an OOB callback correlates (confirmed) or a strong in-band differential
   appears (firm). When no `--oob-domain` is set, run only the in-band fallback and note the limitation.

## Finding content
- **Title:** `SSRF — <rootField> arg <path> triggers server-side outbound request`
- **Description:** the URL arg, the proof (OOB callback id + source IP, or the in-band differential), and the
  internal target reached if any. Redact internal data.
- **Impact:** access to internal services and cloud metadata, internal port scanning, credential theft, and
  pivoting into the internal network.
- **Remediation:** validate and allow-list outbound destinations; resolve and re-check IPs (block RFC1918 /
  link-local / metadata ranges); disable redirects; use an egress proxy with deny-by-default; never fetch
  user-supplied URLs from privileged contexts.
- **References:** `https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/`,
  `https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/918.html`.
- **Confidence:** `"confirmed"` (OOB) / `"firm"` (in-band). **CWE:** `"CWE-918"`. **OWASP:** `"API7:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-I05", cc.Target, "ssrf:"+rootField+"/"+pathKey)`.

## Acceptance criteria
- **Given** `--oob-domain` and a server that fetches the injected URL, a confirmed finding fires correlated to
  the unique token (stubbed poller reports a hit).
- **Given** no `--oob-domain`, the in-band fallback runs; a server that behaves differently for an internal
  target yields a firm finding, otherwise PassReason notes "supply --oob-domain for blind SSRF".
- **Given** a server that ignores the URL arg, no finding. Mutation points gated; no panic.

## Tests (`gqli05_ssrf_test.go`)
- Stub `oob.Client.Poll` to return a hit for the injected token → confirmed finding; no-hit → no OOB finding.
- In-band handler that returns metadata-shaped body for `169.254.169.254` → firm finding.
- No URL args in schema → PassReason/Skip. Assert severity CRITICAL, fingerprint, OWASP `API7:2023`.

## Safety
OOB targets only the **operator-supplied** collaborator domain; in-band targets are loopback/metadata probes
that read, never write. OOB is opt-in. Bounded candidates; mutation points gated; internal data redacted.
