# GQL-A09 — Subscription Authorization Bypass (WebSocket)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-AUTHZ — GraphQL Authorization Testing Suite |
| **Priority** | P2 (Medium) |
| **Severity (of finding)** | HIGH |
| **Story points** | 8 |
| **Complexity** | High |
| **Labels** | `authz`, `subscriptions`, `websocket`, `owasp-api5`, `cwe-285`, `checks` |
| **Category** | `Authorization` |
| **Depends on** | **GQL-A00** (identities, oracle); introduces a WebSocket transport |
| **Files** | `pkg/scanner/checks/gqla09_subscription_authz.go` (+ `_test.go`), **new** `pkg/transport/ws.go` (minimal `graphql-ws` client) |

## Summary
Implement check **GQL-A09** that detects **authorization bypass on GraphQL subscriptions**: an operation that
is correctly authorized over HTTP queries is reachable **without (or with insufficient) auth over the
WebSocket subscription transport** (`graphql-ws` / `graphql-transport-ws`). Subscriptions are frequently
wired through a separate code path where the per-resolver authz applied to queries is not enforced.

## Why it matters
- Subscription authz gaps are OWASP **API5:2023** / **CWE-285** and a commonly-missed surface: the WS
  `connection_init` handshake often skips the auth middleware that guards HTTP POST
  (`SECURITY_PLATFORM_ANALYSIS.md` §2.1 GQL-A09).
- It exercises a transport the scanner doesn't speak yet (WebSocket), so it also lands a reusable `graphql-ws`
  client primitive.

## Engineering Context
(See `EPIC-GQL-AUTHZ.md` shared context + safety. Consume GQL-A00 `cc.Identities` for differential testing and
`authz.Classify` for the HTTP control. Add a **minimal** WebSocket client — a small dependency such as
`nhooyr.io/websocket`/`coder/websocket` or `gorilla/websocket` is acceptable; implement just the
`graphql-transport-ws` subprotocol: `connection_init` → `connection_ack` → `subscribe` → `next`/`error`/
`complete`.)

- `ID()="GQL-A09"`, `Name()="Subscription Authorization Bypass (WebSocket)"`, `Category()=Authorization`,
  `Severity()=HIGH`, `RequiresSchema()=true` (needs a subscription field to target).

## Detection algorithm
1. **Preconditions.** Schema must expose subscription fields (`cc.Schema.SubscriptionFields()`); else `Skip`
   ("no subscription type in schema"). Derive the WS URL from `cc.Target`
   (`http→ws`, `https→wss`; allow override via `--ws-url`). If the WS handshake is unreachable → `Skip` /
   record (not a finding).
2. **Pick a target subscription** that ideally overlaps a sensitive/owned resource (reuse `surface`
   privileged/sensitive heuristics). Build a minimal `subscribe` document with example args
   (`surface.ExampleValue`). Cap to **N=3** subscriptions.
3. **HTTP authz control.** Determine whether the *equivalent* data is authz-protected over HTTP: as the
   lower-privilege/anonymous identity, query the related field (or the subscription's root object) and confirm
   it is **denied** (`ClassAuthDenied`). This establishes that authz *is* expected. If HTTP itself is open,
   this is an A01/A02 issue, not specifically A09 → note and skip.
4. **WS differential probe.** Open the subscription over WebSocket:
   - **As anonymous / lower-privilege identity:** `connection_init` with *no* (or the low-priv) auth, then
     `subscribe`. Wait briefly (bounded, e.g. ≤ 3s) for `connection_ack` + a `next`/`data` message or an
     `error`/`connection_error`/close. `ProbeCount++`.
   - **As the privileged identity:** same, to confirm the subscription legitimately yields data for an
     authorized principal (baseline). `ProbeCount++`.
5. **Decide — flag HIGH when** the subscription **acks and delivers data (`next`) to the anonymous / lower-
   privilege identity** while the **equivalent HTTP query was denied** to that same identity — i.e. the WS path
   skips the authz the HTTP path enforces. Confidence `"confirmed"` when a `next` payload is received;
   `"firm"` when the server `connection_ack`s and `subscribe` is accepted (no immediate error) but no data
   arrives within the window. Redact any delivered payload.
   - **Negative:** WS rejects `connection_init`/`subscribe` for the under-privileged identity (auth error /
     close 4401/4403) → subscription authz enforced.
   - **Inconclusive:** handshake/transport errors, timeouts equal across identities → never flag; record.
6. **Always close cleanly.** Send `complete`/close after each probe; never hold subscriptions open.

## Finding content (when fired)
- **Title:** `Subscription Authorization Bypass — <subscription> delivered over WebSocket without query-level authz`
- **Description:** name the subscription, that the HTTP-equivalent access was denied to the same identity but
  the WS path accepted `subscribe` and delivered `next` data, and include a **redacted** preview of the first
  payload. Note the subprotocol used.
- **Impact:** unauthorized clients can stream data (including real-time sensitive/owned data) via subscriptions
  that bypass the authorization enforced on queries — continuous data exfiltration and privacy breach.
- **Remediation:** enforce authentication at the WS `connection_init` handshake and authorization at the
  subscription resolver (mirror the query/middleware authz on the subscription path); validate the principal
  on every published event, not only at subscribe time; reject unauthenticated `connection_init`.
- **References:**
  - `https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/`
  - `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`
  - `https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md`
  - `https://cwe.mitre.org/data/definitions/285.html`
- **Confidence:** `"confirmed"` / `"firm"`. **CWE:** `"CWE-285"`. **OWASP:** `"API5:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-A09", cc.Target, "sub_authz:"+subField)`.
- **ReproRequest / ReproBody:** synthesize a representative repro (the WS URL + `connection_init`/`subscribe`
  frames as JSON) since there is no `*http.Request`; store the frames in `ReproBody` and a best-effort
  `http.Request` to the WS URL for display.

## Acceptance criteria
- **Given** a WS test server that `connection_ack`s anonymous and pushes a `next` for a subscription whose
  HTTP-equivalent query is denied to anonymous, **then** one HIGH finding fires (Confidence `"confirmed"`,
  redacted payload, CWE/OWASP set).
- **Given** a WS server that rejects unauthenticated `connection_init` (close 4401) while authorized identity
  succeeds, **then** no finding + PassReason.
- **Given** no subscription type in schema, **then** `Skipped`.
- **Given** the WS endpoint is unreachable, **then** `Skipped`/recorded, not a crash.
- Subscriptions are always closed; bounded wait windows; no hang. Malformed frames never panic.

## Tests (`gqla09_subscription_authz_test.go`)
- `httptest.NewServer` upgraded to WebSocket implementing minimal `graphql-transport-ws`: ack anonymous +
  send one `next` → finding; assert payload redaction and clean close.
- WS server that closes anonymous with 4401 but serves the authorized identity → no finding.
- Schema without subscriptions → `Skipped`. Unreachable WS → `Skipped`/recorded.
- Assert severity/category/fingerprint/ProbeCount, bounded timeouts (no test exceeds the wait window).

## Safety & Ethics
Read-only (subscriptions stream data; the check never publishes events). Bounded: ≤ N=3 subscriptions, short
wait windows, subscriptions always closed promptly. Operator-supplied identities only. Delivered payloads are
**redacted** in evidence. The new WS client must enforce read/connect timeouts so a misbehaving server cannot
hang the scan.
