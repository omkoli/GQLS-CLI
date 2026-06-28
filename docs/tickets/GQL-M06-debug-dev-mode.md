# GQL-M06 — Debug / Dev-Mode & Dev-Tooling Detection

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-MISCONFIG |
| **Priority** | P2 |
| **Severity (of finding)** | LOW |
| **Story points** | 3 |
| **Complexity** | Low |
| **Labels** | `misconfig`, `debug`, `dev-mode`, `graphiql`, `voyager` |
| **Category** | `InformationDisclosure` |
| **Depends on** | — (extends GQL-004 playground) |
| **Files** | `pkg/scanner/checks/gqlm06_debug_dev_mode.go` (+ `_test.go`) |

## Summary
Detect production exposure of **debug/development mode** and **dev tooling**: server-side `debug: true`
behavior (verbose errors / dev banners), and in-browser GraphQL IDEs / explorers served on prod — GraphiQL,
GraphQL Playground, Apollo Sandbox, **Altair**, **Voyager**, Banana Cake Pop. GQL-004 detects the classic
Playground; M06 broadens to the full dev-tooling set and a behavioral debug-mode signal.

## Why it matters
- Dev tooling and debug mode on production expose verbose errors, schema explorers, and one-click query
  consoles — lowering the bar for every other attack and often indicating a misconfigured environment.

## Engineering Context
(See `EPIC-GQL-MISCONFIG.md` shared context + safety. Reuse the path-probing approach from
`gql004_playground.go`. Use `cc.ProbeClient()`. Coordinate with GQL-004 so the canonical
`/graphql` Playground is not double-reported — M06 reports the *additional* tools/paths and the debug-mode
behavior.)

- `ID()="GQL-M06"`, `Name()="Debug Mode / Dev Tooling Exposed"`, `Category()=InformationDisclosure`,
  `Severity()=LOW`, `RequiresSchema()=false`.

## Detection algorithm
1. **Tooling paths:** GET a bounded set of common IDE/explorer paths and inspect for their telltale HTML/JS:
   `/altair`, `/voyager`, `/graphiql`, `/playground`, `/sandbox`, `/.well-known/apollo/server-health`,
   `/graphql` with `Accept: text/html` (returns the IDE shell). Match on tool signatures
   (`GraphiQL`, `GraphQL Playground`, `Altair`, `Voyager`, `ApolloSandbox`, `BananaCakePop`). Increment
   `ProbeCount` (cap paths ≤ 6).
2. **Debug-mode behavior:** send an erroring query and check for dev-mode tells: full stack traces, framework
   debug pages (`Werkzeug`, `Rails`, `Symfony`, `Whoops`), `debug`/`development` flags echoed, or Apollo's
   `includeStacktraceInErrorResponses` behavior (coordinate with M03 but key on the dev-mode banner, not the
   `extensions` channel).
3. **Decide — flag LOW when** any non-GQL-004 dev tool is reachable **or** a debug-mode behavioral tell is
   present. List each. Confidence `"confirmed"` (tool fingerprint matched) / `"firm"` (behavioral).

## Finding content
- **Title:** `Debug Mode / Dev Tooling Exposed — <tools/paths>`
- **Description:** which tools/paths are reachable and/or which debug-mode tell was observed; include the path
  and matched signature.
- **Impact:** dev consoles and debug pages give attackers a query IDE, schema explorer, and verbose internals
  on production — accelerating reconnaissance and exploitation.
- **Remediation:** disable GraphiQL/Playground/Altair/Voyager/Sandbox and any debug/development mode in
  production; ensure framework debug pages are off; return generic errors.
- **References:** `https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html`,
  `https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/`.
- **Confidence:** `"confirmed"`/`"firm"`. **CWE:** `"CWE-489"` (active debug code). **OWASP:** `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-M06", cc.Target, "debug_dev:"+sortedTools)`.

## Acceptance criteria
- **Given** a server serving an Altair/Voyager shell at `/altair` or `/voyager`, a LOW finding fires naming the
  tool. **Given** a debug-mode error page, a LOW behavioral finding fires.
- **Given** only the canonical GQL-004 Playground (no extra tools, no debug behavior), M06 does not duplicate
  it (PassReason or omits the already-reported path).
- **Given** a clean prod server, no finding + PassReason. No panic on non-HTML responses.

## Tests (`gqlm06_debug_dev_mode_test.go`)
- Handler serving an Altair shell at `/altair` → finding. Debug error-page handler → behavioral finding.
  Clean handler → PassReason. Assert LOW severity, tools listed, no GQL-004 duplication.

## Safety
Read-only GET path probes + one erroring query. Bounded paths. No secrets in output beyond tool names/paths.
