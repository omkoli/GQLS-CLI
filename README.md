# gqls

GraphQL security scanner. Probes a GraphQL endpoint for common misconfigurations and vulnerabilities. Reads target information from a URL flag, `--header` flags, or a raw `curl` command copied from browser DevTools.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Scan command](#scan-command)
- [Flags reference](#flags-reference)
- [Authorization identities](#authorization-identities)
- [curl input](#curl-input)
- [Configuration file](#configuration-file)
- [Environment variables](#environment-variables)
- [Output formats](#output-formats)
- [Checks](#checks)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

---

## Install

**From source (requires Go 1.24+)**

```sh
git clone https://github.com/omkoli/GQLS-CLI.git
cd gqls
go build -o gqls ./cmd/gqls
```

Homebrew (macOS / Linux)

```sh
brew tap omkoli/gqls
brew install gqls
```

Or install directly in one command:

```sh
brew install omkoli/gqls/gqls
```

---

To embed a version string:

```sh
go build -ldflags "-X main.Version=1.2.3" -o gqls ./cmd/gqls
```

Move the binary somewhere on `$PATH`:

```sh
mv gqls /usr/local/bin/gqls
```

---

## Quick start

```sh
# Minimal scan using a URL
gqls scan --url https://api.example.com/graphql

# Scan with a bearer token
gqls scan \
  --url https://api.example.com/graphql \
  --header 'Authorization: Bearer eyJ...'

# Paste a curl command copied from browser DevTools
gqls scan --curl 'curl https://api.example.com/graphql \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  --data-raw '"'"'{"query":"{ __typename }"}'"'"''

# Save findings to a SARIF file; exit 1 on any CRITICAL finding
gqls scan \
  --url https://api.example.com/graphql \
  --output sarif \
  --output-file results.sarif \
  --fail-on CRITICAL
```

---

## Scan command

```
gqls scan [flags]
```

`--url`, `--curl`, or `--curl-file` must supply the target URL; the remaining flags are optional.

---

## Flags reference

| Flag | Default | Description |
|---|---|---|
| `--url <url>` | — | GraphQL endpoint URL. Required unless supplied by `--curl` or `--curl-file`. |
| `--header <Name: Value>` | — | HTTP header added to every request. Repeatable. Overrides same-name headers from `--curl` / `--curl-file`. |
| `--curl <cmd>` | — | Inline raw curl command string. URL, headers, and body are extracted. |
| `--curl-file <path>` | — | Path to a file containing a raw curl command. Accepts Bash (`\`) and Windows CMD (`^`) multiline formats. |
| `--checks <id,...>` | all | Run only the listed check IDs (comma-separated or repeated flag). |
| `--skip-checks <id,...>` | — | Skip the listed check IDs. |
| `--output <format>` | `terminal` | Output format: `terminal`, `txt`, `json`, `sarif`. |
| `--output-file <path>` | stdout | Write the report to this file instead of stdout. |
| `--fail-on <severity>` | `HIGH` | Exit 1 when any finding meets or exceeds this severity. One of `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `none`. |
| `--no-color` | false | Disable ANSI colour codes in terminal output. |
| `--timeout <duration>` | `30s` | Per-request HTTP timeout (e.g. `10s`, `2m`). |
| `--rate-limit <n>` | `10` | Maximum HTTP requests per second. |
| `--config <path>` | — | Path to a `gqls.yaml` config file. |
| `--identity <spec>` | — | Authorization-testing identity. Repeatable. Format: `name=userA;priv=10;tenant=t1;header=Authorization: Bearer X` (`header=` repeatable). See [Authorization identities](#authorization-identities). |
| `--authz-allow-mutations` | false | Allow authorization checks to send state-changing requests (e.g. mutation-side authz). Off by default. |

---

## Authorization identities

Stateful authorization checks (BOLA/BFLA/BOPLA, cross-tenant isolation, etc.) decide whether an access is
broken by sending the *same* operation as two different principals and comparing the responses. They
therefore require you to supply at least one authenticated **identity**; the scanner never invents or
brute-forces credentials. An `anonymous` identity (no auth headers, privilege `0`) is appended automatically
when at least one identity is configured.

Define identities on the command line (repeat `--identity`):

```bash
gqls scan --url https://api.example.com/graphql \
  --identity 'name=admin;priv=100;header=Authorization: Bearer '"$ADMIN_TOKEN" \
  --identity 'name=userB;priv=10;tenant=t2;header=Authorization: Bearer '"$USERB_TOKEN"
```

…or in `gqls.yaml` (header values support `${ENV_VAR}` expansion):

```yaml
identities:
  - name: admin
    privilege: 100        # higher = more privileged; anonymous is 0
    headers:
      Authorization: "Bearer ${ADMIN_TOKEN}"
  - name: userB
    privilege: 10
    tenant: t2            # optional; used by cross-tenant checks
    headers:
      Authorization: "Bearer ${USERB_TOKEN}"

# Authorization checks are read-only by default. Opt in before any check is
# allowed to send state-changing (mutation) requests:
allow_authz_mutations: false
```

`priv` (or `privilege`) ranks identities so checks can form `(higher-privilege, lower-privilege)` test
pairs; `tenant` scopes an identity to a tenant for cross-tenant tests. Same-named identities from the
config file are overridden by `--identity` flags.

---

## curl input

`--curl` and `--curl-file` accept raw curl commands copied from browser DevTools or manually constructed. The parser extracts the URL, HTTP method, headers, and request body without executing any shell process.

**Supported syntax**

- Bash-style line continuations (`\` + newline)
- Windows CMD-style line continuations (`^` + newline)
- Windows CMD inline escape sequences (`^"`, `^^`)
- Single-quoted strings, double-quoted strings, ANSI-C quoted strings (`$'...'`)
- `curl.exe` prefix (normalized to `curl`)
- Typographic/smart quotes (normalized to ASCII)
- Flags: `-X`/`--request`, `-H`/`--header`, `-d`/`--data`/`--data-raw`/`--data-binary`, `--url`
- Method inference: `POST` when a body is present, `GET` otherwise

**Merge rules**

When `--curl` / `--curl-file` is combined with `--url` or `--header`:

- `--url` wins over the URL in the curl command.
- `--header` values override same-name headers extracted from the curl command.

**Inline example**

```sh
gqls scan --curl 'curl -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ..." \
  --data-raw "{\"query\":\"{ users { id email } }\"}"'
```

**File example**

```sh
# curl.txt
curl 'https://api.example.com/graphql' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer eyJ...' \
  --data-raw '{"query":"{ users { id email } }"}'
```

```sh
gqls scan --curl-file curl.txt
```

---

## Configuration file

gqls looks for `gqls.yaml` in the current directory and then `$HOME/.gqls/gqls.yaml`. Use `--config` to specify an explicit path.

**Precedence (lowest → highest):** config file → environment variables → CLI flags.

```yaml
url: https://api.example.com/graphql

headers:
  Authorization: "Bearer ${API_TOKEN}"
  X-Tenant-ID: "acme"

timeout: 60s
rate_limit: 5

output_format: json
output_file: report.json

fail_on: HIGH
no_color: false

checks: []          # empty = run all
skip_checks:
  - GQL-004

false_positives:
  - "a1b2c3d4e5f6..."   # SHA-256 fingerprint of a known-safe finding
```

Header values may reference environment variables using `${VAR_NAME}` syntax; they are expanded at scan time.

---

## Environment variables

All settings can be provided as environment variables using the `GQLS_` prefix. Environment variables override config-file values but are overridden by CLI flags.

| Variable | Equivalent flag |
|---|---|
| `GQLS_URL` | `--url` |
| `GQLS_OUTPUT_FORMAT` | `--output` |
| `GQLS_OUTPUT_FILE` | `--output-file` |
| `GQLS_FAIL_ON` | `--fail-on` |
| `GQLS_NO_COLOR` | `--no-color` |
| `GQLS_TIMEOUT` | `--timeout` |
| `GQLS_RATE_LIMIT` | `--rate-limit` |

---

## Output formats

### terminal (default)

ANSI-coloured, human-readable output. Each finding block contains:

```
[ HIGH ] GQL-001 — Introspection Enabled
────────────────────────────────────────────────────────────────────────

WHAT WAS FOUND
  GraphQL introspection is enabled at https://api.example.com/graphql. ...

REPRODUCE IT
  curl -X POST \
    'https://api.example.com/graphql' \
    -H 'Content-Type: application/json' \
    --data-raw '{"query":"{ __schema { types { name } } }"}'

ATTACKER IMPACT
  An attacker can enumerate the entire API surface ...

FIX
  Disable introspection in production environments. ...

REFERENCES
  • https://...
```

Followed by a summary table:

```
SCAN SUMMARY
────────────────────────────────────────────────────────────────────────
  Checks run     : 12
  Duration       : 4.231s
  Requests made  : 38

  Findings by severity:
  CRITICAL   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0
  HIGH       ████████░░░░░░░░░░░░░░░░░░░░░░ 2
  MEDIUM     ████░░░░░░░░░░░░░░░░░░░░░░░░░░ 1
  LOW        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0
  INFO       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0
```

Use `--no-color` to strip ANSI codes for CI environments that do not interpret escape sequences.

### txt

Plain-text report with no ANSI codes or JSON. Suitable for attaching to tickets or email. Sections: header, findings index, individual findings (with reproduction curl), clean checks, skipped checks, footer with a stable report ID.

```sh
gqls scan --url https://api.example.com/graphql --output txt --output-file report.txt
```

### json

Indented JSON object. Top-level structure:

```json
{
  "ChecksRun": 12,
  "Duration": 4231000000,
  "RequestsMade": 38,
  "StartTime": "2026-02-28T12:00:00Z",
  "Findings": [
    {
      "CheckID": "GQL-001",
      "CheckName": "Introspection Enabled",
      "Severity": "HIGH",
      "Category": "InformationDisclosure",
      "Title": "...",
      "Description": "...",
      "Impact": "...",
      "Remediation": "...",
      "References": ["..."],
      "Fingerprint": "a1b2c3..."
    }
  ],
  "Schema": { ... },
  "CheckResults": [
    {
      "CheckID": "GQL-001",
      "Ran": true,
      "Skipped": false,
      "SkipReason": "",
      "PassReason": "",
      "Findings": [...],
      "Duration": 210000000,
      "ProbeCount": 3
    }
  ]
}
```

`Duration` and per-check `Duration` values are in nanoseconds. `Severity` is serialized as a string (`"INFO"`, `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`).

```sh
gqls scan --url https://api.example.com/graphql --output json | jq '.Findings[].Severity'
```

### sarif

SARIF 2.1.0 JSON. Rules are emitted under `runs[0].tool.driver.rules`; results under `runs[0].results`. Severity mapping:

| gqls severity | SARIF level |
|---|---|
| CRITICAL, HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
| INFO | `none` |

```sh
gqls scan --url https://api.example.com/graphql --output sarif --output-file results.sarif
```

---

## Checks

| ID | Name | Severity | Category |
|---|---|---|---|
| GQL-001 | Introspection Enabled | HIGH | InformationDisclosure |
| GQL-002 | Introspection Bypass via \_\_type | HIGH | InformationDisclosure |
| GQL-003 | Schema Exposed via Field Suggestions | MEDIUM | InformationDisclosure |
| GQL-004 | GraphQL Playground Exposed | MEDIUM | InformationDisclosure |
| GQL-005 | Stack Trace / Debug Info in Error Responses | MEDIUM | InformationDisclosure |
| GQL-006 | Sensitive Fields Exposed in Schema | INFO | InformationDisclosure |
| GQL-007 | Query Depth Limit Not Enforced | HIGH | DenialOfService |
| GQL-008 | Query Complexity Limit Not Enforced | HIGH | DenialOfService |
| GQL-009 | Batch Query Abuse | HIGH | DenialOfService |
| GQL-010 | GraphQL GET Queries Enabled | LOW | InformationDisclosure |
| GQL-011 | SQL Injection (Error-Based) | CRITICAL | Injection |
| GQL-012 | Unauthenticated Access to Mutations | HIGH | Authentication |
| GQL-D01 | Alias-Based Query Amplification | HIGH | DenialOfService |
| GQL-D02 | Field Duplication / \_\_typename Flooding | HIGH | DenialOfService |
| GQL-D03 | Circular Fragment Spread | HIGH | DenialOfService |
| GQL-D04 | Directive Overloading | MEDIUM | DenialOfService |
| GQL-D05 | Unbounded List/Pagination Argument | HIGH | DenialOfService |
| GQL-D06 | Query Cost Amplification | MEDIUM | DenialOfService |
| GQL-D07 | Persisted Query / APQ Not Enforced | MEDIUM | DenialOfService |
| GQL-D08 | Unbounded Introspection Amplification | LOW | DenialOfService |
| GQL-A01 | Broken Object Level Authorization (BOLA/IDOR) | CRITICAL | Authorization |
| GQL-A02 | Broken Function Level Authorization (BFLA) | CRITICAL | Authorization |
| GQL-A03 | Field-Level Authorization (BOPLA / Excessive Data Exposure) | HIGH | Authorization |
| GQL-A04 | Cross-Tenant Isolation Failure | CRITICAL | Authorization |
| GQL-A05 | Mutation-Side Authorization (Non-Owner Write/Delete) | CRITICAL | Authorization |
| GQL-A06 | Auth Bypass via Aliases (Rate-Limit/Brute-Force Bypass) | HIGH | Authorization |
| GQL-A07 | GraphQL CSRF (State Change via GET / Simple Content-Type) | HIGH | Authorization |
| GQL-A08 | JWT Authentication-Token Weaknesses | HIGH | Authorization |
| GQL-A09 | Subscription Authorization Bypass (WebSocket) | HIGH | Authorization |
| GQL-M01 | GraphQL Engine Fingerprint | INFO | InformationDisclosure |
| GQL-M02 | Known Engine CVEs | varies (per advisory) | InformationDisclosure |
| GQL-M03 | Sensitive Data in GraphQL extensions / Tracing | MEDIUM | InformationDisclosure |
| GQL-M04 | Introspection Reachable via Alternative Transport | MEDIUM | InformationDisclosure |
| GQL-M05 | Schema Reconstructed via Field Suggestions | MEDIUM | InformationDisclosure |
| GQL-M06 | Debug Mode / Dev Tooling Exposed | LOW | InformationDisclosure |
| GQL-M07 | CORS Misconfiguration | MEDIUM | InformationDisclosure |
| GQL-M08 | Missing Security Headers | LOW | InformationDisclosure |
| GQL-M09 | Secrets/Hints Leaked in Schema Descriptions & Defaults | LOW | InformationDisclosure |
| GQL-I01 | Boolean-Based SQL Injection | CRITICAL | Injection |
| GQL-I02 | Time-Based Blind SQL Injection | CRITICAL | Injection |
| GQL-I03 | NoSQL (MongoDB) Operator Injection | CRITICAL | Injection |
| GQL-I04 | OS Command Injection | CRITICAL | Injection |
| GQL-I05 | SSRF via GraphQL Arguments | CRITICAL | Injection |
| GQL-I06 | Cross-Site Scripting (Reflected/Stored via GraphQL) | MEDIUM | Injection |
| GQL-I07 | ORM/GraphQL Operator Injection | HIGH | Injection |
| GQL-I08 | LDAP / XML / Template Injection | HIGH | Injection |
| GQL-B01 | Unrestricted Access to Sensitive Business Flows | HIGH | BusinessLogic |
| GQL-B02 | Mass Assignment via Input Objects | HIGH | Authorization |
| GQL-B03 | Race Condition (Parallel Mutation) | HIGH | BusinessLogic |
| GQL-B04 | User/Identifier Enumeration | MEDIUM | Authorization |

GQL-M01 needs no identities or schema. It identifies the backing GraphQL engine (Apollo, Hasura, graphql-ruby, HotChocolate, AWS AppSync, …) from a few discriminator probes and always emits an INFO finding (the engine, or "not identified" — never a false attribution); the result is reconnaissance context that other checks can build on.

GQL-M02 builds on GQL-M01 and needs no identities or schema. Once the engine is identified, it maps it against a small, hand-curated and dated table of published advisories (CVEs / GHSAs verified against the GitHub Advisory Database / NVD — never fabricated) and emits one finding per applicable advisory at the advisory's severity. It resolves the running version from a benign response banner where possible: a version inside an advisory's affected range fires as `firm`, a version outside every range fires nothing (likely patched), and an unknown version degrades the applicable advisories to `tentative`. It runs no exploit proof-of-concept — version confirmation only. The check skips when no engine could be identified.

GQL-M03 needs no identities or schema. It sends one benign and one deliberately invalid query, parses the structured `extensions` channel (top-level and per-error), and classifies what leaked into a taxonomy: exception **stacktrace**, Apollo **tracing/timing**, **query-plan/cost** metadata, and **backend echoes** (SQL text, file paths, internal hostnames). Severity is set by the most sensitive class found — MEDIUM for stacktrace/backend-echo, LOW for pure timing/cost; benign-only extensions (e.g. a `GRAPHQL_VALIDATION_FAILED` code) produce no finding. Leaked paths/hosts/SQL are redacted in the evidence — the report names the class and offending keys, never the raw secret. It complements GQL-005 (which scans error *message* text) by keying on the structured extensions channel.

GQL-M04 needs no identities or schema. It first sends a canonical POST `application/json` introspection probe; if that already succeeds it skips (GQL-001 owns plainly-enabled introspection). When POST is blocked, it retries the same introspection over alternative transports — `GET ?query=`, POST `text/plain`, form-encoded, whitespace/comment after `__schema`, and a batched array — and fires a MEDIUM `confirmed` finding listing every vector that returned `__schema` despite the POST block. Vectors are tried in a fixed order so findings are deterministic; only `__schema` reachability is confirmed (no schema content is dumped).

GQL-M05 needs no identities and runs read-only against the already-extracted schema. When introspection is disabled but gqls harvested the schema from "Did you mean …" field suggestions (the clairvoyance technique) and recovered a non-trivial schema (≥5 fields), it emits a MEDIUM `confirmed` finding containing a **reconstructed SDL artifact** — proving the introspection lock-down did not actually hide the schema. The SDL is bounded (capped types/fields, with a truncation note) and marks fields/types inferred without full type information as `# partial`. It skips when introspection is enabled (GQL-001 owns that), when the schema came from another method, or when too little was recovered.

GQL-M06 needs no identities or schema. It GETs a bounded set of dev-tooling paths (`/altair`, `/voyager`, `/graphiql`, `/playground`, `/sandbox`, and the canonical endpoint with `Accept: text/html`) and matches in-browser IDE/explorer signatures (GraphiQL, GraphQL Playground, Apollo Sandbox, Altair, Voyager, Banana Cake Pop), then sends one erroring query to detect debug/development-mode tells (framework debug pages like Werkzeug/Whoops/Rails/Symfony, or `X-Debug-*` headers). It emits a single LOW finding listing every additional tool/path and debug tell — `confirmed` when a tool signature matched, `firm` for a purely behavioral tell. It broadens GQL-004 (canonical Playground) and coordinates with it so the canonical-endpoint Playground is not double-reported.

GQL-M07 needs no identities or schema. It sends a bounded set of probes carrying a synthetic attacker `Origin` (a preflight `OPTIONS` and a `POST { __typename }`, plus `Origin: null` and a subdomain-suffix bypass origin) and inspects the `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials` / `Vary` response headers. It maps the result to severity: arbitrary-origin reflection **with** credentials → HIGH; wildcard/null with credentials or bare origin reflection → MEDIUM; wildcard or null acceptance without credentials → LOW; a fixed trusted origin (or no CORS) → no finding. The `confirmed` finding (CWE-942 / API8:2023) records the exact headers observed for each probe. No data is exfiltrated — the finding is the header configuration itself.

GQL-M08 needs no identities or schema. It sends one `POST { __typename }` and inspects the response for baseline hardening gaps: missing `X-Content-Type-Options: nosniff`, missing `Strict-Transport-Security` (HTTPS targets only), missing `Content-Security-Policy` on HTML/IDE responses, and disclosing `Server` (with a version) / `X-Powered-By` headers. It emits a single LOW `confirmed` finding (CWE-693 / API8:2023) listing the gaps in deterministic order with their observed values, or a PassReason when the response is hardened.

GQL-M09 requires a schema (it runs no requests). It walks every type/field/argument description, deprecation reason, and argument default value, matching secret literals (AWS/GitHub/Slack tokens, private keys, `mongodb://user:pass@…` connection strings, `password=`/`api_key=` assignments, high-entropy tokens) and internal hints (RFC1918 IPs, `.internal`/`.local` hosts, `TODO`/`remove in prod`/`internal only` notes). GQL-006 flags sensitive field *names*; M09 covers the free-text and default-value channels it misses. It emits a single `firm` finding listing each location and match class with the value **redacted** via `authz.MaskValue` — LOW overall, MEDIUM when a concrete credential or connection-string is matched (CWE-200/CWE-540, API8:2023). Raw secrets never appear in output.

GQL-I01 requires a schema and finds **boolean-based (differential) SQL injection** — the confirmed in-band oracle that the error-based GQL-011 lacks. For each injectable string leaf (capped at 25; mutation points gated behind `--authz-allow-mutations`) it sends a benign control plus a logically-true and a logically-false predicate, and fires a CRITICAL `confirmed` finding (CWE-89) only when the true predicate returns a data result while the false predicate changes the result set — re-tested once to rule out flakiness. Payloads are redacted in the evidence. It is built on the shared injection engine in `pkg/scanner/inject`: a surface-graph enumerator (`Points`/`Render`) that walks every leaf scalar across the reachable input graph — including nested input objects and list elements, as inline literals or variables — plus differential (`BodyEquivalent`, `ErrorSignal`) and statistical timing oracles. GQL-011 now consumes this engine too, broadening its error-based coverage beyond a single top-level argument.

GQL-I02 requires a schema and detects **time-based blind SQL injection** — the last-resort oracle when there is no error or boolean output. For each injectable string leaf (cap 8; mutation points gated) it injects a per-engine conditional sleep (MySQL `SLEEP`, PostgreSQL `pg_sleep`, MSSQL `WAITFOR DELAY`, Oracle `dbms_pipe.receive_message`) and confirms via `inject.TimingOracle` that the payload response is robustly slower than a matched control — median + MAD over interleaved samples (default 7), above an absolute floor — so jitter and network noise do not produce false positives. It fires a CRITICAL `confirmed` finding (CWE-89) with the measured control vs payload medians as the headline. Sleep payloads are benign (read-only); sampling is bounded and cancellable.

GQL-I03 requires a schema and detects **NoSQL (MongoDB) operator injection** (CWE-943). It replaces an argument value with a Mongo operator object — directly for custom `JSON`/`Object` scalar leaves, or JSON-string-encoded for plain `String`/`ID` leaves (body-parser quirks). It sends a benign control plus a true operator (`{"$ne": …}`, matches everything) and a false operator (`{"$in": []}`, matches nothing) and fires a CRITICAL `confirmed` finding when the result set tracks the operator semantics (true → superset, false → empty), re-tested for consistency. For credential-like fields it also runs the auth-bypass variant (`{"$ne": null}` succeeding where the control was denied). Read-only operators only (no `$where` side effects); mutation points gated; returned data is not echoed.

GQL-I04 requires a schema and detects **OS command injection** (CWE-78) on arguments that may reach a shell (it prioritizes names like `host`, `file`, `cmd`, `url`, `format`). Its primary oracle is statistical timing: it appends a conditional sleep across shell separators (`` `sleep 5` ``, `; sleep 5`, `| sleep 5`, `$(sleep 5)`, `& ping -c 5 …`) and confirms via `inject.TimingOracle` (CRITICAL `confirmed`). It also corroborates with a shell error-signal table (`sh: 1:`, `/bin/sh`, `command not found`, …) for verbose servers (`firm`), and supports an **opt-in out-of-band** path: with `--oob-domain` set (and an OOB poller wired in by the SSRF foundation, GQL-I05), it injects a DNS/HTTP lookup of a unique `<token>.<oob-domain>` subdomain and confirms on a correlated callback. All payloads are benign (sleep/ping/DNS only — never destructive); mutation points are gated and out-of-band probing is skipped (noted in the pass reason) when `--oob-domain` is not configured.

GQL-I05 requires a schema and detects **SSRF** (CWE-918 / OWASP API7:2023) on URL/host-like arguments (`url`, `webhook`, `avatar`, `callback`, `image`, `redirect`, `host`, …; capped at 15, mutation points gated). Its primary oracle is **out-of-band**: with `--oob-domain` set it injects a unique `http://<token>.<oob-domain>/` and confirms on a correlated DNS/HTTP callback (CRITICAL `confirmed`). Without OOB it runs an in-band fallback — a cloud-metadata read (`169.254.169.254`) whose metadata-shaped response is a strong `firm` signal, and an internal-target-vs-control response differential as a weaker `tentative` (MEDIUM) signal — never asserting `confirmed` without OOB, and noting "supply `--oob-domain`" when nothing fires. The reusable OOB interaction client lives in `pkg/scanner/oob` (`--oob-domain` wires it in) and is shared with GQL-I04; its polling backend is pluggable (an interactsh-compatible adapter can be supplied).

GQL-I06 requires a schema and detects where GraphQL **surfaces XSS payloads unencoded** (CWE-79), reasoning over the raw JSON response bytes (not browser execution). It injects a unique, inert, self-attributing marker (`gqls<nonce><svg/onload=alert(1)>`) at query points and fires a MEDIUM `firm` finding when the marker is reflected with the raw `<` intact (an HTML-encoded `&lt;` or JSON-unicode-escaped `<` reflection is correctly encoded → no finding). The stored path is opt-in (`--authz-allow-mutations`): it discovers a rich-text mutation paired with a no-argument getter and runs a safe capture→write→read-back→restore cycle — it never writes without first capturing the original, and always restores it. Markers are inert and reflected snippets are truncated in the evidence.

GQL-I07 requires a schema and detects **ORM/GraphQL operator injection** (CWE-943) — predicate abuse in auto-generated filter languages (Hasura/Postgraphile/Prisma `where`/`_and`/`_or`/`_like`/`_eq`). It discovers `where`/`filter`/bool-exp input-object arguments structurally and injects attacker-controlled predicate objects: a restrictive control, a **widening** predicate (`{_or: [{}]}` → strict superset ⇒ `firm`), and a **target** predicate selecting privileged rows (`{role: {_eq: "admin"}}` → surfaces rows the control hid ⇒ `confirmed`), re-tested for consistency. It is **engine-gated** via the GQL-M01 fingerprint: the full predicate set runs only against Hasura/Postgraphile-style engines, a known non-ORM engine is skipped (noted in the pass reason), and an unknown engine gets a conservative widening-only subset. Read-only predicate widening only; rows are not echoed (`API1:2023`).

GQL-I08 requires a schema and detects three less-common, high-impact injection classes behind GraphQL args, running name-gated sub-probes per point (cap 15, mutations gated): **LDAP** (CWE-90) — a wildcard (`*`) returning a superset of a specific control ⇒ `confirmed`, or an LDAP error signal ⇒ `firm`; **XML/XPath/XXE** (CWE-91) — an **internal-entity-only** canary (`<!ENTITY e "INJ…">`) expanded in the response ⇒ `firm`, an XML parser error ⇒ `firm`, or an XPath-break superset ⇒ `firm`; **SSTI** (CWE-1336) — an arithmetic-evaluation oracle (`${a*b}`/`{{a*b}}`/`#{a*b}`/`<%= a*b %>`/`*{a*b}`) where the product appears but the literal expression does not ⇒ `confirmed`. SSTI uses arithmetic-only payloads (no RCE gadgets) and the XXE probe never sends an external/system entity (no file/network fetch); reflected data is redacted.

GQL-006, GQL-007/GQL-008/GQL-012, GQL-D05, and GQL-A01/A02/A03/A04/A05 require a retrievable schema; they are skipped automatically when schema extraction fails. GQL-A01–A05 additionally require operator-supplied [identities](#authorization-identities) and are skipped otherwise (GQL-A02 needs differing privilege; GQL-A04 needs two identities in different `tenant`s). GQL-A02 only probes privileged mutations when `--authz-allow-mutations` is set, and never invokes destructive ones. **GQL-A05 is disabled by default**: it performs state-changing requests, so it runs only with `--authz-allow-mutations`, tests only non-destructive update-style mutations (destructive-named ones require an explicit `--authz-allow-mutation <name>`), and uses a capture→write→verify→restore cycle that restores the original value.

GQL-A06 needs no identities. It tests an authentication-style operation (auto-discovered from the schema, e.g. `login`/`signin`/`verifyOtp`, or specified with `--authz-login-op`) by aliasing it 20× in one request with clearly-invalid, non-existent credentials; it is skipped when no such operation can be found.

GQL-A07 needs no identities or schema. It sends a non-mutating `{ __typename }` canary over browser-forgeable request shapes (GET `?query=`, POST `text/plain`, POST form-encoded) and flags when any is accepted without a CSRF token / CORS preflight. With `--authz-allow-mutations` and a discoverable safe no-argument mutation, it upgrades the finding to "confirmed" by demonstrating a state-changing mutation over a CSRF vector.

GQL-A08 needs no identities or schema, but does require a JWT bearer token to be supplied (via `--header 'Authorization: Bearer <jwt>'`, `--identity`, or a curl command). It tamper-tests that token for `alg:none` acceptance, weak/guessable HMAC secrets, missing/excessive `exp`, and `kid` injection, using an auth-gated baseline plus a garbage-token negative control to confirm acceptance. The genuine token and signatures are never written to output.

GQL-A09 requires a schema exposing a subscription type. It connects to the GraphQL WebSocket endpoint (derived from the target as `http→ws` / `https→wss`, or set with `--ws-url`) using the `graphql-transport-ws` / `graphql-ws` subprotocol, and flags when a subscription streams data to an anonymous client whose HTTP-equivalent query is denied. Subscriptions are always closed promptly and wait windows are bounded.

**GQL-B01 is disabled by default**: it performs state-changing (business-flow) requests, so it runs only with `--authz-allow-mutations`. Where GQL-A06 targets *authentication* throttling, B01 targets *business-flow* throttling (OWASP API6:2023 / CWE-799). It requires a schema, identifies up to two sensitive-flow mutations by name (`redeem`/`coupon`/`signup`/`invite`/`vote`/`transfer`/…, destructive-named ones excluded unless allow-listed via `--authz-allow-mutation`), and sends **one request aliasing the flow 20×** — every alias performing the *same* logical action with a **bogus, non-existent probe identifier** so a "success" reflects missing server-side validation and per-actor/per-key limiting, not real value transfer. It fires a HIGH finding when all 20 aliased executions succeed with no duplicate/limit rejection (`firm`), upgraded to `confirmed` when a numeric effect field — a credited balance or redemption count — climbs monotonically across the aliases, showing the effect persisted N×. A server that enforces one-per-key (1 success + 19 "already redeemed") produces no finding. The alias count is bounded well below DoS, and cleanup status is reported.

**GQL-B02 is disabled by default**: it performs state-changing requests, so it runs only with `--authz-allow-mutations`. It detects **mass assignment** (OWASP API3:2023 / CWE-915) — a mutation input object that auto-binds a privileged/state field the client should not control (`isAdmin`, `role`, `verified`, `owner`, `tenantId`, …). It requires a schema, and for up to three update-style mutations (id argument + a privileged Boolean/String/ID/enum field reachable through an input object, paired with a read query exposing that field; destructive-named ones excluded unless allow-listed) it runs the GQL-A05 **capture→inject→verify→restore** cycle against an object the configured identity owns. The injected value is a **non-real elevating sentinel** — a boolean toggle, a bogus `gqls-probe-role`, a non-admin enum value, or a bogus id reference — chosen so detection proves the input was honored without actually granting real privilege; the original value is always restored. A read-back confirming the client-supplied value persisted yields `confirmed`; an accepted-but-unverifiable write yields `firm`; an ignored/rejected field yields no finding. Numeric money fields (`balance`/`credit`) are only ever probed as safe no-ops and never produce a finding.

**GQL-B03 is disabled by default**: it fires a parallel burst of state-changing requests, so it runs only with `--authz-allow-mutations`. It detects **race conditions / TOCTOU** (CWE-362 / OWASP API6:2023) in a limited-quantity mutation (`redeem`/`claim`/`withdraw`/`transfer`/`coupon`/…, destructive-named ones excluded unless allow-listed). It requires a schema, picks **one** candidate per run (concurrency is sensitive), and fires **K=20 identical mutations concurrently** — each with its own request, released together through a start barrier and all awaited (no goroutine leak; safe under `-race`) — against a **bogus, non-valuable probe identifier** so an over-application proves a missing atomic guard rather than moving real value. It flags HIGH when more than one execution returns a success class (the business limit should be 1): `confirmed` when a numeric effect field proves the shared quota was over-consumed under the race, `firm` when multiple successes were seen but the post-state could not be quantified. A server with an atomic check-and-act (exactly one success under the burst) produces no finding. The burst is bounded within the client's rate-limiter burst.

GQL-B04 is **read-only** and needs no `--authz-allow-mutations`. It detects **user/identifier enumeration** (OWASP API1:2023 / CWE-204): an auth-flow operation (auto-discovered from the schema — `login`/`resetPassword`/`signup`/`userExists`/… — or named with `--authz-login-op`) that reveals whether an account exists. It sends **two clearly-invalid, non-existent probe identifiers** — a well-formed `gqls-nouser-…@invalid.example` and a malformed `gqls-not-an-email-…` (never a real credential, never a real lockout) — that a safe API would answer identically, and compares them on two channels: the **message/code/shape** differential (a normalized signature with the echoed identifiers redacted, so only a genuine template/class difference counts) yields a `firm` MEDIUM finding, and a robust **timing** gap (`inject.TimingOracle`, e.g. a password hash that runs only for plausible/existing users) yields a `confirmed` one. Identical responses with equal timing produce no finding.

**Run a subset of checks**

```sh
gqls scan --url https://api.example.com/graphql --checks GQL-001 --checks GQL-002
```

**Skip specific checks**

```sh
gqls scan --url https://api.example.com/graphql --skip-checks GQL-004 --skip-checks GQL-010
```

**Suppress a known false positive by fingerprint**

Each finding includes a stable `Fingerprint` (SHA-256 of check ID + target + evidence key). Add the fingerprint to `false_positives` in `gqls.yaml` to suppress it in future scans.

```yaml
false_positives:
  - "a1b2c3d4e5f67890..."
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed. No finding met or exceeded the `--fail-on` threshold (or `--fail-on none`). |
| `1` | Scan completed and at least one finding met or exceeded the `--fail-on` severity. Also returned on fatal startup errors (invalid flags, unreadable config, bad output format, unreadable `--curl-file`). |

The default `--fail-on` threshold is `HIGH`. Set `--fail-on none` to always exit `0` regardless of findings.

**CI usage**

```sh
gqls scan \
  --url "$GRAPHQL_URL" \
  --header "Authorization: Bearer $TOKEN" \
  --output sarif \
  --output-file results.sarif \
  --fail-on HIGH
echo "Exit: $?"
```

---

## Troubleshooting

**`--url is required` despite passing `--curl`**

The curl parser could not extract a URL. Verify the curl string begins with `curl` (or `curl.exe`) and contains a valid `http://` or `https://` URL. Use `--curl-file` if the command spans multiple shell-escaped lines.

**`parsing curl input: curl: unterminated single-quoted string`**

The curl command contains unbalanced quotes, often introduced when copying from a terminal that wraps lines. Save the command to a file and pass it with `--curl-file`.

**`warning: schema extraction failed`**

Schema-dependent checks (GQL-006, GQL-007, GQL-008, GQL-012) will be skipped. Causes:

- Introspection is disabled on the target — expected; GQL-001 will fire if the endpoint responds.
- The endpoint requires authentication that was not supplied. Add credentials via `--header` or `--curl`.
- The endpoint is unreachable. Verify `--url` and network connectivity.

**`error: schema extraction [stage]: message`**

A fatal error occurred during schema extraction at the named stage. Check the URL, authentication headers, and whether the server returns valid JSON.

**No findings on a known-vulnerable endpoint**

- The endpoint may block scanner probe payloads. Use `--curl` to replicate the exact browser request including cookies and CSRF tokens.
- Some checks require schema data. If extraction failed, those checks are skipped (logged as `requires schema (unavailable)`).
- Rate limiting on the server may cause timeouts. Reduce `--rate-limit` or increase `--timeout`.

**ANSI codes appear as raw escape sequences**

Pass `--no-color` or set the environment variable `NO_COLOR=1`. When writing to a file via `--output-file`, colour is disabled automatically.

**`invalid output format "…"`**

Valid values are `terminal`, `txt`, `json`, `sarif` (case-insensitive).

**Authorization header in reproduction curl shows `[REDACTED]`**

The terminal and txt reporters redact the `Authorization` header value in the `REPRODUCE IT` / `REPRODUCE` curl command to prevent credentials from being stored in report files. The actual header is still sent during the scan.
