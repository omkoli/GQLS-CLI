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

GQL-006, GQL-007/GQL-008/GQL-012, GQL-D05, and GQL-A01/A02/A03 require a retrievable schema; they are skipped automatically when schema extraction fails. GQL-A01/A02/A03 additionally require at least two operator-supplied [identities](#authorization-identities) (of differing privilege for GQL-A02) and are skipped otherwise. GQL-A02 only probes privileged mutations when `--authz-allow-mutations` is set, and never invokes destructive ones.

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
