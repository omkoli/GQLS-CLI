# GQL-I04 — OS Command Injection

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P2 |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `injection`, `command-injection`, `rce`, `cwe-78`, `timing-oracle`, `oob` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (points), **GQL-I02** (`inject.TimingOracle`) |
| **Files** | `pkg/scanner/checks/gqli04_os_command_injection.go` (+ `_test.go`) |

## Summary
Detect **OS command injection** on arguments that reach a shell (filenames, hostnames, image/convert params,
ping/lookup utilities). Use a time-based oracle (`; sleep 5`, `& ping -c 5`, `| timeout 5`) confirmed
statistically, plus an optional out-of-band (OOB) callback for blind cases, and an error-based signal for
verbose servers.

## Why it matters
- Command injection (CWE-78) is direct remote code execution — the highest-impact injection class. GraphQL
  args that feed CLI tools (image processing, DNS lookups, PDF/render pipelines) are a frequent vector.

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. Consume `inject.Points`, `inject.TimingOracle`,
`inject.ErrorSignal`. OOB requires the operator flag `--oob-domain` exposed on `CheckContext` as `cc.OOBDomain`
— add it like the other authz config flags. Use `cc.HTTPClient`; gate mutation points behind `cc.AllowMutations`.)

- `ID()="GQL-I04"`, `Name()="OS Command Injection"`, `Category()=Injection`, `Severity()=CRITICAL`,
  `RequiresSchema()=true`.

## Detection algorithm
1. Enumerate injection points; prioritize String args whose names suggest shell-reaching params
   (`host`, `domain`, `url`, `file`, `path`, `cmd`, `name`, `format`, `width`, `height`). Cap small (timing).
2. **Time-based oracle (primary, in-band):** for each candidate, build a control and a payload that appends a
   conditional sleep across separators: `` `sleep 5` ``, `; sleep 5`, `| sleep 5`, `$(sleep 5)`, `& ping -c 5
   127.0.0.1`. Run `inject.TimingOracle(samples=7)`; require a robust effect.
3. **OOB (blind, opt-in):** if `cc.OOBDomain != ""`, inject `; curl http://<unique>.<oob-domain>` /
   `nslookup <unique>.<oob-domain>` with a unique subdomain per point; correlate a DNS/HTTP callback to that
   subdomain (the OOB client/poller is provided by the SSRF foundation in GQL-I05 — reuse it). A correlated
   callback is `"confirmed"`.
4. **Error-based (verbose servers):** `inject.ErrorSignal` against shell/exec error patterns
   (`sh: 1:`, `command not found`, `No such file or directory`, `/bin/sh`) → `"firm"` corroboration.
5. **Decide — flag CRITICAL when** the timing oracle reports a robust effect **or** an OOB callback correlates.
   Confidence `"confirmed"` (OOB or robust timing), `"firm"` (error-only). Negative/inconclusive otherwise.

## Finding content
- **Title:** `OS Command Injection — <rootField> arg <path>`
- **Description:** the point, the separator/payload family that fired, the timing medians or the OOB callback
  id, and any error signal. Mark all payloads as benign probes (sleep/ping/DNS only).
- **Impact:** remote code execution on the API server; full host and data compromise; lateral movement.
- **Remediation:** never pass user input to a shell; use exec APIs with argument arrays (no shell), strict
  allow-lists, and input validation; run workers with least privilege and network egress controls.
- **References:** `https://owasp.org/www-community/attacks/Command_Injection`,
  `https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/78.html`.
- **Confidence:** `"confirmed"`/`"firm"`. **CWE:** `"CWE-78"`. **OWASP:** injection / `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-I04", cc.Target, "cmdi:"+rootField+"/"+pathKey)`.

## Acceptance criteria
- **Given** a server that sleeps when a payload contains `sleep 5` (use a short test sleep), one CRITICAL
  finding fires (confirmed via timing). Constant-latency server → no finding.
- **Given** `--oob-domain` and a server that triggers a DNS/HTTP callback, a confirmed finding fires correlated
  to the unique subdomain; without `--oob-domain` the OOB path is skipped (noted in PassReason).
- Mutation points gated; no panic on timeouts.

## Tests (`gqli04_os_command_injection_test.go`)
- Timing handler that sleeps on `sleep`/`ping` tokens → finding (short sleep + adjustable threshold).
- Constant/jittery handler → no finding.
- OOB path: stub the OOB poller to report a hit for the injected subdomain → confirmed; no `cc.OOBDomain` →
  OOB skipped.
- Assert severity CRITICAL, fingerprint, bounded samples.

## Safety
Only **benign** payloads: `sleep`/`ping`/`timeout`/DNS-lookup of an operator-owned OOB domain — never
destructive commands. OOB is opt-in. Bounded samples/points; mutation points gated.
