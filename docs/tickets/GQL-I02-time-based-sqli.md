# GQL-I02 — Time-Based Blind SQL Injection (Statistical Timing Oracle)

| Field | Value |
|---|---|
| **Type** | Story |
| **Epic** | GQLS-INJECTION |
| **Priority** | P1 |
| **Severity (of finding)** | CRITICAL |
| **Story points** | 5 |
| **Complexity** | Medium |
| **Labels** | `injection`, `sqli`, `time-based`, `blind`, `cwe-89`, `timing-oracle` |
| **Category** | `Injection` |
| **Depends on** | **GQL-I09** (injection points + `inject.TimingOracle`) |
| **Files** | `pkg/scanner/checks/gqli02_time_based_sqli.go` (+ `_test.go`) |

## Summary
Detect **time-based blind SQL injection** by injecting a conditional database sleep (`SLEEP(5)`, `pg_sleep(5)`,
`WAITFOR DELAY '0:0:5'`, `dbms_pipe.receive_message`) and confirming the response is robustly slower than a
matched control using the **statistical timing oracle** (median + MAD over repeated samples) — no single-sample
guessing.

## Why it matters
- Time-based SQLi (CWE-89) works when there is no error leakage and no boolean-observable output — the last
  resort and a very common real-world finding. A statistical oracle kills the false positives that make
  naive timing checks (today's GQL-007 latency heuristic) noisy.

## Engineering Context
(See `EPIC-GQL-INJECTION.md` shared context + safety. Consume `inject.Points`, `inject.Send`,
`inject.TimingOracle`. Use `cc.HTTPClient`; gate mutation points behind `cc.AllowMutations`.)

- `ID()="GQL-I02"`, `Name()="Time-Based Blind SQL Injection"`, `Category()=Injection`,
  `Severity()=CRITICAL`, `RequiresSchema()=true`.

## Detection algorithm
1. Enumerate injection points (cap small — timing is expensive; default ≤ 8 points). String/ID/Int leaves.
2. For each point, define a **control** value (benign) and a **payload** value embedding a conditional sleep
   from a small per-engine table (MySQL `SLEEP`, Postgres `pg_sleep`, MSSQL `WAITFOR`, Oracle, generic). Use a
   fixed sleep `D` (default 5s).
3. Run `inject.TimingOracle(control, payload, samples=7)`: interleave samples, compute median+MAD.
4. **Decide — flag CRITICAL when** `Effect==true`: the payload median exceeds control median by ≳ the injected
   delay and by ≥ k·MAD (k≈3). Confidence `"confirmed"` (statistically robust). When the schema/engine is
   known (GQL-M01), prefer that engine's sleep first to save requests.
   - Negative / inconclusive: no robust effect → not flagged; record control/payload medians in PassProbes.

## Finding content
- **Title:** `Time-Based Blind SQL Injection — <rootField> arg <path>`
- **Description:** the point, the sleep payload family that fired, and the measured `controlMedian` vs
  `payloadMedian` (± MAD, N samples). Make the numbers the headline. Redact the payload string is unnecessary
  (it's a benign sleep) but keep it clearly labeled as a probe.
- **Impact:** blind, byte-by-byte extraction of database contents; full data compromise even with no error or
  boolean output.
- **Remediation:** parameterized queries / prepared statements; input validation; statement timeouts; WAF is
  not sufficient.
- **References:** `https://owasp.org/www-community/attacks/Blind_SQL_Injection`,
  `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html`,
  `https://cwe.mitre.org/data/definitions/89.html`.
- **Confidence:** `"confirmed"`. **CWE:** `"CWE-89"`. **OWASP:** injection / `"API8:2023"`.
- **Fingerprint:** `GenerateFingerprint("GQL-I02", cc.Target, "time_sqli:"+rootField+"/"+pathKey)`.

## Acceptance criteria
- **Given** a server that sleeps when the payload contains a recognized sleep token, one CRITICAL finding
  fires with the measured medians and `Effect=true`; `ProbeCount == 2·samples` for the firing point.
- **Given** a server with constant latency (and a jittery one), no finding (`Effect=false`) — no FP on noise.
- **Given** mutation-only points and `AllowMutations=false`, those points are skipped.
- No panic on errors/timeouts; the wait budget is bounded.

## Tests (`gqli02_time_based_sqli_test.go`)
- `httptest` handler that `time.Sleep`s when the request body contains `SLEEP(`/`pg_sleep(` → finding (use a
  short sleep, e.g. 200ms, and a matching threshold via an injectable constant so the test is fast).
- Constant-latency handler → no finding. Jittery handler (random small delays, no payload effect) → no finding.
- Assert severity CRITICAL, fingerprint set, medians reported, bounded sample count.

## Safety
Conditional **sleep** payloads only — read-only, no data change. Sample count and sleep duration are small,
fixed constants; bounded point count; mutation points gated; cancellable on `ctx.Done()`.
