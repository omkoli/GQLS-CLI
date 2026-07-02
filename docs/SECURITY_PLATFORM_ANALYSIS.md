# gqls → GraphQL Application Security Platform: A Brutally Honest Architecture & Product Review

> Reviewer perspective: Principal AppSec engineer / GraphQL security researcher who has shipped
> commercial scanners. This document is grounded in a full read of the codebase
> (`pkg/scanner/checks`, `pkg/schema`, `pkg/transport`, `cmd/gqls`), not just the README.
>
> Tone: critical by request. The goal is to find every gap, not to flatter.

---

## 0. Executive verdict

**What you actually have:** a *well-engineered, conservative, single-shot misconfiguration scanner* with
12 checks. The Go architecture is genuinely good — a clean dependency-leaf `domain` package, a
self-registering `Check` interface, a thoughtful three-client transport split
(`HTTPClient` / `BaseHTTPClient` / `UnauthenticatedClient`), a real curl-ingestion parser that never
shells out, and — the one genuine technical differentiator — a **schema-extraction pipeline with
field-suggestion harvesting fallback** (`pkg/schema/harvester.go`) when introspection is disabled.
That harvester is the same idea as `clairvoyance` and is more than most "GraphQL scanners" on GitHub do.

**What it is not:** a security platform, an attack engine, or anything an enterprise buyer would pay for
*yet*. Be honest with yourself about the ceiling of the current design:

1. **Every check is a stateless, sequential, fire-and-forget HTTP probe.** There is no crawler, no state
   machine, no attack chaining, no session handling beyond static headers. The most valuable GraphQL
   vulnerabilities — authorization flaws (BOLA/BFLA/BOPLA), business-logic abuse, multi-step chains — are
   *fundamentally stateful* and are structurally impossible in the current engine.
2. **The check coverage skews toward the cheap, well-trodden 20%.** Introspection, playground, suggestions,
   stack traces, depth/complexity, batching, GET, error-based SQLi, unauth mutations. This is the
   "GraphQL Cop / graphql-cop" tier. The entire OWASP API Top 10 authorization surface (API1/API3/API5),
   which is where ~70% of real GraphQL bug-bounty money is, is **absent**.
3. **No server fingerprinting.** You don't know if you're hitting Apollo, graphql-ruby, Hasura, HotChocolate,
   Graphene, gqlgen, Lighthouse, or Yoga — so you can't tailor payloads or map engine-specific CVEs.
   `graphw00f` solves this and you should absorb it.
4. **Detection is mostly regex + status-code heuristics.** Defensible for v1, but it caps your true-positive
   rate and is trivially evaded. There's no differential analysis, no statistical timing model, no oracle.

**The strategic question** is not "which 5 more checks do I add." It's: *do you stay a fast CLI linter
(compete with graphql-cop / InQL, monetize via OSS + support), or do you become an attack engine
(compete with Escape, Inigo, StackHawk, Burp+InQL Pro, and earn enterprise revenue)?* They require
different cores. This document maps both, but my recommendation is unambiguous: **the money and the moat
are in the stateful authorization + business-logic engine. Everything in the roadmap bends toward that.**

---

## 1. Feature Gap Analysis — what is actually implemented, graded

Grades are A–F on *commercial-scanner* standards, not on "is it nice OSS."

| Area | Implementation (from code) | Grade | Brutal note |
|---|---|---|---|
| **Engine architecture** | `Check` interface + global registry, `CheckContext`, sequential runner in `runScan` | B+ | Clean and extensible, but synchronous, single-target, no crawl graph, no shared evidence store between checks. Adding stateful checks will fight this design. |
| **Transport** | Rate-limited (`x/time/rate`), 3 client identities, body buffering for repro | A− | Genuinely thoughtful. Missing: retries/backoff, connection reuse tuning, proxy support, HTTP/2 control, per-host concurrency, response caching/dedup. |
| **Schema extraction** | introspection → minimal introspection → **field-suggestion harvesting** → partial; concurrent endpoint discovery over 13 paths | A | Your best asset. The harvester is a real differentiator. But discovery is a fixed list and POST-only; no GET/`?query=`, no `.well-known`, no persisted-query probing. |
| **curl ingestion** | Real parser, Bash + CMD multiline, ANSI-C quotes, smart-quote normalization, no shell exec | A | Excellent and security-correct. This is a sleeper UX feature. Extend it to HAR and OpenAPI/Postman import. |
| **Auth model** | Static headers; unauth vs base vs full client separation; auth probe in extractor | C | Static bearer/cookie only. No login flow, no token refresh, no OAuth, no multi-role/multi-tenant identities — which is the prerequisite for *all* authorization testing. This is the single biggest blocker to commercial relevance. |
| **Checks: InfoDisclosure** | GQL-001..006, 010 | B | Solid coverage of the easy class. Missing CSRF, field-suggestion *exploitation* (you harvest but don't weaponize), introspection-via-GET, trace/`extensions` leakage taxonomy. |
| **Checks: DoS** | GQL-007 depth, 008 complexity, 009 batch, **D01–D08 (alias amplification, field duplication, circular fragments, directive overloading, unbounded pagination, cost-amplification oracle, persisted-query/APQ enforcement, introspection-as-DoS)** | A | Depth uses latency heuristics (4×, ≥500ms) — noisy and evadable, but the GQLS-DOS suite (D01–D08) now covers the full structural DoS class: alias/field-duplication/fragment-cycle/directive amplification, schema-driven pagination abuse, an empirical cost-amplification oracle, persisted-query allow-list enforcement, and unbounded-introspection amplification. |
| **Checks: Injection** | GQL-011 error-based SQLi only | D+ | One String arg of one query + one mutation, 5 payloads, regex on DB errors. No boolean/time-based, no NoSQL/Mongo, no OS command, no SSRF, no XSS-in-GraphQL, no ORM operator injection. Injection coverage is a rounding error. |
| **Checks: AuthN/AuthZ** | GQL-012 unauth mutations only | D | **The crown jewels of GraphQL security — BOLA, BFLA, field-level authz, cross-tenant IDOR — are entirely missing.** GQL-012 is one narrow slice (anonymous mutation execution). |
| **Reporting** | terminal/txt/json/sarif, repro curl, redaction of `Authorization`, pass-probe transparency | A− | "Show the probes even when clean" is a genuinely good trust feature most tools lack. Missing: HTML report, JUnit XML, GitHub SARIF upload helper, CycloneDX, dedup across runs, severity-with-confidence, CWE/OWASP tags in output. |
| **False-positive handling** | SHA-256 fingerprint suppression via config | B | Good primitive. But fingerprint = `checkID+target+evidenceKey`; it has no confidence score, no triage workflow, no "expected/accepted risk" lifecycle. |
| **Config/CI** | viper precedence (file→env→flags), `--fail-on`, exit codes | B | Correct DevSecOps basics. Missing: baseline/diff mode, policy-as-code, sane non-zero exit taxonomy, container image, official Actions/GitLab templates. |
| **Output integrity** | Auth header redaction in repro, deterministic discovery ordering | A | Mature instincts. Keep this discipline as you scale. |

**One-line summary:** *engineering quality A-, security coverage D+, product surface C.* You have built a
very good chassis and bolted on a starter engine.

---

## 2. Missing GraphQL security checks — the exhaustive list

Organized by category, mapped to OWASP API Top 10 (2023) / OWASP GraphQL Cheat Sheet / CWE. "Have?"
reflects the current code. Priority is P0 (build now) → P3 (later). Complexity is engine effort.

### 2.1 Authorization — the missing 70% (this is where the money is)

| Proposed ID | Check | OWASP / CWE | Have? | Sev | Cx | Pri |
|---|---|---|---|---|---|---|
| GQL-A01 | **BOLA / IDOR** — object access across IDs (e.g. `user(id:)`, `order(id:)`) with role A's token reaching role B's objects | API1 / CWE-639 | ✅ (implemented) | CRIT | H | **P0** |
| GQL-A02 | **BFLA** — privileged mutations/queries reachable by lower-privilege role | API5 / CWE-285 | ✅ (implemented) | CRIT | H | **P0** |
| GQL-A03 | **BOPLA / field-level authz** — sensitive fields (`email`, `ssn`, `isAdmin`) returned to under-privileged roles even when object access is intended | API3 / CWE-213 | ✅ (implemented) | HIGH | H | **P0** |
| GQL-A04 | **Cross-tenant isolation** — tenant A reaching tenant B data via ID/tenant header manipulation | API1 | ✅ (implemented) | CRIT | H | P1 |
| GQL-A05 | **Mutation-side authz** — can a non-owner *update/delete* an object (not just read) | API5 | ✅ (implemented) | CRIT | H | P1 |
| GQL-A06 | **Auth via aliases / batching bypass** — rate-limit / brute-force protection bypass by aliasing `login` N times in one request | API4 / CWE-307 | ✅ (implemented) | HIGH | M | **P0** |
| GQL-A07 | **GraphQL CSRF** — state-changing operation accepted via GET or `Content-Type: text/plain`/`application/x-www-form-urlencoded` without CSRF token | API8 / CWE-352 | ✅ (implemented) | HIGH | L | **P0** |
| GQL-A08 | **JWT weaknesses** — `alg:none`, weak secret, missing `exp`, `kid` injection on the auth token | CWE-347 | ✅ (implemented) | HIGH | M | P1 |
| GQL-A09 | **Subscription authz** — WebSocket subscriptions bypassing the authz applied to queries | API5 | ✅ (implemented) | HIGH | H | P2 |

### 2.2 Denial of Service / resource exhaustion (cheap wins you're missing)

| Proposed ID | Check | Reference | Have? | Sev | Cx | Pri |
|---|---|---|---|---|---|---|
| GQL-D01 | **Alias-based amplification** — `a1:expensiveField a2:expensiveField …` ×1000 in one doc | OWASP CS "Aliases"; PortSwigger | ✅ (implemented) | HIGH | L | **P0** |
| GQL-D02 | **Field duplication / `__typename` flooding** — same field repeated thousands of times (graphql-js amplification class) | GHSA advisories | ✅ (implemented) | HIGH | L | **P0** |
| GQL-D03 | **Circular fragment / fragment-spread bomb** — mutually referential fragments (parser/validator DoS) | OWASP CS | ✅ (implemented) | HIGH | L | P1 |
| GQL-D04 | **Directive overloading** — `@a @a @a …` ×N on a field (known graphql-js DoS class) | GHSA | ✅ (implemented) | MED | L | P1 |
| GQL-D05 | **Array/list argument abuse** — `first: 1000000`, unbounded pagination, `ids: [...]` huge arrays | API4 | ✅ (implemented) | HIGH | M | P1 |
| GQL-D06 | **Query cost vs. response-size oracle** — measure resolver cost amplification factor empirically | API4 | ✅ (implemented) | MED | M | P2 |
| GQL-D07 | **No persisted-query / APQ enforcement** — arbitrary queries accepted where only allow-listed should be | best practice | ✅ (implemented) | MED | M | P2 |
| GQL-D08 | **Introspection-as-DoS** — recursive type introspection size amplification | OWASP CS | ✅ (implemented) | LOW | L | P3 |

> Note on GQL-007: your latency heuristic (`ratio≥4 && d10≥500ms`) will false-positive on cold caches and
> false-negative behind CDNs. Alias amplification (D01) is a *structural* signal — the server either caps
> document size/aliases or it doesn't — far higher signal-to-noise for the same engineering cost.

### 2.3 Injection (current coverage is a rounding error)

| Proposed ID | Check | CWE | Have? | Sev | Cx | Pri |
|---|---|---|---|---|---|---|
| GQL-I01 | **Boolean-based SQLi** (differential true/false) | CWE-89 | ❌ | CRIT | M | P1 |
| GQL-I02 | **Time-based blind SQLi** (`SLEEP`, `pg_sleep`, `WAITFOR`) with statistical timing oracle | CWE-89 | ❌ | CRIT | M | P1 |
| GQL-I03 | **NoSQL injection** — Mongo operator injection (`$ne`, `$gt`, `$where`) via JSON args | CWE-943 | ❌ | CRIT | M | P1 |
| GQL-I04 | **OS command injection** — error + time-based on shell-reaching args | CWE-78 | ❌ | CRIT | M | P2 |
| GQL-I05 | **SSRF via GraphQL args** — URL/host/webhook args, blind via OOB callback | API7 / CWE-918 | ❌ | CRIT | M | **P1** |
| GQL-I06 | **Stored/reflected XSS surfaced through GraphQL** (esp. error reflection, HTML-typed fields) | CWE-79 | ❌ | MED | M | P2 |
| GQL-I07 | **ORM/GraphQL operator injection** (Hasura/Postgraphile `where`/`_like` predicate abuse) | CWE-943 | ❌ | HIGH | M | P2 |
| GQL-I08 | **LDAP/XML/template injection** on injectable args | CWE-90/91/1336 | ❌ | HIGH | M | P3 |
| GQL-I09 | **Injection into *all* injectable args**, not first-String-only; variable + inline + nested input objects | — | ❌ | — | M | **P1** |

> GQL-011 today probes **one** String arg of **one** query and **one** mutation. Real injection coverage
> requires enumerating *every* leaf scalar across the whole reachable input graph, including nested input
> objects and list elements, with multiple oracle strategies. The current check finds only the most naive
> error-leaking endpoint.

### 2.4 Information disclosure / misconfiguration (round out the easy class)

| Proposed ID | Check | Reference | Have? | Sev | Cx | Pri |
|---|---|---|---|---|---|---|
| GQL-M01 | **Server engine fingerprinting** (graphw00f-style: Apollo, graphql-ruby, Hasura, HotChocolate, Graphene, gqlgen, Lighthouse, Yoga, Strawberry, Ariadne…) | graphw00f | ✅ (implemented) | INFO | M | **P0** |
| GQL-M02 | **Engine-specific known-CVE mapping** once fingerprinted | — | ❌ | varies | M | P1 |
| GQL-M03 | **Trace/`extensions` leakage taxonomy** — Apollo tracing, `extensions.exception.stacktrace`, timing metadata | OWASP CS | partial (005) | MED | L | P1 |
| GQL-M04 | **Introspection via GET / alternative content-types** when POST introspection is blocked | PortSwigger | ❌ | MED | L | P1 |
| GQL-M05 | **Suggestion-based full schema reconstruction** (you harvest — now *report* the reconstructed SDL as a finding/artifact) | clairvoyance | partial | MED | M | P1 |
| GQL-M06 | **Debug/dev mode detection** (`debug:true`, GraphiQL on prod, `/altair`, `/voyager`) | — | partial (004) | LOW | L | P2 |
| GQL-M07 | **CORS misconfiguration** on the GraphQL endpoint (`ACAO: *` + credentials) | API8 / CWE-942 | ❌ | MED | L | P1 |
| GQL-M08 | **Security headers** (CSP, `X-Content-Type-Options`, HSTS) on the GraphQL response | API8 | ❌ | LOW | L | P3 |
| GQL-M09 | **Field-level deprecation/secret leakage** via descriptions and default values | — | partial (006) | LOW | L | P3 |

### 2.5 Business logic / abuse (the high-value, hard tier)

| Proposed ID | Check | OWASP | Have? | Sev | Cx | Pri |
|---|---|---|---|---|---|---|
| GQL-B01 | **Unrestricted access to sensitive business flows** (signup/coupon/transfer abuse via batch+alias) | API6 | ✅ (implemented) | HIGH | H | P2 |
| GQL-B02 | **Mass assignment via input objects** — setting `isAdmin`, `role`, `verified` through mutation inputs | API3 / CWE-915 | ✅ (implemented) | HIGH | M | P1 |
| GQL-B03 | **Race conditions** (parallel mutations: double-spend, coupon reuse) | CWE-362 | ❌ | HIGH | H | P3 |
| GQL-B04 | **Enumeration via differential errors** (valid vs invalid user/email timing & message diffs) | API1 | ❌ | MED | M | P2 |

**Bottom line for §2:** you have ~12 checks covering the lowest-difficulty band. A credible commercial
GraphQL scanner needs **40–60 checks**, and the *weighted value* sits almost entirely in §2.1 (authz),
§2.5 (logic), §2.3 (real injection), and the cheap structural DoS in §2.2.

---

## 3. Attack-coverage comparison vs. the canon

Legend: ✅ covered · 🟡 partial · ❌ missing.

### 3.1 vs OWASP API Security Top 10 (2023)

| OWASP API risk | gqls today | Gap severity |
|---|---|---|
| API1 — Broken Object Level Authorization (BOLA) | ✅ (A01 BOLA/IDOR + A04 cross-tenant) | **Low** — object-id IDOR and cross-tenant isolation both covered |
| API2 — Broken Authentication | 🟡 (012 unauth mutations; A06 alias brute-force; A08 JWT weaknesses) | Medium — JWT + alias brute-force covered; no session/OAuth-flow testing |
| API3 — Broken Object Property Level Authz (BOPLA/excessive data + mass assignment) | ✅ (A03 sensitive-field exposure + B02 mass assignment; 006 flags schema fields) | **Low** — both field-read authz and write-side mass assignment covered |
| API4 — Unrestricted Resource Consumption | 🟡 (007/008/009) | Medium — missing alias/dup/SSRF-cost vectors |
| API5 — Broken Function Level Authorization (BFLA) | ✅ (A02 BFLA + A05 mutation-side authz + A09 subscription authz) | **Low** — function-, mutation-, and subscription-side authz all covered |
| API6 — Unrestricted Access to Sensitive Business Flows | 🟡 (B01 batch/alias flow-multiplicity abuse) | Medium — single-request flow multiplicity covered; race-condition (B03) abuse still open |
| API7 — SSRF | ❌ | High |
| API8 — Security Misconfiguration | 🟡 (001/004/005/010) | Medium — missing CSRF/CORS/headers |
| API9 — Improper Inventory Management | 🟡 (endpoint discovery) | Medium — no env/version/deprecated-API inventory |
| API10 — Unsafe Consumption of APIs | ❌ | Low (less GraphQL-specific) |

**You meaningfully cover ~2.5 of 10, and you miss 3 of the 4 "Critical" authorization risks.**

### 3.2 vs OWASP GraphQL Cheat Sheet

| Cheat Sheet recommendation | Tested? |
|---|---|
| Disable introspection in prod | ✅ (001/002) |
| Disable field suggestions | 🟡 (003 detects; doesn't fully reconstruct) |
| Query depth limiting | ✅ (007) |
| Query complexity/cost limiting | ✅ (008) |
| Amount/pagination limiting | ❌ |
| Batching/aliasing limits | 🟡 (009 batch; **no alias amplification**) |
| Timeouts | 🟡 (inferred via latency) |
| Disable GraphiQL/playground in prod | ✅ (004) |
| Don't leak errors/stack traces | ✅ (005) |
| Enforce authorization on every resolver | ❌ |
| Validate & sanitize input (injection) | 🟡 (011 error-SQLi only) |
| CSRF protection | ✅ (A07) |
| Don't allow GET for mutations | 🟡 (010 detects GET queries; not mutation-CSRF) |

### 3.3 vs PortSwigger GraphQL Academy labs

| Academy technique | Tested? |
|---|---|
| Find the endpoint / discovery | ✅ |
| Introspection (and `__schema`/`__type` probing) | ✅ |
| Bypassing introspection defenses (whitespace/`\n` after `__schema`) | ❌ |
| Field suggestions to reconstruct blind schema | 🟡 |
| **Bypassing rate limits using aliases** | ✅ (A06) |
| **Bypassing brute-force protection via aliases/batching** | ✅ (A06) |
| GraphQL CSRF | ✅ (A07) |
| Accessing private data via unguarded fields | ❌ |

> The single most-cited PortSwigger GraphQL attack — **alias-based brute-force / rate-limit bypass** — is
> not implemented. This is a P0, low-complexity, high-credibility addition.

### 3.4 vs bug-bounty / HackerOne reality & research

The recurring GraphQL bounty patterns (HackerOne disclosed reports, Black Hat GraphQL by Aleks & Farhi,
Nikita Stupin's GraphQL pentest notes, Escape/Inigo research):

- **IDOR through GraphQL node/global-ID** — ❌
- **Excessive data exposure on nested edges** (`user { paymentMethods { number } }`) — ❌
- **Mutation authz bypass / mass assignment** — ❌
- **Batching to bypass MFA/OTP** — ❌
- **SSRF via GraphQL `url`/`webhook`/`avatar` args** — ❌
- **Introspection re-enabled in staging/alt env** (API9) — 🟡
- **Apollo Server CSRF** (the reason `csrfPrevention` exists) — ❌

You cover the *scanner-friendly misconfigs*; you miss the *bounty-paying exploits*.

---

## 6. Detection-engine ideas (raise true-positive rate, lower evasion)

For each: why → implementation → complexity → security impact → commercial value → priority.

### 6.1 Differential/oracle-based detection (replace single-shot regex)
- **Why:** regex on error strings (011, 005) and status codes (012) is trivially evaded and noisy.
  Real scanners use *differential analysis*: send a control + a payload, compare responses.
- **Implementation:** a `Probe → Response` evidence store + a `Differ` that compares two responses on
  (status, normalized body, field set, error taxonomy, latency distribution). Booleans-based SQLi,
  authz (role A vs role B on the *same* query), and enumeration all collapse to "compare two responses."
- **Complexity:** Medium (it's the missing core primitive). **Security impact:** High. **Commercial:** High.
  **Priority: P0** — this primitive unlocks half the missing checks.

### 6.2 Statistical timing oracle (for blind injection & DoS)
- **Why:** one latency sample (your 007) is noise. Blind/time-based injection needs confidence.
- **Implementation:** N repeated samples, compute median + MAD, require effect size (e.g. payload median
  > control median + k·MAD across ≥7 trials) before firing. Reuse for time-based SQLi/command injection.
- **Complexity:** Medium. **Impact:** High (kills both FPs and FNs). **Commercial:** Medium. **Priority: P1.**

### 6.3 Server fingerprinting → payload tailoring (graphw00f absorption)
- **Why:** Apollo vs graphql-ruby vs Hasura have different error formats, batching semantics, introspection
  defenses, and CVEs. Blind payloads waste requests and miss engine-specific bugs.
- **Implementation:** port graphw00f's discriminator queries (error-message wording, supported features,
  `__typename` quirks). Gate engine-specific checks on the fingerprint; map to a CVE table (M02).
- **Complexity:** Medium. **Impact:** Medium (multiplier on everything else). **Commercial:** High
  (engine + version + CVE in a report reads as "real scanner"). **Priority: P0.**

### 6.4 Schema-driven payload synthesis & reachability graph
- **Why:** you already parse the schema (`pkg/schema/model.go`). Use it as an *attack-surface graph*:
  every (field, arg, scalar) is an injection candidate; every (object, id-arg) is a BOLA candidate;
  every sensitive field is a BOPLA candidate. This turns coverage from "1 String arg" into "the whole graph."
- **Implementation:** a `surface` package that walks `Schema` → emits typed test candidates with valid
  example values (respecting required args, enums, input objects). Feed candidates to injection/authz engines.
- **Complexity:** Medium-High. **Impact:** Very High (coverage explosion). **Commercial:** High.
  **Priority: P0** — this is the bridge from "12 checks" to "scales with the target."

### 6.5 Response/error taxonomy classifier
- **Why:** "is this an auth error, a validation error, a DB error, a rate-limit, or a success?" is asked
  ad-hoc in every check (see the regex tables duplicated across 011/012). Centralize it.
- **Implementation:** one `classify(Response) → {Success, AuthDenied, Validation, ServerError, RateLimited,
  Injection-Signal, …}` with engine-aware rules. Every check consumes classifications, not raw regex.
- **Complexity:** Low-Medium. **Impact:** Medium (consistency + fewer FPs). **Commercial:** Medium. **Priority: P1.**

### 6.6 Confidence scoring + evidence chain on every finding
- **Why:** enterprise triage needs `confidence ∈ {confirmed, firm, tentative}` (Burp's model) plus the
  exact request/response pair that proves it. You have repro requests; add confidence + captured response.
- **Implementation:** extend `domain.Finding` with `Confidence`, `Evidence []ProbePair{Req,Resp}`,
  `CWE`, `OWASP`. Reporters render it. SARIF carries it in `properties`.
- **Complexity:** Low. **Impact:** Medium. **Commercial:** High (triage is what buyers pay for). **Priority: P1.**

### 6.7 Out-of-band (OOB) interaction server for blind bugs
- **Why:** blind SSRF, blind injection, and blind XXE are invisible without a callback channel
  (Burp Collaborator / interactsh model).
- **Implementation:** integrate an interactsh client, or ship a hosted collaborator; inject unique
  subdomains into URL-typed args; correlate DNS/HTTP hits to findings.
- **Complexity:** High. **Impact:** Very High (unlocks the entire blind class). **Commercial:** Very High
  (this is a paid-tier feature). **Priority: P2.**

---

## 7. Offensive / pentester capabilities

What a pen-tester needs that the current CLI can't do:

| Capability | Why it matters | Cx | Pri |
|---|---|---|---|
| **Interactive REPL / query console** with schema autocomplete | Manual exploitation after the scan; the scanner is recon, the human finishes the kill | M | P2 |
| **Authenticated multi-identity sessions** (define role A/B/C tokens, or login flows) | Prerequisite for *all* authz testing; the #1 missing primitive | M | **P0** |
| **Proxy mode / passive analysis** (sit in front of Burp/ZAP, ingest traffic) | Real engagements feed the scanner from observed traffic, not a single curl | H | P2 |
| **HAR / Postman / OpenAPI import** | Bulk-seed real authenticated requests; extends your great curl parser | M | P1 |
| **Exploit generation** — emit working PoC queries (alias brute-force doc, IDOR query for a found object) | Pen-testers want the payload, not just "you may be vulnerable" | M | P1 |
| **Query mutation/fuzzing engine** (alias counts, arg fuzzing, type confusion, enum brute-force) | Coverage + finds the weird ones | H | P2 |
| **Wordlists for blind field/arg brute-force** when suggestions are off and introspection is off | The hard-mode schema recovery the bounty crowd does by hand | M | P2 |
| **Burp/Caido extension or `mitmproxy` addon** | Meet pen-testers in their existing tool; massive distribution | M | P1 |
| **Resume/replay + rate-limit-aware throttling per host** | Long engagements against fragile targets | M | P2 |
| **Tor/proxy/upstream chaining + custom TLS** | Scope/egress control on real engagements | L | P3 |

> The fastest credibility win with pen-testers: **multi-identity sessions + alias brute-force PoC + a Burp
> extension.** That trio is what gets you cited in writeups.

---

## 9. CI/CD — becoming a first-class DevSecOps tool

For each: why → how → Cx → impact → priority.

- **Baseline + diff mode (P0, Low):** store a baseline of accepted findings; fail the build *only on new*
  findings. Without this, teams disable the scanner after the first noisy run. Implement as
  `--baseline file.json` + fingerprint set-diff (you already have fingerprints — extend them).
- **Official GitHub Action + GitLab template + pre-commit hook (P0, Low):** a marketplace Action that runs
  the container, uploads SARIF to GitHub code-scanning (`github/codeql-action/upload-sarif`), and annotates
  the PR. This is table-stakes adoption surface and you're one YAML file + Dockerfile away.
- **Container image, multi-arch, SBOM-signed (P0, Low):** `ghcr.io/.../gqls`, cosign-signed, so pipelines
  pull a pinned digest.
- **Policy-as-code (P1, Medium):** a `gqls-policy.yaml` (allow severities per category, per-route waivers
  with expiry, required checks). Enterprises buy *governance*, not scans.
- **Exit-code taxonomy (P1, Low):** distinguish "findings ≥ threshold" (1) from "scan/config error" (2)
  from "target unreachable" (3). Today both findings and fatal errors return 1 — CI can't tell them apart.
- **PR review comments / SARIF fix-ups (P1, Medium):** inline annotations on the offending resolver/schema
  file when source is available (schema-to-source mapping).
- **JUnit XML + HTML + CycloneDX outputs (P1, Low-Med):** JUnit for test dashboards, HTML for humans,
  CycloneDX for the API-as-component SBOM story.
- **Drift / scheduled monitoring + history (P2, Medium):** track schema changes & new endpoints over time
  (API9 inventory). "Your prod schema exposed 3 new mutations this week" is a sticky enterprise hook.
- **IaC/registry integration (P2):** discover GraphQL services from k8s ingress / API gateway configs and
  auto-enroll them.

---

## 11. Research & frontier opportunities (where almost no scanner plays)

These are the moat-builders. Honest difficulty ratings included.

| Idea | What it is | Why it's a moat | Research difficulty | Priority |
|---|---|---|---|---|
| **LLM-driven authz hypothesis generation** | Feed the schema + observed roles to an LLM that proposes *which* objects/fields *should* be access-controlled, then auto-derive BOLA/BFLA test cases | Encodes business-context that pure heuristics can't; turns authz testing from "we can't guess intent" into "we propose intent and verify it" | High | P2 |
| **Semantic schema analysis** | Classify every field by *meaning* (PII/financial/owner-scoped/admin) using embeddings, not your current regex table (`sensitivity.go`) | Drives BOPLA + injection prioritization; far beyond `password|ssn` regex | Medium | P1 |
| **Resolver dependency / data-flow graph** | Infer which fields share backing data sources / which mutations affect which queries, from response correlation + timing | Enables attack-path planning and race-condition discovery | High | P3 |
| **Attack-path generation** | Treat the schema as a graph; A* search from "anonymous" to "admin object" through chained queries/mutations | "Here is a 3-step path to PII" is a Escape/Inigo-killer feature | Very High | P3 |
| **Autonomous GraphQL pentest agent** | An agent loop: fingerprint → map surface → hypothesize → probe → observe → refine, with the differential engine (§6.1) as ground truth | The category-defining bet; risky, expensive, high payoff | Very High | P3 |
| **LLM-generated, schema-aware payloads** | Use the schema + engine fingerprint to synthesize injection/abuse payloads tailored to types and the detected backend (Mongo vs PG vs ORM) | Higher hit-rate than static payload lists; adapts to novel APIs | Medium-High | P2 |
| **GraphQL-specific ML on response corpora** | Train a classifier on success/auth-denied/validation/injection-signal responses across engines to replace brittle regex | Detection accuracy as a defensible asset (data moat) | High | P3 |
| **Formal query-cost modeling** | Statically compute worst-case resolver cost from schema + observed amplification, prove DoS without DoSing | Safe DoS findings (no actual outage) — enterprise-safe | High | P2 |

> Caution as a researcher, not a hype-man: the LLM/agent items are *force-multipliers on top of a
> deterministic engine*, not substitutes for it. Build §6.1 (differential oracle) and §6.4 (surface graph)
> first, or the LLM just hallucinates findings you can't verify. The agent without a verifier is a liability.

---

## Competitive landscape — the table you asked for

| Capability | Competitors (Burp+InQL / Escape / Inigo / StackHawk / graphql-cop / clairvoyance / graphw00f) | gqls **has** | gqls **should build** | gqls **differentiator potential** |
|---|---|---|---|---|
| Endpoint discovery | ✅ most | ✅ (13-path concurrent) | GET/`.well-known`/HAR-seeded | Deterministic, parallel, transparent |
| Engine fingerprinting | ✅ graphw00f, Escape | ✅ (GQL-M01) | GQL-M02 CVE map | At parity (graphw00f-style discriminators) |
| Introspection + bypass | ✅ all | ✅ / 🟡 bypass | introspection-via-GET, whitespace bypass | — |
| **Blind schema recovery (suggestions)** | clairvoyance, Escape | ✅ **harvester** | report reconstructed SDL | **Yes — already strong; few CLIs do this** |
| Depth/complexity DoS | ✅ most | ✅ | alias/dup/circular/directive | Structural (non-latency) detection |
| Alias brute-force / rate-limit bypass | ✅ Burp, Escape | ❌ | **GQL-A06/D01** | — (must add; it's P0) |
| **BOLA/BFLA/BOPLA authz** | ✅ Escape/Inigo/StackHawk | ❌ | **GQL-A01..A05** | **Biggest opportunity** |
| Injection (SQLi/NoSQL/SSRF) | 🟡 Burp (generic), Escape | 🟡 error-SQLi | full injection engine + OOB | Schema-driven full-surface coverage |
| CSRF/CORS/headers | ✅ Burp | ❌ | **GQL-A07/M07** | — |
| Multi-identity / login flows | ✅ Escape/StackHawk/Burp | ❌ | **P0 session model** | — (gating dependency) |
| Out-of-band (Collaborator) | ✅ Burp | ❌ | interactsh integration | Bundled OSS OOB |
| **curl/HAR ingestion UX** | 🟡 (Postman/HAR) | ✅ **excellent curl** | HAR/OpenAPI/Postman | **Yes — best-in-class paste-from-DevTools UX** |
| **Transparent pass-probes** | ❌ rare | ✅ | keep & extend | **Yes — trust/explainability angle** |
| SARIF / CI / fail-on | ✅ StackHawk | ✅ | baseline-diff, Action, policy | Strong if you add baseline-diff |
| Reporting depth (confidence/CWE/OWASP) | ✅ commercial | 🟡 | confidence + evidence + tags | — |
| Autonomous/agentic testing | 🟡 Escape (some), research | ❌ | research track | Frontier bet |

**Where you can credibly win:** (1) blind schema recovery + (2) the cleanest curl/DevTools ingestion +
(3) transparent, explainable findings — *combined with* a real authorization engine. The first three are
already partially yours; the authorization engine is the make-or-break.

---

## 13. Product roadmap (v1.5 → v5.0)

Prioritization columns: **UV** user value, **EE** eng effort, **MD** market differentiation,
**RI** revenue impact, **RD** research difficulty. Scale L/M/H.

### v1.5 — "Credible scanner" (close the embarrassing gaps; weeks, not quarters)
Ship the cheap, high-signal, well-known attacks so no reviewer can say "it misses the basics."

| Feature | UV | EE | MD | RI | RD | Pri |
|---|---|---|---|---|---|---|
| Alias amplification + field-dup DoS (D01/D02) | H | L | M | M | L | P0 |
| Alias-based rate-limit/brute-force bypass (A06) | H | M | M | M | L | P0 |
| GraphQL CSRF + CORS + headers (A07/M07/M08) | H | L | M | M | L | P0 |
| Server fingerprinting (M01) | M | M | M | M | L | P0 |
| Baseline/diff mode + container + GitHub Action | H | L | M | H | L | P0 |
| Confidence + CWE/OWASP tags on findings (6.6) | M | L | M | M | L | P1 |
| Exit-code taxonomy + JUnit/HTML output | M | L | L | M | L | P1 |

### v2.0 — "Authorization engine" (the inflection point; the reason to charge money)
Introduce the **multi-identity session model** and the **differential oracle**, then build authz on top.

| Feature | UV | EE | MD | RI | RD | Pri |
|---|---|---|---|---|---|---|
| Multi-identity sessions / login flows (§7) | H | M | H | H | L | P0 |
| Differential/oracle engine (6.1) | H | M | H | H | M | P0 |
| Schema surface graph + payload synthesis (6.4) | H | M | H | H | M | P0 |
| BOLA / BFLA / BOPLA (A01–A03) | H | H | **H** | **H** | M | P0 |
| Full injection engine: boolean/time SQLi, NoSQL, SSRF (I01–I05/I09) | H | M | H | H | M | P1 |
| Statistical timing oracle (6.2) | M | M | M | M | M | P1 |
| HAR/Postman import (§7) | M | M | M | M | L | P1 |

### v3.0 — "Platform" (from CLI to product; SaaS/server, governance, monitoring)
| Feature | UV | EE | MD | RI | RD | Pri |
|---|---|---|---|---|---|---|
| Server/SaaS mode, project & run history, web UI | H | H | H | **H** | M | P0 |
| Policy-as-code + waiver lifecycle (§9) | H | M | H | H | L | P0 |
| OOB interaction server (6.7) for blind bugs | M | H | H | H | M | P1 |
| Schema-drift & inventory monitoring (API9) | M | M | H | H | M | P1 |
| Burp/Caido/mitmproxy extension (§7) | M | M | H | M | L | P1 |
| Mass assignment + business-flow abuse (B01/B02) | M | M | M | M | M | P2 |

### v4.0 — "Intelligence" (semantic + ML, force-multiply detection)
| Feature | UV | EE | MD | RI | RD | Pri |
|---|---|---|---|---|---|---|
| Semantic schema classification (embeddings) (11) | M | M | H | M | M | P1 |
| LLM-assisted authz hypotheses (11) | M | M | **H** | M | H | P2 |
| LLM schema-aware payload synthesis (11) | M | M | H | M | H | P2 |
| ML response classifier (data moat) (11) | M | H | H | M | H | P2 |
| Resolver dependency graph (11) | L | H | H | L | H | P3 |

### v5.0 — "Autonomous GraphQL red team" (the category-defining bet)
| Feature | UV | EE | MD | RI | RD | Pri |
|---|---|---|---|---|---|---|
| Attack-path generation over schema graph (11) | M | H | **H** | M | VH | P2 |
| Autonomous pentest agent (verifier-grounded) (11) | M | VH | **VH** | H | VH | P3 |
| Formal query-cost / safe-DoS proofs (11) | L | H | H | M | H | P3 |
| Continuous autonomous monitoring + auto-PoC | M | VH | VH | H | VH | P3 |

### Sequencing logic (read this if you read nothing else)
1. **v1.5 is non-negotiable and cheap.** Alias attacks + CSRF + fingerprinting + baseline-diff are low
   effort and remove every "it misses the basics" objection. Do this first.
2. **v2.0 is the whole ballgame.** The *session model + differential oracle + surface graph* are three
   medium tasks that **together** unlock authorization, real injection, and most of the high-value checks.
   Build the primitives, not one-off checks. This is where you stop being graphql-cop and start being a
   product someone pays for.
3. **Don't skip to v4/v5.** LLM/agent features on top of a regex engine produce unverifiable findings.
   The deterministic oracle (6.1) is the verifier the AI layer needs. Earn the right to do AI by building
   the engine first.

---

## Appendix A — concrete near-term engineering changes to the current code

Specific, codebase-grounded refactors that make the roadmap buildable:

1. **Add an evidence store to `CheckContext`.** Today each check re-sends and re-parses in isolation.
   Introduce a shared `*ProbeRecorder` so checks can share responses (e.g. fingerprint once, reuse) and so
   the differential engine has a home. (`pkg/scanner/checks/base.go`)
2. **Promote a `surface` package off `pkg/schema`.** Walk `Schema` into typed test candidates
   (injection points, id-bearing object fetchers, sensitive fields). Every new check consumes candidates
   instead of re-implementing `sqliFirstStringArg`-style ad-hoc walks. (see `gql011`'s one-arg limitation)
3. **Extract a `classify(Response)` taxonomy** and delete the duplicated regex tables in `gql011`/`gql012`.
   Make every check express findings as "control vs payload classification differs."
4. **Add `Identity` to the client model.** Generalize the 3-client split
   (`HTTPClient/BaseHTTPClient/UnauthenticatedClient`) into `map[roleName]*transport.Client` so authz
   checks can say "send as role A, then as role B." This is the single most important structural change.
5. **Extend `domain.Finding`** with `Confidence`, `CWE`, `OWASP`, and a captured response alongside
   `ReproRequest`. Reporters and SARIF `properties` render them. (`pkg/domain/domain.go`)
6. **Make the runner concurrent and cancellable per check** with a global request budget, so the engine
   scales to schema-driven candidate explosion without melting the target. (`cmd/gqls/scan.go` loop)
7. **Split exit codes** in `main()` so CI distinguishes findings from errors. (`failOnThresholdError` today
   collides with fatal-error 1.)

---

## Appendix B — reference map

- **OWASP API Security Top 10 (2023)** — API1 BOLA, API3 BOPLA, API4 Resource Consumption, API5 BFLA,
  API6 Business Flows, API7 SSRF, API8 Misconfiguration, API9 Inventory.
- **OWASP GraphQL Cheat Sheet** — introspection, suggestions, depth/complexity/amount limiting, batching,
  authorization-on-every-resolver, injection, CSRF.
- **PortSwigger Web Security Academy — GraphQL** — discovery, introspection bypass, suggestion recovery,
  **alias-based rate-limit / brute-force bypass**, GraphQL CSRF.
- **graphw00f** — GraphQL engine fingerprinting (absorb into M01/M02).
- **clairvoyance** — field-suggestion schema reconstruction (you already do a version of this).
- **Black Hat GraphQL** (Nick Aleks & Dolev Farhi) and **Nikita Stupin's GraphQL pentesting** notes —
  practical batching/IDOR/SSRF/authz methodology.
- **Apollo Server `csrfPrevention`** — exists because GraphQL CSRF via simple content-types is real.
- **CWE** — 639 (BOLA/IDOR), 285 (BFLA), 213/915 (BOPLA/mass assignment), 89/943 (SQL/NoSQL injection),
  918 (SSRF), 352 (CSRF), 347 (JWT), 307 (brute-force), 362 (race), 942 (CORS), 1336 (template injection).

*(CVE/GHSA references above are cited by class — e.g. graphql-js amplification advisories — rather than by
exact identifier where I would otherwise risk a wrong number; verify specific IDs against the GitHub
Advisory Database before publishing externally.)*
