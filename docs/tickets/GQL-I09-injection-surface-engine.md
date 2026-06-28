# GQL-I09 — Injection Surface Graph + Multi-Oracle Engine (enabler)

| Field | Value |
|---|---|
| **Type** | Story (enabler / build first) |
| **Epic** | GQLS-INJECTION — GraphQL Injection Engine |
| **Priority** | P1 — gating dependency for GQL-I01..I08 |
| **Severity (of finding)** | n/a (ships primitives) |
| **Story points** | 8 |
| **Complexity** | Medium |
| **Labels** | `injection`, `foundation`, `surface-graph`, `oracle`, `engine` |
| **Files** | **new** `pkg/scanner/inject/surface.go`, `pkg/scanner/inject/oracle.go`, `pkg/scanner/inject/timing.go` (+ `_test.go`); refactor `pkg/scanner/checks/gql011_sqli_error_based.go` to consume them |

## Summary
Build the shared injection primitives every injection check needs: (1) an **injection-point enumerator** that
walks the whole reachable input graph into typed candidates — every leaf scalar reachable via query/mutation
arguments, **including nested input-object fields and list elements**, addressable as inline literals or
GraphQL **variables**; (2) a **probe/differential helper** for boolean and error oracles; (3) a **statistical
timing oracle** for blind/time-based detection. Produces no finding of its own.

This replaces GQL-011's `sqliFirstStringArg` (one String arg of one query + one mutation) with full
input-graph coverage. Per `docs/SECURITY_PLATFORM_ANALYSIS.md` §2.3: "Real injection coverage requires
enumerating every leaf scalar across the whole reachable input graph … with multiple oracle strategies."

## Engineering Context
(See `EPIC-GQL-INJECTION.md` → Shared Engineering Context + Safety.)

### Part 1 — injection-point enumerator (`pkg/scanner/inject/surface.go`)
```go
type Point struct {
    OpKind    string   // "query" | "mutation"
    RootField string   // root field name, e.g. "user", "createPost"
    Path      []string // arg/input path to the leaf, e.g. ["filter","name"] or ["ids",0]
    ScalarType string  // "String" | "Int" | "ID" | enum name | custom scalar
    ViaVariable bool   // whether the value is injected via a GraphQL variable
    RootField  string
    // Render builds a full document + variables injecting `value` at this point,
    // filling all other required args/fields with benign ExampleValue defaults.
}
func Points(s *schema.Schema) []Point        // deterministic, sorted; respects a cap helper
func (p Point) Render(s *schema.Schema, value string) (doc string, variables map[string]any)
```
- Walk `s.QueryFields()` and `s.MutationFields()`. For each field arg, recurse the type:
  scalar/enum → emit a `Point`; `INPUT_OBJECT` → recurse `InputFields`; `LIST` → recurse element type and
  emit a single index-0 `Point`; `NON_NULL` → unwrap. Track the `Path`.
- Required vs optional: include required args always; include optional args too (they are injectable) but
  mark them so callers can prioritize required ones. Fill *other* required args/fields with
  `surface.ExampleValue` so the document validates.
- Default to **variable** injection (`$inj: <ScalarType>`) so payload strings don't break GraphQL syntax;
  also support inline rendering for engines that differ. The payload `value` is placed in `variables`.
- Tag each point with `OpKind` so callers can gate mutation points behind `cc.AllowMutations`.

### Part 2 — probe + differential oracle (`pkg/scanner/inject/oracle.go`)
- `func Send(ctx, client, target, doc string, variables map[string]any) (*transport.Response, []byte, error)`
  (JSON `{"query":doc,"variables":variables}`; sets Content-Type, increments nothing — caller counts).
- Reuse `authz.Classify` for response classes and `authz.Compare` for differential decisions. Provide
  `func ErrorSignal(body []byte, patterns []*regexp.Regexp) (matched string, ok bool)` (generalizes
  `containsDBError`) so I01/I03/I07/I08 can supply their own engine-error tables.
- `func BodyEquivalent(a, b *transport.Response) bool` — status + normalized-body + error-set equality, for
  boolean-true-vs-false comparison (I01) and enumeration (B04).

### Part 3 — statistical timing oracle (`pkg/scanner/inject/timing.go`)
- `func TimingOracle(ctx, send func() (time.Duration, error), control, payload Builder, samples int) TimingResult`
  — interleave N (default 7) control and payload samples, compute median + MAD for each, and report an
  effect only when `payloadMedian > controlMedian + k·controlMAD` (k≈3) **and** the absolute delta exceeds a
  floor (e.g. the injected sleep, default ≥ 2.5s for a 5s `SLEEP`). Returns `{Effect bool, ControlMedian,
  PayloadMedian, MAD time.Duration, Samples int}`. Used by I02 (time-based SQLi) and I04 (blind command inj).
- Keep sample count small and bounded; abort early on `ctx.Done()`.

### Part 4 — refactor GQL-011
- Re-implement `gql011`'s target collection on top of `inject.Points` (it keeps its error-based payload table
  and `containsDBError`, now expressed via `inject.ErrorSignal`). Behavior for the existing tests must be
  preserved (snapshot them); GQL-011 simply gains broader coverage and becomes "tentative" confidence (single
  error-shot) while I01 provides the "confirmed" differential.

## Acceptance criteria
- **Given** a schema with `user(filter: UserFilter)` where `UserFilter{ name: String, tags: [String] }`,
  `inject.Points` emits points for `["filter","name"]` and `["filter","tags",0]` (and any scalar root args),
  each `Render`-able into a valid document + variables that fills other required fields.
- **Given** a mutation injection point, its `OpKind=="mutation"` so callers can gate it.
- `TimingOracle` reports `Effect=true` only when the payload samples are robustly slower than control
  (median+MAD test over ≥7 samples), and `Effect=false` for equal-latency servers (no false positive on jitter).
- `BodyEquivalent` returns true for identical responses and false when the data/error set differs.
- **Regression:** `go build ./cmd/gqls`, `go vet ./...`, and the existing GQL-011 tests pass unchanged.

## Tests
- `surface_test.go`: fixture schema with nested input objects + list args → assert emitted `Point` paths,
  scalar types, `OpKind`, and that `Render` produces a syntactically valid doc with the payload in `variables`
  and other required fields populated.
- `timing_test.go`: a fake `send` whose payload branch sleeps deterministically → `Effect=true`; equal-latency
  → `Effect=false`; jittery-but-no-effect → `Effect=false` (no FP). Deterministic with a seeded clock.
- `oracle_test.go`: `BodyEquivalent` / `ErrorSignal` table tests; never panics on malformed JSON.

## Safety
Ships capability only. The enumerator marks mutation points so downstream checks honor the write-gate; the
timing oracle is bounded and cancellable. No payloads are defined here (each check supplies its own
non-destructive set).
