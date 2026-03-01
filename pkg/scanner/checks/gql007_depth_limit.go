package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// depthLimitCheck implements GQL-007: Query Depth Limit Not Enforced.
type depthLimitCheck struct{}

func init() {
	MustRegister(&depthLimitCheck{})
}

func (c *depthLimitCheck) ID() string           { return "GQL-007" }
func (c *depthLimitCheck) Name() string         { return "Query Depth Limit Not Enforced" }
func (c *depthLimitCheck) Category() Category   { return DenialOfService }
func (c *depthLimitCheck) Severity() Severity   { return HIGH }
func (c *depthLimitCheck) RequiresSchema() bool { return false }

// depthProbeResult captures the outcome of a single depth-probe request.
type depthProbeResult struct {
	Depth      int
	LatencyMS  int64
	StatusCode int
	BodySize   int
	Error      error
	RawBody    []byte
	Request    *http.Request
	ReproBody  []byte
}

// buildNestedQuery builds a progressively nested GraphQL query string.
// Depth 1 → { fieldName { __typename } }
// Depth N → N levels of fieldName wrapping with { __typename } as the innermost leaf.
// Depth 0 returns the bare leaf query { __typename }.
// If fieldName is empty it defaults to "__schema".
func buildNestedQuery(fieldName string, depth int) string {
	if fieldName == "" {
		fieldName = "__schema"
	}
	inner := "{ __typename }"
	for i := 0; i < depth; i++ {
		inner = "{ " + fieldName + " " + inner + " }"
	}
	return inner
}

// buildIntrospectionNestedQuery builds a valid deeply-nested introspection query by
// cycling through the __Type → fields → __Field → type → __Type chain.
//
//	Depth 0:  { __schema { queryType { kind } } }
//	Depth 1:  { __schema { queryType { fields { type { kind } } } } }
//	Depth N:  N cycles of "fields { type { ... } }" inside queryType
//
// This produces semantically valid GraphQL per the specification, unlike the
// { __schema { __schema { ... } } } pattern which is invalid because __schema is a
// root-level meta-field and is NOT a field on the __Schema type.  Servers correctly
// reject that pattern with a field-not-found validation error at depth ≥ 2,
// independent of any depth limit, so it cannot reliably detect missing depth limits.
func buildIntrospectionNestedQuery(depth int) string {
	if depth <= 0 {
		return "{ __schema { queryType { kind } } }"
	}
	inner := "kind"
	for i := 0; i < depth; i++ {
		inner = "fields { type { " + inner + " } }"
	}
	return "{ __schema { queryType { " + inner + " } } }"
}

// findBestNestableField selects the most useful Query-type field for depth probing.
// Priority:
//  1. A Query field whose return type is an object that has a field returning the same type
//     (self-referential — best for realistic depth probing).
//  2. A Query field that returns any object type.
//  3. Falls back to "__schema" when schema is nil or no suitable field is found.
func findBestNestableField(s *schema.Schema) string {
	if s == nil {
		return "__schema"
	}

	// Priority 1: self-referential type (e.g. User.friends: [User]).
	for _, f := range s.QueryFields() {
		if f.Type == nil {
			continue
		}
		returnTypeName := f.Type.Unwrap().Name
		if returnTypeName == "" {
			continue
		}
		returnType := s.FindType(returnTypeName)
		if returnType == nil || returnType.Kind != schema.KindObject {
			continue
		}
		for _, subField := range returnType.Fields {
			if subField.Type == nil {
				continue
			}
			if subField.Type.Unwrap().Name == returnTypeName {
				return f.Name
			}
		}
	}

	// Priority 2: any Query field returning an object type.
	for _, f := range s.QueryFields() {
		if f.Type == nil {
			continue
		}
		returnTypeName := f.Type.Unwrap().Name
		if returnTypeName == "" {
			continue
		}
		returnType := s.FindType(returnTypeName)
		if returnType == nil || returnType.Kind != schema.KindObject {
			continue
		}
		return f.Name
	}

	return "__schema"
}

// shouldFireFindingB reports whether the exponential-latency finding should be generated,
// and returns the ratio. The conditions are: ratio ≥ 4× AND d10 ≥ 500 ms.
// The 500ms absolute threshold (raised from 200ms) reduces false positives from
// servers where the depth-1 probe happens to be served from cache, inflating the ratio.
func shouldFireFindingB(d1LatencyMS, d10LatencyMS int64) (ratio float64, fire bool) {
	if d1LatencyMS <= 0 {
		return 0, false
	}
	ratio = float64(d10LatencyMS) / float64(d1LatencyMS)
	fire = ratio >= 4.0 && d10LatencyMS >= 500
	return ratio, fire
}

// collectProbes sends one HTTP request per depth, using queryFn(depth) to build each
// query string. Each successful HTTP exchange (including network errors) increments
// result.ProbeCount. On context cancellation it returns whatever has been collected.
func (c *depthLimitCheck) collectProbes(
	ctx context.Context,
	cc *CheckContext,
	queryFn func(depth int) string,
	depths []int,
	result *CheckResult,
) []depthProbeResult {
	probes := make([]depthProbeResult, 0, len(depths))
	for _, depth := range depths {
		select {
		case <-ctx.Done():
			return probes
		default:
		}

		query := queryFn(depth)
		payload, err := json.Marshal(map[string]string{"query": query})
		if err != nil {
			probes = append(probes, depthProbeResult{Depth: depth, Error: err})
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
		if err != nil {
			probes = append(probes, depthProbeResult{Depth: depth, Error: err})
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := cc.ProbeClient().Do(req)
		if err != nil {
			// If the context was cancelled inside Do (e.g. rate limiter), stop cleanly.
			if ctx.Err() != nil {
				return probes
			}
			// Network failure — count the probe and continue to remaining depths.
			result.ProbeCount++
			probes = append(probes, depthProbeResult{Depth: depth, Error: err})
			continue
		}

		result.ProbeCount++
		probes = append(probes, depthProbeResult{
			Depth:      depth,
			LatencyMS:  resp.Latency.Milliseconds(),
			StatusCode: resp.StatusCode,
			BodySize:   len(resp.Body),
			RawBody:    resp.Body,
			Request:    resp.Request,
			ReproBody:  payload,
		})
	}
	return probes
}

// probeSetAllows returns true when every depth in checkDepths returned HTTP 200 with a
// "data" key — i.e. the server executed the query without rejecting it.
func probeSetAllows(probes []depthProbeResult, checkDepths []int) bool {
	byDepth := make(map[int]depthProbeResult, len(probes))
	for _, p := range probes {
		byDepth[p.Depth] = p
	}
	for _, depth := range checkDepths {
		p, ok := byDepth[depth]
		if !ok || p.Error != nil || p.StatusCode != 200 || !bytes.Contains(p.RawBody, []byte(`"data"`)) {
			return false
		}
	}
	return true
}

// findReproProbe returns the request and body for the probe at maxDepth that succeeded.
func findReproProbe(probes []depthProbeResult, maxDepth int) (*http.Request, []byte) {
	for _, p := range probes {
		if p.Depth == maxDepth && p.Error == nil && p.Request != nil {
			return p.Request, p.ReproBody
		}
	}
	return nil, nil
}

// Run executes GQL-007 against the target endpoint.
func (c *depthLimitCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	fieldName := findBestNestableField(cc.Schema)
	maxDepth := 10
	depths := []int{1, 2, 3, 5, 7, 10}
	checkDepths := []int{5, 7, 10}

	// ── Primary probe set ────────────────────────────────────────────────────
	// Uses the schema-derived field (or __schema when no schema is available).
	primaryFn := func(d int) string { return buildNestedQuery(fieldName, d) }
	primaryProbes := c.collectProbes(ctx, cc, primaryFn, depths, &result)

	// ── Introspection probe set ──────────────────────────────────────────────
	// When the primary field is application-level (not __schema), also probe with a
	// valid deeply-nested introspection query cycling through:
	//   __schema → queryType → fields → type → fields → type → ...
	//
	// Note: the naive { __schema { __schema { ... } } } pattern is NOT used here
	// because __schema is only a root-level meta-field — it does not exist as a
	// field on the __Schema type.  Servers reject that pattern with a field
	// validation error at depth ≥ 2, regardless of any depth limit, making it
	// useless for detecting whether introspection queries bypass depth limits.
	var introspectionProbes []depthProbeResult
	if fieldName != "__schema" && ctx.Err() == nil {
		introspectionProbes = c.collectProbes(ctx, cc, buildIntrospectionNestedQuery, depths, &result)
	}

	// ── Finding A ── Hard limit missing (error-based detection) ──────────────
	// Fires when primary probes OR introspection probes at depths 5, 7, 10 all
	// returned HTTP 200 with a "data" key.
	primaryAllows := probeSetAllows(primaryProbes, checkDepths)
	introspectionAllows := len(introspectionProbes) > 0 && probeSetAllows(introspectionProbes, checkDepths)

	if primaryAllows || introspectionAllows {
		var reproReq *http.Request
		var reproBody []byte
		if primaryAllows {
			reproReq, reproBody = findReproProbe(primaryProbes, maxDepth)
		} else {
			reproReq, reproBody = findReproProbe(introspectionProbes, maxDepth)
		}

		result.Findings = append(result.Findings, Finding{
			CheckID:      c.ID(),
			CheckName:    c.Name(),
			Severity:     HIGH,
			Category:     DenialOfService,
			Title:        "No Query Depth Limit Enforced",
			Description:  buildDepthFindingADescription(fieldName, maxDepth, primaryProbes, introspectionProbes),
			Impact:       depthFindingAImpact,
			Remediation:  depthFindingARemediation,
			References:   depthReferences,
			ReproRequest: reproReq,
			ReproBody:    reproBody,
			Fingerprint:  GenerateFingerprint("GQL-007", cc.Target, "depth_limit"),
		})
	}

	// ── Finding B ── Exponential latency growth (timing-based detection) ─────
	// Condition: depth-10 latency ≥ 4× depth-1 latency AND depth-10 ≥ 200 ms.
	// Latency is evaluated on the primary probe set only.
	primaryByDepth := make(map[int]depthProbeResult, len(primaryProbes))
	for _, p := range primaryProbes {
		primaryByDepth[p.Depth] = p
	}
	p1, ok1 := primaryByDepth[1]
	p10, ok10 := primaryByDepth[maxDepth]
	if ok1 && ok10 && p1.Error == nil && p10.Error == nil {
		ratio, fire := shouldFireFindingB(p1.LatencyMS, p10.LatencyMS)
		if fire {
			result.Findings = append(result.Findings, Finding{
				CheckID:     c.ID(),
				CheckName:   c.Name(),
				Severity:    MEDIUM,
				Category:    DenialOfService,
				Title:       "Query Depth Causes Exponential Latency Growth",
				Description: buildDepthFindingBDescription(p1.LatencyMS, p10.LatencyMS, ratio),
				Impact:      depthFindingBImpact,
				Remediation: depthFindingBRemediation,
				References:  depthReferences,
				Fingerprint: GenerateFingerprint("GQL-007", cc.Target, "depth_latency"),
			})
		}
	}

	if len(result.Findings) == 0 {
		result.PassReason = "Query depth limits appear to be enforced. At least one probe at depth 5, 7, or 10 was rejected or returned no data, and latency growth between depth 1 and depth 10 was within the acceptable threshold (< 4× baseline or < 500 ms at depth 10)."
		allProbes := append(primaryProbes, introspectionProbes...)
		for _, p := range allProbes {
			if p.Error != nil || p.Request == nil {
				continue
			}
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   fmt.Sprintf("Depth probe at depth %d — %dms, HTTP %d", p.Depth, p.LatencyMS, p.StatusCode),
				Request: p.Request,
				Body:    p.ReproBody,
			})
		}
	}

	return result, nil
}

// ── Description builders ──────────────────────────────────────────────────────

// buildDepthFindingADescription generates the Finding A description covering both
// the primary probe set and, when present, the introspection probe set.
func buildDepthFindingADescription(fieldName string, maxDepth int, primaryProbes []depthProbeResult, introspectionProbes []depthProbeResult) string {
	depthOrder := []int{1, 2, 3, 5, 7, 10}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"The server accepted GraphQL queries nested to depth %d without\n"+
			"returning an error or truncating the response.\n\n"+
			"Depths tested: 1, 2, 3, 5, 7, 10\n"+
			"Field used:    %s\n"+
			"All returned:  HTTP 200 with data\n\n"+
			"Results:\n",
		maxDepth, fieldName,
	))

	primaryByDepth := make(map[int]depthProbeResult, len(primaryProbes))
	for _, p := range primaryProbes {
		primaryByDepth[p.Depth] = p
	}
	for _, d := range depthOrder {
		p, ok := primaryByDepth[d]
		if !ok {
			sb.WriteString(fmt.Sprintf("  Depth %2d:   (no result)\n", d))
			continue
		}
		if p.Error != nil {
			sb.WriteString(fmt.Sprintf("  Depth %2d:   error: %v\n", d, p.Error))
			continue
		}
		sb.WriteString(fmt.Sprintf("  Depth %2d:   %dms   HTTP %d\n", d, p.LatencyMS, p.StatusCode))
	}

	if len(introspectionProbes) > 0 {
		sb.WriteString("\nIntrospection probe results (__schema → queryType → fields → type cycle):\n")
		introspByDepth := make(map[int]depthProbeResult, len(introspectionProbes))
		for _, p := range introspectionProbes {
			introspByDepth[p.Depth] = p
		}
		for _, d := range depthOrder {
			p, ok := introspByDepth[d]
			if !ok {
				sb.WriteString(fmt.Sprintf("  Depth %2d:   (no result)\n", d))
				continue
			}
			if p.Error != nil {
				sb.WriteString(fmt.Sprintf("  Depth %2d:   error: %v\n", d, p.Error))
				continue
			}
			sb.WriteString(fmt.Sprintf("  Depth %2d:   %dms   HTTP %d\n", d, p.LatencyMS, p.StatusCode))
		}
	}

	return strings.TrimRight(sb.String(), "\n")
}

func buildDepthFindingBDescription(d1, d10 int64, ratio float64) string {
	return fmt.Sprintf(
		"Response time grew significantly with query depth, suggesting resolver\n"+
			"execution cost scales super-linearly with nesting.\n\n"+
			"Depth  1:  %dms  (baseline)\n"+
			"Depth 10:  %dms  (%.1f× baseline)\n\n"+
			"Threshold for flagging: 4× baseline AND ≥ 500ms at depth 10.\n\n"+
			"This indicates the server is executing resolvers — likely database queries —\n"+
			"at each level of nesting without batching or short-circuiting.",
		d1, d10, ratio,
	)
}

// ── Static finding text ───────────────────────────────────────────────────────

const depthFindingAImpact = `Without a depth limit, a single query can trigger exponential resolver ` +
	`execution. A query nested to depth 10 on a social graph (user→friends→friends→...) ` +
	`can result in O(branching_factor^10) database calls from one HTTP request, ` +
	`causing server exhaustion or complete unavailability.`

const depthFindingARemediation = `graphql-depth-limit (Node.js):
  import depthLimit from 'graphql-depth-limit'
  const server = new ApolloServer({
    validationRules: [depthLimit(5)]
  })

graphql-go:
  Use gqlgen with complexity limits or the graphql-go-tools depth limiter.

Generic:
  Reject any query where AST depth exceeds your configured maximum
  at the validation layer before execution begins.`

const depthFindingBImpact = `Even with a depth limit in place, if the growth is exponential, a query ` +
	`at the maximum allowed depth may still consume disproportionate resources. ` +
	`Attackers can use this for sustained resource exhaustion without triggering ` +
	`rate limits, because each request appears legitimate.`

const depthFindingBRemediation = `In addition to depth limiting, implement query complexity analysis. ` +
	`Use DataLoader (Node.js) or equivalent to batch and cache resolver calls, ` +
	`turning O(n) database calls into O(1) per query level.`

var depthReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://www.howtographql.com/advanced/4-security/",
	"https://spec.graphql.org/October2021/#sec-Validation",
}
