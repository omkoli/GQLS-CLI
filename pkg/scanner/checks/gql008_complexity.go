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

// complexityCheck implements GQL-008: Query Complexity Limit Not Enforced.
type complexityCheck struct{}

func init() {
	MustRegister(&complexityCheck{})
}

func (c *complexityCheck) ID() string           { return "GQL-008" }
func (c *complexityCheck) Name() string         { return "Query Complexity Limit Not Enforced" }
func (c *complexityCheck) Category() Category   { return DenialOfService }
func (c *complexityCheck) Severity() Severity   { return HIGH }
func (c *complexityCheck) RequiresSchema() bool { return false }

// fallbackQuery is the wide introspection query used when no schema is available.
// It touches every field of the introspection system and is valid on any GraphQL server.
const fallbackQuery = `{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        description
        isDeprecated
        deprecationReason
        type { name kind ofType { name kind } }
        args { name description defaultValue type { name kind } }
      }
      inputFields { name description defaultValue type { name kind } }
      interfaces { name kind }
      enumValues { name description isDeprecated }
      possibleTypes { name kind }
    }
    directives {
      name
      description
      locations
      args { name description type { name kind } }
    }
  }
}`

// buildMaximalQuery constructs the widest valid query possible from the schema.
// When schema is nil it returns the static fallback introspection query with fieldCount -1.
//
// When schema is provided:
//   - Iterates every field on the Query root type
//   - For fields returning an object type, inlines all scalar/enum sub-fields (level 2)
//   - Stops at two levels — never recurses into object fields of object fields
//   - Skips deprecated fields and built-in types
//
// Returns the query string and the total number of field selections made.
func buildMaximalQuery(s *schema.Schema) (string, int) {
	if s == nil {
		return fallbackQuery, -1
	}

	queryFields := s.QueryFields()
	if len(queryFields) == 0 {
		return fallbackQuery, -1
	}

	var sb strings.Builder
	total := 0

	sb.WriteString("{\n")
	for _, f := range queryFields {
		if f.IsDeprecated {
			continue
		}
		if f.Type == nil {
			continue
		}
		unwrapped := f.Type.Unwrap()
		if unwrapped == nil {
			continue
		}
		// Skip built-in introspection object types (e.g. __Schema, __Type).
		// Standard scalars (String, Int, etc.) have KindScalar and must NOT be skipped.
		if unwrapped.Kind == schema.KindObject && s.IsBuiltinType(unwrapped.Name) {
			continue
		}

		returnType := s.FindType(unwrapped.Name)

		if returnType == nil || returnType.Kind != schema.KindObject {
			// Scalar, enum, or unknown type at the top level — select it directly.
			sb.WriteString(fmt.Sprintf("  %s\n", f.Name))
			total++
			continue
		}

		// Gather scalar/enum sub-fields from the object type (level 2).
		scalarFields := collectScalarFields(s, returnType)
		if len(scalarFields) == 0 {
			// Object with no selectable scalar fields — skip to avoid invalid empty selection.
			continue
		}

		sb.WriteString(fmt.Sprintf("  %s {\n", f.Name))
		total++ // count the level-1 field
		for _, sf := range scalarFields {
			sb.WriteString(fmt.Sprintf("    %s\n", sf))
			total++
		}
		sb.WriteString("  }\n")
	}
	sb.WriteString("}")

	query := sb.String()
	// If we selected nothing, fall back to the static query.
	if total == 0 {
		return fallbackQuery, -1
	}
	return query, total
}

// buildRealisticBaseline returns a small resolver-touching query for use as the
// latency baseline in Finding B. It avoids { __typename } because that meta-field
// is resolved in-process on most frameworks without touching resolvers or the
// database, which artificially deflates the baseline and inflates the ratio.
//
// Pass 1: first non-deprecated Query field returning a scalar or enum directly.
// Pass 2: first non-deprecated Query field returning an object with a scalar child.
//
// Returns ("", false) when no suitable field is found (schema nil, empty Query
// type, or all fields return only object/interface types with no scalar leaf).
// Callers must skip Finding B when ok is false.
func buildRealisticBaseline(s *schema.Schema) (query string, ok bool) {
	if s == nil {
		return "", false
	}

	// Pass 1: direct scalar / enum at the Query root.
	for _, f := range s.QueryFields() {
		if f.IsDeprecated || f.Type == nil {
			continue
		}
		unwrapped := f.Type.Unwrap()
		if unwrapped == nil {
			continue
		}
		if unwrapped.Kind == schema.KindScalar || unwrapped.Kind == schema.KindEnum {
			return fmt.Sprintf("{ %s }", f.Name), true
		}
		td := s.FindType(unwrapped.Name)
		if td != nil && (td.Kind == schema.KindScalar || td.Kind == schema.KindEnum) {
			return fmt.Sprintf("{ %s }", f.Name), true
		}
	}

	// Pass 2: object-returning field with at least one scalar child.
	for _, f := range s.QueryFields() {
		if f.IsDeprecated || f.Type == nil {
			continue
		}
		unwrapped := f.Type.Unwrap()
		if unwrapped == nil {
			continue
		}
		if unwrapped.Kind == schema.KindObject && s.IsBuiltinType(unwrapped.Name) {
			continue
		}
		td := s.FindType(unwrapped.Name)
		if td == nil || td.Kind != schema.KindObject {
			continue
		}
		scalarFields := collectScalarFields(s, td)
		if len(scalarFields) > 0 {
			return fmt.Sprintf("{ %s { %s } }", f.Name, scalarFields[0]), true
		}
	}

	return "", false
}

// collectScalarFields returns the names of all non-deprecated scalar/enum fields
// on typeDef. It does NOT recurse into nested objects (two-level cap enforcement).
// Standard scalars (String, Int, Float, Boolean, ID) are always included.
// Built-in introspection object types (e.g. __Type) are skipped.
func collectScalarFields(s *schema.Schema, typeDef *schema.TypeDef) []string {
	var out []string
	for _, f := range typeDef.Fields {
		if f.IsDeprecated {
			continue
		}
		if f.Type == nil {
			continue
		}
		unwrapped := f.Type.Unwrap()
		if unwrapped == nil {
			continue
		}
		// Skip built-in introspection object types (e.g. __Type, __Field).
		// Standard scalars (String, Int, etc.) have KindScalar so they pass through.
		if unwrapped.Kind == schema.KindObject && s.IsBuiltinType(unwrapped.Name) {
			continue
		}
		// Accept scalars and enums only — skip objects (two-level cap).
		fieldType := s.FindType(unwrapped.Name)
		if fieldType != nil && fieldType.Kind == schema.KindObject {
			continue
		}
		// fieldType == nil means it's a standard scalar not declared in the user schema.
		out = append(out, f.Name)
	}
	return out
}

// complexityProbeResult captures the outcome of a single HTTP probe.
type complexityProbeResult struct {
	StatusCode int
	LatencyMS  int64
	BodySize   int
	HasData    bool
	HasErrors  bool
	RawBody    []byte
	Error      error
	Request    *http.Request
	ReproBody  []byte
}

// sendProbe sends a single GraphQL query and records the result.
func sendProbe(ctx context.Context, cc *CheckContext, query string) complexityProbeResult {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return complexityProbeResult{Error: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return complexityProbeResult{Error: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.HTTPClient.Do(req)
	if err != nil {
		return complexityProbeResult{Error: err}
	}

	hasData := bytes.Contains(resp.Body, []byte(`"data"`))
	hasErrors := false
	// Check for non-empty errors array or errors key.
	if bytes.Contains(resp.Body, []byte(`"errors"`)) {
		// Parse to see if errors array is non-empty.
		var parsed struct {
			Errors []json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(resp.Body, &parsed) == nil && len(parsed.Errors) > 0 {
			hasErrors = true
		}
	}

	return complexityProbeResult{
		StatusCode: resp.StatusCode,
		LatencyMS:  resp.Latency.Milliseconds(),
		BodySize:   len(resp.Body),
		HasData:    hasData,
		HasErrors:  hasErrors,
		RawBody:    resp.Body,
		Request:    resp.Request,
		ReproBody:  payload,
	}
}

// Run executes GQL-008 against the target endpoint.
func (c *complexityCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	maximalQuery, fieldCount := buildMaximalQuery(cc.Schema)

	// Determine the baseline query for the latency check (Finding B).
	// When schema is available, use a minimal realistic query that exercises a
	// real resolver, avoiding the cache-hit deflation of { __typename }.
	// When no realistic baseline can be built (schema nil or no suitable field),
	// fall back to { __typename } for probe 1 but suppress Finding B entirely.
	baselineQuery, hasRealisticBaseline := buildRealisticBaseline(cc.Schema)
	if !hasRealisticBaseline {
		baselineQuery = "{ __typename }"
	}

	// ── Probe 1 (baseline) — send first so warmup does not skew its latency ──
	select {
	case <-ctx.Done():
		return result, nil
	default:
	}

	baseline := sendProbe(ctx, cc, baselineQuery)
	if ctx.Err() != nil {
		return result, nil
	}
	if baseline.Error == nil {
		result.ProbeCount++
	}

	// ── Probe 2 (maximal query) ───────────────────────────────────────────────
	select {
	case <-ctx.Done():
		return result, nil
	default:
	}

	maximal := sendProbe(ctx, cc, maximalQuery)
	if ctx.Err() != nil {
		return result, nil
	}
	if maximal.Error == nil {
		result.ProbeCount++
	}

	// ── Finding A — No complexity limit (structural) ──────────────────────────
	// Condition: HTTP 200, body has "data" key, no non-empty "errors" array.
	if maximal.Error == nil &&
		maximal.StatusCode == 200 &&
		maximal.HasData &&
		!maximal.HasErrors {

		result.Findings = append(result.Findings, Finding{
			CheckID:      c.ID(),
			CheckName:    c.Name(),
			Severity:     HIGH,
			Category:     DenialOfService,
			Title:        "No Query Complexity Limit Enforced",
			Description:  buildComplexityFindingADescription(fieldCount, maximal.BodySize, maximal.LatencyMS),
			Impact:       buildComplexityFindingAImpact(fieldCount),
			Remediation:  complexityRemediation,
			References:   complexityReferences,
			ReproRequest: maximal.Request,
			ReproBody:    maximal.ReproBody,
			Fingerprint:  GenerateFingerprint("GQL-008", cc.Target, "complexity"),
		})
	}

	// ── Finding B — Disproportionate latency ──────────────────────────────────
	// Only evaluated when hasRealisticBaseline is true. { __typename } resolves
	// in-process on most frameworks without touching resolvers, artificially
	// deflating the baseline and causing false positives on well-behaved servers.
	// Condition: maximal latency ≥ 3× realistic baseline AND maximal ≥ 500ms.
	if hasRealisticBaseline && maximal.Error == nil && baseline.Error == nil && baseline.LatencyMS > 0 {
		ratio := float64(maximal.LatencyMS) / float64(baseline.LatencyMS)
		if ratio >= 3.0 && maximal.LatencyMS >= 500 {
			result.Findings = append(result.Findings, Finding{
				CheckID:     c.ID(),
				CheckName:   c.Name(),
				Severity:    MEDIUM,
				Category:    DenialOfService,
				Title:       "Wide Query Causes Disproportionate Latency",
				Description: buildComplexityFindingBDescription(baselineQuery, baseline.LatencyMS, maximal.LatencyMS, fieldCount, ratio),
				Impact: "Server response time scales with query width, indicating resolvers execute " +
					"in parallel without cost budgeting. Sustained wide queries cause resource " +
					"exhaustion without triggering rate limits.",
				Remediation: complexityRemediation,
				References:  complexityReferences,
				Fingerprint: GenerateFingerprint("GQL-008", cc.Target, "complexity_latency"),
			})
		}
	}

	if len(result.Findings) == 0 {
		result.PassReason = "Query complexity limits appear to be enforced. The wide field query was either rejected, returned errors, or completed without triggering the disproportionate-latency threshold (< 3× baseline or < 500 ms for the wide query)."
		if baseline.Error == nil && baseline.Request != nil {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   fmt.Sprintf("Baseline probe — %s (%dms, HTTP %d)", baselineQuery, baseline.LatencyMS, baseline.StatusCode),
				Request: baseline.Request,
				Body:    baseline.ReproBody,
			})
		}
		if maximal.Error == nil && maximal.Request != nil {
			fieldLabel := formatFieldCount(fieldCount)
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   fmt.Sprintf("Maximal complexity probe — %s fields (%dms, HTTP %d)", fieldLabel, maximal.LatencyMS, maximal.StatusCode),
				Request: maximal.Request,
				Body:    maximal.ReproBody,
			})
		}
	}

	return result, nil
}

// ── Description builders ──────────────────────────────────────────────────────

func buildComplexityFindingADescription(fieldCount, bodySize int, latencyMS int64) string {
	var sb strings.Builder

	if fieldCount == -1 {
		sb.WriteString("The server accepted a wide introspection query without rejecting it for\n" +
			"complexity. Schema-based field count was unavailable; the static introspection\n" +
			"query (covering all __schema fields) was used instead.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf(
			"The server accepted a query selecting %d fields without rejecting it for\n"+
				"complexity. No complexity limit or cost budget was detected.\n\n",
			fieldCount,
		))
	}

	sb.WriteString("Results:\n")
	sb.WriteString(fmt.Sprintf("  %-22s %v\n", "Fields selected:", formatFieldCount(fieldCount)))
	sb.WriteString(fmt.Sprintf("  %-22s %d bytes\n", "Response body size:", bodySize))
	sb.WriteString(fmt.Sprintf("  %-22s %dms\n", "Latency:", latencyMS))

	return strings.TrimRight(sb.String(), "\n")
}

func formatFieldCount(fieldCount int) string {
	if fieldCount == -1 {
		return "unknown (introspection fallback)"
	}
	return fmt.Sprintf("%d", fieldCount)
}

func buildComplexityFindingAImpact(fieldCount int) string {
	if fieldCount == -1 {
		return "A single HTTP request selecting an unbounded number of introspection fields " +
			"can force the server to execute many resolver functions simultaneously. " +
			"Unlike depth attacks, complexity attacks are invisible to depth limiters."
	}
	return fmt.Sprintf(
		"A single HTTP request selecting %d fields can force the server to execute %d "+
			"resolver functions and potentially %d database queries simultaneously. "+
			"Unlike depth attacks, complexity attacks are invisible to depth limiters.",
		fieldCount, fieldCount, fieldCount,
	)
}

func buildComplexityFindingBDescription(baselineQuery string, baselineMS, maximalMS int64, fieldCount int, ratio float64) string {
	fieldStr := formatFieldCount(fieldCount)
	return fmt.Sprintf(
		"Baseline (%s): %dms\n"+
			"Maximal query (%s fields): %dms (%.1fx baseline)\n\n"+
			"Threshold for flagging: 3× baseline AND ≥ 500ms for the wide query.\n\n"+
			"The server took significantly longer to respond to the wide query than to\n"+
			"the minimal baseline, indicating resolvers are executing without a cost budget.",
		baselineQuery, baselineMS, fieldStr, maximalMS, ratio,
	)
}

// ── Static finding text ───────────────────────────────────────────────────────

const complexityRemediation = `graphql-cost-analysis (Node.js):
  import costAnalysis from 'graphql-cost-analysis'
  const server = new ApolloServer({
    validationRules: [costAnalysis({ maximumCost: 1000, defaultCost: 1 })]
  })

graphql-query-complexity (Node.js):
  import { createComplexityLimitRule } from 'graphql-query-complexity'
  const server = new ApolloServer({
    validationRules: [createComplexityLimitRule(1000)]
  })

gqlgen ComplexityLimit directive (Go):
  func (c Config) Complexity(typeName, fieldName string, childComplexity int, args map[string]interface{}) int {
    return childComplexity + 1
  }
  srv := handler.NewDefaultServer(generated.NewExecutableSchema(cfg))
  srv.Use(extension.ComplexityLimit(1000))

Generic:
  Assign a cost to each field, reject queries exceeding a total cost
  budget before execution begins. Start with a cost of 1 per field
  and tune based on actual resolver expense (e.g. database queries cost more).`

var complexityReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://www.apollographql.com/docs/apollo-server/performance/apq/",
	"https://github.com/slicknode/graphql-query-complexity",
	"https://spec.graphql.org/October2021/#sec-Validation",
}
