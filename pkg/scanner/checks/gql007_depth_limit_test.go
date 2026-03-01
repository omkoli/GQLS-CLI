package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── buildIntrospectionNestedQuery unit tests ──────────────────────────────────

func TestBuildIntrospectionNestedQuery_Depth0_IsValid(t *testing.T) {
	q := buildIntrospectionNestedQuery(0)
	assert.Contains(t, q, "__schema")
	assert.Contains(t, q, "queryType")
	// "fields" must NOT appear at depth 0 — it is the first cycle element.
	assert.NotContains(t, q, "fields")
}

func TestBuildIntrospectionNestedQuery_Depth1(t *testing.T) {
	q := buildIntrospectionNestedQuery(1)
	// Exactly one cycle: fields { type { kind } }
	assert.Equal(t, 1, strings.Count(q, "fields"), "depth 1 must add exactly one 'fields' level")
	assert.Equal(t, 1, strings.Count(q, "type"), "depth 1 must add exactly one 'type' level")
	assert.Contains(t, q, "__schema")
	assert.Contains(t, q, "queryType")
}

func TestBuildIntrospectionNestedQuery_DepthN_FieldsCount(t *testing.T) {
	for _, depth := range []int{2, 3, 5, 7, 10} {
		q := buildIntrospectionNestedQuery(depth)
		assert.Equal(t, depth, strings.Count(q, "fields"),
			"depth %d must produce exactly %d 'fields' occurrences", depth, depth)
	}
}

func TestBuildIntrospectionNestedQuery_AlwaysContainsSchema(t *testing.T) {
	for _, depth := range []int{0, 1, 5, 10} {
		q := buildIntrospectionNestedQuery(depth)
		assert.Contains(t, q, "__schema",
			"introspection query at depth %d must start with __schema", depth)
	}
}

// ── buildNestedQuery unit tests ───────────────────────────────────────────────

func TestBuildNestedQuery_Depth1(t *testing.T) {
	q := buildNestedQuery("user", 1)
	// Structure: { user { __typename } }
	assert.Contains(t, q, "user")
	assert.Contains(t, q, "__typename")
	// Only one level of user nesting — user appears exactly once.
	assert.Equal(t, 1, strings.Count(q, "user"), "expected 'user' to appear exactly once at depth 1")
	// The opening brace after 'user' is present.
	idx := strings.Index(q, "user")
	require.NotEqual(t, -1, idx)
	rest := q[idx+len("user"):]
	assert.Contains(t, rest, "{", "expected an opening brace after the field name")
}

func TestBuildNestedQuery_Depth3(t *testing.T) {
	q := buildNestedQuery("user", 3)
	assert.Equal(t, 3, strings.Count(q, "user"), "expected 'user' to appear 3 times at depth 3")
	assert.Equal(t, 1, strings.Count(q, "__typename"), "__typename must appear exactly once (innermost only)")
}

func TestBuildNestedQuery_DepthZero_ReturnsValid(t *testing.T) {
	// Must not panic and must return a non-empty string.
	q := buildNestedQuery("user", 0)
	assert.NotEmpty(t, q)
	// Should still be parseable as a GraphQL selection (contains braces).
	assert.Contains(t, q, "{")
}

func TestBuildNestedQuery_EmptyField_UsesSchemaFallback(t *testing.T) {
	q := buildNestedQuery("", 3)
	assert.Contains(t, q, "__schema", "empty fieldName must fall back to __schema")
}

// ── findBestNestableField unit tests ─────────────────────────────────────────

func TestFindBestNestableField_NilSchema_ReturnsFallback(t *testing.T) {
	assert.Equal(t, "__schema", findBestNestableField(nil))
}

func TestFindBestNestableField_SelfReferentialType_Preferred(t *testing.T) {
	// Schema: Query.user → User; User.friends → [User] (self-referential).
	// Also has Query.posts → Post to ensure self-referential wins over plain object.
	userType := &schema.TypeDef{
		Name: "User",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{
				Name: "friends",
				Type: &schema.TypeRef{
					Kind: schema.KindList,
					OfType: &schema.TypeRef{
						Kind: schema.KindObject,
						Name: "User",
					},
				},
			},
		},
	}
	postType := &schema.TypeDef{
		Name:   "Post",
		Kind:   schema.KindObject,
		Fields: []*schema.FieldDef{{Name: "title", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}}},
	}
	queryType := &schema.TypeDef{
		Name: "Query",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "posts", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Post"}},
			{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}},
		},
	}
	s := &schema.Schema{
		QueryType: queryType,
		Types: map[string]*schema.TypeDef{
			"Query": queryType,
			"User":  userType,
			"Post":  postType,
		},
	}

	result := findBestNestableField(s)
	assert.Equal(t, "user", result, "self-referential field should be preferred")
}

// ── shouldFireFindingB unit tests (multiplier logic) ─────────────────────────

func TestGQL007_LatencyMultiplier_Calculation(t *testing.T) {
	// d1=50ms, d10=600ms → ratio=12.0, floor met → fires.
	ratio, fire := shouldFireFindingB(50, 600)
	assert.InDelta(t, 12.0, ratio, 0.01)
	assert.True(t, fire, "ratio=12.0 and d10=600ms ≥ 500ms should fire")

	// d1=50ms, d10=150ms → ratio=3.0 < 4× → does NOT fire.
	_, fire = shouldFireFindingB(50, 150)
	assert.False(t, fire, "ratio=3.0 is below 4× threshold")

	// d1=10ms, d10=400ms → ratio=40.0 ≥ 4× but d10=400ms < 500ms floor → does NOT fire.
	_, fire = shouldFireFindingB(10, 400)
	assert.False(t, fire, "d10=400ms is below the 500ms absolute floor")
}

// ── Integration tests using httptest servers ──────────────────────────────────

// newDepthCheckContext creates a CheckContext pointing at srv with a high-RPS client
// so rate limiting does not slow down unit tests.
func newDepthCheckContext(t *testing.T, srv *httptest.Server, s *schema.Schema) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(10*time.Second, 500, nil),
		Schema:     s,
	}
}

// acceptAllHandler returns {"data":{"__typename":"Query"}} for every request.
func acceptAllHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
}

func TestGQL007_NoDepthLimit_FindingA_Generated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(acceptAllHandler))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Equal(t, 6, result.ProbeCount, "expected 6 probes (one per depth in the ladder)")

	var findingA *Finding
	for i := range result.Findings {
		if result.Findings[i].Fingerprint == GenerateFingerprint("GQL-007", srv.URL, "depth_limit") {
			findingA = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, findingA, "Finding A (no depth limit) should be generated")
	assert.Equal(t, HIGH, findingA.Severity)
	assert.Equal(t, DenialOfService, findingA.Category)
}

func TestGQL007_DepthLimitEnforced_NoFindingA(t *testing.T) {
	// Server returns an error for depth ≥ 3 by counting occurrences of "__schema".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		depth := strings.Count(string(body), `__schema`)
		if depth >= 3 {
			_, _ = fmt.Fprint(w, `{"errors":[{"message":"max depth exceeded"}]}`)
		} else {
			_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
		}
	}))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	for _, f := range result.Findings {
		assert.NotEqual(t, GenerateFingerprint("GQL-007", srv.URL, "depth_limit"), f.Fingerprint,
			"Finding A must NOT be generated when depth limit is enforced")
	}
}

func TestGQL007_ExponentialLatency_FindingB_Generated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency test in short mode")
	}

	// Server sleeps depth²×6ms; depth-10 → 600ms (≥500ms floor), ratio=100× (≥4×).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		depth := strings.Count(string(body), `__schema`)
		if depth < 1 {
			depth = 1
		}
		sleepMS := depth * depth * 6
		time.Sleep(time.Duration(sleepMS) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &depthLimitCheck{}
	// Use a long timeout so the depth-10 probe (600ms sleep) can complete.
	cc := &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(30*time.Second, 500, nil),
		Schema:     nil,
	}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)

	var findingB *Finding
	for i := range result.Findings {
		if result.Findings[i].Fingerprint == GenerateFingerprint("GQL-007", srv.URL, "depth_latency") {
			findingB = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, findingB, "Finding B (exponential latency) should be generated")
	assert.Equal(t, MEDIUM, findingB.Severity)
	// Description must mention the depth-1 and depth-10 latency values.
	assert.Contains(t, findingB.Description, "ms")
}

func TestGQL007_FastServer_NoFindingB(t *testing.T) {
	// Server always responds immediately — even if ratio > 4×, absolute floor is not met.
	srv := httptest.NewServer(http.HandlerFunc(acceptAllHandler))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	for _, f := range result.Findings {
		assert.NotEqual(t, GenerateFingerprint("GQL-007", srv.URL, "depth_latency"), f.Fingerprint,
			"Finding B must NOT fire when absolute latency at depth 10 is well below 200ms")
	}
}

func TestGQL007_BothFindings_WhenApplicable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency test in short mode")
	}

	// Server: accepts all depths (no error) AND sleeps depth²×6ms.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		depth := strings.Count(string(body), `__schema`)
		if depth < 1 {
			depth = 1
		}
		time.Sleep(time.Duration(depth*depth*6) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &depthLimitCheck{}
	cc := &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(30*time.Second, 500, nil),
		Schema:     nil,
	}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Findings), "both Finding A and Finding B must be generated")

	fingerprintA := GenerateFingerprint("GQL-007", srv.URL, "depth_limit")
	fingerprintB := GenerateFingerprint("GQL-007", srv.URL, "depth_latency")
	var hasA, hasB bool
	for _, f := range result.Findings {
		if f.Fingerprint == fingerprintA {
			hasA = true
		}
		if f.Fingerprint == fingerprintB {
			hasB = true
		}
	}
	assert.True(t, hasA, "Finding A (depth_limit) must be present")
	assert.True(t, hasB, "Finding B (depth_latency) must be present")
}

func TestGQL007_ContextCancelled_ReturnsPartialResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var count atomic.Int32
	// probe2Written is closed after the 2nd response is fully flushed.
	probe2Written := make(chan struct{})
	// block is a test-controlled gate that keeps probe-3 handlers busy until the
	// test is done, preventing srv.Close() from hanging.
	block := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := count.Add(1)
		// Probe 3+: block on the gate so Do() stays in-flight while we cancel ctx.
		// The gate is closed by the deferred close(block) before srv.Close() runs.
		if n >= 3 {
			<-block
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if n == 2 {
			close(probe2Written)
		}
	}))
	// Defers execute LIFO: close(block) first (unblocks any stuck handler),
	// then srv.Close() can complete without hanging.
	defer srv.Close()
	defer close(block)

	type runOut struct {
		result CheckResult
		err    error
	}
	out := make(chan runOut, 1)
	go func() {
		chk := &depthLimitCheck{}
		r, e := chk.Run(ctx, newDepthCheckContext(t, srv, nil))
		out <- runOut{r, e}
	}()

	// Wait for the 2nd response to be flushed to the client.
	select {
	case <-probe2Written:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for probe 2 to be written")
	}
	// Brief grace period for the transport client to finish reading the 2nd response body.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case o := <-out:
		require.NoError(t, o.err)
		assert.Equal(t, 2, o.result.ProbeCount, "should have sent exactly 2 probes before context cancellation")
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func TestGQL007_NetworkError_ContinuesRemainingProbes(t *testing.T) {
	// Server counts requests and closes the connection on depths 3 and 5.
	// Depth is inferred by counting __schema occurrences (fieldName for nil schema).
	var totalRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests.Add(1)
		body, _ := io.ReadAll(r.Body)
		depth := strings.Count(string(body), `__schema`)

		if depth == 3 || depth == 5 {
			// Abruptly close the connection to simulate a network error.
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, _ := hijacker.Hijack()
				if conn != nil {
					_ = conn.Close()
				}
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	// All 6 probes must be attempted (errors don't abort the loop).
	assert.Equal(t, 6, result.ProbeCount, "all 6 depth probes must be attempted even when some error")
}

// ── Schema-based findBestNestableField integration ────────────────────────────

func TestGQL007_SchemaWithOnlyObjectField_UsesObjectField(t *testing.T) {
	// Schema: Query.posts → Post (plain object, no self-reference).
	postType := &schema.TypeDef{
		Name: "Post",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "title", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
		},
	}
	queryType := &schema.TypeDef{
		Name: "Query",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "posts", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Post"}},
		},
	}
	s := &schema.Schema{
		QueryType: queryType,
		Types:     map[string]*schema.TypeDef{"Query": queryType, "Post": postType},
	}
	assert.Equal(t, "posts", findBestNestableField(s), "should fall back to plain object field when no self-referential type exists")
}

func TestGQL007_SchemaWithNoObjectFields_FallsBackToSchema(t *testing.T) {
	// Schema: Query.version → String (scalar only).
	queryType := &schema.TypeDef{
		Name: "Query",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "version", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
		},
	}
	s := &schema.Schema{
		QueryType: queryType,
		Types:     map[string]*schema.TypeDef{"Query": queryType},
	}
	assert.Equal(t, "__schema", findBestNestableField(s), "should fall back to __schema when no object fields on Query")
}

// ── Fingerprint and metadata tests ───────────────────────────────────────────

func TestGQL007_Metadata(t *testing.T) {
	chk := &depthLimitCheck{}
	assert.Equal(t, "GQL-007", chk.ID())
	assert.Equal(t, "Query Depth Limit Not Enforced", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQL007_FindingA_FingerprintIsStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(acceptAllHandler))
	defer srv.Close()

	chk := &depthLimitCheck{}
	r1, _ := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))
	r2, _ := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NotEmpty(t, r1.Findings)
	require.NotEmpty(t, r2.Findings)

	// The depth_limit finding must have a 64-char SHA-256 hex fingerprint.
	for _, f := range r1.Findings {
		if f.Fingerprint == GenerateFingerprint("GQL-007", srv.URL, "depth_limit") {
			assert.Len(t, f.Fingerprint, 64)
			// Same fingerprint on second run (stable).
			for _, f2 := range r2.Findings {
				if f2.Fingerprint == f.Fingerprint {
					return
				}
			}
			t.Fatal("fingerprint not stable across runs")
		}
	}
}

func TestGQL007_FindingA_ReproBodyPopulated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(acceptAllHandler))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	for _, f := range result.Findings {
		if f.Fingerprint == GenerateFingerprint("GQL-007", srv.URL, "depth_limit") {
			assert.NotEmpty(t, f.ReproBody, "Finding A must carry a non-empty ReproBody")
			// Body must be valid JSON with a "query" key.
			var parsed map[string]string
			require.NoError(t, json.Unmarshal(f.ReproBody, &parsed))
			assert.Contains(t, parsed, "query")
			return
		}
	}
	t.Fatal("Finding A not generated")
}

func TestGQL007_FindingA_DescriptionContainsFieldAndDepth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(acceptAllHandler))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	for _, f := range result.Findings {
		if f.Fingerprint == GenerateFingerprint("GQL-007", srv.URL, "depth_limit") {
			assert.Contains(t, f.Description, "__schema", "description must mention the field used")
			assert.Contains(t, f.Description, "10", "description must mention the max depth")
			return
		}
	}
	t.Fatal("Finding A not generated")
}

// ── Additional edge-case tests ────────────────────────────────────────────────

func TestGQL007_ErrorOnlyResponse_NoFindingA(t *testing.T) {
	// Server always returns only "errors", never "data".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"not allowed"}]}`)
	}))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	for _, f := range result.Findings {
		assert.NotEqual(t, GenerateFingerprint("GQL-007", srv.URL, "depth_limit"), f.Fingerprint,
			"Finding A must NOT fire when server always returns errors")
	}
}

func TestGQL007_NonOKStatusCode_NoFindingA(t *testing.T) {
	// Server returns 429 Too Many Requests for deep probes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		depth := strings.Count(string(body), `__schema`)
		if depth >= 5 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"errors":[{"message":"rate limited"}]}`)
		} else {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
		}
	}))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	for _, f := range result.Findings {
		assert.NotEqual(t, GenerateFingerprint("GQL-007", srv.URL, "depth_limit"), f.Fingerprint,
			"Finding A must NOT fire when depth-5+ returns non-200 status")
	}
}

func TestGQL007_ProbeCount_AllDepthsSent(t *testing.T) {
	var requestBodies []string
	var mu atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBodies = append(requestBodies, string(body))
		mu.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, nil))

	require.NoError(t, err)
	assert.Equal(t, 6, result.ProbeCount)
	assert.Equal(t, int32(6), mu.Load())

	// Verify each depth was actually probed by checking __schema occurrence counts.
	expectedDepths := []int{1, 2, 3, 5, 7, 10}
	gotDepths := make([]int, 0, len(requestBodies))
	for _, b := range requestBodies {
		gotDepths = append(gotDepths, strings.Count(b, `__schema`))
	}
	assert.ElementsMatch(t, expectedDepths, gotDepths, "each configured depth must be probed")
}

// ── Dual probe-set tests (schema field + introspection __schema) ──────────────

// makeSchemaWithObjectField builds a minimal Schema in which Query.<fieldName>
// returns an object type, so that findBestNestableField returns fieldName
// (not the "__schema" fallback).
func makeSchemaWithObjectField(fieldName string) *schema.Schema {
	itemType := &schema.TypeDef{
		Name: "Item",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "id", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
		},
	}
	queryType := &schema.TypeDef{
		Name: "Query",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: fieldName, Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Item"}},
		},
	}
	return &schema.Schema{
		QueryType: queryType,
		Types:     map[string]*schema.TypeDef{"Query": queryType, "Item": itemType},
	}
}

// TestGQL007_WithSchema_BothProbeSetsSent verifies that when the schema provides a
// non-__schema field, the check sends both the primary probe set (schema field) and
// the introspection probe set (__schema), for a total of 12 probes.
func TestGQL007_WithSchema_BothProbeSetsSent(t *testing.T) {
	var requestBodies []string
	var mu atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBodies = append(requestBodies, string(body))
		mu.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	s := makeSchemaWithObjectField("node")
	require.Equal(t, "node", findBestNestableField(s), "precondition: schema field is node, not __schema")

	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, s))

	require.NoError(t, err)
	// 6 primary probes (node) + 6 introspection probes (__schema) = 12.
	assert.Equal(t, 12, result.ProbeCount, "expected 12 probes: 6 primary + 6 introspection")
	assert.Equal(t, int32(12), mu.Load())

	// At least one request body must contain "node" (primary probe set).
	hasNode := false
	hasSchema := false
	for _, b := range requestBodies {
		if strings.Contains(b, "node") {
			hasNode = true
		}
		if strings.Contains(b, "__schema") {
			hasSchema = true
		}
	}
	assert.True(t, hasNode, "at least one probe must use the schema-derived field 'node'")
	assert.True(t, hasSchema, "at least one probe must use the introspection field '__schema'")
}

// TestGQL007_IntrospectionProbesBypassDepthLimit_FindingAGenerated verifies that
// Finding A fires even when the server blocks deep application-field queries but
// allows deeply nested introspection queries ({ __schema { __schema { ... } } }).
func TestGQL007_IntrospectionProbesBypassDepthLimit_FindingAGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)

		// Block deep queries that use the application field "node".
		// The query body is JSON like {"query":"{ node { node { ... } } }"} so
		// counting occurrences of "node" gives the nesting depth.
		if nodeDepth := strings.Count(string(body), "node"); nodeDepth >= 5 {
			_, _ = fmt.Fprint(w, `{"errors":[{"message":"max depth exceeded"}]}`)
			return
		}
		// Always accept introspection (__schema) queries regardless of depth.
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	s := makeSchemaWithObjectField("node")
	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, s))

	require.NoError(t, err)

	var findingA *Finding
	fpA := GenerateFingerprint("GQL-007", srv.URL, "depth_limit")
	for i := range result.Findings {
		if result.Findings[i].Fingerprint == fpA {
			findingA = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, findingA, "Finding A must fire when introspection probes bypass the depth limit")
	assert.Equal(t, HIGH, findingA.Severity)
	// Description must mention the introspection probe section.
	assert.Contains(t, findingA.Description, "__schema")
}

// TestGQL007_BothProbeSetsBlocked_NoFindingA verifies that Finding A is not generated
// when the server correctly blocks deep queries for both the schema-derived field and
// the introspection probe set.
//
// Introspection probes use buildIntrospectionNestedQuery which cycles through
//
//	__schema → queryType → fields { type { fields { type { ... } } } }
//
// so depth is detected by counting "fields" occurrences in the request body
// (one per cycle), not by counting "__schema" (which always appears exactly once).
func TestGQL007_BothProbeSetsBlocked_NoFindingA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// Primary probe depth: count the application field name.
		nodeDepth := strings.Count(bodyStr, "node")
		// Introspection probe depth: each cycle adds one "fields" level.
		introspDepth := strings.Count(bodyStr, "fields")
		if nodeDepth >= 5 || introspDepth >= 5 {
			_, _ = fmt.Fprint(w, `{"errors":[{"message":"max depth exceeded"}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	s := makeSchemaWithObjectField("node")
	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, s))

	require.NoError(t, err)
	fpA := GenerateFingerprint("GQL-007", srv.URL, "depth_limit")
	for _, f := range result.Findings {
		assert.NotEqual(t, fpA, f.Fingerprint,
			"Finding A must NOT fire when both probe sets are blocked at depth ≥ 5")
	}
}

// TestGQL007_IntrospectionDescription_ContainsSection verifies the description
// includes the introspection probe section when a schema field is used.
func TestGQL007_IntrospectionDescription_ContainsSection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(acceptAllHandler))
	defer srv.Close()

	s := makeSchemaWithObjectField("node")
	chk := &depthLimitCheck{}
	result, err := chk.Run(context.Background(), newDepthCheckContext(t, srv, s))

	require.NoError(t, err)
	fpA := GenerateFingerprint("GQL-007", srv.URL, "depth_limit")
	for _, f := range result.Findings {
		if f.Fingerprint == fpA {
			assert.Contains(t, f.Description, "Introspection probe results",
				"description must include an introspection probe section when schema field is used")
			assert.Contains(t, f.Description, "__schema → queryType → fields → type cycle",
				"description must identify the valid introspection cycle used for probing")
			return
		}
	}
	t.Fatal("Finding A not generated")
}
