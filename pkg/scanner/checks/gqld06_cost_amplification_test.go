package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCostCheckContext creates a CheckContext pointing at srv with a high-RPS
// client and the given per-request timeout.
func newCostCheckContext(t *testing.T, srv *httptest.Server, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

var aliasCountRe = regexp.MustCompile(`a\d+:`)

// readQuery extracts the GraphQL query string from a request body.
func readQuery(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Query string `json:"query"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Query
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD06_Metadata(t *testing.T) {
	chk := &costAmplificationCheck{}
	assert.Equal(t, "GQL-D06", chk.ID())
	assert.Equal(t, "Query Cost Amplification", chk.Name())
	assert.Equal(t, MEDIUM, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQLD06_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D06" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D06 must self-register via init()")
}

// ── Vulnerable: response size scales steeply with cost ─────────────────────────

func TestGQLD06_HighAmplification_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readQuery(r)
		// Response size scales with the structural cost of the query.
		padding := strings.Repeat("x", len(q)*100)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"x":"%s"}}`, padding)
	}))
	defer srv.Close()

	chk := &costAmplificationCheck{}
	result, err := chk.Run(context.Background(), newCostCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "steep size amplification must produce one finding")

	f := result.Findings[0]
	assert.Equal(t, "GQL-D06", f.CheckID)
	assert.Equal(t, MEDIUM, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, "High Query-Cost Amplification (No Effective Cost Limit)", f.Title)
	assert.Equal(t, 3, result.ProbeCount, "the gradient has exactly G=3 steps")
	assert.Len(t, f.Fingerprint, 64)
	assert.Equal(t, GenerateFingerprint("GQL-D06", srv.URL, "cost_amplification"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.Contains(t, f.Description, "AF_size", "description must report the size amplification factor")
	assert.Regexp(t, regexp.MustCompile(`AF_size\):\s+\d+`), f.Description)
	assert.Empty(t, result.PassReason)
}

func TestGQLD06_ReportedSizeFactorMeetsThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readQuery(r)
		padding := strings.Repeat("x", len(q)*100)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"x":"%s"}}`, padding)
	}))
	defer srv.Close()

	chk := &costAmplificationCheck{}
	result, err := chk.Run(context.Background(), newCostCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)

	// Extract the reported AF_size and assert it is at least the threshold.
	m := regexp.MustCompile(`AF_size\):\s+(\d+)×`).FindStringSubmatch(result.Findings[0].Description)
	require.NotNil(t, m, "description must contain a numeric AF_size")
	var af int
	_, _ = fmt.Sscanf(m[1], "%d", &af)
	assert.GreaterOrEqual(t, af, int(afSizeThreshold), "reported AF_size must meet the firing threshold")
}

// ── Protected: cost gradient rejected ──────────────────────────────────────────

func TestGQLD06_ComplexityRejection_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readQuery(r)
		w.Header().Set("Content-Type", "application/json")
		// Reject the costliest step (widest alias count).
		if len(aliasCountRe.FindAllString(q, -1)) >= 16 {
			_, _ = io.WriteString(w, `{"errors":[{"message":"Query is too complex"}]}`)
			return
		}
		padding := strings.Repeat("x", len(q)*100)
		_, _ = fmt.Fprintf(w, `{"data":{"x":"%s"}}`, padding)
	}))
	defer srv.Close()

	chk := &costAmplificationCheck{}
	result, err := chk.Run(context.Background(), newCostCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a cost/complexity rejection must not produce a finding")
	assert.Contains(t, result.PassReason, "cost")
	require.NotEmpty(t, result.PassProbes, "the gradient must be recorded as PassProbes")
	assert.Equal(t, 3, result.ProbeCount)
}

// ── Flat server: constant body, low amplification ──────────────────────────────

func TestGQLD06_FlatResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &costAmplificationCheck{}
	result, err := chk.Run(context.Background(), newCostCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a flat (constant-size) response must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	require.Len(t, result.PassProbes, 3, "all gradient steps recorded as PassProbes")
}

// ── Deterministic gradient ordering (cheapest first) ───────────────────────────

func TestGQLD06_GradientOrderedCheapestFirst(t *testing.T) {
	var widths []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readQuery(r)
		widths = append(widths, len(aliasCountRe.FindAllString(q, -1)))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &costAmplificationCheck{}
	_, err := chk.Run(context.Background(), newCostCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.Len(t, widths, 3)
	assert.Equal(t, []int{1, 8, 16}, widths, "gradient must be sent cheapest (narrowest) first")
}

// ── Latency-inconclusive path ──────────────────────────────────────────────────

func TestGQLD06_LatencyInconclusive_NoPanic(t *testing.T) {
	// Fast, flat localhost responses keep min latency below the floor, exercising
	// the latency-inconclusive branch. It must not panic and must not fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &costAmplificationCheck{}
	require.NotPanics(t, func() {
		result, err := chk.Run(context.Background(), newCostCheckContext(t, srv, 10*time.Second))
		require.NoError(t, err)
		assert.Empty(t, result.Findings)
	})
}

// ── Context cancellation ────────────────────────────────────────────────────────

func TestGQLD06_ContextCancelled_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	chk := &costAmplificationCheck{}
	require.NotPanics(t, func() {
		result, err := chk.Run(ctx, newCostCheckContext(t, srv, 10*time.Second))
		assert.NoError(t, err)
		assert.Empty(t, result.Findings)
	})
}

// ── Unit tests for the metric helpers ──────────────────────────────────────────

func TestGQLD06_ComputeAFSize(t *testing.T) {
	steps := []costStep{
		{reqBytes: 40, respBytes: 100},
		{reqBytes: 200, respBytes: 20000}, // largest response → drives AF
		{reqBytes: 80, respBytes: 400},
	}
	af, best := computeAFSize(steps)
	assert.Equal(t, 100.0, af, "AF_size = 20000/200")
	assert.Equal(t, 20000, best.respBytes)
}

func TestGQLD06_ComputeAFLat_InconclusiveBelowFloor(t *testing.T) {
	steps := []costStep{
		{latencyMS: 0},
		{latencyMS: 2},
		{latencyMS: 4},
	}
	_, _, ok := computeAFLat(steps)
	assert.False(t, ok, "baseline below the noise floor must be inconclusive")
}

func TestGQLD06_ComputeAFLat_Conclusive(t *testing.T) {
	steps := []costStep{
		{latencyMS: 10},
		{latencyMS: 50},
		{latencyMS: 200},
	}
	af, maxLat, ok := computeAFLat(steps)
	require.True(t, ok)
	assert.Equal(t, int64(200), maxLat)
	assert.Equal(t, 20.0, af, "AF_lat = 200/10")
}

func TestGQLD06_BuildCostQueryShape(t *testing.T) {
	// No schema → introspection fallback, aliased and depth-graded.
	q := buildCostQuery("__schema", 2, 8)
	assert.Equal(t, 8, len(aliasCountRe.FindAllString(q, -1)), "width aliases must be present")
	assert.Contains(t, q, "__schema { queryType {")

	// Schema-derived nestable field → nested field chain.
	q = buildCostQuery("friends", 3, 2)
	assert.Contains(t, q, "a0: friends { friends { friends { __typename } } }")
	assert.Equal(t, 2, len(aliasCountRe.FindAllString(q, -1)))
}
