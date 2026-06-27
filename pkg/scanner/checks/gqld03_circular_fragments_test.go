package checks

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCycleCheckContext creates a CheckContext pointing at srv with a high-RPS
// client and the given per-request timeout.
func newCycleCheckContext(t *testing.T, srv *httptest.Server, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

// isCycleBody reports whether body is the circular-fragment probe rather than
// the benign control.
func isCycleBody(body []byte) bool {
	return bytes.Contains(body, []byte("fragment A on"))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD03_Metadata(t *testing.T) {
	chk := &circularFragmentCheck{}
	assert.Equal(t, "GQL-D03", chk.ID())
	assert.Equal(t, "Circular Fragment Spread", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQLD03_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D03" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D03 must self-register via init()")
}

// ── Compliant: cycle correctly rejected ────────────────────────────────────────

func TestGQLD03_CycleRejected_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isCycleBody(body) {
			_, _ = io.WriteString(w, `{"errors":[{"message":"Cannot spread fragment \"A\" within itself."}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(context.Background(), newCycleCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a spec-compliant cycle rejection must not produce a finding")
	assert.Contains(t, result.PassReason, "spec-compliant")
	require.Len(t, result.PassProbes, 2)
	assert.Equal(t, 2, result.ProbeCount)
}

// ── Vulnerable paths ────────────────────────────────────────────────────────────

func TestGQLD03_CycleTimesOut_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if isCycleBody(body) {
			time.Sleep(2 * time.Second) // hang past the client timeout for the cycle only
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(context.Background(), newCycleCheckContext(t, srv, 250*time.Millisecond))

	require.NoError(t, err, "a timeout on the cycle probe must not surface as a Run error")
	require.Len(t, result.Findings, 1, "a cycle that hangs past the timeout is a positive signal")
	f := result.Findings[0]
	assert.Equal(t, "GQL-D03", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, "Fragment Cycle Not Rejected (Validator DoS)", f.Title)
	assert.Len(t, f.Fingerprint, 64)
	assert.Equal(t, GenerateFingerprint("GQL-D03", srv.URL, "circular_fragment"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.Contains(t, f.Description, "timed out")
	assert.Contains(t, f.Description, "fragment A on", "description must include the circular document")
	assert.Equal(t, 2, result.ProbeCount)
}

func TestGQLD03_Cycle5xx_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isCycleBody(body) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"errors":[{"message":"stack overflow"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(context.Background(), newCycleCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "a 5xx on the cycle probe is a positive signal")
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "HTTP 500")
}

func TestGQLD03_CycleHangsSuperLinear_FindingGenerated(t *testing.T) {
	// The cycle returns a slow 200 with data and no validation error — isolating
	// the super-linear hang branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isCycleBody(body) {
			time.Sleep(1500 * time.Millisecond)
			_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(context.Background(), newCycleCheckContext(t, srv, 5*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "super-linear hang must produce a finding")
	assert.Contains(t, result.Findings[0].Description, "super-linear")
}

// ── Inconclusive: clean response, no cycle error ────────────────────────────────

func TestGQLD03_CleanResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(context.Background(), newCycleCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a clean unrelated 200 must not produce a finding")
	assert.Contains(t, result.PassReason, "inconclusive")
	require.Len(t, result.PassProbes, 2)
}

// ── Control failure ─────────────────────────────────────────────────────────────

func TestGQLD03_ControlFails_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errors":[{"message":"down"}]}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(context.Background(), newCycleCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a failed baseline must not produce a finding")
	assert.Contains(t, result.PassReason, "baseline")
	assert.Equal(t, 1, result.ProbeCount, "cycle probe must not be sent when control fails")
	require.Len(t, result.PassProbes, 1)
}

func TestGQLD03_ControlNetworkError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	target := srv.URL
	srv.Close()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(context.Background(), &CheckContext{
		Target:     target,
		HTTPClient: transport.NewClient(2*time.Second, 500, nil),
	})

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	assert.Equal(t, 1, result.ProbeCount)
}

// ── Context cancellation ────────────────────────────────────────────────────────

func TestGQLD03_ContextCancelled_NoPanicNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	chk := &circularFragmentCheck{}
	result, err := chk.Run(ctx, newCycleCheckContext(t, srv, 10*time.Second))

	assert.NoError(t, err, "Run must return nil error on cancellation")
	assert.Empty(t, result.Findings, "a cancelled context must not be treated as a positive signal")
}

// ── Probe shape ─────────────────────────────────────────────────────────────────

func TestGQLD03_ProbesAreJSONPostWithContentType(t *testing.T) {
	var methods []string
	var contentTypes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	_, err := chk.Run(context.Background(), newCycleCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.Len(t, methods, 2)
	for i := range methods {
		assert.Equal(t, http.MethodPost, methods[i])
		assert.Equal(t, "application/json", contentTypes[i])
	}
}

// ── Root type selection ─────────────────────────────────────────────────────────

func TestGQLD03_UsesSchemaRootTypeName(t *testing.T) {
	var cycleBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if isCycleBody(body) {
			cycleBody = body
		}
		w.Header().Set("Content-Type", "application/json")
		// Respond compliant so no finding is produced; we only inspect the body.
		if isCycleBody(body) {
			_, _ = io.WriteString(w, `{"errors":[{"message":"Cannot spread fragment within itself"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	cc := newCycleCheckContext(t, srv, 10*time.Second)
	cc.Schema = &schema.Schema{QueryType: &schema.TypeDef{Name: "RootQuery", Kind: schema.KindObject}}

	chk := &circularFragmentCheck{}
	_, err := chk.Run(context.Background(), cc)
	require.NoError(t, err)

	require.NotEmpty(t, cycleBody)
	assert.Contains(t, string(cycleBody), "on RootQuery", "schema-derived root type name must be used")
}

func TestGQLD03_RootQueryTypeName_FallsBackToQuery(t *testing.T) {
	assert.Equal(t, "Query", rootQueryTypeName(nil))
	assert.Equal(t, "Query", rootQueryTypeName(&schema.Schema{}))
	assert.Equal(t, "Query", rootQueryTypeName(&schema.Schema{QueryType: &schema.TypeDef{Name: ""}}))
	assert.Equal(t, "RootQuery", rootQueryTypeName(&schema.Schema{QueryType: &schema.TypeDef{Name: "RootQuery"}}))
}

func TestGQLD03_DocumentFormsCycleWithRootType(t *testing.T) {
	doc := buildCircularFragmentDoc("Query")
	assert.Contains(t, doc, "fragment A on Query")
	assert.Contains(t, doc, "fragment B on Query")
	assert.Contains(t, doc, "...A")
	assert.Contains(t, doc, "...B")
}

// ── Fingerprint stability ───────────────────────────────────────────────────────

func TestGQLD03_FingerprintStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isCycleBody(body) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"errors":[{"message":"boom"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &circularFragmentCheck{}
	r1, _ := chk.Run(context.Background(), newCycleCheckContext(t, srv, 10*time.Second))
	r2, _ := chk.Run(context.Background(), newCycleCheckContext(t, srv, 10*time.Second))

	require.NotEmpty(t, r1.Findings)
	require.NotEmpty(t, r2.Findings)
	assert.Equal(t, r1.Findings[0].Fingerprint, r2.Findings[0].Fingerprint, "fingerprint must be stable across runs")
}
