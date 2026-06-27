package checks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIntrospectionCheckContext creates a CheckContext (with optional schema)
// pointing at srv with a high-RPS client and timeout.
func newIntrospectionCheckContext(t *testing.T, srv *httptest.Server, sc *schema.Schema, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		Schema:     sc,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

// isAmplifiedIntrospection reports whether body is the recursive (ofType-chain)
// introspection probe rather than the tiny baseline.
func isAmplifiedIntrospection(body []byte) bool {
	return bytes.Contains(body, []byte("ofType"))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD08_Metadata(t *testing.T) {
	chk := &introspectionDoSCheck{}
	assert.Equal(t, "GQL-D08", chk.ID())
	assert.Equal(t, "Unbounded Introspection Amplification", chk.Name())
	assert.Equal(t, LOW, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQLD08_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D08" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D08 must self-register via init()")
}

// ── Vulnerable: large amplified introspection response ─────────────────────────

func TestGQLD08_LargeIntrospection_FindingGenerated(t *testing.T) {
	bigData := strings.Repeat("x", 1_100_000) // > 1 MB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isAmplifiedIntrospection(body) {
			_, _ = fmt.Fprintf(w, `{"data":{"__schema":{"types":[{"name":"%s"}]}}}`, bigData)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer srv.Close()

	chk := &introspectionDoSCheck{}
	result, err := chk.Run(context.Background(), newIntrospectionCheckContext(t, srv, nil, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)

	f := result.Findings[0]
	assert.Equal(t, "GQL-D08", f.CheckID)
	assert.Equal(t, LOW, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, "Unbounded Introspection Response (Amplification + Recon)", f.Title)
	assert.GreaterOrEqual(t, result.ProbeCount, 1)
	assert.Len(t, f.Fingerprint, 64)
	assert.Equal(t, GenerateFingerprint("GQL-D08", srv.URL, "introspection_dos"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.Contains(t, f.Description, "Amplified", "description must report baseline vs amplified sizes")
	assert.Empty(t, result.PassReason)
}

func TestGQLD08_RatioAmplification_FindingGenerated(t *testing.T) {
	// Under the 1 MB floor, but ≥ 20× the baseline → still fires via ratio.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isAmplifiedIntrospection(body) {
			_, _ = fmt.Fprintf(w, `{"data":{"__schema":{"types":"%s"}}}`, strings.Repeat("x", 50_000))
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer srv.Close()

	chk := &introspectionDoSCheck{}
	result, err := chk.Run(context.Background(), newIntrospectionCheckContext(t, srv, nil, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "≥20× baseline must fire via the ratio signal")
}

// ── Introspection disabled ──────────────────────────────────────────────────────

func TestGQLD08_IntrospectionDisabledError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":[{"message":"GraphQL introspection is not allowed"}]}`)
	}))
	defer srv.Close()

	chk := &introspectionDoSCheck{}
	result, err := chk.Run(context.Background(), newIntrospectionCheckContext(t, srv, nil, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.Contains(t, result.PassReason, "not applicable")
	assert.Equal(t, 1, result.ProbeCount, "amplified probe must not be sent when introspection is rejected")
}

func TestGQLD08_DisabledViaMetadata_ShortCircuit(t *testing.T) {
	// A server that WOULD return a big introspection response, but metadata says
	// introspection is disabled — the check must short-circuit without probing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"__schema":{"types":"%s"}}}`, strings.Repeat("x", 2_000_000))
	}))
	defer srv.Close()

	sc := &schema.Schema{Metadata: schema.ExtractionMetadata{IntrospectionEnabled: false}}
	chk := &introspectionDoSCheck{}
	result, err := chk.Run(context.Background(), newIntrospectionCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.Contains(t, result.PassReason, "not applicable")
	assert.Equal(t, 0, result.ProbeCount, "no probes when metadata proves introspection is disabled")
}

// ── Bounded introspection: no amplification ─────────────────────────────────────

func TestGQLD08_BoundedIntrospection_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isAmplifiedIntrospection(body) {
			// Small bounded response (server caps introspection size).
			_, _ = io.WriteString(w, `{"data":{"__schema":{"types":[{"name":"Query"}]}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer srv.Close()

	chk := &introspectionDoSCheck{}
	result, err := chk.Run(context.Background(), newIntrospectionCheckContext(t, srv, nil, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a small bounded introspection response must not produce a finding")
	assert.Contains(t, result.PassReason, "safe bounds")
	require.Len(t, result.PassProbes, 2)
}

// ── Enabled-via-metadata still probes ──────────────────────────────────────────

func TestGQLD08_EnabledViaMetadata_Probes(t *testing.T) {
	bigData := strings.Repeat("x", 1_100_000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isAmplifiedIntrospection(body) {
			_, _ = fmt.Fprintf(w, `{"data":{"__schema":{"types":"%s"}}}`, bigData)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer srv.Close()

	sc := &schema.Schema{Metadata: schema.ExtractionMetadata{IntrospectionEnabled: true}}
	chk := &introspectionDoSCheck{}
	result, err := chk.Run(context.Background(), newIntrospectionCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "introspection enabled via metadata must still be probed and flagged")
	assert.Equal(t, 2, result.ProbeCount)
}

// ── Query builder shape ─────────────────────────────────────────────────────────

func TestGQLD08_AmplifiedQueryIsBounded(t *testing.T) {
	q := buildAmplifiedIntrospectionQuery()
	assert.Contains(t, q, "ofType", "amplified query must nest the ofType chain")
	assert.Contains(t, q, "__schema { types {")
	// The ofType chain is capped at 8 nested levels per TypeRef, and the query
	// reuses that bounded TypeRef across the 3 type positions (field type, arg
	// type, inputField type) → exactly 24 occurrences. The cap guarantees a
	// single, bounded request rather than an escalating one.
	assert.Equal(t, 24, strings.Count(q, "ofType"), "ofType nesting must stay bounded (8 levels × 3 TypeRefs)")
}
