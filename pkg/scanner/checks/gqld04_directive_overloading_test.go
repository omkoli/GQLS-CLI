package checks

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDirectiveCheckContext creates a CheckContext pointing at srv with a
// high-RPS client and the given per-request timeout.
func newDirectiveCheckContext(t *testing.T, srv *httptest.Server, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

// isOverloadBody reports whether body is the overload probe (many repeated
// directives) rather than the single-directive control.
func isOverloadBody(body []byte) bool {
	return bytes.Count(body, []byte("@skip")) > 5
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD04_Metadata(t *testing.T) {
	chk := &directiveOverloadingCheck{}
	assert.Equal(t, "GQL-D04", chk.ID())
	assert.Equal(t, "Directive Overloading", chk.Name())
	assert.Equal(t, MEDIUM, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQLD04_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D04" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D04 must self-register via init()")
}

// ── Vulnerable: server executes the overload document ──────────────────────────

func TestGQLD04_OverloadAccepted_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1, "exactly one MEDIUM finding expected")

	f := result.Findings[0]
	assert.Equal(t, "GQL-D04", f.CheckID)
	assert.Equal(t, "Directive Overloading", f.CheckName)
	assert.Equal(t, MEDIUM, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, "No Directive-Count Limit (Directive Overloading)", f.Title)
	assert.GreaterOrEqual(t, result.ProbeCount, 2, "control + overload probes")
	assert.Len(t, f.Fingerprint, 64, "fingerprint must be a 64-char hex string")
	assert.Equal(t, GenerateFingerprint("GQL-D04", srv.URL, "directive_overloading"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.NotEmpty(t, f.Impact)
	assert.Contains(t, f.Description, "200", "description must state the directive count")
	assert.Contains(t, f.Description, "structural acceptance")

	require.NotEmpty(t, f.ReproBody)
	assert.True(t, isOverloadBody(f.ReproBody), "ReproBody must be the overload query")
	assert.NotNil(t, f.ReproRequest)
	assert.Empty(t, result.PassReason)
}

func TestGQLD04_OverloadRequestCarriesRepeatedDirectives(t *testing.T) {
	var overloadBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if isOverloadBody(body) {
			overloadBody = body
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	_, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.NotEmpty(t, overloadBody)
	assert.Equal(t, directiveCount, bytes.Count(overloadBody, []byte("@skip(if: false)")),
		"overload document must contain exactly directiveCount @skip directives")
}

// ── Protected: directive-uniqueness rejection ──────────────────────────────────

func TestGQLD04_DirectiveUniquenessError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isOverloadBody(body) {
			_, _ = io.WriteString(w, `{"errors":[{"message":"The directive \"@skip\" can only be used once at this location."}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a directive-uniqueness rejection must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	require.Len(t, result.PassProbes, 2, "both control and overload probes must be recorded")
	assert.Equal(t, 2, result.ProbeCount)
}

func TestGQLD04_OverloadNon200_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isOverloadBody(body) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":[{"message":"rejected"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "HTTP 400 on the overload probe must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	assert.Len(t, result.PassProbes, 2)
}

func TestGQLD04_OverloadFast200NoData_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isOverloadBody(body) {
			_, _ = io.WriteString(w, `{"extensions":{"note":"handled"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
}

// ── Unresponsiveness paths ─────────────────────────────────────────────────────

func TestGQLD04_OverloadTimesOut_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if isOverloadBody(body) {
			time.Sleep(2 * time.Second) // hang past the client timeout for the overload only
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 250*time.Millisecond))

	require.NoError(t, err, "a timeout under overloading must not surface as a Run error")
	require.Len(t, result.Findings, 1, "timeout under bounded overloading is a positive signal")
	assert.Equal(t, MEDIUM, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "unresponsive")
	assert.Equal(t, 2, result.ProbeCount)
}

func TestGQLD04_Overload5xx_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isOverloadBody(body) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"errors":[{"message":"internal error"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "5xx under overloading is a positive signal")
	assert.Equal(t, MEDIUM, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "unresponsive")
}

// ── Super-linear latency branch ────────────────────────────────────────────────

func TestGQLD04_SuperLinearLatency_FindingGenerated(t *testing.T) {
	// The overload returns a fast-to-parse 200 WITHOUT a data object (so the
	// structural branch does not fire) but takes far longer than the control —
	// isolating the latency-ratio branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isOverloadBody(body) {
			time.Sleep(1500 * time.Millisecond)
			_, _ = io.WriteString(w, `{"extensions":{"validated":true}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 5*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "super-linear validation time must produce a finding")
	assert.Equal(t, MEDIUM, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "super-linear validation time")
}

// ── Control failure ─────────────────────────────────────────────────────────────

func TestGQLD04_ControlFails_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errors":[{"message":"down"}]}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a failed baseline must not produce a finding")
	assert.Contains(t, result.PassReason, "baseline")
	assert.Equal(t, 1, result.ProbeCount, "overload probe must not be sent when control fails")
	require.Len(t, result.PassProbes, 1)
}

func TestGQLD04_ControlNetworkError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	target := srv.URL
	srv.Close()

	chk := &directiveOverloadingCheck{}
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

func TestGQLD04_ContextCancelled_NoPanicNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	chk := &directiveOverloadingCheck{}
	result, err := chk.Run(ctx, newDirectiveCheckContext(t, srv, 10*time.Second))

	assert.NoError(t, err, "Run must return nil error on cancellation")
	assert.Empty(t, result.Findings, "a cancelled context must not be treated as a positive signal")
}

// ── Probe shape ─────────────────────────────────────────────────────────────────

func TestGQLD04_ProbesAreJSONPostWithContentType(t *testing.T) {
	var methods []string
	var contentTypes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	_, err := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.Len(t, methods, 2)
	for i := range methods {
		assert.Equal(t, http.MethodPost, methods[i])
		assert.Equal(t, "application/json", contentTypes[i])
	}
}

// ── Fingerprint stability ───────────────────────────────────────────────────────

func TestGQLD04_FingerprintStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &directiveOverloadingCheck{}
	r1, _ := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))
	r2, _ := chk.Run(context.Background(), newDirectiveCheckContext(t, srv, 10*time.Second))

	require.NotEmpty(t, r1.Findings)
	require.NotEmpty(t, r2.Findings)
	assert.Equal(t, r1.Findings[0].Fingerprint, r2.Findings[0].Fingerprint, "fingerprint must be stable across runs")
}
