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

// newDupCheckContext creates a CheckContext pointing at srv with a high-RPS
// client and the given per-request timeout.
func newDupCheckContext(t *testing.T, srv *httptest.Server, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

// isFloodBody reports whether body is the flood probe (many duplicated
// __typename selections) rather than the single-selection control.
func isFloodBody(body []byte) bool {
	return bytes.Count(body, []byte("__typename")) > 5
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD02_Metadata(t *testing.T) {
	chk := &fieldDuplicationCheck{}
	assert.Equal(t, "GQL-D02", chk.ID())
	assert.Equal(t, "Field Duplication / __typename Flooding", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQLD02_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D02" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D02 must self-register via init()")
}

// ── Vulnerable: server executes the flood document ─────────────────────────────

func TestGQLD02_FloodAccepted_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1, "exactly one HIGH finding expected")

	f := result.Findings[0]
	assert.Equal(t, "GQL-D02", f.CheckID)
	assert.Equal(t, "Field Duplication / __typename Flooding", f.CheckName)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, "No Document-Size / Field-Duplication Limit", f.Title)
	assert.GreaterOrEqual(t, result.ProbeCount, 2, "control + flood probes")
	assert.Len(t, f.Fingerprint, 64, "fingerprint must be a 64-char hex string")
	assert.Equal(t, GenerateFingerprint("GQL-D02", srv.URL, "field_duplication"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.NotEmpty(t, f.Impact)
	assert.Contains(t, f.Description, "256", "description must state the duplication count")
	assert.Contains(t, f.Description, "structural acceptance")

	require.NotEmpty(t, f.ReproBody)
	assert.True(t, isFloodBody(f.ReproBody), "ReproBody must be the flood query")
	assert.NotNil(t, f.ReproRequest)
	assert.Empty(t, result.PassReason)
}

func TestGQLD02_FloodRequestCarriesDuplicates(t *testing.T) {
	var floodBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if isFloodBody(body) {
			floodBody = body
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	_, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.NotEmpty(t, floodBody)
	assert.Equal(t, dupCount, bytes.Count(floodBody, []byte("__typename")),
		"flood document must contain exactly dupCount __typename selections")
}

// ── Protected: document-size / cost rejection ──────────────────────────────────

func TestGQLD02_DocumentTooLarge_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isFloodBody(body) {
			_, _ = io.WriteString(w, `{"errors":[{"message":"Query document too large"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a document-size rejection must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	require.Len(t, result.PassProbes, 2, "both control and flood probes must be recorded")
	assert.Equal(t, 2, result.ProbeCount)
}

func TestGQLD02_FloodNon200_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isFloodBody(body) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":[{"message":"rejected"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "HTTP 400 on the flood probe must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	assert.Len(t, result.PassProbes, 2)
}

func TestGQLD02_FloodFast200NoData_NoFinding(t *testing.T) {
	// A fast 200 without a data object and no rejection keyword is neither a
	// structural nor a timing signal — must not flag.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isFloodBody(body) {
			_, _ = io.WriteString(w, `{"extensions":{"note":"handled"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
}

// ── Unresponsiveness paths ─────────────────────────────────────────────────────

func TestGQLD02_FloodTimesOut_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if isFloodBody(body) {
			time.Sleep(2 * time.Second) // hang past the client timeout for the flood only
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 250*time.Millisecond))

	require.NoError(t, err, "a timeout under duplication must not surface as a Run error")
	require.Len(t, result.Findings, 1, "timeout under bounded duplication is a positive signal")
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "unresponsive")
	assert.Equal(t, 2, result.ProbeCount)
}

func TestGQLD02_Flood5xx_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isFloodBody(body) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"errors":[{"message":"internal error"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "5xx under duplication is a positive signal")
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "unresponsive")
}

// ── Super-linear latency branch ────────────────────────────────────────────────

func TestGQLD02_SuperLinearLatency_FindingGenerated(t *testing.T) {
	// The flood returns a fast-to-parse 200 WITHOUT a data object (so the
	// structural branch does not fire) but takes far longer than the control —
	// isolating the latency-ratio branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isFloodBody(body) {
			time.Sleep(1500 * time.Millisecond)
			_, _ = io.WriteString(w, `{"extensions":{"validated":true}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 5*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "super-linear validation time must produce a finding")
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "super-linear validation time")
}

// ── Control failure ─────────────────────────────────────────────────────────────

func TestGQLD02_ControlFails_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errors":[{"message":"down"}]}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a failed baseline must not produce a finding")
	assert.Contains(t, result.PassReason, "baseline")
	assert.Equal(t, 1, result.ProbeCount, "flood probe must not be sent when control fails")
	require.Len(t, result.PassProbes, 1)
}

func TestGQLD02_ControlNetworkError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	target := srv.URL
	srv.Close() // close before running so the connection is refused

	chk := &fieldDuplicationCheck{}
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

func TestGQLD02_ContextCancelled_NoPanicNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	chk := &fieldDuplicationCheck{}
	result, err := chk.Run(ctx, newDupCheckContext(t, srv, 10*time.Second))

	assert.NoError(t, err, "Run must return nil error on cancellation")
	assert.Empty(t, result.Findings, "a cancelled context must not be treated as a positive signal")
}

// ── Probe shape ─────────────────────────────────────────────────────────────────

func TestGQLD02_ProbesAreJSONPostWithContentType(t *testing.T) {
	var methods []string
	var contentTypes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	_, err := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.Len(t, methods, 2)
	for i := range methods {
		assert.Equal(t, http.MethodPost, methods[i])
		assert.Equal(t, "application/json", contentTypes[i])
	}
}

// ── Fingerprint stability ───────────────────────────────────────────────────────

func TestGQLD02_FingerprintStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	chk := &fieldDuplicationCheck{}
	r1, _ := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))
	r2, _ := chk.Run(context.Background(), newDupCheckContext(t, srv, 10*time.Second))

	require.NotEmpty(t, r1.Findings)
	require.NotEmpty(t, r2.Findings)
	assert.Equal(t, r1.Findings[0].Fingerprint, r2.Findings[0].Fingerprint, "fingerprint must be stable across runs")
}
