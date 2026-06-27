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

// newPersistedCheckContext creates a CheckContext pointing at srv with a
// high-RPS client and the given per-request timeout.
func newPersistedCheckContext(t *testing.T, srv *httptest.Server, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

// isArbitraryBody reports whether body is the arbitrary-operation probe.
func isArbitraryBody(body []byte) bool {
	return bytes.Contains(body, []byte("z9q1"))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD07_Metadata(t *testing.T) {
	chk := &persistedQueryCheck{}
	assert.Equal(t, "GQL-D07", chk.ID())
	assert.Equal(t, "Persisted Query / APQ Not Enforced", chk.Name())
	assert.Equal(t, MEDIUM, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQLD07_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D07" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D07 must self-register via init()")
}

// ── Vulnerable: arbitrary op executes, APQ supported ───────────────────────────

func TestGQLD07_ArbitraryExecuted_APQSupported_FindingWithNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isArbitraryBody(body) {
			_, _ = io.WriteString(w, `{"data":{"z9q1":"Query","z9q2":"Query"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"errors":[{"message":"PersistedQueryNotFound","extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}`)
	}))
	defer srv.Close()

	chk := &persistedQueryCheck{}
	result, err := chk.Run(context.Background(), newPersistedCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)

	f := result.Findings[0]
	assert.Equal(t, "GQL-D07", f.CheckID)
	assert.Equal(t, MEDIUM, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, "Arbitrary Operations Accepted (No Persisted-Query Allow-List)", f.Title)
	assert.Equal(t, 2, result.ProbeCount)
	assert.Len(t, f.Fingerprint, 64)
	assert.Equal(t, GenerateFingerprint("GQL-D07", srv.URL, "apq_not_enforced"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.Contains(t, f.Description, "APQ supported but allow-listing not enforced",
		"description must carry the APQ-nuance note when PersistedQueryNotFound is returned")
	assert.Empty(t, result.PassReason)
}

// ── Vulnerable: arbitrary op executes, APQ not supported ───────────────────────

func TestGQLD07_ArbitraryExecuted_APQNotSupported_FindingNoNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isArbitraryBody(body) {
			_, _ = io.WriteString(w, `{"data":{"z9q1":"Query","z9q2":"Query"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"errors":[{"message":"PersistedQueryNotSupported"}]}`)
	}))
	defer srv.Close()

	chk := &persistedQueryCheck{}
	result, err := chk.Run(context.Background(), newPersistedCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, MEDIUM, result.Findings[0].Severity)
	assert.NotContains(t, result.Findings[0].Description, "allow-listing not enforced",
		"the APQ-nuance note must be absent when APQ is not supported")
	assert.Contains(t, result.Findings[0].Description, "not supported")
}

// ── Protected: allow-list enforced ─────────────────────────────────────────────

func TestGQLD07_AdHocRejected_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if isArbitraryBody(body) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":[{"message":"operation not in allow-list"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"errors":[{"message":"PersistedQueryNotFound"}]}`)
	}))
	defer srv.Close()

	chk := &persistedQueryCheck{}
	result, err := chk.Run(context.Background(), newPersistedCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a rejected ad-hoc operation must not produce a finding")
	assert.Contains(t, result.PassReason, "persisted/allow-listed")
	require.Len(t, result.PassProbes, 2)
	assert.Equal(t, 2, result.ProbeCount)
}

// ── Control / cancellation ─────────────────────────────────────────────────────

func TestGQLD07_ContextCancelled_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"z9q1":"Query","z9q2":"Query"}}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	chk := &persistedQueryCheck{}
	require.NotPanics(t, func() {
		result, err := chk.Run(ctx, newPersistedCheckContext(t, srv, 10*time.Second))
		assert.NoError(t, err)
		assert.Empty(t, result.Findings)
	})
}

// ── APQ classification unit test ───────────────────────────────────────────────

func TestGQLD07_ClassifyAPQ(t *testing.T) {
	assert.Equal(t, apqSupported, classifyAPQ(apqProbeResult{body: []byte(`{"errors":[{"message":"PersistedQueryNotFound"}]}`)}))
	assert.Equal(t, apqSupported, classifyAPQ(apqProbeResult{body: []byte(`{"errors":[{"extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}`)}))
	assert.Equal(t, apqNotSupported, classifyAPQ(apqProbeResult{body: []byte(`{"errors":[{"message":"PersistedQueryNotSupported"}]}`)}))
	assert.Equal(t, apqNotSupported, classifyAPQ(apqProbeResult{body: []byte(`{"errors":[{"message":"You must provide a query string."}]}`)}))
	assert.Equal(t, apqUnknown, classifyAPQ(apqProbeResult{body: []byte(`{"data":{"__typename":"Query"}}`)}))
	assert.Equal(t, apqUnknown, classifyAPQ(apqProbeResult{err: io.EOF}))
}

// ── Probe shape ─────────────────────────────────────────────────────────────────

func TestGQLD07_APQProbeOmitsQueryField(t *testing.T) {
	var apqBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !isArbitraryBody(body) {
			apqBody = append([]byte(nil), body...)
		}
		w.Header().Set("Content-Type", "application/json")
		if isArbitraryBody(body) {
			_, _ = io.WriteString(w, `{"data":{"z9q1":"Query"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"errors":[{"message":"PersistedQueryNotFound"}]}`)
	}))
	defer srv.Close()

	chk := &persistedQueryCheck{}
	_, err := chk.Run(context.Background(), newPersistedCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.NotEmpty(t, apqBody)
	assert.Contains(t, string(apqBody), "persistedQuery")
	assert.NotContains(t, string(apqBody), `"query":`, "the APQ probe must omit the query field")
}
