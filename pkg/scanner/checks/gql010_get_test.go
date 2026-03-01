package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGETQueriesCheck_FindingOnDataResponse verifies that a successful GET
// returning a valid GraphQL {"data": ...} body produces a MEDIUM finding.
func TestGETQueriesCheck_FindingOnDataResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "{__typename}", r.URL.Query().Get("query"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	chk := &getQueriesCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	f := result.Findings[0]
	assert.Equal(t, "GQL-010", f.CheckID)
	assert.Equal(t, MEDIUM, f.Severity)
	assert.Equal(t, Misconfiguration, f.Category)
	assert.NotEmpty(t, f.Fingerprint)
	assert.NotNil(t, f.ReproRequest)
	assert.Equal(t, 1, result.ProbeCount)
}

// TestGETQueriesCheck_MethodNotAllowed verifies that an HTTP 405 response
// produces no finding.
func TestGETQueriesCheck_MethodNotAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	chk := &getQueriesCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	require.Len(t, result.PassProbes, 1)
	assert.Equal(t, 1, result.ProbeCount)
}

// TestGETQueriesCheck_NonGraphQLResponse verifies that a response without a
// GraphQL "data" field produces no finding.
func TestGETQueriesCheck_NonGraphQLResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()

	chk := &getQueriesCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	require.Len(t, result.PassProbes, 1)
	assert.Equal(t, 1, result.ProbeCount)
}

// TestGETQueriesCheck_NetworkError verifies that a connection failure produces
// no finding, captures the error, and still increments ProbeCount.
func TestGETQueriesCheck_NetworkError(t *testing.T) {
	// Open a server, record its address, then close it so connections are refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	target := srv.URL
	srv.Close()

	cc := &CheckContext{
		Target:     target,
		HTTPClient: transport.NewClient(1*time.Second, 100, nil),
	}

	chk := &getQueriesCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err) // Run must not surface errors; it records them internally.
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotNil(t, result.Error)
	assert.Equal(t, 1, result.ProbeCount)
}

// TestGETQueriesCheck_Metadata verifies the check's static metadata.
func TestGETQueriesCheck_Metadata(t *testing.T) {
	chk := &getQueriesCheck{}
	assert.Equal(t, "GQL-010", chk.ID())
	assert.Equal(t, "GraphQL GET Queries Enabled", chk.Name())
	assert.Equal(t, MEDIUM, chk.Severity())
	assert.Equal(t, Misconfiguration, chk.Category())
	assert.False(t, chk.RequiresSchema())
}
