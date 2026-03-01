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

func newTestCheckContext(t *testing.T, srv *httptest.Server) *CheckContext {
	t.Helper()
	client := transport.NewClient(5*time.Second, 100, nil)
	return &CheckContext{
		Target:                srv.URL,
		HTTPClient:            client,
		UnauthenticatedClient: transport.NewClient(5*time.Second, 100, nil),
	}
}

func TestIntrospectionCheck_Enabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer srv.Close()

	chk := &introspectionCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "GQL-001", result.Findings[0].CheckID)
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Equal(t, InformationDisclosure, result.Findings[0].Category)
	assert.NotEmpty(t, result.Findings[0].Fingerprint)
}

func TestIntrospectionCheck_Disabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
	}))
	defer srv.Close()

	chk := &introspectionCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings, "no finding when introspection is disabled")
}

func TestIntrospectionCheck_NullSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// __schema is present but null — some servers return this when disabled.
		_, _ = w.Write([]byte(`{"data":{"__schema":null}}`))
	}))
	defer srv.Close()

	chk := &introspectionCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestIntrospectionCheck_Metadata(t *testing.T) {
	chk := &introspectionCheck{}
	assert.Equal(t, "GQL-001", chk.ID())
	assert.Equal(t, HIGH, chk.Severity())
	assert.False(t, chk.RequiresSchema())
	assert.Equal(t, InformationDisclosure, chk.Category())
}

// TestIntrospectionCheck_CurlFile_IgnoresCurlHeaders verifies that when
// cc.ParsedCurl is non-nil (i.e. --curl-file was provided), GQL-001 probes
// introspection with a bare client — it must NOT forward the curl command's
// auth headers to the endpoint. The server in this test rejects requests that
// carry an Authorization header so that the check can only succeed if the
// curl headers were correctly stripped.
func TestIntrospectionCheck_CurlFile_IgnoresCurlHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Simulate an endpoint that blocks introspection when an auth token is
		// present (e.g. it returns an auth-scoped error) but allows it otherwise.
		if r.Header.Get("Authorization") != "" {
			_, _ = w.Write([]byte(`{"errors":[{"message":"forbidden"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer srv.Close()

	// Build a client that carries an Authorization header — as would happen
	// when cfg.Headers is populated from a parsed curl file.
	clientWithAuth := transport.NewClient(5*time.Second, 100, map[string]string{
		"Authorization": "Bearer secret-token",
	})

	cc := &CheckContext{
		Target:                srv.URL,
		HTTPClient:            clientWithAuth,
		UnauthenticatedClient: transport.NewClient(5*time.Second, 100, nil),
		// Non-nil ParsedCurl signals that --curl / --curl-file was provided.
		ParsedCurl: &CurlRequest{
			Method:  "POST",
			URL:     srv.URL,
			Headers: map[string]string{"Authorization": "Bearer secret-token"},
			Body:    `{"query":"{ currentUser { name } }"}`,
		},
	}

	chk := &introspectionCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	// The probe must have reached the server without auth headers, so the
	// server returned schema data and introspection is flagged as enabled.
	require.Len(t, result.Findings, 1, "expected introspection-enabled finding when curl headers are stripped")
	assert.Equal(t, "GQL-001", result.Findings[0].CheckID)
}
