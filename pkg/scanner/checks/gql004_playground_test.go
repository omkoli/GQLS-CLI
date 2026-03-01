package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlaygroundCheck_GraphiQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div id="graphiql">Loading GraphiQL...</div></body></html>`))
	}))
	defer srv.Close()

	chk := &playgroundCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "GQL-004", result.Findings[0].CheckID)
	assert.Equal(t, MEDIUM, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "GraphiQL")
}

func TestPlaygroundCheck_ApolloSandbox(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script src="https://embeddable-sandbox.api.apollographql.com/embeddable-sandbox/v2/..."></script></body></html>`))
	}))
	defer srv.Close()

	chk := &playgroundCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Contains(t, result.Findings[0].Description, "Apollo Sandbox")
}

func TestPlaygroundCheck_NothingExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer srv.Close()

	chk := &playgroundCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "no finding when no playground signatures present")
}

func TestPlaygroundCheck_Metadata(t *testing.T) {
	chk := &playgroundCheck{}
	assert.Equal(t, "GQL-004", chk.ID())
	assert.Equal(t, MEDIUM, chk.Severity())
	assert.False(t, chk.RequiresSchema())
	assert.Equal(t, InformationDisclosure, chk.Category())
}

func TestPlaygroundCheck_MultiplePlaygroundsReported(t *testing.T) {
	// A page embedding both GraphiQL and Apollo Sandbox should produce a finding for each.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<div id="graphiql">Loading GraphiQL...</div>
			<script src="https://embeddable-sandbox.api.apollographql.com/embeddable-sandbox/v2/..."></script>
		</body></html>`))
	}))
	defer srv.Close()

	chk := &playgroundCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 2, "both GraphiQL and Apollo Sandbox should be reported")
	names := []string{result.Findings[0].Description, result.Findings[1].Description}
	assert.True(t, containsSubstring(names, "GraphiQL"), "GraphiQL finding expected")
	assert.True(t, containsSubstring(names, "Apollo Sandbox"), "Apollo Sandbox finding expected")
}

func containsSubstring(strs []string, sub string) bool {
	for _, s := range strs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestPlaygroundCheck_CaseInsensitive(t *testing.T) {
	// Ensure matching works regardless of HTML casing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><title>GraphQL Playground</title></html>`))
	}))
	defer srv.Close()

	chk := &playgroundCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
}
