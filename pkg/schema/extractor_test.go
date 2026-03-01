package schema

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validIntrospectionResponse is a minimal but complete introspection JSON response.
const validIntrospectionResponse = `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": null,
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "Query",
          "description": "",
          "fields": [
            {
              "name": "ping",
              "description": "Health check",
              "args": [],
              "type": { "kind": "SCALAR", "name": "String", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        }
      ],
      "directives": []
    }
  }
}`

// testTimeout is the per-request timeout used in extractor tests.
const testTimeout = 10 * time.Second

func TestExtract_IntrospectionEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validIntrospectionResponse))
	}))
	defer srv.Close()

	client := transport.NewClient(10*time.Second, 100, nil)
	extractor := NewExtractor(client, testTimeout)

	result, err := extractor.Extract(context.Background(), srv.URL+"/graphql")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Schema)

	assert.Equal(t, MethodIntrospection, result.Schema.ExtractionMethod)
	assert.NotEmpty(t, result.Schema.Types)
	assert.NotNil(t, result.Schema.QueryType)

	// No fatal errors.
	for _, e := range result.Errors {
		assert.False(t, e.Fatal, "unexpected fatal error: %s", e.Message)
	}
}

func TestExtract_IntrospectionDisabled_FallsBackToSuggestions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
	}))
	defer srv.Close()

	client := transport.NewClient(10*time.Second, 100, nil)
	extractor := NewExtractor(client, testTimeout)

	result, err := extractor.Extract(context.Background(), srv.URL+"/graphql")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should fall back to field suggestion method or return partial.
	if result.Schema != nil {
		assert.True(t,
			result.Schema.ExtractionMethod == MethodFieldSuggestion ||
				result.Schema.ExtractionMethod == MethodPartial,
			"expected field_suggestion or partial, got %q", result.Schema.ExtractionMethod)
	}
}

func TestExtract_AuthRequired_NoCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := transport.NewClient(10*time.Second, 100, nil)
	extractor := NewExtractor(client, testTimeout)

	result, err := extractor.Extract(context.Background(), srv.URL+"/graphql")
	require.NoError(t, err)
	require.NotNil(t, result)

	var fatalFound bool
	for _, e := range result.Errors {
		if e.Fatal && e.Stage == "auth_probe" {
			fatalFound = true
		}
	}
	assert.True(t, fatalFound, "expected fatal ExtractionError with stage 'auth_probe'")
}

func TestExtract_AuthRequired_WithCredentials(t *testing.T) {
	const testToken = "Bearer test-token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validIntrospectionResponse))
	}))
	defer srv.Close()

	client := transport.NewClient(10*time.Second, 100, map[string]string{
		"Authorization": testToken,
	})
	extractor := NewExtractor(client, testTimeout)

	result, err := extractor.Extract(context.Background(), srv.URL+"/graphql")
	require.NoError(t, err)
	require.NotNil(t, result)

	// No fatal errors.
	for _, e := range result.Errors {
		assert.False(t, e.Fatal, "unexpected fatal error: %s", e.Message)
	}

	// Extraction should succeed.
	require.NotNil(t, result.Schema)
	assert.True(t, result.Schema.Metadata.AuthRequired)
}

func TestDiscoverEndpoint_FindsNonStandardPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)
	discovered, ok := discoverEndpoint(context.Background(), srv.URL, client)

	assert.True(t, ok, "endpoint discovery should succeed")
	assert.Contains(t, discovered, "/api/graphql")
}

func TestDiscoverEndpoint_NoneFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)
	discovered, ok := discoverEndpoint(context.Background(), srv.URL, client)

	assert.False(t, ok)
	assert.Empty(t, discovered)
}

func TestNormalizeURL_AddsSchemAndStripsTrailingSlash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com/graphql", "https://example.com/graphql"},
		{"https://example.com/graphql/", "https://example.com/graphql"},
		{"http://example.com/", "http://example.com/"},
		{"https://example.com/graphql", "https://example.com/graphql"},
	}

	for _, tc := range tests {
		got, err := normalizeURL(tc.input)
		require.NoError(t, err, "input: %s", tc.input)
		assert.Equal(t, tc.expected, got, "input: %s", tc.input)
	}
}

// TestNormalizeURL_RejectsNonHTTPSchemes verifies that ftp://, file://, and ssh://
// URLs are rejected, while http://, https://, and plain hostnames are accepted.
func TestNormalizeURL_RejectsNonHTTPSchemes(t *testing.T) {
	rejectCases := []string{
		"ftp://example.com/graphql",
		"file:///etc/passwd",
		"ssh://example.com",
		"javascript://foo",
		"data://example.com",
	}
	for _, input := range rejectCases {
		_, err := normalizeURL(input)
		assert.Error(t, err, "expected error for scheme in %q", input)
		assert.Contains(t, err.Error(), "unsupported URL scheme", "error must mention scheme for %q", input)
	}

	acceptCases := []struct {
		input string
		want  string
	}{
		{"example.com/graphql", "https://example.com/graphql"},
		{"http://example.com/graphql", "http://example.com/graphql"},
		{"https://example.com/graphql", "https://example.com/graphql"},
	}
	for _, tc := range acceptCases {
		got, err := normalizeURL(tc.input)
		assert.NoError(t, err, "expected no error for %q", tc.input)
		assert.Equal(t, tc.want, got)
	}
}

// TestDiscoverEndpoint_PrefersEarlierIndex verifies that when multiple paths respond as
// valid GraphQL endpoints, the one with the lowest index in commonGraphQLPaths is returned.
func TestDiscoverEndpoint_PrefersEarlierIndex(t *testing.T) {
	// Both /graphql (index 0) and /api/graphql (index 1) will respond with valid data.
	// The discovery must return /graphql regardless of goroutine scheduling.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/graphql", "/api/graphql":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)

	// Run multiple times to rule out luck in goroutine scheduling.
	for i := 0; i < 10; i++ {
		discovered, ok := discoverEndpoint(context.Background(), srv.URL, client)
		assert.True(t, ok, "endpoint discovery should succeed (run %d)", i)
		assert.True(t, len(discovered) > 0 && discovered[len(discovered)-len("/graphql"):] == "/graphql",
			"run %d: expected /graphql (lowest index) but got %q", i, discovered)
	}
}

func TestHasSchemaData(t *testing.T) {
	valid := json.RawMessage(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	assert.True(t, hasSchemaData(valid))

	noSchema := json.RawMessage(`{"data":{"__schema":null}}`)
	assert.False(t, hasSchemaData(noSchema))

	errors := json.RawMessage(`{"errors":[{"message":"disabled"}]}`)
	assert.False(t, hasSchemaData(errors))
}
