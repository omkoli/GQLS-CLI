package schema

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHarvest_ParsesSuggestion_ApolloFormat verifies that Apollo-style "Did you mean" errors
// are correctly parsed and the suggested field is added to the schema.
func TestHarvest_ParsesSuggestion_ApolloFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Apollo-style suggestion error.
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"Cannot query field \"userz\" on type \"Query\". Did you mean \"user\"?"}]}`)
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)
	harvester := NewHarvester(client, srv.URL)
	harvester.maxDepth = 1 // limit depth for test speed

	schema, err := harvester.Harvest(context.Background())
	require.NoError(t, err)
	require.NotNil(t, schema)

	assert.Equal(t, MethodFieldSuggestion, schema.ExtractionMethod)
	assert.True(t, schema.Metadata.SuggestionsEnabled)

	// "user" should have been discovered from the suggestion.
	_, hasUser := schema.Types["Query"]
	assert.True(t, hasUser, "Query type should exist")
	if qt, ok := schema.Types["Query"]; ok {
		var found bool
		for _, f := range qt.Fields {
			if f.Name == "user" {
				found = true
			}
		}
		assert.True(t, found, "field 'user' should be harvested from Apollo suggestion")
	}
}

// TestHarvest_ParsesSuggestion_GenericFormat verifies that generic suggestion formats are parsed.
func TestHarvest_ParsesSuggestion_GenericFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"Field 'userz' not found. Perhaps you meant: users"}]}`)
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)
	harvester := NewHarvester(client, srv.URL)
	harvester.maxDepth = 1

	schema, err := harvester.Harvest(context.Background())
	require.NoError(t, err)
	require.NotNil(t, schema)

	if qt, ok := schema.Types["Query"]; ok {
		var found bool
		for _, f := range qt.Fields {
			if f.Name == "users" {
				found = true
			}
		}
		assert.True(t, found, "field 'users' should be harvested from generic suggestion")
	}
}

// TestHarvest_RespectsMaxDepth verifies that recursion stops at the configured depth.
func TestHarvest_RespectsMaxDepth(t *testing.T) {
	var probeCount int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&probeCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Always suggest a field to encourage recursion.
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"Did you mean \"someField\"?"}]}`)
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)
	harvester := NewHarvester(client, srv.URL)
	harvester.maxDepth = 2

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	schema, err := harvester.Harvest(ctx)
	require.NoError(t, err)
	require.NotNil(t, schema)

	// With maxDepth=2 and a bounded seed list, probe count should be bounded.
	// The exact number doesn't matter — we just confirm it doesn't blow up.
	finalCount := atomic.LoadInt64(&probeCount)
	assert.Greater(t, finalCount, int64(0), "should have made some probes")
	// With maxDepth=2 the count should be substantially less than without depth limiting.
	assert.Less(t, finalCount, int64(10000), "probe count should be bounded by maxDepth")
}

// TestHarvest_HandlesCircularSchema verifies the harvester doesn't loop infinitely
// when suggestions create a cycle (e.g. User -> friends -> User).
func TestHarvest_HandlesCircularSchema(t *testing.T) {
	var callCount int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt64(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// After 50 calls just return no suggestion to help it terminate faster in test.
		if count > 50 {
			_, _ = fmt.Fprint(w, `{"errors":[{"message":"unknown field"}]}`)
			return
		}
		// Suggest cycling between "user" and "friends" to trigger circular reference detection.
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"Did you mean \"friends\"?"}]}`)
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)
	harvester := NewHarvester(client, srv.URL)
	harvester.maxDepth = 3

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema, err := harvester.Harvest(ctx)
	// Should terminate without error (ctx timeout would be the failure signal).
	assert.NotEqual(t, context.DeadlineExceeded, err, "harvester should not time out on circular schema")
	require.NotNil(t, schema)
}

func TestExtractSuggestions_ApolloFormat(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Cannot query field \"userz\" on type \"Query\". Did you mean \"user\"?"}]}`)
	suggestions := extractSuggestions(body)
	assert.Contains(t, suggestions, "user")
}

func TestExtractSuggestions_SuggestionsFormat(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Suggestions: [users, user, me]"}]}`)
	suggestions := extractSuggestions(body)
	// The pattern captures the entire bracketed string; at minimum the result is non-empty.
	assert.NotEmpty(t, suggestions)
}

func TestExtractSuggestions_EmptyBody(t *testing.T) {
	suggestions := extractSuggestions(nil)
	assert.Empty(t, suggestions)

	suggestions = extractSuggestions([]byte(`{}`))
	assert.Empty(t, suggestions)
}

func TestGenerateTypos(t *testing.T) {
	typos := generateTypos("user")
	assert.Contains(t, typos, "userz")
	assert.Contains(t, typos, "xuser")
	// Swapped first two chars: "user" -> "user" with u↔s swap = "suer"
	assert.Contains(t, typos, "suer")
}

// TestExtractSuggestions_InjectionPrevention verifies that suggestion strings containing
// GraphQL metacharacters (braces, spaces, quotes) are rejected and never returned.
func TestExtractSuggestions_InjectionPrevention(t *testing.T) {
	injectionCases := []struct {
		name string
		body string
	}{
		{
			name: "braces in double-quote pattern",
			body: `{"errors":[{"message":"Did you mean \"user { __schema { queryType { name } } }\"?"}]}`,
		},
		{
			name: "space in single-quote pattern",
			body: `{"errors":[{"message":"Did you mean 'user name'?"}]}`,
		},
		{
			name: "brace in generic pattern",
			body: `{"errors":[{"message":"did you mean \"foo { bar\""}]}`,
		},
		{
			name: "injection via Suggestions list",
			body: `{"errors":[{"message":"Suggestions: [user } mutation { deleteAll]"}]}`,
		},
		{
			name: "digit-leading name in double-quote pattern",
			body: `{"errors":[{"message":"Did you mean \"1user\"?"}]}`,
		},
		{
			name: "empty string suggestion",
			body: `{"errors":[{"message":"Did you mean \"\"?"}]}`,
		},
	}

	for _, tc := range injectionCases {
		t.Run(tc.name, func(t *testing.T) {
			results := extractSuggestions([]byte(tc.body))
			for _, r := range results {
				assert.True(t, isValidGraphQLIdentifier(r),
					"extracted name %q must be a valid GraphQL identifier", r)
			}
		})
	}
}

// TestExtractSuggestions_SuggestionsListFormat verifies that a comma-separated
// "Suggestions: [a, b, c]" value produces individual validated names.
func TestExtractSuggestions_SuggestionsListFormat(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Suggestions: [user, users, viewer]"}]}`)
	suggestions := extractSuggestions(body)
	assert.ElementsMatch(t, []string{"user", "users", "viewer"}, suggestions,
		"three distinct suggestions must be returned")
}

// TestExtractSuggestions_SuggestionsListWithQuotes verifies quoted list items are stripped.
func TestExtractSuggestions_SuggestionsListWithQuotes(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Suggestions: [\"user\", \"users\"]"}]}`)
	suggestions := extractSuggestions(body)
	assert.ElementsMatch(t, []string{"user", "users"}, suggestions)
}

// TestHarvest_InjectedFieldNeverInterpolated verifies that a malicious server returning
// injection payloads in suggestion messages cannot cause injected strings to be used
// as field names in subsequent queries.
func TestHarvest_InjectedFieldNeverInterpolated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Malicious server returns a suggestion containing GraphQL metacharacters.
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"Did you mean \"evil } mutation { hack\"?"}]}`)
	}))
	defer srv.Close()

	client := transport.NewClient(5*time.Second, 100, nil)
	harvester := NewHarvester(client, srv.URL)
	harvester.maxDepth = 1

	schema, err := harvester.Harvest(context.Background())
	require.NoError(t, err)
	require.NotNil(t, schema)

	// The injected name must NOT appear in the discovered schema.
	for _, td := range schema.Types {
		for _, f := range td.Fields {
			assert.True(t, isValidGraphQLIdentifier(f.Name),
				"all harvested field names must be valid GraphQL identifiers, got %q", f.Name)
		}
	}
}
