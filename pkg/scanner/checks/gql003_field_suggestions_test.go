package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldSuggestionsCheck_Metadata(t *testing.T) {
	chk := &fieldSuggestionsCheck{}
	assert.Equal(t, "GQL-003", chk.ID())
	assert.Equal(t, MEDIUM, chk.Severity())
	assert.False(t, chk.RequiresSchema())
	assert.Equal(t, InformationDisclosure, chk.Category())
}

// TestFieldSuggestionsCheck_SuggestionsLeaked verifies that when introspection is disabled
// but the server returns suggestion error messages, a GQL-003 finding is generated.
func TestFieldSuggestionsCheck_SuggestionsLeaked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Simulate a server with introspection disabled but suggestions enabled.
		// The __schema probe returns an error; typo probes return a single-suggestion message.
		_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"userz\" on type \"Query\". Did you mean \"user\"?"}]}`))
	}))
	defer srv.Close()

	chk := &fieldSuggestionsCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "GQL-003", result.Findings[0].CheckID)
	assert.Equal(t, MEDIUM, result.Findings[0].Severity)
	assert.Equal(t, InformationDisclosure, result.Findings[0].Category)
	assert.Contains(t, result.Findings[0].Description, "Did you mean")
	assert.Equal(t, GenerateFingerprint("GQL-003", srv.URL, "field_suggestions_enabled"), result.Findings[0].Fingerprint)
}

// TestFieldSuggestionsCheck_NoSuggestions verifies that no finding is generated when the
// server returns generic errors without suggestion messages.
func TestFieldSuggestionsCheck_NoSuggestions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Field not found"}]}`))
	}))
	defer srv.Close()

	chk := &fieldSuggestionsCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
}

// TestFieldSuggestionsCheck_SkippedWhenIntrospectionEnabled verifies that GQL-003 is
// skipped when full introspection is on, since GQL-001 already covers that case.
func TestFieldSuggestionsCheck_SkippedWhenIntrospectionEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer srv.Close()

	chk := &fieldSuggestionsCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Skipped)
	assert.Empty(t, result.Findings)
}

// TestFieldSuggestionsCheck_SuggestionVariants verifies all supported suggestion message
// formats are recognised.
func TestFieldSuggestionsCheck_SuggestionVariants(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    string
	}{
		{"double-quote did-you-mean", `Did you mean "users"?`, "users"},
		{"single-quote did-you-mean", `Did you mean 'orders'?`, "orders"},
		{"lowercase did-you-mean", `did you mean "profile"`, "profile"},
		{"perhaps-you-meant", `Perhaps you meant: viewer`, "viewer"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use json.Marshal to correctly encode the message string so that
			// any double quotes inside are properly escaped in the JSON payload.
			msgJSON, err := json.Marshal(tc.message)
			require.NoError(t, err)
			body := []byte(`{"errors":[{"message":` + string(msgJSON) + `}]}`)
			suggestions := extractFieldSuggestions(body)
			require.Len(t, suggestions, 1)
			assert.Equal(t, tc.want, suggestions[0])
		})
	}
}

// TestFieldSuggestionsCheck_FindingContainsFieldNames verifies that discovered field names
// appear in the finding description.
func TestFieldSuggestionsCheck_FindingContainsFieldNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field. Did you mean \"admin\"?"}]}`))
	}))
	defer srv.Close()

	chk := &fieldSuggestionsCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Contains(t, result.Findings[0].Description, "admin")
}
