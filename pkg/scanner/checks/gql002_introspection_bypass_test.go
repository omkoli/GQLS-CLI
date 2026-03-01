package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionBypassCheck_Metadata(t *testing.T) {
	chk := &introspectionBypassCheck{}
	assert.Equal(t, "GQL-002", chk.ID())
	assert.Equal(t, HIGH, chk.Severity())
	assert.False(t, chk.RequiresSchema())
	assert.Equal(t, InformationDisclosure, chk.Category())
}

// TestIntrospectionBypassCheck_BypassSucceeds verifies that when __schema is blocked but
// __type responds with data, a GQL-002 finding is generated.
func TestIntrospectionBypassCheck_BypassSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.Contains(body.Query, "__schema") {
			_, _ = w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"data":{"__type":{"name":"Query","fields":[{"name":"users","type":{"name":"UserConnection","kind":"OBJECT"}}]}}}`))
		}
	}))
	defer srv.Close()

	chk := &introspectionBypassCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "GQL-002", result.Findings[0].CheckID)
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Equal(t, InformationDisclosure, result.Findings[0].Category)
	assert.Contains(t, result.Findings[0].Description, "bypass")
	assert.Equal(t, GenerateFingerprint("GQL-002", srv.URL, "introspection_bypass_type_probe"), result.Findings[0].Fingerprint)
}

// TestIntrospectionBypassCheck_SkippedWhenFullIntrospectionEnabled verifies that GQL-002
// is skipped when full introspection is on (GQL-001 territory).
func TestIntrospectionBypassCheck_SkippedWhenFullIntrospectionEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer srv.Close()

	chk := &introspectionBypassCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Skipped)
	assert.Empty(t, result.Findings)
}

// TestIntrospectionBypassCheck_BothBlocked verifies that when both __schema and __type are
// blocked, no finding is generated.
func TestIntrospectionBypassCheck_BothBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
	}))
	defer srv.Close()

	chk := &introspectionBypassCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings, "no finding when both __schema and __type are blocked")
}

// TestIntrospectionBypassCheck_NullType verifies that a null __type response is not
// treated as a successful bypass.
func TestIntrospectionBypassCheck_NullType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.Contains(body.Query, "__schema") {
			_, _ = w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"data":{"__type":null}}`))
		}
	}))
	defer srv.Close()

	chk := &introspectionBypassCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings, "null __type should not trigger a bypass finding")
}
