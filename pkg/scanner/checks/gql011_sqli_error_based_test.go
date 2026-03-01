package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqliStringArgSchema returns a minimal schema with one query field ("user")
// that accepts a String-typed argument ("id"), making it injectable.
func sqliStringArgSchema() *schema.Schema {
	strType := &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}
	field := &schema.FieldDef{
		Name: "user",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
		Args: []*schema.ArgDef{{Name: "id", Type: strType}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	return &schema.Schema{
		QueryType: qt,
		Types:     map[string]*schema.TypeDef{"Query": qt},
	}
}

// sqliIntArgSchema returns a schema where the only query field argument is Int-typed,
// so the check finds no injectable String arguments.
func sqliIntArgSchema() *schema.Schema {
	intType := &schema.TypeRef{Kind: schema.KindScalar, Name: "Int"}
	field := &schema.FieldDef{
		Name: "user",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
		Args: []*schema.ArgDef{{Name: "id", Type: intType}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	return &schema.Schema{
		QueryType: qt,
		Types:     map[string]*schema.TypeDef{"Query": qt},
	}
}

// TestSQLiErrorBased_SQLSTATEInErrors verifies that a GraphQL errors array
// containing "SQLSTATE" is detected and produces a HIGH finding.
func TestSQLiErrorBased_SQLSTATEInErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"SQLSTATE 42000: Syntax error near ''''"}]}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	chk := &sqliErrorBasedCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	f := result.Findings[0]
	assert.Equal(t, "GQL-011", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, Injection, f.Category)
	assert.NotEmpty(t, f.Fingerprint)
	assert.NotNil(t, f.ReproRequest)
	assert.NotNil(t, f.ReproBody)
	assert.Greater(t, result.ProbeCount, 0)
}

// TestSQLiErrorBased_ValidationErrorOnly verifies that a response containing
// only a GraphQL validation error (no database indicator) is not flagged.
func TestSQLiErrorBased_ValidationErrorOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"errors":[{"message":"Expected type String!, found Int.",` +
				`"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`,
		))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	chk := &sqliErrorBasedCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	assert.NotEmpty(t, result.PassProbes)
}

// TestSQLiErrorBased_HTTP500WithMySQL verifies that an HTTP 500 response whose
// body contains "mysql" is detected and produces a HIGH finding.
func TestSQLiErrorBased_HTTP500WithMySQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`Internal server error: mysql query failed`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	chk := &sqliErrorBasedCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	f := result.Findings[0]
	assert.Equal(t, "GQL-011", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, Injection, f.Category)
	assert.NotEmpty(t, f.Fingerprint)
}

// TestSQLiErrorBased_CleanResponse verifies that a well-formed GraphQL response
// with no error indicators produces no findings.
func TestSQLiErrorBased_CleanResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"user":{"__typename":"User"}}}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	chk := &sqliErrorBasedCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	assert.NotEmpty(t, result.PassProbes)
}

// TestSQLiErrorBased_NoInjectableArg verifies that when the schema contains no
// String-typed arguments, the check sets a pass reason and makes no HTTP probes.
func TestSQLiErrorBased_NoInjectableArg(t *testing.T) {
	probeCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probeCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliIntArgSchema()

	chk := &sqliErrorBasedCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	assert.Equal(t, 0, result.ProbeCount)
	assert.Equal(t, 0, probeCount, "no HTTP requests should be made when no injectable String args exist")
}

// TestSQLiErrorBased_Metadata verifies the check's static metadata values.
func TestSQLiErrorBased_Metadata(t *testing.T) {
	chk := &sqliErrorBasedCheck{}
	assert.Equal(t, "GQL-011", chk.ID())
	assert.Equal(t, "SQL Injection (Error-Based)", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, Injection, chk.Category())
	assert.False(t, chk.RequiresSchema())
}
