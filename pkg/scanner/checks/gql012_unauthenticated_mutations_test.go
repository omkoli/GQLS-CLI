package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mutAuthObjectSchema builds a minimal schema with one mutation field ("createUser")
// that returns an object type, requiring a { __typename } sub-selection.
func mutAuthObjectSchema(target string) *schema.Schema {
	mt := &schema.TypeDef{
		Name: "Mutation",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{
				Name: "createUser",
				Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
			},
		},
	}
	return &schema.Schema{
		Endpoint:     target,
		MutationType: mt,
		Types:        map[string]*schema.TypeDef{"Mutation": mt},
	}
}

// mutAuthScalarSchema builds a minimal schema with one mutation ("deleteUser")
// that returns a scalar Boolean — no sub-selection is valid.
func mutAuthScalarSchema(target string) *schema.Schema {
	mt := &schema.TypeDef{
		Name: "Mutation",
		Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{
				Name: "deleteUser",
				Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "Boolean"},
			},
		},
	}
	return &schema.Schema{
		Endpoint:     target,
		MutationType: mt,
		Types:        map[string]*schema.TypeDef{"Mutation": mt},
	}
}

// ── Skip conditions ───────────────────────────────────────────────────────────

// TestUnauthMutations_Skipped_NoCurlMutationAndNoSchema verifies that when no
// curl mutation is available and cc.Schema is nil, the check is skipped.
func TestUnauthMutations_Skipped_NoCurlMutationAndNoSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.False(t, result.Ran)
	assert.True(t, result.Skipped)
	assert.NotEmpty(t, result.SkipReason)
	assert.Empty(t, result.Findings)
}

// TestUnauthMutations_Skipped_SchemaHasNoMutationType verifies that the check is
// skipped when a schema is present but has no mutation type defined.
func TestUnauthMutations_Skipped_SchemaHasNoMutationType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject},
	}

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.False(t, result.Ran)
	assert.True(t, result.Skipped)
	assert.NotEmpty(t, result.SkipReason)
}

// TestUnauthMutations_Skipped_CurlHasQueryNotMutation_NoSchema verifies that when
// the curl body contains a query (not a mutation) and no schema is available, the
// check is skipped.
func TestUnauthMutations_Skipped_CurlHasQueryNotMutation_NoSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.ParsedCurl = &CurlRequest{
		Method: "POST",
		URL:    srv.URL,
		Body:   `{"query":"{ users { id } }"}`,
	}

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.False(t, result.Ran)
	assert.True(t, result.Skipped)
}

// ── Auth enforced (no finding) ────────────────────────────────────────────────

// TestUnauthMutations_CurlMutation_401_AuthEnforced verifies that a 401 response
// produces no finding.
func TestUnauthMutations_CurlMutation_401_AuthEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Unauthorized"}]}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.ParsedCurl = &CurlRequest{
		Method:  "POST",
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
		Body:    `{"query":"mutation CreateUser { createUser { id } }"}`,
	}

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
}

// TestUnauthMutations_CurlMutation_403_AuthEnforced verifies that a 403 response
// produces no finding.
func TestUnauthMutations_CurlMutation_403_AuthEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.ParsedCurl = &CurlRequest{
		Method:  "POST",
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
		Body:    `{"query":"mutation DeleteAccount { deleteAccount }"}`,
	}

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
}

// TestUnauthMutations_AuthErrorMessage_NotAuthorized_Enforced verifies that an
// error message containing "not authorized" is classified as auth enforced.
func TestUnauthMutations_AuthErrorMessage_NotAuthorized_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"You are not authorized to perform this mutation"}]}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.ParsedCurl = &CurlRequest{
		Method:  "POST",
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer token"},
		Body:    `{"query":"mutation UpdateProfile { updateProfile(name: \"x\") { id } }"}`,
	}

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
}

// TestUnauthMutations_AuthErrorMessage_Forbidden_Enforced verifies that an error
// message containing "forbidden" is classified as auth enforced.
func TestUnauthMutations_AuthErrorMessage_Forbidden_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"forbidden"}]}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = mutAuthObjectSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	assert.NotEmpty(t, result.PassProbes)
}

// TestUnauthMutations_Schema_AllEnforced_401 verifies that when all schema-derived
// probes are met with 401 responses, no finding is raised and PassProbes is populated.
func TestUnauthMutations_Schema_AllEnforced_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Unauthorized"}]}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = mutAuthObjectSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	assert.NotEmpty(t, result.PassProbes)
}

// ── Auth not enforced (finding expected) ─────────────────────────────────────

// TestUnauthMutations_CurlMutation_200WithData_NotEnforced verifies that a 200
// response with a non-null data payload raises a HIGH finding and that the probe
// was sent without an Authorization header.
func TestUnauthMutations_CurlMutation_200WithData_NotEnforced(t *testing.T) {
	authHeaderReceived := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authHeaderReceived = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"createUser":{"__typename":"User","id":"1"}}}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.ParsedCurl = &CurlRequest{
		Method:  "POST",
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
		Body:    `{"query":"mutation CreateUser { createUser { id } }"}`,
	}

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.False(t, authHeaderReceived, "Authorization header must NOT be sent by GQL-012 probes")
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	f := result.Findings[0]
	assert.Equal(t, "GQL-012", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, Authentication, f.Category)
	assert.NotEmpty(t, f.Fingerprint)
	assert.NotNil(t, f.ReproRequest)
	assert.NotNil(t, f.ReproBody)
	assert.Greater(t, result.ProbeCount, 0)
}

// TestUnauthMutations_Schema_ValidationError_NotEnforced verifies that a GraphQL
// "required argument not provided" validation error signals auth is not enforced.
func TestUnauthMutations_Schema_ValidationError_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"errors":[{"message":"argument 'input' of type 'CreateUserInput!' is required, but it was not provided."}]}`,
		))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = mutAuthObjectSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	f := result.Findings[0]
	assert.Equal(t, "GQL-012", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, Authentication, f.Category)
	assert.NotEmpty(t, f.Fingerprint)
	assert.NotNil(t, f.ReproRequest)
	assert.NotNil(t, f.ReproBody)
}

// TestUnauthMutations_Schema_ScalarReturn_200WithData_NotEnforced verifies that a
// mutation returning a scalar (no sub-selection required) is probed correctly and
// a 200 response with data is flagged.
func TestUnauthMutations_Schema_ScalarReturn_200WithData_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"deleteUser":true}}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = mutAuthScalarSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "GQL-012", result.Findings[0].CheckID)
	assert.Equal(t, HIGH, result.Findings[0].Severity)
}

// TestUnauthMutations_Finding_ContainsCounts verifies that the finding description
// includes the tested count, reachable count, and example mutation name.
func TestUnauthMutations_Finding_ContainsCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"createUser":{"__typename":"User"}}}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = mutAuthObjectSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	desc := result.Findings[0].Description
	// Description must include counts and example mutation name.
	assert.Contains(t, desc, "1 of 1")
	assert.Contains(t, desc, "createUser")
}

// ── Fallthrough from curl-query to schema ─────────────────────────────────────

// TestUnauthMutations_CurlQueryBody_FallsToSchema verifies that when the curl body
// contains a query (not a mutation), the check falls through to schema-based probing.
func TestUnauthMutations_CurlQueryBody_FallsToSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.ParsedCurl = &CurlRequest{
		Method: "POST",
		URL:    srv.URL,
		Body:   `{"query":"{ currentUser { id } }"}`,
	}
	cc.Schema = mutAuthObjectSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	// 401 → auth enforced → no finding.
	assert.Empty(t, result.Findings)
}

// ── Inconclusive responses ────────────────────────────────────────────────────

// TestUnauthMutations_Inconclusive_NoFinding verifies that when all probe responses
// are inconclusive (non-JSON body, no status match), no finding is raised.
func TestUnauthMutations_Inconclusive_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = mutAuthObjectSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
}

// ── Auth header stripping ─────────────────────────────────────────────────────

// TestUnauthMutations_AuthHeadersNotForwarded verifies that GQL-012 never forwards
// Authorization headers even when cc.HTTPClient carries them.
func TestUnauthMutations_AuthHeadersNotForwarded(t *testing.T) {
	authHeaderReceived := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authHeaderReceived = true
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	clientWithAuth := transport.NewClient(5*time.Second, 100, map[string]string{
		"Authorization": "Bearer should-not-be-sent",
	})
	cc := &CheckContext{
		Target:                srv.URL,
		HTTPClient:            clientWithAuth,
		UnauthenticatedClient: transport.NewClient(5*time.Second, 100, nil),
		ParsedCurl: &CurlRequest{
			Method:  "POST",
			URL:     srv.URL,
			Headers: map[string]string{"Authorization": "Bearer should-not-be-sent"},
			Body:    `{"query":"mutation Test { testMutation { __typename } }"}`,
		},
	}

	chk := &unauthMutationsCheck{}
	_, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.False(t, authHeaderReceived, "Authorization header must NOT be forwarded by GQL-012 probes")
}

// ── Metadata ──────────────────────────────────────────────────────────────────

// TestUnauthMutations_Metadata verifies the check's static metadata.
func TestUnauthMutations_Metadata(t *testing.T) {
	chk := &unauthMutationsCheck{}
	assert.Equal(t, "GQL-012", chk.ID())
	assert.Equal(t, "Unauthenticated Access to Mutations", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, Authentication, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

// ── Unit tests for helper functions ──────────────────────────────────────────

// TestIsMutationBody verifies mutation detection in JSON request bodies.
func TestIsMutationBody(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"query":"mutation CreateUser { createUser { id } }"}`, true},
		{`{"query":"mutation { createUser { id } }"}`, true},
		{`{"query":"  mutation   Foo { bar }"}`, true},
		{`{"query":"{ currentUser { id } }"}`, false},
		{`{"query":"query GetUser { user { id } }"}`, false},
		{`not json`, false},
		{`{}`, false},
		{`{"query":""}`, false},
	}
	for _, tc := range cases {
		got := isMutationBody(tc.body)
		assert.Equal(t, tc.want, got, "isMutationBody(%q)", tc.body)
	}
}

// TestEvalMutationAuth_StatusCodes verifies status-code-based auth classification.
func TestEvalMutationAuth_StatusCodes(t *testing.T) {
	make401 := func() *transport.Response {
		return &transport.Response{StatusCode: 401, Body: []byte(`{}`)}
	}
	make403 := func() *transport.Response {
		return &transport.Response{StatusCode: 403, Body: []byte(`{}`)}
	}

	assert.Equal(t, mutAuthEnforced, evalMutationAuth(make401()))
	assert.Equal(t, mutAuthEnforced, evalMutationAuth(make403()))
}

// TestEvalMutationAuth_AuthMessages verifies auth error message classification.
func TestEvalMutationAuth_AuthMessages(t *testing.T) {
	messages := []string{
		"Unauthorized",
		"unauthenticated request",
		"not authorized to perform this action",
		"forbidden",
	}
	for _, msg := range messages {
		body, _ := json.Marshal(map[string]interface{}{
			"errors": []map[string]string{{"message": msg}},
		})
		resp := &transport.Response{StatusCode: 200, Body: body}
		assert.Equal(t, mutAuthEnforced, evalMutationAuth(resp), "message: %q", msg)
	}
}

// TestEvalMutationAuth_ValidationErrors verifies validation error classification.
func TestEvalMutationAuth_ValidationErrors(t *testing.T) {
	messages := []string{
		"argument 'input' of type 'CreateUserInput!' is required, but it was not provided.",
		"Expected type String!, found Int.",
		"Got invalid value 123; Expected type String",
		"Unknown argument \"foo\" on field \"Mutation.createUser\".",
		"cannot query field \"nonexistent\" on type \"Mutation\".",
	}
	for _, msg := range messages {
		body, _ := json.Marshal(map[string]interface{}{
			"errors": []map[string]string{{"message": msg}},
		})
		resp := &transport.Response{StatusCode: 200, Body: body}
		assert.Equal(t, mutAuthNotEnforced, evalMutationAuth(resp), "message: %q", msg)
	}
}

// TestEvalMutationAuth_MissingRequiredArgumentsMessage verifies that the
// "Field 'X' is missing required arguments: Y" message format (used by
// Shopify, graphql-ruby and others) is classified as not enforced.
func TestEvalMutationAuth_MissingRequiredArgumentsMessage(t *testing.T) {
	// Exact message from the Shopify GraphQL API.
	body := []byte(`{"errors":[{"message":"Field 'securityFindingSeverityOverride' is missing required arguments: input","locations":[{"line":1,"column":24}],"path":["mutation GQL012Probe","securityFindingSeverityOverride"],"extensions":{"code":"missingRequiredArguments","className":"Field","name":"securityFindingSeverityOverride","arguments":"input"}}]}`)
	resp := &transport.Response{StatusCode: 200, Body: body}
	assert.Equal(t, mutAuthNotEnforced, evalMutationAuth(resp))
}

// TestEvalMutationAuth_MissingRequiredArgumentsExtCode verifies that the
// extensions.code "missingRequiredArguments" field alone is sufficient to
// classify a response as not enforced, independent of the message text.
func TestEvalMutationAuth_MissingRequiredArgumentsExtCode(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{
		"errors": []map[string]interface{}{
			{
				"message": "some field validation problem",
				"extensions": map[string]string{
					"code": "missingRequiredArguments",
				},
			},
		},
	})
	resp := &transport.Response{StatusCode: 200, Body: body}
	assert.Equal(t, mutAuthNotEnforced, evalMutationAuth(resp))
}

// TestEvalMutationAuth_GraphQLValidationFailedExtCode verifies that
// extensions.code "GRAPHQL_VALIDATION_FAILED" (Apollo convention) is
// classified as not enforced.
func TestEvalMutationAuth_GraphQLValidationFailedExtCode(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{
		"errors": []map[string]interface{}{
			{
				"message": "Expected type String!, found Int.",
				"extensions": map[string]string{
					"code": "GRAPHQL_VALIDATION_FAILED",
				},
			},
		},
	})
	resp := &transport.Response{StatusCode: 200, Body: body}
	assert.Equal(t, mutAuthNotEnforced, evalMutationAuth(resp))
}

// TestUnauthMutations_Schema_MissingRequiredArgs_NotEnforced is an integration
// test using the exact Shopify-style response body that previously caused a
// false negative (was incorrectly classified as inconclusive).
func TestUnauthMutations_Schema_MissingRequiredArgs_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Field 'securityFindingSeverityOverride' is missing required arguments: input","locations":[{"line":1,"column":24}],"path":["mutation GQL012Probe","securityFindingSeverityOverride"],"extensions":{"code":"missingRequiredArguments","className":"Field","name":"securityFindingSeverityOverride","arguments":"input"}}]}`))
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = mutAuthObjectSchema(srv.URL)

	chk := &unauthMutationsCheck{}
	result, err := chk.Run(context.Background(), cc)

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1, "expected HIGH finding: server reached schema validation without auth")
	f := result.Findings[0]
	assert.Equal(t, "GQL-012", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, Authentication, f.Category)
	assert.NotEmpty(t, f.Fingerprint)
}

// TestEvalMutationAuth_DataPresent verifies that a 200 with non-null data is not enforced.
func TestEvalMutationAuth_DataPresent(t *testing.T) {
	resp := &transport.Response{
		StatusCode: 200,
		Body:       []byte(`{"data":{"createUser":{"__typename":"User"}}}`),
	}
	assert.Equal(t, mutAuthNotEnforced, evalMutationAuth(resp))
}

// TestEvalMutationAuth_DataNull verifies that data:null without other signals is inconclusive.
func TestEvalMutationAuth_DataNull(t *testing.T) {
	resp := &transport.Response{
		StatusCode: 200,
		Body:       []byte(`{"data":null,"errors":[{"message":"something unexpected"}]}`),
	}
	assert.Equal(t, mutAuthInconclusive, evalMutationAuth(resp))
}

// TestEvalMutationAuth_NonJSONBody verifies that a non-JSON body is inconclusive.
func TestEvalMutationAuth_NonJSONBody(t *testing.T) {
	resp := &transport.Response{
		StatusCode: 500,
		Body:       []byte("Internal Server Error"),
	}
	assert.Equal(t, mutAuthInconclusive, evalMutationAuth(resp))
}

// TestMutSelectionSet verifies the selection set logic for various return types.
func TestMutSelectionSet(t *testing.T) {
	s := &schema.Schema{
		Types: map[string]*schema.TypeDef{
			"User":    {Name: "User", Kind: schema.KindObject},
			"Boolean": {Name: "Boolean", Kind: schema.KindScalar},
		},
	}

	cases := []struct {
		typeRef *schema.TypeRef
		want    string
	}{
		{nil, " { __typename }"},
		{&schema.TypeRef{Kind: schema.KindObject, Name: "User"}, " { __typename }"},
		{&schema.TypeRef{Kind: schema.KindInterface, Name: "Node"}, " { __typename }"},
		{&schema.TypeRef{Kind: schema.KindUnion, Name: "SearchResult"}, " { __typename }"},
		{&schema.TypeRef{Kind: schema.KindScalar, Name: "Boolean"}, ""},
		{&schema.TypeRef{Kind: schema.KindEnum, Name: "Status"}, ""},
		// NonNull-wrapped object → Unwrap → OBJECT → needs selection.
		{
			&schema.TypeRef{
				Kind: schema.KindNonNull,
				OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
			},
			" { __typename }",
		},
		// NonNull-wrapped scalar → Unwrap → SCALAR → no selection.
		{
			&schema.TypeRef{
				Kind: schema.KindNonNull,
				OfType: &schema.TypeRef{Kind: schema.KindScalar, Name: "Boolean"},
			},
			"",
		},
	}

	for _, tc := range cases {
		got := mutSelectionSet(tc.typeRef, s)
		assert.Equal(t, tc.want, got, "TypeRef: %+v", tc.typeRef)
	}
}
