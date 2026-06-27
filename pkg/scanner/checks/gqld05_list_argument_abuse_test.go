package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPaginationCheckContext creates a CheckContext (with the given schema)
// pointing at srv with a high-RPS client and timeout.
func newPaginationCheckContext(t *testing.T, srv *httptest.Server, sc *schema.Schema, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		Schema:     sc,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

// listField builds a Query field returning [<elemType>] with an Int pagination arg.
func listField(name, argName, elemType string) *schema.FieldDef {
	return &schema.FieldDef{
		Name: name,
		Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: elemType}},
		Args: []*schema.ArgDef{
			{Name: argName, Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "Int"}},
		},
	}
}

// paginationSchema builds a schema whose Query type exposes the given fields,
// plus a User object type used as the list element.
func paginationSchema(fields ...*schema.FieldDef) *schema.Schema {
	return &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: fields},
		Types: map[string]*schema.TypeDef{
			"User": {Name: "User", Kind: schema.KindObject},
			"Post": {Name: "Post", Kind: schema.KindObject},
		},
	}
}

var firstValueRe = regexp.MustCompile(`\b(?:first|last|limit|count|take|pageSize|perPage|size)\s*:\s*(\d+)`)
var queryFieldRe = regexp.MustCompile(`query \{ (\w+)\(`)

// requestedPageSize extracts the integer pagination value from a request body.
func requestedPageSize(body []byte) int {
	m := firstValueRe.FindSubmatch(body)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// scalingItemsHandler echoes a data object containing as many {"__typename":"User"}
// items as the requested page size — modelling a server with no max page size.
func scalingItemsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := requestedPageSize(body)
		items := strings.Repeat(`{"__typename":"User"},`, n)
		items = strings.TrimSuffix(items, ",")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"items":[%s]}}`, items)
	}
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD05_Metadata(t *testing.T) {
	chk := &listArgumentAbuseCheck{}
	assert.Equal(t, "GQL-D05", chk.ID())
	assert.Equal(t, "Unbounded List/Pagination Argument", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.True(t, chk.RequiresSchema(), "GQL-D05 requires a schema")
}

func TestGQLD05_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D05" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D05 must self-register via init()")
}

// ── Vulnerable: large page honored ─────────────────────────────────────────────

func TestGQLD05_UnboundedPagination_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(scalingItemsHandler())
	defer srv.Close()

	sc := paginationSchema(listField("users", "first", "User"))
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "one HIGH finding expected for the unbounded field")

	f := result.Findings[0]
	assert.Equal(t, "GQL-D05", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Contains(t, f.Title, `"users"`, "title must name the field")
	assert.Contains(t, f.Title, `"first"`, "title must name the arg")
	assert.GreaterOrEqual(t, result.ProbeCount, 2)
	assert.Len(t, f.Fingerprint, 64)
	assert.Equal(t, GenerateFingerprint("GQL-D05", srv.URL, "pagination_users"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.Contains(t, f.Description, "10000")
	require.NotEmpty(t, f.ReproBody)
	assert.Contains(t, string(f.ReproBody), "10000", "ReproBody must be the abuse query")
	assert.Empty(t, result.PassReason)
}

// ── Protected: max-page rejection ──────────────────────────────────────────────

func TestGQLD05_MaxPageEnforced_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if requestedPageSize(body) > 100 {
			_, _ = io.WriteString(w, `{"errors":[{"message":"first must be less than 100"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"items":[{"__typename":"User"}]}}`)
	}))
	defer srv.Close()

	sc := paginationSchema(listField("users", "first", "User"))
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a max-page rejection must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	require.NotEmpty(t, result.PassProbes, "both probes must be recorded for the protected field")
}

func TestGQLD05_SilentClamp_NoFinding(t *testing.T) {
	// Server silently clamps first:10000 to 100 items — it enforced a limit, so
	// the near-max returned-count signal must not fire (no false positive).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := requestedPageSize(body)
		if n > 100 {
			n = 100
		}
		items := strings.TrimSuffix(strings.Repeat(`{"__typename":"User"},`, n), ",")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"items":[%s]}}`, items)
	}))
	defer srv.Close()

	sc := paginationSchema(listField("users", "first", "User"))
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a silently clamped page must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
}

// ── Candidate selection bounded to 2 ───────────────────────────────────────────

func TestGQLD05_CandidatesBoundedToTwo(t *testing.T) {
	var mu = make(chan string, 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if m := queryFieldRe.FindSubmatch(body); m != nil {
			mu <- string(m[1])
		}
		// Return a small, non-scaling page so no finding fires.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"items":[{"__typename":"User"}]}}`)
	}))
	defer srv.Close()

	sc := paginationSchema(
		listField("users", "first", "User"),
		listField("posts", "limit", "Post"),
		listField("comments", "first", "User"),
		listField("tags", "first", "User"),
	)
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 10*time.Second))
	require.NoError(t, err)

	close(mu)
	seen := map[string]bool{}
	for name := range mu {
		seen[name] = true
	}

	assert.Equal(t, 4, result.ProbeCount, "exactly 2 candidates × 2 probes = 4 requests")
	assert.Len(t, seen, 2, "only the first 2 schema-order candidates must be probed")
	assert.True(t, seen["users"] && seen["posts"], "the first two list fields must be the ones probed")
}

// ── Distinct per-field fingerprints ────────────────────────────────────────────

func TestGQLD05_PerFieldFindingsHaveDistinctFingerprints(t *testing.T) {
	srv := httptest.NewServer(scalingItemsHandler())
	defer srv.Close()

	sc := paginationSchema(
		listField("users", "first", "User"),
		listField("posts", "limit", "Post"),
	)
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 2, "both unbounded fields must fire")
	assert.NotEqual(t, result.Findings[0].Fingerprint, result.Findings[1].Fingerprint,
		"each field must carry a distinct fingerprint")

	titles := result.Findings[0].Title + "|" + result.Findings[1].Title
	assert.Contains(t, titles, `"users"`)
	assert.Contains(t, titles, `"posts"`)
}

// ── Unresponsiveness ────────────────────────────────────────────────────────────

func TestGQLD05_AbuseTimesOut_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if requestedPageSize(body) > 100 {
			time.Sleep(2 * time.Second) // hang on the large page only
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"items":[{"__typename":"User"}]}}`)
	}))
	defer srv.Close()

	sc := paginationSchema(listField("users", "first", "User"))
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 250*time.Millisecond))

	require.NoError(t, err, "a timeout on the abuse probe must not surface as a Run error")
	require.Len(t, result.Findings, 1)
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "time out")
}

// ── No paginated fields / nil schema ───────────────────────────────────────────

func TestGQLD05_NoPaginatedFields_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	// A non-list field, and a list field without a recognized pagination arg.
	sc := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
			{Name: "me", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}},
			{Name: "tags", Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}}},
		}},
		Types: map[string]*schema.TypeDef{"User": {Name: "User", Kind: schema.KindObject}},
	}
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.Contains(t, result.PassReason, "No list fields")
	assert.Equal(t, 0, result.ProbeCount, "no probes when no candidates exist")
}

func TestGQLD05_NilSchema_NoPanic(t *testing.T) {
	chk := &listArgumentAbuseCheck{}
	require.NotPanics(t, func() {
		result, err := chk.Run(context.Background(), &CheckContext{
			Target:     "http://127.0.0.1:0",
			HTTPClient: transport.NewClient(time.Second, 500, nil),
		})
		require.NoError(t, err)
		assert.Empty(t, result.Findings)
		assert.Equal(t, 0, result.ProbeCount)
		assert.NotEmpty(t, result.PassReason)
	})
}

// ── Control failure ─────────────────────────────────────────────────────────────

func TestGQLD05_ControlFails_FieldSkipped(t *testing.T) {
	// The field requires another argument, so the control (first:1) errors and the
	// field is skipped without a finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":[{"message":"argument \"org\" of type \"ID!\" is required"}]}`)
	}))
	defer srv.Close()

	sc := paginationSchema(listField("users", "first", "User"))
	chk := &listArgumentAbuseCheck{}
	result, err := chk.Run(context.Background(), newPaginationCheckContext(t, srv, sc, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a field whose control errors must be skipped, not flagged")
	assert.Equal(t, 1, result.ProbeCount, "abuse probe must not be sent when the control fails")
	assert.NotEmpty(t, result.PassReason)
}

// ── Candidate detection unit tests ─────────────────────────────────────────────

func TestGQLD05_FindPaginationCandidates(t *testing.T) {
	// nil schema → no candidates, no panic.
	assert.Empty(t, findPaginationCandidates(nil, 2))

	// Plain object list with an Int "first" arg → candidate with __typename selection.
	sc := paginationSchema(listField("users", "first", "User"))
	cands := findPaginationCandidates(sc, 2)
	require.Len(t, cands, 1)
	assert.Equal(t, "users", cands[0].field)
	assert.Equal(t, "first", cands[0].arg)
	assert.Equal(t, "{ __typename }", cands[0].selection)

	// A non-integer pagination arg is ignored.
	strArg := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{{
			Name: "users",
			Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}},
			Args: []*schema.ArgDef{{Name: "first", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}}},
		}}},
		Types: map[string]*schema.TypeDef{"User": {Name: "User", Kind: schema.KindObject}},
	}
	assert.Empty(t, findPaginationCandidates(strArg, 2), "non-Int pagination arg must not be a candidate")

	// Scalar list ([String]) → leaf selection "".
	scalarList := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{{
			Name: "names",
			Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
			Args: []*schema.ArgDef{{Name: "limit", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "Int"}}},
		}}},
	}
	cands = findPaginationCandidates(scalarList, 2)
	require.Len(t, cands, 1)
	assert.Equal(t, "", cands[0].selection)
}

func TestGQLD05_ConnectionFieldDetected(t *testing.T) {
	// search: UserConnection (object) with edges: [UserEdge] → connection candidate.
	sc := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{{
			Name: "search",
			Type: &schema.TypeRef{Kind: schema.KindObject, Name: "UserConnection"},
			Args: []*schema.ArgDef{{Name: "first", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "Int"}}},
		}}},
		Types: map[string]*schema.TypeDef{
			"UserConnection": {Name: "UserConnection", Kind: schema.KindObject, Fields: []*schema.FieldDef{
				{Name: "edges", Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "UserEdge"}}},
			}},
			"UserEdge": {Name: "UserEdge", Kind: schema.KindObject},
		},
	}
	cands := findPaginationCandidates(sc, 2)
	require.Len(t, cands, 1)
	assert.Equal(t, "search", cands[0].field)
	assert.Equal(t, "{ edges { __typename } }", cands[0].selection)
}
