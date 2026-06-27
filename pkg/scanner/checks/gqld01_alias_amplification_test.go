package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAliasCheckContext creates a CheckContext pointing at srv with a high-RPS
// client and the given per-request timeout.
func newAliasCheckContext(t *testing.T, srv *httptest.Server, timeout time.Duration) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(timeout, 500, nil),
	}
}

// aliasKeyRe extracts the alias keys (the token before each ':') from a query.
var aliasKeyRe = regexp.MustCompile(`(\w+):`)

// echoAliasHandler returns a handler that reflects every alias key present in
// the incoming query back as a data object — modelling a server with no alias
// limit that executes a resolver per alias.
func echoAliasHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(body, &req)

		data := map[string]string{}
		for _, m := range aliasKeyRe.FindAllStringSubmatch(req.Query, -1) {
			data[m[1]] = "Query"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQLD01_Metadata(t *testing.T) {
	chk := &aliasAmplificationCheck{}
	assert.Equal(t, "GQL-D01", chk.ID())
	assert.Equal(t, "Alias-Based Query Amplification", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

func TestGQLD01_RegisteredInRegistry(t *testing.T) {
	var found bool
	for _, c := range All() {
		if c.ID() == "GQL-D01" {
			found = true
			break
		}
	}
	assert.True(t, found, "GQL-D01 must self-register via init()")
}

// ── Vulnerable: server executes the amplified document ─────────────────────────

func TestGQLD01_AliasesAccepted_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(echoAliasHandler())
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1, "exactly one HIGH finding expected")

	f := result.Findings[0]
	assert.Equal(t, "GQL-D01", f.CheckID)
	assert.Equal(t, "Alias-Based Query Amplification", f.CheckName)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, "No Alias Limit — Query Amplification Possible", f.Title)
	assert.GreaterOrEqual(t, result.ProbeCount, 2, "control + amplified probes")
	assert.NotEmpty(t, f.Fingerprint)
	assert.Len(t, f.Fingerprint, 64, "fingerprint must be a 64-char hex string")
	assert.Equal(t, GenerateFingerprint("GQL-D01", srv.URL, "alias_amplification"), f.Fingerprint)
	assert.NotEmpty(t, f.References)
	assert.NotEmpty(t, f.Remediation)
	assert.NotEmpty(t, f.Impact)
	assert.Contains(t, f.Description, "100", "description must state the alias count")
	assert.Contains(t, f.Description, "__typename", "description must name the field used")

	// Repro must be the amplified request body and carry the highest alias key.
	require.NotEmpty(t, f.ReproBody)
	assert.Contains(t, string(f.ReproBody), "a99", "ReproBody must be the amplified query")
	assert.NotNil(t, f.ReproRequest)
	assert.Empty(t, result.PassReason, "no PassReason when a finding fires")
}

func TestGQLD01_AmplifiedRequestCarriesAllAliases(t *testing.T) {
	var amplifiedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("a99")) {
			amplifiedBody = body
		}
		data := map[string]string{}
		for _, m := range aliasKeyRe.FindAllStringSubmatch(string(body), -1) {
			data[m[1]] = "Query"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	_, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	var parsed struct {
		Query string `json:"query"`
	}
	require.NoError(t, json.Unmarshal(amplifiedBody, &parsed))
	// Every alias key a0..a99 must be present in the document.
	for i := 0; i < aliasCount; i++ {
		assert.Contains(t, parsed.Query, "a"+strconv.Itoa(i)+":", "alias a%d must be present", i)
	}
}

// ── Protected: validation/limit rejection ──────────────────────────────────────

func TestGQLD01_TooManyAliasesError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte("a99")) {
			_, _ = io.WriteString(w, `{"errors":[{"message":"Too many aliases"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"c0":"Query"}}`)
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "alias-limit rejection must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	require.Len(t, result.PassProbes, 2, "both control and amplified probes must be recorded")
	assert.Equal(t, 2, result.ProbeCount)
}

func TestGQLD01_AmplifiedNon200_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte("a99")) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":[{"message":"query rejected"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"c0":"Query"}}`)
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "HTTP 400 on the amplified probe must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
	assert.Len(t, result.PassProbes, 2)
}

func TestGQLD01_AmplifiedMissingAliasKeys_NoFinding(t *testing.T) {
	// 200 with a data object, but the server collapsed/limited the aliases so the
	// echoed keys are incomplete — must NOT flag.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte("a99")) {
			_, _ = io.WriteString(w, `{"data":{"a0":"Query"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"c0":"Query"}}`)
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "incomplete alias echo must not produce a finding")
	assert.NotEmpty(t, result.PassReason)
}

// ── Unresponsiveness paths ─────────────────────────────────────────────────────

func TestGQLD01_AmplifiedTimesOut_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("a99")) {
			// Hang well past the client timeout for the amplified document only.
			time.Sleep(2 * time.Second)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"c0":"Query"}}`)
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	// Short client timeout so the amplified probe times out; the control is fast.
	result, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 250*time.Millisecond))

	require.NoError(t, err, "a timeout under aliasing must not surface as a Run error")
	require.Len(t, result.Findings, 1, "timeout under bounded aliasing is a positive signal")
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "unresponsive")
	assert.Equal(t, 2, result.ProbeCount)
}

func TestGQLD01_Amplified5xx_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte("a99")) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"errors":[{"message":"internal error"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"c0":"Query"}}`)
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "5xx under aliasing is a positive signal")
	assert.Equal(t, HIGH, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Description, "unresponsive")
}

// ── Control failure ─────────────────────────────────────────────────────────────

func TestGQLD01_ControlFails_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errors":[{"message":"down"}]}`)
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "a failed baseline must not produce a finding")
	assert.Contains(t, result.PassReason, "baseline")
	assert.Equal(t, 1, result.ProbeCount, "amplified probe must not be sent when control fails")
	require.Len(t, result.PassProbes, 1)
}

func TestGQLD01_ControlNetworkError_NoFinding(t *testing.T) {
	srv := httptest.NewServer(echoAliasHandler())
	target := srv.URL
	srv.Close() // close before running so the connection is refused

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), &CheckContext{
		Target:     target,
		HTTPClient: transport.NewClient(2*time.Second, 500, nil),
	})

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassReason)
	assert.Equal(t, 1, result.ProbeCount)
}

// ── Context cancellation ────────────────────────────────────────────────────────

func TestGQLD01_ContextCancelled_NoPanicNoFinding(t *testing.T) {
	srv := httptest.NewServer(echoAliasHandler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(ctx, newAliasCheckContext(t, srv, 10*time.Second))

	assert.NoError(t, err, "Run must return nil error on cancellation")
	assert.Empty(t, result.Findings, "a cancelled context must not be treated as a positive signal")
}

// ── Probe shape ─────────────────────────────────────────────────────────────────

func TestGQLD01_ProbesAreJSONPostWithContentType(t *testing.T) {
	var methods []string
	var contentTypes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
		echoAliasHandler()(w, r)
	}))
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	_, err := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))
	require.NoError(t, err)

	require.Len(t, methods, 2)
	for i := range methods {
		assert.Equal(t, http.MethodPost, methods[i])
		assert.Equal(t, "application/json", contentTypes[i])
	}
}

// ── Schema-driven field selection ───────────────────────────────────────────────

func TestGQLD01_UsesSchemaScalarField(t *testing.T) {
	var sawField bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("serverTime")) {
			sawField = true
		}
		data := map[string]string{}
		for _, m := range aliasKeyRe.FindAllStringSubmatch(string(body), -1) {
			data[m[1]] = "ok"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer srv.Close()

	cc := newAliasCheckContext(t, srv, 10*time.Second)
	cc.Schema = &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Kind: schema.KindObject,
			Fields: []*schema.FieldDef{
				{Name: "serverTime", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
			},
		},
		Types: map[string]*schema.TypeDef{},
	}

	chk := &aliasAmplificationCheck{}
	result, err := chk.Run(context.Background(), cc)
	require.NoError(t, err)

	assert.True(t, sawField, "the schema-derived scalar field must be used in the probes")
	require.Len(t, result.Findings, 1)
	assert.Contains(t, result.Findings[0].Description, "serverTime")
}

func TestGQLD01_PickAmplifiableField(t *testing.T) {
	// nil schema → __typename leaf.
	f, sel := pickAmplifiableField(nil)
	assert.Equal(t, "__typename", f)
	assert.Equal(t, "", sel)

	// A scalar field with no required args is preferred and needs no selection.
	scalarSchema := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
			{Name: "version", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
		}},
		Types: map[string]*schema.TypeDef{},
	}
	f, sel = pickAmplifiableField(scalarSchema)
	assert.Equal(t, "version", f)
	assert.Equal(t, "", sel)

	// A field with a required (NON_NULL, no default) arg is skipped in favour of
	// the next eligible scalar field.
	reqArg := &schema.ArgDef{
		Name: "id",
		Type: &schema.TypeRef{Kind: schema.KindNonNull, OfType: &schema.TypeRef{Kind: schema.KindScalar, Name: "ID"}},
	}
	skipSchema := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
			{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{reqArg}},
			{Name: "status", Type: &schema.TypeRef{Kind: schema.KindEnum, Name: "Status"}},
		}},
		Types: map[string]*schema.TypeDef{},
	}
	f, sel = pickAmplifiableField(skipSchema)
	assert.Equal(t, "status", f)
	assert.Equal(t, "", sel)

	// An object-returning field (no required args) gets a __typename sub-selection.
	objSchema := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
			{Name: "me", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}},
		}},
		Types: map[string]*schema.TypeDef{},
	}
	f, sel = pickAmplifiableField(objSchema)
	assert.Equal(t, "me", f)
	assert.Equal(t, " { __typename }", sel)

	// When every field requires an argument, fall back to __typename.
	allRequired := &schema.Schema{
		QueryType: &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
			{Name: "node", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Node"}, Args: []*schema.ArgDef{reqArg}},
		}},
		Types: map[string]*schema.TypeDef{},
	}
	f, sel = pickAmplifiableField(allRequired)
	assert.Equal(t, "__typename", f)
	assert.Equal(t, "", sel)
}

func TestGQLD01_FieldHasRequiredArg(t *testing.T) {
	def := "default"
	cases := []struct {
		name string
		arg  *schema.ArgDef
		want bool
	}{
		{"non-null no default is required", &schema.ArgDef{Type: &schema.TypeRef{Kind: schema.KindNonNull}}, true},
		{"non-null with default is optional", &schema.ArgDef{Type: &schema.TypeRef{Kind: schema.KindNonNull}, DefaultValue: &def}, false},
		{"nullable is optional", &schema.ArgDef{Type: &schema.TypeRef{Kind: schema.KindScalar}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &schema.FieldDef{Name: "x", Args: []*schema.ArgDef{tc.arg}}
			assert.Equal(t, tc.want, fieldHasRequiredArg(f))
		})
	}
}

// ── Fingerprint stability ───────────────────────────────────────────────────────

func TestGQLD01_FingerprintStable(t *testing.T) {
	srv := httptest.NewServer(echoAliasHandler())
	defer srv.Close()

	chk := &aliasAmplificationCheck{}
	r1, _ := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))
	r2, _ := chk.Run(context.Background(), newAliasCheckContext(t, srv, 10*time.Second))

	require.NotEmpty(t, r1.Findings)
	require.NotEmpty(t, r2.Findings)
	assert.Equal(t, r1.Findings[0].Fingerprint, r2.Findings[0].Fingerprint, "fingerprint must be stable across runs")
}
