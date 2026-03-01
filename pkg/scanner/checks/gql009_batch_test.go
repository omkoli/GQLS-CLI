package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBatchCheckContext creates a CheckContext pointing at srv with a high-RPS client.
func newBatchCheckContext(t *testing.T, srv *httptest.Server) *CheckContext {
	t.Helper()
	return &CheckContext{
		Target:     srv.URL,
		HTTPClient: transport.NewClient(10*time.Second, 500, nil),
	}
}

// successBatchResponse returns a JSON array of n identical success responses.
func successBatchResponse(n int) string {
	if n == 0 {
		return "[]"
	}
	single := `{"data":{"__typename":"Query"}}`
	parts := make([]string, n)
	for i := range parts {
		parts[i] = single
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGQL009_Metadata(t *testing.T) {
	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	assert.Equal(t, "GQL-009", chk.ID())
	assert.Equal(t, "Batch Query Abuse", chk.Name())
	assert.Equal(t, HIGH, chk.Severity())
	assert.Equal(t, DenialOfService, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

// ── Happy-path: finding generated ─────────────────────────────────────────────

func TestGQL009_AllSuccess_FindingGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.Len(t, result.Findings, 1)
	f := result.Findings[0]
	assert.Equal(t, "GQL-009", f.CheckID)
	assert.Equal(t, HIGH, f.Severity)
	assert.Equal(t, DenialOfService, f.Category)
	assert.Equal(t, GenerateFingerprint("GQL-009", srv.URL, "batch_abuse"), f.Fingerprint)
}

func TestGQL009_AllSuccess_EmptyErrorsArray_FindingGenerated(t *testing.T) {
	// "errors":[] is not a failure — empty errors array must still be treated as success.
	single := `{"data":{"__typename":"Query"},"errors":[]}`
	parts := make([]string, defaultBatchSize)
	for i := range parts {
		parts[i] = single
	}
	body := "[" + strings.Join(parts, ",") + "]"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "empty errors array must not prevent finding generation")
}

// ── Pass paths: no finding ────────────────────────────────────────────────────

func TestGQL009_NonArrayResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"Batching is not supported"}]}`)
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "non-array response must not generate a finding")
	assert.NotEmpty(t, result.PassReason)
	assert.NotEmpty(t, result.PassProbes)
}

func TestGQL009_FewerResponsesThanSent_NoFinding(t *testing.T) {
	// Server returns only half the requested operations — batch size limit enforced.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize/2))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "partial response count must not generate a finding")
	assert.NotEmpty(t, result.PassReason)
	assert.Contains(t, result.PassReason, "50")
}

func TestGQL009_OneOperationHasError_NoFinding(t *testing.T) {
	// 99 successes + 1 response with a non-empty errors array.
	parts := make([]string, defaultBatchSize)
	for i := 0; i < defaultBatchSize-1; i++ {
		parts[i] = `{"data":{"__typename":"Query"}}`
	}
	parts[defaultBatchSize-1] = `{"data":null,"errors":[{"message":"rate limited"}]}`
	body := "[" + strings.Join(parts, ",") + "]"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "partial error must not generate a finding")
	assert.NotEmpty(t, result.PassReason)
}

func TestGQL009_OneOperationMissingData_NoFinding(t *testing.T) {
	// 99 successes + 1 response without a "data" key.
	parts := make([]string, defaultBatchSize)
	for i := 0; i < defaultBatchSize-1; i++ {
		parts[i] = `{"data":{"__typename":"Query"}}`
	}
	parts[defaultBatchSize-1] = `{"errors":[{"message":"unauthorized"}]}`
	body := "[" + strings.Join(parts, ",") + "]"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "missing data key must not generate a finding")
}

// ── Probe count and request structure ─────────────────────────────────────────

func TestGQL009_ProbeCountIsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Equal(t, 1, result.ProbeCount, "exactly one HTTP request must be sent")
}

func TestGQL009_RequestBodyIsJSONArray(t *testing.T) {
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	_, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))
	require.NoError(t, err)

	// Body must be a JSON array.
	var ops []json.RawMessage
	require.NoError(t, json.Unmarshal(capturedBody, &ops), "request body must be a JSON array")
	assert.Len(t, ops, defaultBatchSize, "array must contain exactly defaultBatchSize operations")

	// Every element must be a GraphQL operation with a "query" key.
	for i, op := range ops {
		var parsed map[string]string
		require.NoError(t, json.Unmarshal(op, &parsed), "element %d must be valid JSON", i)
		assert.Contains(t, parsed, "query", "element %d must contain a 'query' key", i)
		assert.Contains(t, parsed["query"], "__typename", "element %d query must be { __typename }", i)
	}
}

// ── Custom batch size ─────────────────────────────────────────────────────────

func TestGQL009_CustomBatchSize_SentAndChecked(t *testing.T) {
	const customSize = 5
	var receivedCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ops []json.RawMessage
		_ = json.Unmarshal(body, &ops)
		receivedCount = len(ops)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(customSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: customSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Equal(t, customSize, receivedCount, "server must receive exactly customSize operations")
	require.Len(t, result.Findings, 1)
	assert.Contains(t, result.Findings[0].Description, fmt.Sprintf("%d", customSize),
		"description must reference the configured batch size")
}

func TestGQL009_ZeroBatchSize_FallsBackToDefault(t *testing.T) {
	var receivedCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ops []json.RawMessage
		_ = json.Unmarshal(body, &ops)
		receivedCount = len(ops)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: 0}
	_, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Equal(t, defaultBatchSize, receivedCount, "zero batchSize must fall back to defaultBatchSize")
}

// ── Finding fields ────────────────────────────────────────────────────────────

func TestGQL009_FindingDescriptionMentionsBatchSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Contains(t, result.Findings[0].Description, fmt.Sprintf("%d", defaultBatchSize),
		"description must mention the batch size")
}

func TestGQL009_FindingImpactMentionsBatchSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Contains(t, result.Findings[0].Impact, fmt.Sprintf("%d", defaultBatchSize),
		"impact must mention the amplification factor")
}

func TestGQL009_FindingReproBodyIsValidJSONArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	f := result.Findings[0]
	require.NotEmpty(t, f.ReproBody, "ReproBody must not be empty")

	var ops []json.RawMessage
	require.NoError(t, json.Unmarshal(f.ReproBody, &ops), "ReproBody must be a valid JSON array")
	assert.Len(t, ops, defaultBatchSize)
}

func TestGQL009_FindingReferencesPopulated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.NotEmpty(t, result.Findings[0].References, "finding must include at least one reference URL")
}

func TestGQL009_FindingRemediationPopulated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.NotEmpty(t, result.Findings[0].Remediation)
}

// ── Fingerprint stability ─────────────────────────────────────────────────────

func TestGQL009_FingerprintStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	r1, _ := chk.Run(context.Background(), newBatchCheckContext(t, srv))
	r2, _ := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NotEmpty(t, r1.Findings)
	require.NotEmpty(t, r2.Findings)

	fp := GenerateFingerprint("GQL-009", srv.URL, "batch_abuse")
	assert.Len(t, fp, 64, "fingerprint must be a 64-char hex string")

	var found bool
	for _, f := range r2.Findings {
		if f.Fingerprint == fp {
			found = true
			break
		}
	}
	assert.True(t, found, "fingerprint must be stable across runs")
}

// ── PassProbes when no finding ────────────────────────────────────────────────

func TestGQL009_PassProbes_NonArrayResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"errors":[{"message":"batch not supported"}]}`)
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	require.NotEmpty(t, result.PassProbes, "PassProbes must be populated when no finding is generated")
	assert.NotEmpty(t, result.PassProbes[0].Label)
	assert.NotNil(t, result.PassProbes[0].Body)
}

func TestGQL009_PassProbes_PartialResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(1))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassProbes)
}

func TestGQL009_PassProbes_PartialErrors(t *testing.T) {
	parts := make([]string, defaultBatchSize)
	for i := 0; i < defaultBatchSize-1; i++ {
		parts[i] = `{"data":{"__typename":"Query"}}`
	}
	parts[defaultBatchSize-1] = `{"errors":[{"message":"forbidden"}]}`
	body := "[" + strings.Join(parts, ",") + "]"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))

	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.NotEmpty(t, result.PassProbes)
}

// ── Context cancellation ──────────────────────────────────────────────────────

func TestGQL009_ContextCancelled_ReturnsNoError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before Run is called

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	result, err := chk.Run(ctx, newBatchCheckContext(t, srv))

	// A pre-cancelled context causes the HTTP request to fail; the check must
	// surface this as result.Error and return nil from Run itself.
	assert.NoError(t, err, "Run must return nil error even when context is cancelled")
	assert.Empty(t, result.Findings)
}

// ── Content-Type header ───────────────────────────────────────────────────────

func TestGQL009_RequestContentTypeIsJSON(t *testing.T) {
	var capturedCT string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, successBatchResponse(defaultBatchSize))
	}))
	defer srv.Close()

	chk := &batchAbuseCheck{batchSize: defaultBatchSize}
	_, err := chk.Run(context.Background(), newBatchCheckContext(t, srv))
	require.NoError(t, err)

	assert.Equal(t, "application/json", capturedCT, "request must carry Content-Type: application/json")
}
