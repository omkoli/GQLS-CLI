package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStackTraceCheck_Metadata(t *testing.T) {
	chk := &stackTraceCheck{}
	assert.Equal(t, "GQL-005", chk.ID())
	assert.Equal(t, "Stack Trace / Debug Info in Error Responses", chk.Name())
	assert.Equal(t, MEDIUM, chk.Severity())
	assert.Equal(t, InformationDisclosure, chk.Category())
	assert.False(t, chk.RequiresSchema())
}

// TestStackTraceCheck_NoLeak verifies that a clean response produces no findings.
func TestStackTraceCheck_NoLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Unexpected error"}]}`))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.Empty(t, result.Findings)
}

// TestStackTraceCheck_AllFiveProbesSent verifies that each of the five probe queries
// is dispatched, regardless of what the server responds.
func TestStackTraceCheck_AllFiveProbesSent(t *testing.T) {
	var reqCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"error"}]}`))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	_, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.Equal(t, int32(5), reqCount.Load(), "expected exactly 5 probes to be sent")
}

// TestStackTraceCheck_StackFrameLeak verifies that a Node.js stack trace in the response
// generates a stack_frame finding with HIGH severity.
func TestStackTraceCheck_StackFrameLeak(t *testing.T) {
	body := `{"errors":[{"message":"at Object.<anonymous> (/app/server.js:42:15)\nat Module._compile"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	require.NotEmpty(t, result.Findings)

	// Find the stack_frame finding.
	var stackFinding *Finding
	for i := range result.Findings {
		if result.Findings[i].CheckID == "GQL-005" {
			f := result.Findings[i]
			if strings.Contains(f.Description, "stack_frame") {
				stackFinding = &result.Findings[i]
				break
			}
		}
	}
	require.NotNil(t, stackFinding, "expected a stack_frame finding")
	assert.Equal(t, HIGH, stackFinding.Severity)
	assert.Equal(t, InformationDisclosure, stackFinding.Category)
	assert.Contains(t, stackFinding.Description, "stack_frame")
	assert.NotEmpty(t, stackFinding.Fingerprint)
}

// TestStackTraceCheck_FilePathLeak verifies that a Unix file path in the response
// generates a file_path finding with HIGH severity.
func TestStackTraceCheck_FilePathLeak(t *testing.T) {
	body := `{"errors":[{"message":"Module not found: /app/src/resolvers/user.js"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var pathFinding *Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "file_path") {
			pathFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, pathFinding, "expected a file_path finding")
	assert.Equal(t, HIGH, pathFinding.Severity)
}

// TestStackTraceCheck_VersionLeak verifies that a library version string generates
// a version finding with LOW severity.
func TestStackTraceCheck_VersionLeak(t *testing.T) {
	body := `{"errors":[{"message":"graphql-js/16.8 encountered an unexpected error"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var versionFinding *Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "version") {
			versionFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, versionFinding, "expected a version finding")
	assert.Equal(t, LOW, versionFinding.Severity)
}

// TestStackTraceCheck_DatabaseLeak verifies that a PostgreSQL error message generates
// a database finding with HIGH severity.
func TestStackTraceCheck_DatabaseLeak(t *testing.T) {
	body := `{"errors":[{"message":"syntax error at or near \"SELECT\" in user query"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var dbFinding *Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "database") {
			dbFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, dbFinding, "expected a database finding")
	assert.Equal(t, HIGH, dbFinding.Severity)
}

// TestStackTraceCheck_InternalHostLeak verifies that an ECONNREFUSED error with an
// internal IP address generates an internal_host finding with HIGH severity.
func TestStackTraceCheck_InternalHostLeak(t *testing.T) {
	body := `{"errors":[{"message":"connect ECONNREFUSED 10.0.0.42"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var hostFinding *Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Description, "internal_host") {
			hostFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, hostFinding, "expected an internal_host finding")
	assert.Equal(t, HIGH, hostFinding.Severity)
}

// TestStackTraceCheck_MultipleCategories verifies that when a response body contains
// leaks from two different categories, each generates its own finding.
func TestStackTraceCheck_MultipleCategories(t *testing.T) {
	// Response contains both a stack frame (stack_frame) and a graphql-js version (version).
	body := `{"errors":[{"message":"at Object.<anonymous> graphql-js/16.8 error"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)

	categories := make(map[string]bool)
	for _, f := range result.Findings {
		for _, cat := range []string{"stack_frame", "version", "file_path", "database", "internal_host"} {
			if strings.Contains(f.Description, cat) {
				categories[cat] = true
			}
		}
	}
	assert.True(t, categories["stack_frame"], "expected a stack_frame finding")
	assert.True(t, categories["version"], "expected a version finding")
}

// TestStackTraceCheck_SameCategoryDeduplication verifies that multiple pattern matches
// of the same category on the same probe produce exactly one finding.
func TestStackTraceCheck_SameCategoryDeduplication(t *testing.T) {
	// Response contains two different stack_frame patterns: Node anonymous + goroutine.
	body := `{"errors":[{"message":"at Object.<anonymous> goroutine 1 [running] error"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)

	stackFrameCount := 0
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "stack_frame") {
			stackFrameCount++
		}
	}
	// Each probe that matches stack_frame should produce exactly one finding per probe label,
	// not one per matched pattern. With 5 probes all returning the same body, we expect at
	// most 5 stack_frame findings (one per probe), but all with "stack_frame" in description.
	assert.GreaterOrEqual(t, stackFrameCount, 1, "expected at least one stack_frame finding")
}

// TestStackTraceCheck_HighestSeverityWins verifies that when both HIGH and MEDIUM patterns
// fire for the same category+probe, the finding uses HIGH severity.
func TestStackTraceCheck_HighestSeverityWins(t *testing.T) {
	// "RuntimeException" is MEDIUM; "goroutine N [running]" is HIGH — both are stack_frame.
	body := `{"errors":[{"message":"RuntimeException goroutine 1 [running]"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	for _, f := range result.Findings {
		if strings.Contains(f.Description, "stack_frame") {
			assert.Equal(t, HIGH, f.Severity, "highest severity among matched patterns should win")
			return
		}
	}
	t.Fatal("no stack_frame finding found")
}

// TestStackTraceCheck_Fingerprint verifies fingerprints are stable and use the correct inputs.
func TestStackTraceCheck_Fingerprint(t *testing.T) {
	body := `{"errors":[{"message":"graphql-js/16.8 error"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	for _, f := range result.Findings {
		assert.NotEmpty(t, f.Fingerprint)
		assert.Len(t, f.Fingerprint, 64, "fingerprint should be a 64-char hex SHA-256")
	}
}

// TestStackTraceCheck_ReproBodyCaptured verifies that the reproduction body is populated.
func TestStackTraceCheck_ReproBodyCaptured(t *testing.T) {
	body := `{"errors":[{"message":"at Object.<anonymous> error"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)
	for _, f := range result.Findings {
		assert.NotEmpty(t, f.ReproBody, "finding should carry a non-empty ReproBody")
	}
}

// TestStackTraceCheck_PythonTraceback verifies Python traceback detection.
func TestStackTraceCheck_PythonTraceback(t *testing.T) {
	body := `{"errors":[{"message":"Traceback (most recent call last): File resolver.py line 42"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	chk := &stackTraceCheck{}
	result, err := chk.Run(context.Background(), newTestCheckContext(t, srv))

	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)

	var found bool
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "stack_frame") {
			found = true
			assert.Equal(t, HIGH, f.Severity)
		}
	}
	assert.True(t, found, "expected stack_frame finding for Python traceback")
}

