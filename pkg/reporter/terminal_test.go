package reporter

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gqls-cli/gqls/pkg/domain"
)

// buildRequest is a test helper that creates an *http.Request with preset headers.
func buildRequest(t *testing.T, method, rawURL string, headers map[string]string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	req := &http.Request{
		Method: method,
		URL:    u,
		Header: make(http.Header),
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestGenerateCurlCommand_RedactsAuthorizationHeader(t *testing.T) {
	req := buildRequest(t, "POST", "http://example.com/graphql", map[string]string{
		"Authorization": "Bearer super-secret-token",
		"Content-Type":  "application/json",
	})

	cmd := GenerateCurlCommand(req, []byte(`{"query":"{ __typename }"}`))

	assert.NotContains(t, cmd, "super-secret-token", "Authorization value must be redacted")
	assert.Contains(t, cmd, "[REDACTED]", "Authorization must be replaced with [REDACTED]")
	assert.Contains(t, cmd, "Content-Type", "non-sensitive headers must be preserved")
}

func TestGenerateCurlCommand_PreservesNonSensitiveHeaders(t *testing.T) {
	req := buildRequest(t, "POST", "http://example.com/graphql", map[string]string{
		"X-Request-Id": "abc-123", // net/http canonicalises header names
		"Content-Type": "application/json",
		"Accept":       "application/json",
	})

	cmd := GenerateCurlCommand(req, nil)

	// net/http canonicalises header keys (e.g. "X-Request-Id"), so check the canonical form.
	assert.Contains(t, cmd, "X-Request-Id", "X-Request-Id should be present")
	assert.Contains(t, cmd, "abc-123", "X-Request-Id value should be preserved")
	assert.Contains(t, cmd, "Content-Type", "Content-Type should be present")
	assert.Contains(t, cmd, "Accept", "Accept should be present")
}

func TestGenerateCurlCommand_NilRequest(t *testing.T) {
	cmd := GenerateCurlCommand(nil, nil)
	assert.Equal(t, "(no request captured)", cmd)
}

func TestGenerateCurlCommand_IncludesBody(t *testing.T) {
	req := buildRequest(t, "POST", "http://example.com/graphql", nil)
	body := []byte(`{"query":"{ users { id } }"}`)

	cmd := GenerateCurlCommand(req, body)

	assert.Contains(t, cmd, "--data-raw", "body should produce a --data-raw argument")
	assert.Contains(t, cmd, `{"query":"{ users { id } }"}`)
}

func TestRenderer_NoColorProducesNoANSICodes(t *testing.T) {
	var buf bytes.Buffer
	rend := NewRenderer(&buf, true /* noColor */)

	f := domain.Finding{
		CheckID:     "GQL-001",
		CheckName:   "Introspection Enabled",
		Severity:    domain.HIGH,
		Category:    domain.InformationDisclosure,
		Description: "Introspection is enabled on the endpoint.",
		Impact:      "Attackers can enumerate all types.",
		Remediation: "Disable introspection in production.",
		References:  []string{"https://owasp.org"},
	}

	require.NoError(t, rend.RenderFinding(f))

	output := buf.String()
	assert.NotEmpty(t, output)
	assert.NotContains(t, output, "\x1b[", "no ANSI escape codes when NoColor=true")
}

func TestRenderer_WithColorProducesANSICodes(t *testing.T) {
	var buf bytes.Buffer
	rend := NewRenderer(&buf, false /* noColor */)

	f := domain.Finding{
		CheckID:     "GQL-001",
		CheckName:   "Introspection Enabled",
		Severity:    domain.HIGH,
		Category:    domain.InformationDisclosure,
		Description: "Introspection is enabled.",
		Impact:      "Schema enumeration.",
		Remediation: "Disable introspection.",
	}

	require.NoError(t, rend.RenderFinding(f))

	output := buf.String()
	assert.Contains(t, output, "\x1b[", "ANSI escape codes expected when NoColor=false")
}

func TestRenderer_RenderSummary_NoColor(t *testing.T) {
	var buf bytes.Buffer
	rend := NewRenderer(&buf, true)

	result := &ScanResult{
		ChecksRun:    5,
		RequestsMade: 20,
		Findings: []domain.Finding{
			{Severity: domain.HIGH},
			{Severity: domain.MEDIUM},
			{Severity: domain.LOW},
		},
	}

	require.NoError(t, rend.RenderSummary(result))

	output := buf.String()
	assert.NotContains(t, output, "\x1b[", "no ANSI codes when NoColor=true")
	assert.Contains(t, output, "Checks run")
	assert.Contains(t, output, "Requests made")
}

func TestRenderer_RenderSummary_BarChart(t *testing.T) {
	var buf bytes.Buffer
	rend := NewRenderer(&buf, true)

	result := &ScanResult{
		ChecksRun:    3,
		RequestsMade: 9,
		Findings: []domain.Finding{
			{Severity: domain.CRITICAL},
			{Severity: domain.HIGH},
			{Severity: domain.HIGH},
		},
	}

	require.NoError(t, rend.RenderSummary(result))

	output := buf.String()
	// Block chars must appear when there are findings.
	assert.True(t,
		strings.Contains(output, "█") || strings.Contains(output, "░"),
		"bar chart should contain block characters")
}
