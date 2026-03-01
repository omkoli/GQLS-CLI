package reporter

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gqls-cli/gqls/pkg/domain"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func minimalScanResult() *ScanResult {
	return &ScanResult{
		ChecksRun:    1,
		Duration:     5 * time.Second,
		RequestsMade: 3,
		StartTime:    time.Date(2024, 1, 15, 10, 32, 44, 0, time.UTC),
	}
}

func buildFinding(checkID, checkName string, sev domain.Severity, withRepro bool) domain.Finding {
	f := domain.Finding{
		CheckID:     checkID,
		CheckName:   checkName,
		Title:       checkName,
		Severity:    sev,
		Category:    domain.InformationDisclosure,
		Description: "A security issue was discovered at the target endpoint.",
		Impact:      "An attacker can exploit this to gain unauthorised access.",
		Remediation: "Disable this feature in your production configuration.",
		References:  []string{"https://owasp.org/www-project-top-ten/"},
	}
	if withRepro {
		u, _ := url.Parse("https://api.example.com/graphql")
		f.ReproRequest = &http.Request{
			Method: "POST",
			URL:    u,
			Header: make(http.Header),
		}
		f.ReproRequest.Header.Set("Content-Type", "application/json")
		f.ReproBody = []byte(`{"query":"{ __typename }"}`)
	}
	return f
}

// ── TestTXTRenderer_Header_ContainsTarget ────────────────────────────────────

func TestTXTRenderer_Header_ContainsTarget(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	target := "https://api.example.com/graphql"

	require.NoError(t, r.RenderReport(target, result))

	out := buf.String()
	assert.Contains(t, out, target, "output must contain the target URL")
	assert.Contains(t, out, "GQLS SECURITY SCAN REPORT", "output must contain the report title")
}

// ── TestTXTRenderer_Header_SchemaNotAvailable ────────────────────────────────

func TestTXTRenderer_Header_SchemaNotAvailable(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	result.Schema = nil

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	assert.Contains(t, buf.String(), "Not available")
}

// ── TestTXTRenderer_Header_SummaryCountsCorrect ──────────────────────────────

func TestTXTRenderer_Header_SummaryCountsCorrect(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	result.Findings = []domain.Finding{
		buildFinding("GQL-001", "Check One", domain.HIGH, false),
		buildFinding("GQL-002", "Check Two", domain.HIGH, false),
		buildFinding("GQL-003", "Check Three", domain.MEDIUM, false),
	}

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	out := buf.String()
	assert.Contains(t, out, "HIGH      2", "HIGH count must be 2")
	assert.Contains(t, out, "MEDIUM    1", "MEDIUM count must be 1")
	assert.Contains(t, out, "TOTAL     3", "TOTAL must be 3")
}

// ── TestTXTRenderer_TOC_SortedBySeverity ────────────────────────────────────

func TestTXTRenderer_TOC_SortedBySeverity(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	result.Findings = []domain.Finding{
		buildFinding("GQL-002", "Medium Check", domain.MEDIUM, false),
		buildFinding("GQL-001", "High Check", domain.HIGH, false),
		buildFinding("GQL-005", "Info Check", domain.INFO, false),
	}

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	out := buf.String()
	// Find positions of the check IDs in the TOC to verify ordering.
	posHigh := strings.Index(out, "GQL-001")
	posMedium := strings.Index(out, "GQL-002")
	posInfo := strings.Index(out, "GQL-005")

	assert.Less(t, posHigh, posMedium, "HIGH finding must appear before MEDIUM in output")
	assert.Less(t, posMedium, posInfo, "MEDIUM finding must appear before INFO in output")

	// Verify #1 is the HIGH finding.
	idxLine := findLineWith(out, "GQL-001")
	assert.Contains(t, idxLine, " 1 ", "GQL-001 (HIGH) must be #1 in the TOC")
}

// ── TestTXTRenderer_Finding_NoReproWhenNoRequest ─────────────────────────────

func TestTXTRenderer_Finding_NoReproWhenNoRequest(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	result.Findings = []domain.Finding{
		buildFinding("GQL-006", "Schema Check", domain.INFO, false /* no repro */),
	}

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	assert.NotContains(t, buf.String(), "REPRODUCE", "REPRODUCE section must be absent when no ReproRequest")
}

// ── TestTXTRenderer_Finding_ReproRedactsAuth ─────────────────────────────────

func TestTXTRenderer_Finding_ReproRedactsAuth(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	f := buildFinding("GQL-001", "Introspection", domain.HIGH, true /* with repro */)
	f.ReproRequest.Header.Set("Authorization", "Bearer secret123")
	result.Findings = []domain.Finding{f}

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	out := buf.String()
	assert.Contains(t, out, "[REDACTED]", "Authorization header must be redacted")
	assert.NotContains(t, out, "secret123", "secret token must not appear in output")
}

// ── TestTXTRenderer_WordWrap_BreaksAtWordBoundary ────────────────────────────

func TestTXTRenderer_WordWrap_BreaksAtWordBoundary(t *testing.T) {
	input := "the quick brown fox jumped over the lazy dog"
	wrapped := wordWrap(input, 20)

	for _, line := range strings.Split(wrapped, "\n") {
		assert.LessOrEqual(t, len(line), 20, "no line should exceed 20 characters: %q", line)
	}

	// Verify no word is split mid-word: every word in input must appear intact.
	for _, word := range strings.Fields(input) {
		assert.Contains(t, wrapped, word, "word %q must appear intact", word)
	}
}

// ── TestTXTRenderer_WordWrap_PreservesCodeLines ──────────────────────────────

func TestTXTRenderer_WordWrap_PreservesCodeLines(t *testing.T) {
	codeLine := "    const x = 1;"
	input := "prose line\n" + codeLine
	wrapped := wordWrap(input, 10)

	assert.Contains(t, wrapped, codeLine, "code line starting with 4 spaces must pass through unchanged")
}

// ── TestTXTRenderer_WordWrap_PreservesParagraphBreaks ────────────────────────

func TestTXTRenderer_WordWrap_PreservesParagraphBreaks(t *testing.T) {
	input := "first paragraph\n\nsecond paragraph"
	wrapped := wordWrap(input, 80)

	assert.Contains(t, wrapped, "\n\n", "double newline paragraph break must be preserved")

	parts := strings.Split(wrapped, "\n\n")
	require.Len(t, parts, 2)
	assert.Contains(t, parts[0], "first paragraph")
	assert.Contains(t, parts[1], "second paragraph")
}

// ── TestTXTRenderer_SkippedChecks_RenderedWhenPresent ────────────────────────

func TestTXTRenderer_SkippedChecks_RenderedWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	result.CheckResults = []domain.CheckResult{
		{
			CheckID:    "GQL-006",
			Skipped:    true,
			SkipReason: "schema unavailable",
		},
	}

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	out := buf.String()
	assert.Contains(t, out, "SKIPPED CHECKS", "skipped checks section must appear")
	assert.Contains(t, out, "GQL-006", "skipped check ID must appear")
	assert.Contains(t, out, "schema unavailable", "skip reason must appear")
}

// ── TestTXTRenderer_SkippedChecks_NotRenderedWhenNone ────────────────────────

func TestTXTRenderer_SkippedChecks_NotRenderedWhenNone(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	result.CheckResults = []domain.CheckResult{
		{CheckID: "GQL-001", Ran: true, Skipped: false},
	}

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	assert.NotContains(t, buf.String(), "SKIPPED CHECKS", "skipped checks section must be absent")
}

// ── TestTXTRenderer_Footer_ContainsReportID ──────────────────────────────────

func TestTXTRenderer_Footer_ContainsReportID(t *testing.T) {
	target := "https://api.example.com/graphql"
	startTime := time.Date(2024, 1, 15, 10, 32, 44, 0, time.UTC)

	result := &ScanResult{StartTime: startTime}

	var buf1 bytes.Buffer
	r1 := NewTXTRenderer(&buf1)
	require.NoError(t, r1.RenderReport(target, result))

	var buf2 bytes.Buffer
	r2 := NewTXTRenderer(&buf2)
	require.NoError(t, r2.RenderReport(target, result))

	id1 := extractReportID(buf1.String())
	id2 := extractReportID(buf2.String())

	assert.NotEmpty(t, id1, "report ID must be non-empty")
	assert.Equal(t, id1, id2, "report ID must be deterministic for same target and start time")
}

// ── TestTXTRenderer_Footer_ContainsVersion ───────────────────────────────────

func TestTXTRenderer_Footer_ContainsVersion(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	require.NoError(t, r.RenderReport("https://example.com/gql", minimalScanResult()))
	assert.Contains(t, buf.String(), "Generated by gqls")
}

// ── TestTXTRenderer_NoAnsiCodes ──────────────────────────────────────────────

func TestTXTRenderer_NoAnsiCodes(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRenderer(&buf)
	result := minimalScanResult()
	result.Findings = []domain.Finding{
		buildFinding("GQL-001", "Critical Finding", domain.CRITICAL, true),
		buildFinding("GQL-002", "High Finding", domain.HIGH, false),
		buildFinding("GQL-003", "Medium Finding", domain.MEDIUM, false),
		buildFinding("GQL-004", "Low Finding", domain.LOW, false),
		buildFinding("GQL-005", "Info Finding", domain.INFO, false),
	}

	require.NoError(t, r.RenderReport("https://example.com/gql", result))

	assert.NotContains(t, buf.String(), "\x1b[", "txt output must never contain ANSI escape codes")
}

// ── TestTXTRenderer_Width_RespectsCustomWidth ────────────────────────────────

func TestTXTRenderer_Width_RespectsCustomWidth(t *testing.T) {
	var buf bytes.Buffer
	r := NewTXTRendererWithWidth(&buf, 120)
	require.NoError(t, r.RenderReport("https://example.com/gql", minimalScanResult()))

	out := buf.String()
	// Separator lines must be 120 characters wide.
	assert.Contains(t, out, strings.Repeat("=", 120), "separator must be 120 chars wide")
	assert.NotContains(t, out, strings.Repeat("=", 121), "separator must not exceed 120 chars")
}

// ── TestReporterFactory_UnknownFormat_ReturnsError ───────────────────────────

func TestReporterFactory_UnknownFormat_ReturnsError(t *testing.T) {
	rep, err := New("xml", os.Stdout, false, "dev")
	assert.Nil(t, rep, "reporter must be nil for unknown format")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xml", "error must mention the unknown format")
	assert.Contains(t, err.Error(), "terminal", "error must list valid formats")
}

// ── TestReporterFactory_AllFormats_Instantiate ───────────────────────────────

func TestReporterFactory_AllFormats_Instantiate(t *testing.T) {
	formats := []string{"terminal", "txt", "json", "sarif"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			rep, err := New(format, &buf, false, "dev")
			require.NoError(t, err, "New must not error for format %q", format)
			assert.NotNil(t, rep, "reporter must not be nil for format %q", format)
		})
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// findLineWith returns the first line in text that contains substr.
func findLineWith(text, substr string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

// extractReportID finds the "Report ID: <id>" line and returns the id value.
func extractReportID(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Report ID:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
