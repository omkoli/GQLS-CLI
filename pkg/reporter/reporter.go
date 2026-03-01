// Package reporter contains output formatters for scan results.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gqls-cli/gqls/pkg/domain"
	"github.com/gqls-cli/gqls/pkg/schema"
)

// ScanResult holds aggregated output from a complete scan run.
type ScanResult struct {
	// ChecksRun is the number of checks that were executed.
	ChecksRun int
	// Duration is the total wall-clock time of the scan.
	Duration time.Duration
	// RequestsMade is the total number of HTTP requests sent.
	RequestsMade int
	// StartTime is when the scan began.
	StartTime time.Time
	// Findings contains every finding from every check.
	Findings []domain.Finding
	// Schema is the extracted GraphQL schema (may be nil).
	Schema *schema.Schema
	// CheckResults contains individual check outcomes, including skipped checks.
	CheckResults []domain.CheckResult
}

// Reporter is the interface implemented by all output format renderers.
type Reporter interface {
	// RenderReport writes the complete report for a full scan result.
	RenderReport(target string, result *ScanResult) error
	// RenderFinding writes a single finding block.
	RenderFinding(f domain.Finding) error
	// RenderSummary writes a summary of the scan result without individual findings.
	RenderSummary(result *ScanResult) error
}

// New returns the appropriate Reporter for the given format and version string.
// Valid formats: "terminal", "txt", "json", "sarif".
// Returns error for unknown format.
func New(format string, w io.Writer, noColor bool, version string) (Reporter, error) {
	switch format {
	case "terminal":
		return NewRenderer(w, noColor), nil
	case "txt":
		r := NewTXTRenderer(w)
		r.Version = version
		return r, nil
	case "json":
		return NewJSONRenderer(w), nil
	case "sarif":
		return NewSARIFRenderer(w, version), nil
	default:
		return nil, fmt.Errorf("unknown output format %q: valid formats are terminal, txt, json, sarif", format)
	}
}

// jsonReporter wraps JSON marshaling as a Reporter.
type jsonReporter struct {
	w io.Writer
}

// NewJSONRenderer creates a Reporter that outputs indented JSON.
func NewJSONRenderer(w io.Writer) Reporter {
	return &jsonReporter{w: w}
}

func (r *jsonReporter) RenderReport(_ string, result *ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling JSON: %w", err)
	}
	_, err = fmt.Fprintln(r.w, string(data))
	return err
}

func (r *jsonReporter) RenderFinding(f domain.Finding) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(r.w, string(data))
	return err
}

func (r *jsonReporter) RenderSummary(result *ScanResult) error {
	return r.RenderReport("", result)
}

// sarifReporter wraps SARIF 2.1.0 generation as a Reporter.
type sarifReporter struct {
	w       io.Writer
	version string
}

// NewSARIFRenderer creates a Reporter that outputs SARIF 2.1.0.
func NewSARIFRenderer(w io.Writer, version string) Reporter {
	return &sarifReporter{w: w, version: version}
}

func (r *sarifReporter) RenderReport(target string, result *ScanResult) error {
	sarifReport := NewReport(r.version)
	for _, f := range result.Findings {
		sarifReport.AddRule(
			f.CheckID, f.CheckName, f.Description, f.Impact,
			f.Severity.String(), []string{string(f.Category)},
		)
		uri := target
		if f.ReproRequest != nil {
			uri = f.ReproRequest.URL.String()
		}
		sarifReport.AddResult(f.CheckID, f.Description, uri, f.Severity.String())
	}
	data, err := sarifReport.Marshal()
	if err != nil {
		return fmt.Errorf("marshalling SARIF: %w", err)
	}
	_, err = fmt.Fprintln(r.w, string(data))
	return err
}

func (r *sarifReporter) RenderFinding(_ domain.Finding) error {
	// SARIF requires full context; single-finding output is a no-op.
	return nil
}

func (r *sarifReporter) RenderSummary(result *ScanResult) error {
	return r.RenderReport("", result)
}
