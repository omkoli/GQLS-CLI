// Package domain contains the core data types shared across the scanner engine,
// reporters, and CLI orchestration layers.
//
// No other internal package should be imported here; this package is a dependency
// leaf so that every layer (checks, transport, reporter, cmd) can import it
// without introducing cycles.
package domain

import (
	"encoding/json"
	"net/http"
	"time"
)

// Severity represents the risk level of a security finding.
type Severity int

const (
	// INFO is for informational observations with negligible direct risk.
	INFO Severity = iota
	// LOW is for findings with limited exploitability or impact.
	LOW
	// MEDIUM is for findings with moderate exploitability or impact.
	MEDIUM
	// HIGH is for findings with significant exploitability or impact.
	HIGH
	// CRITICAL is for findings that are immediately exploitable with severe impact.
	CRITICAL
)

// String returns the canonical uppercase name of the severity level.
func (s Severity) String() string {
	switch s {
	case INFO:
		return "INFO"
	case LOW:
		return "LOW"
	case MEDIUM:
		return "MEDIUM"
	case HIGH:
		return "HIGH"
	case CRITICAL:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// MarshalJSON encodes Severity as a JSON string (e.g. "HIGH").
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// ParseSeverity converts a string to a Severity constant, returning INFO on unknown values.
func ParseSeverity(s string) Severity {
	switch s {
	case "CRITICAL":
		return CRITICAL
	case "HIGH":
		return HIGH
	case "MEDIUM":
		return MEDIUM
	case "LOW":
		return LOW
	default:
		return INFO
	}
}

// Category classifies the type of vulnerability a check tests for.
type Category string

const (
	// InformationDisclosure covers checks that detect data-leakage issues.
	InformationDisclosure Category = "InformationDisclosure"
	// DenialOfService covers checks that detect resource-exhaustion vectors.
	DenialOfService Category = "DenialOfService"
	// Authentication covers checks that detect auth bypass or weakness.
	Authentication Category = "Authentication"
	// Authorization covers checks that detect broken object/function/property
	// level authorization (BOLA/BFLA/BOPLA), cross-tenant isolation failures,
	// and related access-control weaknesses.
	Authorization Category = "Authorization"
	// Injection covers checks that detect injection-style vulnerabilities.
	Injection Category = "Injection"
	// BusinessLogic covers checks that detect abuse of sensitive business flows
	// (unrestricted flow multiplicity/quantity limits, race conditions, and
	// related logic-abuse weaknesses).
	BusinessLogic Category = "BusinessLogic"
)

// Finding represents a single security issue discovered by a check.
type Finding struct {
	// CheckID is the unique identifier of the check that produced this finding.
	CheckID string
	// CheckName is the human-readable name of the check.
	CheckName string
	// Severity is the risk level of this finding.
	Severity Severity
	// Category is the vulnerability category.
	Category Category
	// Title is a short headline for the summary table.
	Title string
	// Description explains what was observed.
	Description string
	// Impact describes what an attacker could achieve.
	Impact string
	// Remediation provides actionable fix guidance.
	Remediation string
	// References is a list of external URLs (CVEs, OWASP, writeups, etc.).
	References []string
	// ReproRequest is the HTTP request that triggered the finding (may be nil).
	ReproRequest *http.Request
	// ReproBody is the request body bytes for the reproduction request.
	ReproBody []byte
	// Fingerprint is a stable SHA-256 hash for deduplication and FP suppression.
	Fingerprint string
	// Confidence expresses how strongly the evidence supports the finding:
	// "confirmed", "firm", or "tentative". Empty when a check does not set it.
	Confidence string `json:",omitempty"`
	// CWE is the Common Weakness Enumeration identifier (e.g. "CWE-639").
	// Empty when a check does not set it.
	CWE string `json:",omitempty"`
	// OWASP is the OWASP API Security Top 10 identifier (e.g. "API1:2023").
	// Empty when a check does not set it.
	OWASP string `json:",omitempty"`
}

// PassProbe records a single HTTP probe that was sent by a check that produced no findings.
// It is used to show readers exactly what requests the scanner made and what it received no
// vulnerability signals from, so they can understand the basis for a clean result.
type PassProbe struct {
	// Label describes what the probe was testing.
	Label string
	// Request is the HTTP request that was sent.
	Request *http.Request
	// Body is the request body bytes that were sent.
	Body []byte
}

// CheckResult contains the complete outcome of a single check execution.
type CheckResult struct {
	// CheckID identifies which check produced this result.
	CheckID string
	// Ran is true when the check was executed (not skipped).
	Ran bool
	// Skipped is true when the check was not executed.
	Skipped bool
	// SkipReason explains why the check was skipped.
	SkipReason string
	// PassReason explains why the check produced no findings when it ran successfully.
	PassReason string
	// PassProbes records every HTTP probe sent during a clean (no-finding) run.
	PassProbes []PassProbe
	// Findings contains every security issue discovered.
	Findings []Finding
	// Error holds any fatal error that prevented the check from completing.
	Error error
	// Duration is the wall-clock time the check spent executing.
	Duration time.Duration
	// ProbeCount is the number of HTTP requests made by this check.
	ProbeCount int
}

// CurlRequest holds the structured HTTP request data extracted from a parsed
// curl command. Injection-based and context-dependent checks use this to
// reproduce the original request environment as closely as possible.
//
// Rule: callers must call Clone before modifying any field received through
// CheckContext.ParsedCurl to avoid mutating the shared original.
type CurlRequest struct {
	// Method is the HTTP method from the curl command (e.g. "GET", "POST").
	Method string
	// URL is the full request URL from the curl command.
	URL string
	// Headers are the raw request headers from the curl command.
	Headers map[string]string
	// Body is the raw request body string from the curl command.
	Body string
}

// Clone returns a deep copy of r. When r is nil, Clone returns nil.
func (r *CurlRequest) Clone() *CurlRequest {
	if r == nil {
		return nil
	}
	c := &CurlRequest{
		Method: r.Method,
		URL:    r.URL,
		Body:   r.Body,
	}
	if r.Headers != nil {
		c.Headers = make(map[string]string, len(r.Headers))
		for k, v := range r.Headers {
			c.Headers[k] = v
		}
	}
	return c
}
