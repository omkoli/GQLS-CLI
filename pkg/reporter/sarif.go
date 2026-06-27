// Package reporter contains output formatters for scan results.
package reporter

import (
	"encoding/json"
	"strings"
)

// SARIFReport is the root object of a SARIF 2.1.0 log file.
type SARIFReport struct {
	// Version is always "2.1.0".
	Version string `json:"version"`
	// Schema is the URI of the SARIF JSON schema.
	Schema string `json:"$schema"`
	// Runs contains one entry per tool execution.
	Runs []SARIFRun `json:"runs"`
}

// SARIFRun represents a single execution of a static-analysis tool.
type SARIFRun struct {
	// Tool describes the analysis tool that produced the run.
	Tool SARIFTool `json:"tool"`
	// Results contains all findings from this run.
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the static-analysis tool.
type SARIFTool struct {
	// Driver is the primary tool component.
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver identifies the tool and enumerates its rules.
type SARIFDriver struct {
	// Name is the tool name.
	Name string `json:"name"`
	// Version is the tool version string.
	Version string `json:"version"`
	// InformationURI is a URL with more information about the tool.
	InformationURI string `json:"informationUri"`
	// Rules is the de-duplicated list of check definitions.
	Rules []SARIFRule `json:"rules"`
}

// SARIFRule defines a reportable issue type.
type SARIFRule struct {
	// ID is the stable rule identifier (e.g. "GQL-001").
	ID string `json:"id"`
	// Name is a short human-readable title.
	Name string `json:"name"`
	// ShortDescription is a one-line description of the rule.
	ShortDescription SARIFMessage `json:"shortDescription"`
	// FullDescription is a more detailed description.
	FullDescription SARIFMessage `json:"fullDescription"`
	// Properties holds extra metadata such as severity tags.
	Properties SARIFProperties `json:"properties"`
}

// SARIFResult is a single finding produced by the tool.
type SARIFResult struct {
	// RuleID links this result back to its SARIFRule.
	RuleID string `json:"ruleId"`
	// Level is one of: "error", "warning", "note", "none".
	Level string `json:"level"`
	// Message describes this specific occurrence.
	Message SARIFMessage `json:"message"`
	// Locations points to where the issue was detected.
	Locations []SARIFLocation `json:"locations"`
}

// SARIFLocation identifies where a finding was detected.
type SARIFLocation struct {
	// PhysicalLocation points to the artifact (URL) that was tested.
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation wraps the artifact location.
type SARIFPhysicalLocation struct {
	// ArtifactLocation identifies the scanned artifact.
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation identifies a scanned resource by URI.
type SARIFArtifactLocation struct {
	// URI is the resource identifier (typically the GraphQL endpoint URL).
	URI string `json:"uri"`
}

// SARIFMessage carries a human-readable text string.
type SARIFMessage struct {
	// Text is the message content.
	Text string `json:"text"`
}

// SARIFProperties carries additional metadata for a rule.
type SARIFProperties struct {
	// Tags is a list of category strings.
	Tags []string `json:"tags"`
	// Severity is the original scanner severity string (e.g. "HIGH").
	Severity string `json:"severity"`
	// CWE is the Common Weakness Enumeration identifier, when known.
	CWE string `json:"cwe,omitempty"`
	// OWASP is the OWASP API Security Top 10 identifier, when known.
	OWASP string `json:"owasp,omitempty"`
	// Confidence expresses how strongly evidence supports the finding, when set.
	Confidence string `json:"confidence,omitempty"`
}

// NewReport creates a new SARIF 2.1.0 report stamped with the given tool version.
func NewReport(toolVersion string) *SARIFReport {
	return &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "gqls",
						Version:        toolVersion,
						InformationURI: "https://github.com/gqls-cli/gqls",
						Rules:          []SARIFRule{},
					},
				},
				Results: []SARIFResult{},
			},
		},
	}
}

// AddRule appends a rule to the report, silently skipping duplicates (same ID).
func (r *SARIFReport) AddRule(id, name, shortDesc, fullDesc, severity string, tags []string) {
	run := &r.Runs[0]
	for _, existing := range run.Tool.Driver.Rules {
		if existing.ID == id {
			return
		}
	}
	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, SARIFRule{
		ID:               id,
		Name:             name,
		ShortDescription: SARIFMessage{Text: shortDesc},
		FullDescription:  SARIFMessage{Text: fullDesc},
		Properties: SARIFProperties{
			Severity: severity,
			Tags:     tags,
		},
	})
}

// SetRuleClassification attaches optional triage metadata (CWE, OWASP,
// confidence) to an existing rule. Empty values are left unset so legacy rules
// serialize unchanged. It is a no-op when the rule ID is unknown.
func (r *SARIFReport) SetRuleClassification(id, cwe, owasp, confidence string) {
	run := &r.Runs[0]
	for i := range run.Tool.Driver.Rules {
		if run.Tool.Driver.Rules[i].ID != id {
			continue
		}
		if cwe != "" {
			run.Tool.Driver.Rules[i].Properties.CWE = cwe
		}
		if owasp != "" {
			run.Tool.Driver.Rules[i].Properties.OWASP = owasp
		}
		if confidence != "" {
			run.Tool.Driver.Rules[i].Properties.Confidence = confidence
		}
		return
	}
}

// AddResult appends a finding to the report, mapping severity to a SARIF level.
func (r *SARIFReport) AddResult(ruleID, message, uri, severity string) {
	run := &r.Runs[0]
	run.Results = append(run.Results, SARIFResult{
		RuleID:  ruleID,
		Level:   severityToLevel(severity),
		Message: SARIFMessage{Text: message},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
				},
			},
		},
	})
}

// Marshal serializes the report to indented SARIF JSON.
func (r *SARIFReport) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// severityToLevel converts a scanner severity string to a SARIF level string.
// CRITICAL/HIGH → "error", MEDIUM → "warning", LOW → "note", INFO/unknown → "none".
func severityToLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "none"
	}
}
