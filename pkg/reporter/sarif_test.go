package reporter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSARIF_MarshalProducesValidJSON(t *testing.T) {
	report := NewReport("1.0.0")
	data, err := report.Marshal()
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Equal(t, "2.1.0", raw["version"])
	_, hasSchema := raw["$schema"]
	assert.True(t, hasSchema, "$schema key must be present")
}

func TestSARIF_SeverityMapping(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"INFO", "none"},
		{"unknown", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.severity, func(t *testing.T) {
			assert.Equal(t, tc.want, severityToLevel(tc.severity))
		})
	}
}

func TestSARIF_MultipleResultsProducedCorrectly(t *testing.T) {
	report := NewReport("1.0.0")
	report.AddRule("GQL-001", "Introspection Enabled", "Short", "Full", "HIGH", []string{"info-disclosure"})
	report.AddResult("GQL-001", "Introspection is enabled", "http://example.com/graphql", "HIGH")
	report.AddResult("GQL-001", "Second finding", "http://example.com/graphql", "MEDIUM")

	data, err := report.Marshal()
	require.NoError(t, err)

	var parsed SARIFReport
	require.NoError(t, json.Unmarshal(data, &parsed))

	require.Len(t, parsed.Runs, 1)
	require.Len(t, parsed.Runs[0].Results, 2)
	assert.Equal(t, "GQL-001", parsed.Runs[0].Results[0].RuleID)
	assert.Equal(t, "error", parsed.Runs[0].Results[0].Level)
	assert.Equal(t, "warning", parsed.Runs[0].Results[1].Level)
}

func TestSARIF_RuleDeduplication(t *testing.T) {
	report := NewReport("1.0.0")

	// Add the same rule twice.
	report.AddRule("GQL-001", "Introspection Enabled", "Short", "Full", "HIGH", []string{"tag"})
	report.AddRule("GQL-001", "Introspection Enabled", "Short", "Full", "HIGH", []string{"tag"})

	// Add a different rule.
	report.AddRule("GQL-002", "Field Suggestion", "Short2", "Full2", "MEDIUM", []string{"tag2"})

	data, err := report.Marshal()
	require.NoError(t, err)

	var parsed SARIFReport
	require.NoError(t, json.Unmarshal(data, &parsed))

	assert.Len(t, parsed.Runs[0].Tool.Driver.Rules, 2,
		"duplicate rule should produce exactly one rule entry")
}

func TestSARIF_ResultLocationContainsURI(t *testing.T) {
	report := NewReport("1.0.0")
	report.AddRule("GQL-001", "Test", "Short", "Full", "LOW", nil)
	report.AddResult("GQL-001", "message", "http://target.example.com/gql", "LOW")

	data, err := report.Marshal()
	require.NoError(t, err)

	var parsed SARIFReport
	require.NoError(t, json.Unmarshal(data, &parsed))

	require.Len(t, parsed.Runs[0].Results[0].Locations, 1)
	uri := parsed.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	assert.Equal(t, "http://target.example.com/gql", uri)
}

func TestSARIF_PropertiesContainSeverity(t *testing.T) {
	report := NewReport("1.0.0")
	report.AddRule("GQL-003", "Test Rule", "Short", "Full", "CRITICAL", []string{"injection"})

	data, err := report.Marshal()
	require.NoError(t, err)

	var parsed SARIFReport
	require.NoError(t, json.Unmarshal(data, &parsed))

	require.Len(t, parsed.Runs[0].Tool.Driver.Rules, 1)
	assert.Equal(t, "CRITICAL", parsed.Runs[0].Tool.Driver.Rules[0].Properties.Severity)
	assert.Equal(t, []string{"injection"}, parsed.Runs[0].Tool.Driver.Rules[0].Properties.Tags)
}
