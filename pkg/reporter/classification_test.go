package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/domain"
)

func TestClassificationLine(t *testing.T) {
	if got := classificationLine(domain.Finding{}); got != "" {
		t.Fatalf("expected empty classification for bare finding, got %q", got)
	}
	f := domain.Finding{CWE: "CWE-639", OWASP: "API1:2023", Confidence: "confirmed"}
	got := classificationLine(f)
	for _, want := range []string{"CWE-639", "API1:2023", "confidence: confirmed"} {
		if !strings.Contains(got, want) {
			t.Fatalf("classification %q missing %q", got, want)
		}
	}
}

func TestTerminal_RendersClassificationWhenSet(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf, true) // no color
	f := domain.Finding{
		CheckID: "GQL-A01", CheckName: "BOLA", Severity: domain.CRITICAL,
		Category: domain.Authorization, Description: "leak",
		CWE: "CWE-639", OWASP: "API1:2023", Confidence: "confirmed",
	}
	if err := r.RenderFinding(f); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "CLASSIFICATION") || !strings.Contains(out, "CWE-639") {
		t.Fatalf("expected CLASSIFICATION section with CWE in output:\n%s", out)
	}
}

func TestTerminal_OmitsClassificationWhenUnset(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf, true)
	f := domain.Finding{CheckID: "GQL-001", CheckName: "x", Severity: domain.HIGH, Description: "d"}
	if err := r.RenderFinding(f); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "CLASSIFICATION") {
		t.Fatal("CLASSIFICATION section should be absent for legacy findings")
	}
}

func TestJSON_OmitsEmptyClassificationFields(t *testing.T) {
	data, err := json.Marshal(domain.Finding{CheckID: "GQL-001"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"Confidence", "CWE", "OWASP"} {
		if strings.Contains(string(data), k) {
			t.Fatalf("empty %s should be omitted from JSON: %s", k, data)
		}
	}

	data2, _ := json.Marshal(domain.Finding{CheckID: "GQL-A01", CWE: "CWE-639"})
	if !strings.Contains(string(data2), "CWE-639") {
		t.Fatalf("non-empty CWE should be present: %s", data2)
	}
}

func TestSARIF_SetRuleClassification(t *testing.T) {
	report := NewReport("test")
	report.AddRule("GQL-A01", "BOLA", "short", "full", "CRITICAL", []string{"Authorization"})
	report.SetRuleClassification("GQL-A01", "CWE-639", "API1:2023", "confirmed")

	props := report.Runs[0].Tool.Driver.Rules[0].Properties
	if props.CWE != "CWE-639" || props.OWASP != "API1:2023" || props.Confidence != "confirmed" {
		t.Fatalf("classification not set on rule: %+v", props)
	}

	// Unknown rule id is a no-op (must not panic).
	report.SetRuleClassification("GQL-XXX", "CWE-1", "", "")
}
