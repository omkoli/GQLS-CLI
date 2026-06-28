package checks

import (
	"strings"
	"testing"
)

func runM03(t *testing.T, body string) CheckResult {
	t.Helper()
	srv := fpServer(body, nil)
	t.Cleanup(srv.Close)
	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, err := (&extensionsLeakageCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	return res
}

// Given errors[].extensions.exception.stacktrace, a MEDIUM finding fires listing
// the stacktrace class with a redacted sample (no raw file paths in output).
func TestM03_Stacktrace_MediumRedacted(t *testing.T) {
	const rawPath = "/var/app/src/server.js:42:15"
	body := `{"errors":[{"message":"Unexpected error","extensions":{"code":"INTERNAL_SERVER_ERROR","exception":{"stacktrace":["Error: boom","    at resolve (` + rawPath + `)","    at /var/app/node_modules/graphql/execution/execute.js:119:7"]}}}]}`

	res := runM03(t, body)
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM {
		t.Fatalf("severity = %v, want MEDIUM", f.Severity)
	}
	if f.Category != InformationDisclosure {
		t.Fatalf("category = %v, want InformationDisclosure", f.Category)
	}
	if f.Confidence != "firm" || f.CWE != "CWE-200" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q/%q, want firm/CWE-200/API8:2023", f.Confidence, f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Title, "stacktrace") {
		t.Fatalf("title should list the stacktrace class: %s", f.Title)
	}
	if !strings.Contains(f.Description, "exception.stacktrace") {
		t.Fatalf("description should name the offending key: %s", f.Description)
	}
	// Redaction: the raw file path must never appear anywhere in the finding.
	for _, field := range []string{f.Title, f.Description, f.Impact, f.Remediation} {
		if strings.Contains(field, rawPath) || strings.Contains(field, "/var/app") {
			t.Fatalf("raw file path leaked into finding output: %q", field)
		}
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
	if res.ProbeCount != 2 {
		t.Fatalf("ProbeCount = %d, want 2", res.ProbeCount)
	}
}

// Given only extensions.tracing timing, a LOW finding fires (timing class).
func TestM03_TracingOnly_Low(t *testing.T) {
	body := `{"data":{"__typename":"Query"},"extensions":{"tracing":{"version":1,"startTime":"2020-01-01T00:00:00Z","endTime":"2020-01-01T00:00:00.1Z","duration":100000000,"execution":{"resolvers":[{"path":["__typename"],"parentType":"Query","fieldName":"__typename","startOffset":1,"duration":50}]}}}}`

	res := runM03(t, body)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != LOW {
		t.Fatalf("severity = %v, want LOW (timing only)", f.Severity)
	}
	if !strings.Contains(f.Title, "tracing/timing") {
		t.Fatalf("title should list the tracing class: %s", f.Title)
	}
	if !strings.Contains(f.Description, "extensions.tracing") {
		t.Fatalf("description should name extensions.tracing: %s", f.Description)
	}
}

// Given benign-only extensions (validation code), no finding fires.
func TestM03_BenignCode_NoFinding(t *testing.T) {
	body := `{"errors":[{"message":"Cannot query field \"invalid\" on type \"Query\".","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`

	res := runM03(t, body)
	if len(res.Findings) != 0 {
		t.Fatalf("benign code must not fire, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a pass reason for the clean extensions channel")
	}
}

// Backend echo (SQL error text) in extensions → MEDIUM finding.
func TestM03_BackendEcho_Medium(t *testing.T) {
	body := `{"errors":[{"message":"db error","extensions":{"exception":{"sqlMessage":"You have an error in your SQL syntax near 'SELECT'"}}}]}`

	res := runM03(t, body)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM {
		t.Fatalf("severity = %v, want MEDIUM (backend echo)", f.Severity)
	}
	if !strings.Contains(f.Title, "backend-echo") {
		t.Fatalf("title should list the backend-echo class: %s", f.Title)
	}
	// The SQL fragment must be masked, not echoed verbatim.
	if strings.Contains(f.Description, "You have an error in your SQL syntax") {
		t.Fatalf("raw SQL error leaked into finding: %s", f.Description)
	}
}

// No panic and no finding on missing / non-object extensions.
func TestM03_NonObjectExtensions_NoPanic(t *testing.T) {
	bodies := []string{
		`{"data":{"__typename":"Query"}}`,                                              // no extensions at all
		`{"errors":[{"message":"x","extensions":"not-an-object"}],"extensions":12345}`, // non-object extensions
		`{"errors":[{"message":"x","extensions":null}]}`,                               // null extensions
		`not even json`, // unparseable body
	}
	for _, b := range bodies {
		res := runM03(t, b)
		if len(res.Findings) != 0 {
			t.Fatalf("body %q should yield no findings, got %+v", b, res.Findings)
		}
	}
}

// Multiple classes → severity is the most sensitive, all classes listed,
// fingerprint stable across runs.
func TestM03_MultiClass_StableFingerprint(t *testing.T) {
	body := `{"data":{"__typename":"Query"},"extensions":{"tracing":{"duration":5},"cacheControl":{"version":1}},"errors":[{"message":"boom","extensions":{"exception":{"stacktrace":["at /usr/src/app/index.js:1:1"]}}}]}`

	// Reuse one server (stable target URL) so the fingerprint comparison reflects
	// the class set, not the ephemeral httptest port.
	srv := fpServer(body, nil)
	defer srv.Close()
	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res1, err := (&extensionsLeakageCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := (&extensionsLeakageCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res1.Findings) != 1 || len(res2.Findings) != 1 {
		t.Fatalf("expected 1 finding each, got %d/%d", len(res1.Findings), len(res2.Findings))
	}
	f := res1.Findings[0]
	if f.Severity != MEDIUM {
		t.Fatalf("severity = %v, want MEDIUM (stacktrace dominates)", f.Severity)
	}
	for _, class := range []string{"stacktrace", "tracing/timing", "query-plan/cost"} {
		if !strings.Contains(f.Title, class) {
			t.Fatalf("title should list class %q: %s", class, f.Title)
		}
	}
	if f.Fingerprint != res2.Findings[0].Fingerprint {
		t.Fatalf("fingerprint not stable: %q vs %q", f.Fingerprint, res2.Findings[0].Fingerprint)
	}
}

func TestM03_Metadata(t *testing.T) {
	c := &extensionsLeakageCheck{}
	if c.ID() != "GQL-M03" {
		t.Fatalf("ID = %q, want GQL-M03", c.ID())
	}
	if c.Severity() != MEDIUM {
		t.Fatalf("Severity = %v, want MEDIUM", c.Severity())
	}
	if c.Category() != InformationDisclosure {
		t.Fatalf("Category = %v, want InformationDisclosure", c.Category())
	}
	if c.RequiresSchema() {
		t.Fatal("RequiresSchema should be false")
	}
}
