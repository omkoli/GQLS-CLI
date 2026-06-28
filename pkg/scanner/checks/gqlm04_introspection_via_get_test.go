package checks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	m04SchemaResp = `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`
	m04DeniedResp = `{"errors":[{"message":"GraphQL introspection is not allowed"}]}`
)

// m04Query extracts the GraphQL query text from a request, handling JSON
// (single + batched), form-encoded, and GET ?query= shapes.
func m04Query(r *http.Request) string {
	if r.Method == http.MethodGet {
		return r.URL.Query().Get("query")
	}
	body, _ := io.ReadAll(r.Body)
	// JSON object
	var single struct {
		Query string `json:"query"`
	}
	if json.Unmarshal(body, &single) == nil && single.Query != "" {
		return single.Query
	}
	// Batched JSON array
	var batch []struct {
		Query string `json:"query"`
	}
	if json.Unmarshal(body, &batch) == nil && len(batch) > 0 {
		return batch[0].Query
	}
	// Form-encoded
	if vals, err := parseForm(string(body)); err == nil {
		return vals
	}
	return ""
}

func parseForm(body string) (string, error) {
	for _, kv := range strings.Split(body, "&") {
		if strings.HasPrefix(kv, "query=") {
			return urlDecode(strings.TrimPrefix(kv, "query=")), nil
		}
	}
	return "", io.EOF
}

func urlDecode(s string) string {
	// Minimal decode sufficient for the test payloads.
	s = strings.ReplaceAll(s, "+", " ")
	s = strings.ReplaceAll(s, "%7B", "{")
	s = strings.ReplaceAll(s, "%7D", "}")
	s = strings.ReplaceAll(s, "%20", " ")
	s = strings.ReplaceAll(s, "%0A", "\n")
	s = strings.ReplaceAll(s, "%23", "#")
	return s
}

func m04Server(t *testing.T, accept func(r *http.Request, q string) bool) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := m04Query(r)
		if strings.Contains(q, "__schema") && accept(r, q) {
			_, _ = io.WriteString(w, m04SchemaResp)
			return
		}
		_, _ = io.WriteString(w, m04DeniedResp)
	}))
	t.Cleanup(srv.Close)
	return &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
}

// POST denied, GET introspection succeeds → finding naming the GET vector.
func TestM04_GETBypass_Fires(t *testing.T) {
	cc := m04Server(t, func(r *http.Request, q string) bool {
		return r.Method == http.MethodGet
	})
	res, err := (&introspectionViaGetCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatalf("should not skip: %s", res.SkipReason)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM || f.Category != InformationDisclosure {
		t.Fatalf("severity/category = %v/%v, want MEDIUM/InformationDisclosure", f.Severity, f.Category)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-200" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q/%q, want confirmed/CWE-200/API8:2023", f.Confidence, f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Title, "GET") {
		t.Fatalf("title should name the GET vector: %s", f.Title)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
}

// POST denied, only the whitespace-bypass document succeeds → finding.
func TestM04_WhitespaceBypass_Fires(t *testing.T) {
	cc := m04Server(t, func(r *http.Request, q string) bool {
		// Accept only the newline-after-__schema variant (not the canonical or comment).
		return r.Method == http.MethodPost && strings.Contains(q, "__schema\n")
	})
	res, err := (&introspectionViaGetCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	if !strings.Contains(res.Findings[0].Title, "whitespace bypass") {
		t.Fatalf("title should name the whitespace vector: %s", res.Findings[0].Title)
	}
}

// POST introspection already enabled → check skips (no GQL-001 duplicate).
func TestM04_PostEnabled_Skips(t *testing.T) {
	cc := m04Server(t, func(r *http.Request, q string) bool { return true }) // everything answers __schema
	res, err := (&introspectionViaGetCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.Ran {
		t.Fatalf("expected skip (Skipped=true, Ran=false), got Skipped=%v Ran=%v", res.Skipped, res.Ran)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("skip must not emit findings, got %+v", res.Findings)
	}
	if !strings.Contains(res.SkipReason, "GQL-001") {
		t.Fatalf("skip reason should reference GQL-001: %q", res.SkipReason)
	}
}

// All vectors blocked → no finding, PassReason set.
func TestM04_AllBlocked_PassReason(t *testing.T) {
	cc := m04Server(t, func(r *http.Request, q string) bool { return false }) // nothing answers __schema
	res, err := (&introspectionViaGetCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
	if res.Skipped {
		t.Fatal("should not skip when POST is blocked; should pass")
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason when all vectors are blocked")
	}
}

// Multiple working vectors are listed in the fixed, deterministic order. GET
// (vector index 0) and the whitespace bypass (index 3) are cleanly
// distinguishable: GET by method, whitespace by the newline immediately after
// __schema (the comment variant has " #gqls" in between, so it is not matched).
func TestM04_MultiVector_DeterministicOrder(t *testing.T) {
	cc := m04Server(t, func(r *http.Request, q string) bool {
		return r.Method == http.MethodGet || strings.Contains(q, "__schema\n")
	})
	res, err := (&introspectionViaGetCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	title := res.Findings[0].Title
	gi := strings.Index(title, "GET")
	wi := strings.Index(title, "whitespace")
	if gi < 0 || wi < 0 {
		t.Fatalf("title should list both GET and whitespace vectors: %s", title)
	}
	if gi > wi {
		t.Fatalf("vectors out of order (GET must precede whitespace): %s", title)
	}
}

func TestM04_Metadata(t *testing.T) {
	c := &introspectionViaGetCheck{}
	if c.ID() != "GQL-M04" {
		t.Fatalf("ID = %q, want GQL-M04", c.ID())
	}
	if c.Severity() != MEDIUM || c.Category() != InformationDisclosure || c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
