package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func m08Server(t *testing.T, headers map[string]string) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	t.Cleanup(srv.Close)
	return &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
}

// Missing nosniff + exposed X-Powered-By → LOW finding listing both.
func TestM08_MissingNosniffAndPoweredBy(t *testing.T) {
	cc := m08Server(t, map[string]string{"X-Powered-By": "Express"}) // no nosniff
	res, err := (&securityHeadersCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != LOW || f.Category != InformationDisclosure {
		t.Fatalf("severity/category = %v/%v, want LOW/InformationDisclosure", f.Severity, f.Category)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-693" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q/%q, want confirmed/CWE-693/API8:2023", f.Confidence, f.CWE, f.OWASP)
	}
	for _, want := range []string{"X-Content-Type-Options", "X-Powered-By"} {
		if !strings.Contains(f.Title, want) {
			t.Fatalf("title should list %q: %s", want, f.Title)
		}
	}
	if !strings.Contains(f.Description, "Express") {
		t.Fatalf("description should include the observed X-Powered-By value: %s", f.Description)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
}

// A hardened (http) response → no finding + PassReason.
func TestM08_Hardened_PassReason(t *testing.T) {
	cc := m08Server(t, map[string]string{"X-Content-Type-Options": "nosniff"})
	res, err := (&securityHeadersCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("hardened response should produce no finding, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason for a hardened response")
	}
}

// HSTS is considered only for https targets (target-string based).
func TestM08_HSTS_OnlyHTTPS(t *testing.T) {
	hardened := http.Header{}
	hardened.Set("X-Content-Type-Options", "nosniff") // only HSTS could be missing

	httpsGaps := m08Evaluate("https://api.example.com/graphql", hardened)
	if !m08HasGap(httpsGaps, "strict-transport-security") {
		t.Fatalf("https target without HSTS should flag HSTS, got %v", m08GapKeys(httpsGaps))
	}

	httpGaps := m08Evaluate("http://api.example.com/graphql", hardened)
	if m08HasGap(httpGaps, "strict-transport-security") {
		t.Fatalf("http target must not flag HSTS, got %v", m08GapKeys(httpGaps))
	}
}

// CSP is flagged only for HTML responses; deterministic key ordering.
func TestM08_CSP_HTMLOnly_AndOrdering(t *testing.T) {
	jsonH := http.Header{}
	jsonH.Set("X-Content-Type-Options", "nosniff")
	jsonH.Set("Content-Type", "application/json")
	if m08HasGap(m08Evaluate("http://t/graphql", jsonH), "content-security-policy") {
		t.Fatal("CSP must not be flagged for a JSON response")
	}

	htmlH := http.Header{}
	htmlH.Set("Content-Type", "text/html")
	htmlH.Set("X-Powered-By", "PHP/8.1")
	htmlH.Set("Server", "nginx/1.25.0")
	gaps := m08Evaluate("https://t/graphql", htmlH)
	keys := m08GapKeys(gaps)
	// Expect: content-security-policy, server-disclosure, strict-transport-security,
	// x-content-type-options, x-powered-by — sorted ascending by key.
	if !sortedAscending(keys) {
		t.Fatalf("gap keys must be sorted ascending, got %v", keys)
	}
	for _, want := range []string{"content-security-policy", "strict-transport-security", "x-content-type-options", "server-disclosure", "x-powered-by"} {
		if !m08HasGap(gaps, want) {
			t.Fatalf("expected gap %q in %v", want, keys)
		}
	}
}

// Server header without a version is not treated as disclosing.
func TestM08_ServerWithoutVersion_NotFlagged(t *testing.T) {
	h := http.Header{}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Server", "cloudflare") // no version digits
	if m08HasGap(m08Evaluate("http://t/graphql", h), "server-disclosure") {
		t.Fatal("versionless Server header must not be flagged as disclosure")
	}
	h.Set("Server", "Apache/2.4.57")
	if !m08HasGap(m08Evaluate("http://t/graphql", h), "server-disclosure") {
		t.Fatal("versioned Server header should be flagged")
	}
}

// Empty header set must not panic and yields the baseline gap (nosniff).
func TestM08_EmptyHeaders_NoPanic(t *testing.T) {
	gaps := m08Evaluate("http://t/graphql", http.Header{})
	if !m08HasGap(gaps, "x-content-type-options") {
		t.Fatalf("empty headers should at least flag missing nosniff, got %v", m08GapKeys(gaps))
	}
}

func TestM08_Metadata(t *testing.T) {
	c := &securityHeadersCheck{}
	if c.ID() != "GQL-M08" {
		t.Fatalf("ID = %q, want GQL-M08", c.ID())
	}
	if c.Severity() != LOW || c.Category() != InformationDisclosure || c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}

// ── test helpers ──

func m08HasGap(gaps []m08Gap, key string) bool {
	for _, g := range gaps {
		if g.key == key {
			return true
		}
	}
	return false
}

func m08GapKeys(gaps []m08Gap) []string {
	out := make([]string, len(gaps))
	for i, g := range gaps {
		out[i] = g.key
	}
	return out
}

func sortedAscending(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
