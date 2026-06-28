package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// m06Routes maps a request to a (statusCode, headers, body) response, letting
// each test shape per-path / per-method behavior.
type m06Routes func(r *http.Request) (int, map[string]string, string)

func m06ServerCC(t *testing.T, routes m06Routes) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, headers, body := routes(r)
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "text/html")
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
}

const altairShell = `<!DOCTYPE html><html><head><title>Altair</title></head><body><app-root>altair-graphql</app-root></body></html>`

// Altair shell served at /altair → LOW confirmed finding naming Altair.
func TestM06_AltairPath_Fires(t *testing.T) {
	cc := m06ServerCC(t, func(r *http.Request) (int, map[string]string, string) {
		if r.URL.Path == "/altair" {
			return 200, nil, altairShell
		}
		return 404, nil, "not found"
	})
	res, err := (&debugDevModeCheck{}).Run(t.Context(), cc)
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
	if f.Confidence != "confirmed" || f.CWE != "CWE-489" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q/%q, want confirmed/CWE-489/API8:2023", f.Confidence, f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Title, "Altair") {
		t.Fatalf("title should name Altair: %s", f.Title)
	}
	if !strings.Contains(f.Description, "/altair") {
		t.Fatalf("description should include the path: %s", f.Description)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
}

// A framework debug page on the error probe → behavioral (firm) finding.
func TestM06_DebugErrorPage_BehavioralFinding(t *testing.T) {
	cc := m06ServerCC(t, func(r *http.Request) (int, map[string]string, string) {
		if r.Method == http.MethodPost {
			return 500, map[string]string{"Content-Type": "text/html"},
				`<html><head><title>Werkzeug Debugger</title></head><body>Werkzeug powered traceback</body></html>`
		}
		return 404, nil, "not found" // no dev tools on any path
	})
	res, err := (&debugDevModeCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != LOW {
		t.Fatalf("severity = %v, want LOW", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Fatalf("confidence = %q, want firm (behavioral)", f.Confidence)
	}
	if !strings.Contains(f.Title, "Werkzeug") {
		t.Fatalf("title should name the debug tell: %s", f.Title)
	}
}

// A debug HTTP header on the error probe → behavioral finding.
func TestM06_DebugHeader_BehavioralFinding(t *testing.T) {
	cc := m06ServerCC(t, func(r *http.Request) (int, map[string]string, string) {
		if r.Method == http.MethodPost {
			return 200, map[string]string{"Content-Type": "application/json", "X-Debug-Token": "abc123"},
				`{"errors":[{"message":"nope"}]}`
		}
		return 404, nil, "not found"
	})
	res, _ := (&debugDevModeCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Confidence != "firm" {
		t.Fatalf("confidence = %q, want firm", res.Findings[0].Confidence)
	}
	if !strings.Contains(res.Findings[0].Title, "debug HTTP header") {
		t.Fatalf("title should name the debug header tell: %s", res.Findings[0].Title)
	}
}

// Only the canonical-endpoint Playground (GQL-004 territory), no extra tools, no
// debug behavior → M06 does not duplicate it (PassReason, no finding).
func TestM06_CanonicalPlaygroundOnly_NoDuplicate(t *testing.T) {
	cc := m06ServerCC(t, func(r *http.Request) (int, map[string]string, string) {
		if r.Method == http.MethodGet && (r.URL.Path == "" || r.URL.Path == "/") {
			return 200, nil, `<html><body><div id="graphiql">graphiql</div></body></html>`
		}
		if r.Method == http.MethodPost {
			return 200, map[string]string{"Content-Type": "application/json"}, `{"errors":[{"message":"bad"}]}`
		}
		return 404, nil, "not found"
	})
	res, _ := (&debugDevModeCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 0 {
		t.Fatalf("M06 must not duplicate the canonical GraphiQL (GQL-004 owns it), got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason when only the canonical Playground is present")
	}
}

// Clean prod server → no finding + PassReason. No panic on non-HTML bodies.
func TestM06_Clean_PassReason(t *testing.T) {
	cc := m06ServerCC(t, func(r *http.Request) (int, map[string]string, string) {
		if r.Method == http.MethodPost {
			return 200, map[string]string{"Content-Type": "application/json"}, `{"data":{"__typename":"Query"}}`
		}
		return 404, map[string]string{"Content-Type": "application/json"}, `{"errors":[{"message":"not found"}]}`
	})
	res, err := (&debugDevModeCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("clean server should produce no findings, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason for a clean server")
	}
}

// A non-canonical tool plus a debug tell aggregate into one finding (confirmed,
// since a tool matched), with deterministic label ordering.
func TestM06_ToolAndDebug_Aggregate(t *testing.T) {
	cc := m06ServerCC(t, func(r *http.Request) (int, map[string]string, string) {
		if r.URL.Path == "/voyager" {
			return 200, nil, `<html><title>GraphQL Voyager</title><body>graphql-voyager</body></html>`
		}
		if r.Method == http.MethodPost {
			return 500, map[string]string{"Content-Type": "text/html"}, `<html>Werkzeug debugger</html>`
		}
		return 404, nil, "nope"
	})
	res, _ := (&debugDevModeCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Confidence != "confirmed" {
		t.Fatalf("confidence = %q, want confirmed (a tool matched)", f.Confidence)
	}
	// Deterministic order: "Voyager" < "Werkzeug debugger" alphabetically.
	vi := strings.Index(f.Title, "Voyager")
	wi := strings.Index(f.Title, "Werkzeug")
	if vi < 0 || wi < 0 || vi > wi {
		t.Fatalf("labels missing or out of order: %s", f.Title)
	}
}

func TestM06_Metadata(t *testing.T) {
	c := &debugDevModeCheck{}
	if c.ID() != "GQL-M06" {
		t.Fatalf("ID = %q, want GQL-M06", c.ID())
	}
	if c.Severity() != LOW || c.Category() != InformationDisclosure || c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
