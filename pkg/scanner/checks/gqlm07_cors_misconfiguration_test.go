package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// m07Server builds a CheckContext pointing at a server whose CORS headers are
// produced by the supplied function from the request's Origin.
func m07Server(t *testing.T, cors func(origin string, h http.Header)) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cors(r.Header.Get("Origin"), w.Header())
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	t.Cleanup(srv.Close)
	return &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
}

// Reflecting the attacker Origin + ACAC true → HIGH finding with exact headers.
func TestM07_ReflectWithCredentials_High(t *testing.T) {
	cc := m07Server(t, func(origin string, h http.Header) {
		if origin != "" && origin != "null" {
			h.Set("Access-Control-Allow-Origin", origin) // reflect any origin
			h.Set("Access-Control-Allow-Credentials", "true")
		}
	})
	res, err := (&corsMisconfigurationCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != HIGH {
		t.Fatalf("severity = %v, want HIGH (reflection + credentials)", f.Severity)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-942" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q/%q, want confirmed/CWE-942/API8:2023", f.Confidence, f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Title, "reflected origin + credentials") {
		t.Fatalf("title should describe the pattern: %s", f.Title)
	}
	// Exact headers captured in the description.
	if !strings.Contains(f.Description, m07AttackerOrigin) ||
		!strings.Contains(f.Description, "Access-Control-Allow-Credentials: true") {
		t.Fatalf("description should include exact ACAO/ACAC: %s", f.Description)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
}

// ACAO "*" without credentials → LOW.
func TestM07_WildcardNoCredentials_Low(t *testing.T) {
	cc := m07Server(t, func(origin string, h http.Header) {
		h.Set("Access-Control-Allow-Origin", "*")
	})
	res, _ := (&corsMisconfigurationCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != LOW {
		t.Fatalf("severity = %v, want LOW (wildcard, no creds)", f.Severity)
	}
	if !strings.Contains(f.Title, "wildcard origin") {
		t.Fatalf("title should name wildcard: %s", f.Title)
	}
}

// ACAO restricted to a fixed trusted origin → no finding + PassReason.
func TestM07_FixedOrigin_NoFinding(t *testing.T) {
	cc := m07Server(t, func(origin string, h http.Header) {
		h.Set("Access-Control-Allow-Origin", "https://trusted.example")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Vary", "Origin")
	})
	res, err := (&corsMisconfigurationCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("fixed trusted origin must not fire, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason for a safe fixed-origin allowlist")
	}
}

// No CORS headers at all → no finding, no panic.
func TestM07_NoCORSHeaders_NoPanic(t *testing.T) {
	cc := m07Server(t, func(origin string, h http.Header) {})
	res, err := (&corsMisconfigurationCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("no CORS headers should produce no finding, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason when no CORS headers are present")
	}
}

// Origin: null accepted (reflected as null) without credentials → LOW.
func TestM07_NullOrigin_Low(t *testing.T) {
	cc := m07Server(t, func(origin string, h http.Header) {
		if origin == "null" {
			h.Set("Access-Control-Allow-Origin", "null")
		}
	})
	res, _ := (&corsMisconfigurationCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != LOW {
		t.Fatalf("severity = %v, want LOW (null origin, no creds)", f.Severity)
	}
	if !strings.Contains(f.Title, "null origin") {
		t.Fatalf("title should name null origin: %s", f.Title)
	}
}

// Reflection + credentials must outrank a co-present null acceptance (severity
// and pattern selection are deterministic).
func TestM07_PrimaryPattern_HighestWins(t *testing.T) {
	cc := m07Server(t, func(origin string, h http.Header) {
		// Reflect everything (including null) with credentials.
		if origin != "" {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
		}
	})
	res, _ := (&corsMisconfigurationCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != HIGH {
		t.Fatalf("severity = %v, want HIGH (reflect+creds dominates null)", res.Findings[0].Severity)
	}
}

func TestM07_Metadata(t *testing.T) {
	c := &corsMisconfigurationCheck{}
	if c.ID() != "GQL-M07" {
		t.Fatalf("ID = %q, want GQL-M07", c.ID())
	}
	if c.Severity() != MEDIUM || c.Category() != InformationDisclosure || c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
