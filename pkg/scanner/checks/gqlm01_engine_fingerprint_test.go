package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
)

func fpProbeClient() *transport.Client { return transport.NewClient(2*time.Second, 50, nil) }

func fpServer(body string, headers map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		_, _ = io.WriteString(w, body)
	}))
}

func TestM01_IdentifiesApollo(t *testing.T) {
	srv := fpServer(`{"errors":[{"message":"Cannot query field \"x\" on type \"Query\". Did you mean \"y\"?","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`, nil)
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, err := (&engineFingerprintCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != INFO || f.Category != InformationDisclosure {
		t.Fatalf("unexpected severity/category: %v/%v", f.Severity, f.Category)
	}
	if !strings.Contains(f.Title, "Apollo Server") {
		t.Fatalf("title should name the engine: %s", f.Title)
	}
	if f.Confidence != "firm" || f.CWE != "CWE-200" || f.OWASP != "API8:2023" {
		t.Fatalf("classification not set: %q %q %q", f.Confidence, f.CWE, f.OWASP)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
	if res.ProbeCount < 1 || res.ProbeCount > 6 {
		t.Fatalf("probe count %d out of bound", res.ProbeCount)
	}
	// Evidence must be captured in the description.
	if !strings.Contains(f.Description, "GRAPHQL_VALIDATION_FAILED") && !strings.Contains(f.Description, "Did you mean") {
		t.Fatalf("description should carry the discriminating evidence: %s", f.Description)
	}
}

func TestM01_IdentifiesHasura(t *testing.T) {
	srv := fpServer(`{"errors":[{"message":"not found in type: 'query_root'"}]}`, map[string]string{"x-hasura-role": "anon"})
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, _ := (&engineFingerprintCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Title, "Hasura") {
		t.Fatalf("expected a Hasura finding, got %+v", res.Findings)
	}
}

func TestM01_UnknownNoFalseAttribution(t *testing.T) {
	srv := fpServer(`{"errors":[{"message":"Validation error"}]}`, nil)
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, _ := (&engineFingerprintCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 INFO finding for unknown, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != INFO || !strings.Contains(f.Title, "Not Identified") {
		t.Fatalf("expected INFO 'Not Identified' finding, got %q (%v)", f.Title, f.Severity)
	}
}

func TestM01_Unreachable(t *testing.T) {
	srv := fpServer(`{}`, nil)
	url := srv.URL
	srv.Close()

	cc := &CheckContext{Target: url, BaseHTTPClient: fpProbeClient()}
	res, err := (&engineFingerprintCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	// Probes were attempted (and failed); no engine identified → an INFO
	// "not identified" finding is acceptable, but never a crash.
	if len(res.Findings) == 1 && strings.Contains(res.Findings[0].Title, "Identified —") {
		t.Fatal("must not identify an engine against an unreachable endpoint")
	}
}
