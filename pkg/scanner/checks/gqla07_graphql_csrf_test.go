package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// csrfDataHandler accepts every request shape and returns a valid data object —
// the vulnerable behavior (no CSRF/preflight enforcement).
func csrfDataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
}

func csrfContext(url string) *CheckContext {
	return &CheckContext{Target: url, BaseHTTPClient: aliasProbeClient()}
}

func TestCSRF_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(csrfDataHandler))
	defer srv.Close()

	res, err := (&graphqlCSRFCheck{}).Run(t.Context(), csrfContext(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != Authorization || f.CWE != "CWE-352" || f.OWASP != "API8:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "firm" {
		t.Fatalf("expected firm confidence (query-only, no --authz-allow-mutations), got %q", f.Confidence)
	}
	if !strings.Contains(f.Description, "GET") || !strings.Contains(f.Description, "text/plain") {
		t.Fatalf("description should list accepted vectors: %s", f.Description)
	}
	if f.Fingerprint == "" || res.ProbeCount != 4 {
		t.Fatalf("fingerprint/probe count wrong: fp=%q probes=%d (want 4)", f.Fingerprint, res.ProbeCount)
	}
}

func TestCSRF_MutationConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(csrfDataHandler))
	defer srv.Close()

	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "ping", Type: bolaScalar("Boolean")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "health", Type: bolaScalar("String")}}}
	cc := csrfContext(srv.URL)
	cc.Schema = &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{"Query": query, "Mutation": mutation}}
	cc.AllowMutations = true

	res, err := (&graphqlCSRFCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Confidence != "confirmed" {
		t.Fatalf("expected confirmed confidence when a mutation executes over a CSRF vector, got %q", res.Findings[0].Confidence)
	}
	if !strings.Contains(res.Findings[0].Description, "ping") {
		t.Fatalf("description should mention the demonstrated mutation: %s", res.Findings[0].Description)
	}
}

func TestCSRF_ApolloRejected(t *testing.T) {
	// JSON POST works; browser-forgeable shapes are blocked with a CSRF error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet || r.Header.Get("Content-Type") != "application/json" {
			_, _ = io.WriteString(w, `{"errors":[{"message":"This operation has been blocked as a potential CSRF"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	res, err := (&graphqlCSRFCheck{}).Run(t.Context(), csrfContext(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason")
	}
}

func TestCSRF_JSONOnly(t *testing.T) {
	// Only application/json POST is accepted; other shapes are rejected by status.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/json":
			_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusUnsupportedMediaType)
		}
	}))
	defer srv.Close()

	res, err := (&graphqlCSRFCheck{}).Run(t.Context(), csrfContext(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason")
	}
}

func TestCSRF_BaselineDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	res, err := (&graphqlCSRFCheck{}).Run(t.Context(), csrfContext(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings when the baseline fails, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason for the failed baseline")
	}
}
