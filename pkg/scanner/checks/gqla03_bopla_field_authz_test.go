package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

// boplaSchema builds a Query{ user(id: ID!): User } schema. When sensitive is
// true, User carries sensitive email/ssn fields.
func boplaSchema(sensitive bool) *schema.Schema {
	fields := []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")},
		{Name: "name", Type: bolaScalar("String")},
	}
	if sensitive {
		fields = append(fields,
			&schema.FieldDef{Name: "email", Type: bolaScalar("String"), SensitivityScore: 4, Tags: []string{"pii"}},
			&schema.FieldDef{Name: "ssn", Type: bolaScalar("String"), SensitivityScore: 10, Tags: []string{"pii"}},
		)
	}
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: fields}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	return &schema.Schema{QueryType: query, Types: map[string]*schema.TypeDef{"User": user, "Query": query}}
}

func boplaContext(url string, sensitive bool) *CheckContext {
	return &CheckContext{
		Target:     url,
		Schema:     boplaSchema(sensitive),
		Identities: bflaIdentities(url),
		AuthzSeeds: map[string]string{"user": "42"},
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestBOPLA_Exposed(t *testing.T) {
	// Every caller receives the same object including its sensitive fields.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","name":"Victim","email":"victim@example.com","ssn":"111-22-3333"}}}`)
	}))
	defer srv.Close()

	res, err := (&boplaCheck{}).Run(t.Context(), boplaContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != Authorization {
		t.Fatalf("unexpected severity/category: %v/%v", f.Severity, f.Category)
	}
	if f.CWE != "CWE-213" || f.OWASP != "API3:2023" || f.Confidence != "confirmed" {
		t.Fatalf("classification not set: %q %q %q", f.Confidence, f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Description, "User.ssn") || !strings.Contains(f.Description, "User.email") {
		t.Fatalf("description should list exposed field paths: %s", f.Description)
	}
	// Redaction: raw sensitive values must never appear.
	for _, raw := range []string{"111-22-3333", "victim@example.com"} {
		if strings.Contains(f.Description, raw) {
			t.Fatalf("raw sensitive value %q leaked in description: %s", raw, f.Description)
		}
	}
	if f.Fingerprint == "" || res.ProbeCount < 2 {
		t.Fatalf("fingerprint/probe count wrong: fp=%q probes=%d", f.Fingerprint, res.ProbeCount)
	}
}

func TestBOPLA_ProtectedNull(t *testing.T) {
	// The object is accessible to everyone, but sensitive fields are nulled for
	// non-privileged callers — field-level authz working as intended.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tokenOf(r) == "admin" {
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","name":"V","email":"a@b.c","ssn":"111-22-3333"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","name":"V","email":null,"ssn":null}}}`)
	}))
	defer srv.Close()

	res, err := (&boplaCheck{}).Run(t.Context(), boplaContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason explaining the clean result")
	}
}

func TestBOPLA_FieldError(t *testing.T) {
	// Non-privileged callers get a field-level authorization error (and null).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tokenOf(r) == "admin" {
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","email":"a@b.c","ssn":"111-22-3333"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","email":null,"ssn":null}},"errors":[{"message":"Not authorized to access field ssn"}]}`)
	}))
	defer srv.Close()

	res, err := (&boplaCheck{}).Run(t.Context(), boplaContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (field-level authz enforced), got %d", len(res.Findings))
	}
}

func TestBOPLA_ObjectDenied(t *testing.T) {
	// The object itself is denied to non-privileged callers — an A01 concern.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tokenOf(r) == "admin" {
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","email":"a@b.c","ssn":"111-22-3333"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"user":null},"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
	}))
	defer srv.Close()

	res, err := (&boplaCheck{}).Run(t.Context(), boplaContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (object denied → defer to A01), got %d", len(res.Findings))
	}
}

func TestBOPLA_NoSensitiveFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","name":"V"}}}`)
	}))
	defer srv.Close()

	res, err := (&boplaCheck{}).Run(t.Context(), boplaContext(srv.URL, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.PassReason == "" {
		t.Fatalf("expected no findings + PassReason, got %d findings, pass=%q", len(res.Findings), res.PassReason)
	}
	if !strings.Contains(res.PassReason, "no sensitive fields") {
		t.Fatalf("PassReason should note absence of sensitive fields: %q", res.PassReason)
	}
}

func TestBOPLA_NoIdentities(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql", Schema: boplaSchema(true)}
	res, err := (&boplaCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}
