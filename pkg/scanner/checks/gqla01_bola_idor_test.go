package checks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

func bolaScalar(name string) *schema.TypeRef {
	return &schema.TypeRef{Kind: schema.KindScalar, Name: name}
}

func bolaFixtureSchema() *schema.Schema {
	idArg := &schema.ArgDef{Name: "id", Type: &schema.TypeRef{Kind: schema.KindNonNull, OfType: bolaScalar("ID")}}
	user := &schema.TypeDef{
		Name: "User", Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "id", Type: bolaScalar("ID")},
			{Name: "name", Type: bolaScalar("String")},
			{Name: "email", Type: bolaScalar("String"), SensitivityScore: 4, Tags: []string{"pii"}},
		},
	}
	query := &schema.TypeDef{
		Name: "Query", Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArg}},
			{Name: "users", Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}}},
		},
	}
	return &schema.Schema{QueryType: query, Types: map[string]*schema.TypeDef{"User": user, "Query": query}}
}

func authClient(url, token string) *transport.Client {
	return transport.NewClient(5*time.Second, 50, map[string]string{"Authorization": "Bearer " + token})
}

func bolaContext(url string, seed bool) *CheckContext {
	cc := &CheckContext{
		Target: url,
		Schema: bolaFixtureSchema(),
		Identities: []Identity{
			{Name: "admin", Privilege: 100, Client: authClient(url, "admin")},
			{Name: "userB", Privilege: 10, Client: authClient(url, "userB")},
			{Name: "anonymous", Privilege: 0, Client: transport.NewClient(5*time.Second, 50, nil)},
		},
	}
	if seed {
		cc.AuthzSeeds = map[string]string{"user": "42"}
	}
	return cc
}

func bolaReadQuery(r *http.Request) string {
	b, _ := io.ReadAll(r.Body)
	var p struct {
		Query string `json:"query"`
	}
	_ = json.Unmarshal(b, &p)
	return p.Query
}

func tokenOf(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestBOLA_VulnerableWithSeed(t *testing.T) {
	// Server returns the same object (id 42, incl. a sensitive email) to every
	// caller — a broken object-level authorization.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","name":"Victim","email":"victim@example.com"}}}`)
	}))
	defer srv.Close()

	res, err := (&bolaCheck{}).Run(t.Context(), bolaContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != CRITICAL || f.Category != Authorization {
		t.Fatalf("unexpected severity/category: %v/%v", f.Severity, f.Category)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-639" || f.OWASP != "API1:2023" {
		t.Fatalf("classification not set: %q %q %q", f.Confidence, f.CWE, f.OWASP)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
	if res.ProbeCount < 2 {
		t.Fatalf("expected ProbeCount >= 2, got %d", res.ProbeCount)
	}
	// Evidence must be redacted: the raw email must never appear.
	if strings.Contains(f.Description, "victim@example.com") {
		t.Fatalf("raw email leaked in finding description: %s", f.Description)
	}
	if !strings.Contains(f.Description, "userB") || !strings.Contains(f.Description, "admin") {
		t.Fatalf("description should name attacker and owner: %s", f.Description)
	}
}

func TestBOLA_Protected(t *testing.T) {
	// Object 42 is owned by "admin"; everyone else is forbidden.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tokenOf(r) == "admin" {
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","name":"Admin"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"user":null},"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
	}))
	defer srv.Close()

	res, err := (&bolaCheck{}).Run(t.Context(), bolaContext(srv.URL, true))
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

func TestBOLA_DifferentObject(t *testing.T) {
	// Each token sees its own distinct object — proper isolation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch tokenOf(r) {
		case "admin":
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"42","name":"Admin"}}}`)
		case "userB":
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"99","name":"UserB"}}}`)
		default:
			_, _ = io.WriteString(w, `{"data":{"user":null},"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
		}
	}))
	defer srv.Close()

	res, err := (&bolaCheck{}).Run(t.Context(), bolaContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (different objects), got %d", len(res.Findings))
	}
}

func TestBOLA_NoIdentities(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql", Schema: bolaFixtureSchema()}
	res, err := (&bolaCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}

func TestBOLA_SelfDiscoveryViaList(t *testing.T) {
	// No seed: the owner id is discovered from the `users` list query, then the
	// vulnerable fetch returns the same object to the attacker.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := bolaReadQuery(r)
		if strings.Contains(q, "users") {
			_, _ = io.WriteString(w, `{"data":{"users":[{"id":"7"}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"user":{"id":"7","name":"Victim"}}}`)
	}))
	defer srv.Close()

	res, err := (&bolaCheck{}).Run(t.Context(), bolaContext(srv.URL, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding via self-discovery, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
}

func TestBOLA_NoFetchers(t *testing.T) {
	// Schema with only a list field (no id-bearing fetcher).
	users := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "id", Type: bolaScalar("ID")}}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "users", Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}}},
	}}
	cc := &CheckContext{
		Target: "http://example.com/graphql",
		Schema: &schema.Schema{QueryType: query, Types: map[string]*schema.TypeDef{"User": users, "Query": query}},
		Identities: []Identity{
			{Name: "admin", Privilege: 100, Client: transport.NewClient(time.Second, 10, nil)},
			{Name: "anonymous", Privilege: 0, Client: transport.NewClient(time.Second, 10, nil)},
		},
	}
	res, err := (&bolaCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.PassReason == "" {
		t.Fatalf("expected no findings + PassReason, got %d findings, pass=%q", len(res.Findings), res.PassReason)
	}
}
