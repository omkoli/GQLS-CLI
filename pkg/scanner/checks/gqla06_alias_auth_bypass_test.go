package checks

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// aliasProbeClient builds a plain probe client for the alias auth-bypass tests
// (GQL-A06 uses cc.ProbeClient() rather than per-identity clients).
func aliasProbeClient() *transport.Client { return transport.NewClient(5*time.Second, 50, nil) }

// ── fixtures ─────────────────────────────────────────────────────────────────

var aliasNameRe = regexp.MustCompile(`\b(a\d+):`)

// aliasAuthSchema: Mutation{ login(email: String!, password: String!): Boolean }.
func aliasAuthSchema() *schema.Schema {
	login := &schema.FieldDef{Name: "login", Type: bolaScalar("Boolean"),
		Args: []*schema.ArgDef{strArgNN("email"), strArgNN("password")}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "health", Type: bolaScalar("String")}}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{login}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{"Query": query, "Mutation": mutation}}
}

// echoAliasesHandler returns a data object with every aliased field set to false,
// i.e. it executes every aliased login attempt (the vulnerable behavior).
func echoAliasesHandler(w http.ResponseWriter, r *http.Request) {
	q := bolaReadQuery(r)
	w.Header().Set("Content-Type", "application/json")
	matches := aliasNameRe.FindAllStringSubmatch(q, -1)
	var b strings.Builder
	b.WriteString(`{"data":{`)
	for i, m := range matches {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:false", m[1])
	}
	b.WriteString("}}")
	_, _ = io.WriteString(w, b.String())
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestAliasAuth_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoAliasesHandler))
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, Schema: aliasAuthSchema(), BaseHTTPClient: aliasProbeClient()} // op auto-discovered
	res, err := (&aliasAuthBypassCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != Authorization || f.CWE != "CWE-307" || f.OWASP != "API4:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if !strings.Contains(f.Title, "Alias") {
		t.Fatalf("title should reference aliases: %s", f.Title)
	}
	if f.Fingerprint == "" || res.ProbeCount < 2 {
		t.Fatalf("fingerprint/probe count wrong: fp=%q probes=%d", f.Fingerprint, res.ProbeCount)
	}
	// Clearly-invalid sentinel credentials must be used (never a real credential).
	body := string(f.ReproBody)
	if !strings.Contains(body, "invalid.example") || !strings.Contains(body, "gqls-invalid-") {
		t.Fatalf("expected invalid sentinel credentials in the aliased request: %s", body)
	}
}

func TestAliasAuth_Limited(t *testing.T) {
	// The server rejects documents with more than one operation/alias.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if len(aliasNameRe.FindAllString(bolaReadQuery(r), -1)) > 1 {
			_, _ = io.WriteString(w, `{"errors":[{"message":"Too many operations in a single request"}]}`)
			return
		}
		echoAliasesHandler(w, r)
	}))
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, Schema: aliasAuthSchema(), BaseHTTPClient: aliasProbeClient()}
	res, err := (&aliasAuthBypassCheck{}).Run(t.Context(), cc)
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

func TestAliasAuth_SnippetFlagNoSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoAliasesHandler))
	defer srv.Close()

	// No schema, operator supplies a full operation snippet.
	cc := &CheckContext{Target: srv.URL, AuthzLoginOp: `login(email: "x@y.z", password: "p")`, BaseHTTPClient: aliasProbeClient()}
	res, err := (&aliasAuthBypassCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding via snippet flag, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
}

func TestAliasAuth_NoOpSkipped(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql"} // no schema, no flag
	res, err := (&aliasAuthBypassCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}

func TestAliasAuth_EndpointDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoAliasesHandler))
	url := srv.URL
	srv.Close() // make the endpoint unreachable

	cc := &CheckContext{Target: url, Schema: aliasAuthSchema(), BaseHTTPClient: aliasProbeClient()}
	res, err := (&aliasAuthBypassCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings when endpoint is down, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason for the unreachable endpoint")
	}
}
