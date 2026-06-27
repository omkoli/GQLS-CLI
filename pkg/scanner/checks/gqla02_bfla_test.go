package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

func bflaIdentities(url string) []Identity {
	return []Identity{
		{Name: "admin", Privilege: 100, Client: authClient(url, "admin")},
		{Name: "userB", Privilege: 10, Client: authClient(url, "userB")},
		{Name: "anonymous", Privilege: 0, Client: transport.NewClient(5*time.Second, 50, nil)},
	}
}

func idArgNN() *schema.ArgDef {
	return &schema.ArgDef{Name: "id", Type: &schema.TypeRef{Kind: schema.KindNonNull, OfType: bolaScalar("ID")}}
}

// bflaFullSchema has a privileged query (adminUsers) and two privileged
// mutations (deleteUser destructive, promoteToAdmin non-destructive).
func bflaFullSchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "id", Type: bolaScalar("ID")}}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "health", Type: bolaScalar("String")},
		{Name: "adminUsers", Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}}},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "deleteUser", Type: bolaScalar("Boolean"), Args: []*schema.ArgDef{idArgNN()}},
		{Name: "promoteToAdmin", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{"User": user, "Query": query, "Mutation": mutation}}
}

// bflaMutationOnlySchema has only a privileged (destructive) mutation.
func bflaMutationOnlySchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "id", Type: bolaScalar("ID")}}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "health", Type: bolaScalar("String")}}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "deleteUser", Type: bolaScalar("Boolean"), Args: []*schema.ArgDef{idArgNN()}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{"User": user, "Query": query, "Mutation": mutation}}
}

// bflaPromoteSchema has only a privileged non-destructive mutation.
func bflaPromoteSchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "id", Type: bolaScalar("ID")}}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "health", Type: bolaScalar("String")}}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "promoteToAdmin", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{"User": user, "Query": query, "Mutation": mutation}}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestBFLA_VulnerableQuery(t *testing.T) {
	// adminUsers executes for every caller — broken function-level authz.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"adminUsers":[{"id":"1"}]}}`)
	}))
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, Schema: bflaFullSchema(), Identities: bflaIdentities(srv.URL)}
	res, err := (&bflaCheck{}).Run(t.Context(), cc)
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
	if f.Confidence != "confirmed" || f.CWE != "CWE-285" || f.OWASP != "API5:2023" {
		t.Fatalf("classification not set: %q %q %q", f.Confidence, f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Title, "adminUsers") || !strings.Contains(f.Title, "query") {
		t.Fatalf("title should name the query op: %s", f.Title)
	}
	if f.Fingerprint == "" || res.ProbeCount < 2 {
		t.Fatalf("fingerprint/probe count wrong: fp=%q probes=%d", f.Fingerprint, res.ProbeCount)
	}
}

func TestBFLA_Protected(t *testing.T) {
	// adminUsers is callable only by admin; others are forbidden.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tokenOf(r) == "admin" {
			_, _ = io.WriteString(w, `{"data":{"adminUsers":[{"id":"1"}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":null,"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
	}))
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, Schema: bflaFullSchema(), Identities: bflaIdentities(srv.URL)}
	res, err := (&bflaCheck{}).Run(t.Context(), cc)
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

func TestBFLA_BaselineDenied(t *testing.T) {
	// Nobody (not even admin) can call adminUsers → op must be skipped, no FP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":null,"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
	}))
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, Schema: bflaFullSchema(), Identities: bflaIdentities(srv.URL)}
	res, err := (&bflaCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (baseline cannot call op), got %d", len(res.Findings))
	}
	if !strings.Contains(res.PassReason, "not callable by the privileged baseline") {
		t.Fatalf("PassReason should note baseline-denied skip: %q", res.PassReason)
	}
}

func TestBFLA_WriteGatedMutationNotProbed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"deleteUser":true}}`)
	}))
	defer srv.Close()

	// AllowMutations defaults to false → the destructive mutation must not be sent.
	cc := &CheckContext{Target: srv.URL, Schema: bflaMutationOnlySchema(), Identities: bflaIdentities(srv.URL)}
	res, err := (&bflaCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatalf("write-gated mutation must not hit the server; got %d requests", hits.Load())
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if !strings.Contains(res.PassReason, "write-gated") {
		t.Fatalf("PassReason should mention write-gating: %q", res.PassReason)
	}
}

func TestBFLA_AllowMutationsExecutes(t *testing.T) {
	var sawMutation atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(bolaReadQuery(r), "mutation") {
			sawMutation.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"promoteToAdmin":{"id":"1"}}}`)
	}))
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, Schema: bflaPromoteSchema(), Identities: bflaIdentities(srv.URL), AllowMutations: true}
	res, err := (&bflaCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	if !strings.Contains(res.Findings[0].Title, "mutation") || !strings.Contains(res.Findings[0].Title, "promoteToAdmin") {
		t.Fatalf("title should name the mutation op: %s", res.Findings[0].Title)
	}
	if !sawMutation.Load() {
		t.Fatal("expected the server to receive a mutation when --authz-allow-mutations is set")
	}
}

func TestBFLA_NoIdentities(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql", Schema: bflaFullSchema()}
	res, err := (&bflaCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}
