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

func tenantClient(headers map[string]string) *transport.Client {
	return transport.NewClient(5*time.Second, 50, headers)
}

// tenantIdent builds a tenant identity. When withHeader is true it carries an
// X-Tenant-Id header equal to its tenant.
func tenantIdent(name, tenant, token string, withHeader bool) Identity {
	hdrs := map[string]string{"Authorization": "Bearer " + token}
	if withHeader {
		hdrs["X-Tenant-Id"] = tenant
	}
	return Identity{Name: name, Privilege: 10, Tenant: tenant, Client: tenantClient(hdrs), Headers: hdrs}
}

// tokenTenant maps a known test token to its real tenant.
func tokenTenant(r *http.Request) string {
	switch tokenOf(r) {
	case "alice":
		return "t1"
	case "bob":
		return "t2"
	default:
		return ""
	}
}

func xtContext(url string, withHeader bool) *CheckContext {
	return &CheckContext{
		Target: url,
		Schema: boplaSchema(false), // Query{ user(id: ID!): User{ id name } }
		Identities: []Identity{
			tenantIdent("alice", "t1", "alice", withHeader),
			tenantIdent("bob", "t2", "bob", withHeader),
		},
		AuthzSeeds: map[string]string{"user": "200"}, // object 200 belongs to tenant t2 (bob)
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestXTenant_ObjectIDVector(t *testing.T) {
	// Server ignores tenancy entirely: object 200 is returned to any caller.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"user":{"id":"200","name":"VictimObj"}}}`)
	}))
	defer srv.Close()

	res, err := (&crossTenantCheck{}).Run(t.Context(), xtContext(srv.URL, false))
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
	if f.CWE != "CWE-639" || f.OWASP != "API1:2023" || f.Confidence != "confirmed" {
		t.Fatalf("classification not set: %q %q %q", f.Confidence, f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Title, "object-id crossing") {
		t.Fatalf("expected object-id vector in title: %s", f.Title)
	}
	if f.Fingerprint == "" || res.ProbeCount < 2 {
		t.Fatalf("fingerprint/probe count wrong: fp=%q probes=%d", f.Fingerprint, res.ProbeCount)
	}
}

func TestXTenant_HeaderVector(t *testing.T) {
	// Server trusts the X-Tenant-Id header: object 200 is returned iff the header
	// says tenant t2 — regardless of which token (tenant) is authenticated.
	var sawOverride atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Tenant-Id") == "t2" {
			if tokenOf(r) == "alice" { // tenant t1 token wielding tenant t2 header
				sawOverride.Store(true)
			}
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"200","name":"VictimObj"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"user":null},"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
	}))
	defer srv.Close()

	res, err := (&crossTenantCheck{}).Run(t.Context(), xtContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	if !strings.Contains(res.Findings[0].Title, "tenant header manipulation") {
		t.Fatalf("expected tenant-header vector in title: %s", res.Findings[0].Title)
	}
	if !sawOverride.Load() {
		t.Fatal("expected the check to send tenant t1's token with tenant t2's X-Tenant-Id header")
	}
}

func TestXTenant_Enforced(t *testing.T) {
	// Server scopes by the authenticated token's tenant and ignores the header,
	// so neither the id nor the header vector can cross the boundary.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tokenTenant(r) == "t2" { // object 200 belongs to t2 (bob)
			_, _ = io.WriteString(w, `{"data":{"user":{"id":"200","name":"VictimObj"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"user":null},"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
	}))
	defer srv.Close()

	res, err := (&crossTenantCheck{}).Run(t.Context(), xtContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (tenant isolation enforced), got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason explaining the clean result")
	}
}

// xtArgSchema has a fetcher with a required tenant-scoping argument:
// account(id: ID!, tenantId: ID!): Account.
func xtArgSchema() *schema.Schema {
	account := &schema.TypeDef{Name: "Account", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")},
		{Name: "name", Type: bolaScalar("String")},
	}}
	idArg := &schema.ArgDef{Name: "id", Type: &schema.TypeRef{Kind: schema.KindNonNull, OfType: bolaScalar("ID")}}
	tenantArg := &schema.ArgDef{Name: "tenantId", Type: &schema.TypeRef{Kind: schema.KindNonNull, OfType: bolaScalar("ID")}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "account", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Account"}, Args: []*schema.ArgDef{idArg, tenantArg}},
	}}
	return &schema.Schema{QueryType: query, Types: map[string]*schema.TypeDef{"Account": account, "Query": query}}
}

func TestXTenant_ArgVector(t *testing.T) {
	// Server trusts the tenantId argument: account 200 is returned when the arg
	// says t2, regardless of the authenticated token's tenant.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(bolaReadQuery(r), `tenantId: "t2"`) {
			_, _ = io.WriteString(w, `{"data":{"account":{"id":"200","name":"VictimObj"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"account":null},"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
	}))
	defer srv.Close()

	cc := &CheckContext{
		Target: srv.URL,
		Schema: xtArgSchema(),
		Identities: []Identity{
			tenantIdent("alice", "t1", "alice", false),
			tenantIdent("bob", "t2", "bob", false),
		},
		AuthzSeeds: map[string]string{"account": "200"},
	}
	res, err := (&crossTenantCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	if !strings.Contains(res.Findings[0].Title, "tenant argument manipulation") {
		t.Fatalf("expected tenant-arg vector in title: %s", res.Findings[0].Title)
	}
}

func TestXTenant_SingleTenantSkipped(t *testing.T) {
	cc := &CheckContext{
		Target: "http://example.com/graphql",
		Schema: boplaSchema(false),
		Identities: []Identity{
			tenantIdent("alice", "t1", "alice", true),
			tenantIdent("alice2", "t1", "alice2", true), // same tenant
		},
	}
	res, err := (&crossTenantCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}
