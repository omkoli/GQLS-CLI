package checks

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ── stateful coupon-redeem test server ───────────────────────────────────────

// bizAliasCallRe extracts (alias, code) pairs from an aliased redeemCoupon
// document so the stub can enforce a per-code one-time rule.
var bizAliasCallRe = regexp.MustCompile(`(a\d+):\s*redeemCoupon\(code:\s*"([^"]*)"\)`)

// bizServer is a tiny stateful GraphQL stub. redeemCoupon(code) increments a
// per-code counter and returns { balance } equal to the running count.
//   - protect=false: every redemption succeeds (the vulnerable behavior);
//     balance climbs 1,2,…,N across the aliased executions.
//   - protect=true : the first redemption of a code succeeds; every subsequent
//     one for the same code is rejected as "already redeemed".
type bizServer struct {
	mu        sync.Mutex
	counts    map[string]int
	protect   bool
	hits      atomic.Int32
	mutations atomic.Int32
}

func newBizServer(protect bool) *bizServer {
	return &bizServer{counts: map[string]int{}, protect: protect}
}

func (b *bizServer) handler(w http.ResponseWriter, r *http.Request) {
	b.hits.Add(1)
	q := bolaReadQuery(r)
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(strings.TrimSpace(q), "mutation") {
		_, _ = io.WriteString(w, `{"data":{}}`)
		return
	}
	b.mutations.Add(1)

	matches := bizAliasCallRe.FindAllStringSubmatch(q, -1)
	b.mu.Lock()
	defer b.mu.Unlock()

	var data, errs []string
	for _, m := range matches {
		alias, code := m[1], m[2]
		b.counts[code]++
		cnt := b.counts[code]
		if b.protect && cnt > 1 {
			data = append(data, fmt.Sprintf("%q:null", alias))
			errs = append(errs, `{"message":"coupon already redeemed"}`)
			continue
		}
		data = append(data, fmt.Sprintf(`%q:{"balance":%d,"__typename":"Redemption"}`, alias, cnt))
	}

	var sb strings.Builder
	sb.WriteString(`{"data":{` + strings.Join(data, ",") + "}")
	if len(errs) > 0 {
		sb.WriteString(`,"errors":[` + strings.Join(errs, ",") + "]")
	}
	sb.WriteString("}")
	_, _ = io.WriteString(w, sb.String())
}

// ── fixtures ─────────────────────────────────────────────────────────────────

// bizFlowSchema: Mutation{ redeemCoupon(code: String!): Redemption } with a
// numeric Redemption.balance effect field (for the confirmed read-back).
func bizFlowSchema() *schema.Schema {
	redemption := &schema.TypeDef{Name: "Redemption", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "balance", Type: bolaScalar("Int")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "health", Type: bolaScalar("String")},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "redeemCoupon", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Redemption"},
			Args: []*schema.ArgDef{strArgNN("code")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation,
		Types: map[string]*schema.TypeDef{"Redemption": redemption, "Query": query, "Mutation": mutation}}
}

// bizFlowScalarSchema: redeemCoupon returns a bare Boolean (no effect field →
// firm, not confirmed).
func bizFlowScalarSchema() *schema.Schema {
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "health", Type: bolaScalar("String")},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "redeemCoupon", Type: bolaScalar("Boolean"), Args: []*schema.ArgDef{strArgNN("code")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation,
		Types: map[string]*schema.TypeDef{"Query": query, "Mutation": mutation}}
}

// bizFlowDestructiveSchema: only a destructive-named flow (would otherwise match
// the sensitive-flow regex on "coupon").
func bizFlowDestructiveSchema() *schema.Schema {
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "health", Type: bolaScalar("String")},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "deleteCoupon", Type: bolaScalar("Boolean"), Args: []*schema.ArgDef{strArgNN("code")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation,
		Types: map[string]*schema.TypeDef{"Query": query, "Mutation": mutation}}
}

func bizContext(url string, s *schema.Schema) *CheckContext {
	return &CheckContext{
		Target:         url,
		Schema:         s,
		AllowMutations: true,
		HTTPClient:     transport.NewClient(5*time.Second, 50, nil),
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestBizFlow_VulnerableConfirmed(t *testing.T) {
	bs := newBizServer(false) // unprotected: honors all 20 aliases
	srv := httptest.NewServer(http.HandlerFunc(bs.handler))
	defer srv.Close()

	res, err := (&businessFlowAbuseCheck{}).Run(t.Context(), bizContext(srv.URL, bizFlowSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != BusinessLogic || f.CWE != "CWE-799" || f.OWASP != "API6:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "confirmed" {
		t.Fatalf("expected confirmed confidence (balance climbed across aliases), got %q", f.Confidence)
	}
	if !strings.Contains(f.Title, "redeemCoupon") || !strings.Contains(f.Title, "20") {
		t.Fatalf("title should name the mutation and multiplicity: %s", f.Title)
	}
	if f.Fingerprint == "" || res.ProbeCount < 1 {
		t.Fatalf("fingerprint/probe count wrong: fp=%q probes=%d", f.Fingerprint, res.ProbeCount)
	}
	// The probe must use a bogus, non-valuable identifier (never a real coupon).
	if !strings.Contains(string(f.ReproBody), "gqls-b01-") {
		t.Fatalf("expected a bogus probe identifier in the request: %s", f.ReproBody)
	}
	if bs.mutations.Load() != 1 {
		t.Fatalf("expected exactly one aliased mutation request, got %d", bs.mutations.Load())
	}
}

func TestBizFlow_VulnerableFirmWhenNoEffectField(t *testing.T) {
	// Boolean-returning flow: multiplicity is provable (firm) but there is no
	// numeric effect field to read back for a confirmed verdict.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := bolaReadQuery(r)
		var data []string
		for _, m := range aliasNameRe.FindAllStringSubmatch(q, -1) {
			data = append(data, fmt.Sprintf("%q:true", m[1]))
		}
		_, _ = io.WriteString(w, `{"data":{`+strings.Join(data, ",")+"}}")
	}))
	defer srv.Close()

	res, err := (&businessFlowAbuseCheck{}).Run(t.Context(), bizContext(srv.URL, bizFlowScalarSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	if res.Findings[0].Confidence != "firm" {
		t.Fatalf("expected firm confidence (no effect field), got %q", res.Findings[0].Confidence)
	}
}

func TestBizFlow_Protected(t *testing.T) {
	bs := newBizServer(true) // enforces one-per-code
	srv := httptest.NewServer(http.HandlerFunc(bs.handler))
	defer srv.Close()

	res, err := (&businessFlowAbuseCheck{}).Run(t.Context(), bizContext(srv.URL, bizFlowSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings against a one-per-key server, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason explaining the clean result")
	}
}

func TestBizFlow_DisabledByDefault(t *testing.T) {
	bs := newBizServer(false)
	srv := httptest.NewServer(http.HandlerFunc(bs.handler))
	defer srv.Close()

	cc := bizContext(srv.URL, bizFlowSchema())
	cc.AllowMutations = false // the default

	res, err := (&businessFlowAbuseCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
	if bs.hits.Load() != 0 {
		t.Fatalf("disabled check must send zero requests; got %d", bs.hits.Load())
	}
}

func TestBizFlow_DestructiveNotInvoked(t *testing.T) {
	bs := newBizServer(false)
	srv := httptest.NewServer(http.HandlerFunc(bs.handler))
	defer srv.Close()

	res, err := (&businessFlowAbuseCheck{}).Run(t.Context(), bizContext(srv.URL, bizFlowDestructiveSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if bs.hits.Load() != 0 {
		t.Fatalf("destructive-named flow must not be probed; got %d requests", bs.hits.Load())
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason")
	}
}

func TestBizFlow_NoCandidates(t *testing.T) {
	// A schema with no sensitive-flow mutation → clean pass, no requests.
	bs := newBizServer(false)
	srv := httptest.NewServer(http.HandlerFunc(bs.handler))
	defer srv.Close()

	res, err := (&businessFlowAbuseCheck{}).Run(t.Context(), bizContext(srv.URL, mutAuthzSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.PassReason == "" {
		t.Fatalf("expected clean pass with reason, got findings=%d pass=%q", len(res.Findings), res.PassReason)
	}
	if bs.hits.Load() != 0 {
		t.Fatalf("no candidate should mean zero requests; got %d", bs.hits.Load())
	}
}

func TestBizFlow_NoSchemaSkipped(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql", AllowMutations: true}
	res, err := (&businessFlowAbuseCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason when schema is nil, got %+v", res)
	}
}
