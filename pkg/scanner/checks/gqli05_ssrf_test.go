package checks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// i05URLSchema returns a query with a URL-like String arg ("url").
func i05URLSchema() *schema.Schema {
	strType := &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}
	field := &schema.FieldDef{
		Name: "fetch",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Result"},
		Args: []*schema.ArgDef{{Name: "url", Type: strType}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	return &schema.Schema{QueryType: qt, Types: map[string]*schema.TypeDef{"Query": qt}}
}

func i05Inj(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var p struct {
		Variables struct {
			Inj string `json:"inj"`
		} `json:"variables"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Variables.Inj
}

// --oob-domain set + correlated callback → confirmed CRITICAL.
func TestI05_OOB_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"fetch":{"__typename":"Result"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i05URLSchema()
	cc.OOBDomain = "oob.example"
	cc.OOBPoller = &fakeOOBPoller{hit: true}

	res, err := (&ssrfCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != CRITICAL || f.Confidence != "confirmed" {
		t.Fatalf("want CRITICAL/confirmed, got %v/%q", f.Severity, f.Confidence)
	}
	if f.CWE != "CWE-918" || f.OWASP != "API7:2023" {
		t.Fatalf("classification = %q/%q, want CWE-918/API7:2023", f.CWE, f.OWASP)
	}
	if !strings.Contains(f.Title, "fetch") || f.Fingerprint == "" {
		t.Fatalf("title/fingerprint not set: %q %q", f.Title, f.Fingerprint)
	}
}

// --oob-domain set but no callback → no finding.
func TestI05_OOB_NoHit_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"fetch":{"__typename":"Result"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i05URLSchema()
	cc.OOBDomain = "oob.example"
	cc.OOBPoller = &fakeOOBPoller{hit: false}

	res, _ := (&ssrfCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 {
		t.Fatalf("no callback must not fire, got %+v", res.Findings)
	}
}

// In-band: cloud-metadata-shaped response → firm CRITICAL.
func TestI05_InBand_Metadata_Firm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(i05Inj(r), "169.254.169.254") {
			_, _ = io.WriteString(w, `{"data":{"fetch":{"body":"ami-id: ami-123\ninstance-id: i-456\niam/info"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"fetch":{"body":"ok"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i05URLSchema() // no OOBDomain → in-band fallback

	res, err := (&ssrfCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != CRITICAL || f.Confidence != "firm" {
		t.Fatalf("metadata in-band should be CRITICAL/firm, got %v/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(strings.ToLower(f.Description), "metadata") {
		t.Fatalf("description should reference metadata: %s", f.Description)
	}
}

// Server ignores the URL arg → no finding; PassReason suggests --oob-domain.
func TestI05_IgnoresURL_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"fetch":{"body":"static"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i05URLSchema()

	res, err := (&ssrfCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("URL-ignoring server must not fire, got %+v", res.Findings)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "oob-domain") {
		t.Fatalf("PassReason should suggest --oob-domain: %q", res.PassReason)
	}
}

// No URL-like args → PassReason, no probes.
func TestI05_NoURLArgs_PassReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema() // user(id: String) — no URL-like arg

	res, _ := (&ssrfCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 || res.ProbeCount != 0 {
		t.Fatalf("no URL args → no findings/probes, got findings=%d probes=%d", len(res.Findings), res.ProbeCount)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "url") {
		t.Fatalf("PassReason should note no URL args: %q", res.PassReason)
	}
}

// Mutation-only URL points + AllowMutations=false → gated, no probes.
func TestI05_MutationOnly_Gated(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	strType := &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}
	field := &schema.FieldDef{
		Name: "setWebhook",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Result"},
		Args: []*schema.ArgDef{{Name: "url", Type: strType}},
	}
	mt := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	s := &schema.Schema{MutationType: mt, Types: map[string]*schema.TypeDef{"Mutation": mt}}

	cc := newTestCheckContext(t, srv)
	cc.Schema = s
	cc.AllowMutations = false

	res, _ := (&ssrfCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 || res.ProbeCount != 0 || probed {
		t.Fatalf("gated mutation points must not be probed: findings=%d probes=%d probed=%v", len(res.Findings), res.ProbeCount, probed)
	}
}

func TestI05_Metadata(t *testing.T) {
	c := &ssrfCheck{}
	if c.ID() != "GQL-I05" {
		t.Fatalf("ID = %q, want GQL-I05", c.ID())
	}
	if c.Severity() != CRITICAL || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
