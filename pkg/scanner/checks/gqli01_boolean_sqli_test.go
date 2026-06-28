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

// i01InjValue extracts variables.inj from a GraphQL request body.
func i01InjValue(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var p struct {
		Variables struct {
			Inj string `json:"inj"`
		} `json:"variables"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Variables.Inj
}

// i01MutationOnlySchema returns a schema whose only injectable point is a mutation arg.
func i01MutationOnlySchema() *schema.Schema {
	strType := &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}
	field := &schema.FieldDef{
		Name: "createUser",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
		Args: []*schema.ArgDef{{Name: "name", Type: strType}},
	}
	mt := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	return &schema.Schema{MutationType: mt, Types: map[string]*schema.TypeDef{"Mutation": mt}}
}

// A backend whose result set tracks the predicate → CRITICAL confirmed finding.
func TestI01_BooleanDifferential_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inj := i01InjValue(r)
		if strings.Contains(inj, "1'='1") { // tautology → rows
			_, _ = io.WriteString(w, `{"data":{"users":[{"id":"1"},{"id":"2"},{"id":"3"}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"users":[]}}`) // contradiction / baseline → no rows
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	res, err := (&booleanSQLiCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != CRITICAL || f.Category != Injection {
		t.Fatalf("severity/category = %v/%v, want CRITICAL/Injection", f.Severity, f.Category)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-89" {
		t.Fatalf("classification = %q/%q, want confirmed/CWE-89", f.Confidence, f.CWE)
	}
	if res.ProbeCount < 3 {
		t.Fatalf("ProbeCount = %d, want >= 3", res.ProbeCount)
	}
	if !strings.Contains(f.Title, "user") {
		t.Fatalf("title should name the root field: %s", f.Title)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
	// Payloads must be redacted — the raw tautology must not appear in output.
	if strings.Contains(f.Description, "OR '1'='1") || strings.Contains(f.Description, "OR '1'='2") {
		t.Fatalf("raw SQLi payload leaked into finding: %s", f.Description)
	}
}

// A backend insensitive to the predicate → no finding.
func TestI01_Insensitive_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"users":[{"id":"1"}]}}`) // identical regardless of input
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	res, err := (&booleanSQLiCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("predicate-insensitive server must not fire, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason when no injection is detected")
	}
}

// Only mutation injection points + AllowMutations=false → gated, no probes.
func TestI01_MutationOnly_WriteGated(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i01MutationOnlySchema()
	cc.AllowMutations = false

	res, err := (&booleanSQLiCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("write-gated mutation points must not fire, got %+v", res.Findings)
	}
	if res.ProbeCount != 0 || probed {
		t.Fatalf("no probes should be sent to gated mutation points (ProbeCount=%d, probed=%v)", res.ProbeCount, probed)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "write-gated") &&
		!strings.Contains(strings.ToLower(res.PassReason), "mutation") {
		t.Fatalf("PassReason should mention write-gating: %q", res.PassReason)
	}
}

// Nil schema → skipped.
func TestI01_NoSchema_Skips(t *testing.T) {
	res, _ := (&booleanSQLiCheck{}).Run(context.Background(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

// Malformed responses must never panic and must not produce a finding.
func TestI01_MalformedResponse_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json at all")
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	res, err := (&booleanSQLiCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("malformed responses must not produce a finding, got %+v", res.Findings)
	}
}

func TestI01_Metadata(t *testing.T) {
	c := &booleanSQLiCheck{}
	if c.ID() != "GQL-I01" {
		t.Fatalf("ID = %q, want GQL-I01", c.ID())
	}
	if c.Severity() != CRITICAL || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
