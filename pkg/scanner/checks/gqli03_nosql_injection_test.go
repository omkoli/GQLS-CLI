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

// i03Op decodes variables.inj (object or JSON-string-encoded) and reports
// whether it carries a $ne operator or an empty $in.
func i03Op(r *http.Request) (hasNe, hasInEmpty bool) {
	body, _ := io.ReadAll(r.Body)
	var p struct {
		Variables struct {
			Inj json.RawMessage `json:"inj"`
		} `json:"variables"`
	}
	_ = json.Unmarshal(body, &p)

	parse := func(raw []byte) {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return
		}
		if _, ok := m["$ne"]; ok {
			hasNe = true
		}
		if v, ok := m["$in"]; ok {
			var arr []any
			if json.Unmarshal(v, &arr) == nil && len(arr) == 0 {
				hasInEmpty = true
			}
		}
	}

	// Object mode: inj is a JSON object.
	parse(p.Variables.Inj)
	// String mode: inj is a JSON string whose contents are a JSON object.
	var s string
	if json.Unmarshal(p.Variables.Inj, &s) == nil {
		parse([]byte(s))
	}
	return hasNe, hasInEmpty
}

func i03JSONScalar() *schema.TypeRef { return &schema.TypeRef{Kind: schema.KindScalar, Name: "JSON"} }

func i03FilterSchema() *schema.Schema {
	field := &schema.FieldDef{
		Name: "users",
		Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}},
		Args: []*schema.ArgDef{{Name: "filter", Type: i03JSONScalar()}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	return &schema.Schema{
		QueryType: qt,
		Types:     map[string]*schema.TypeDef{"Query": qt, "JSON": {Name: "JSON", Kind: schema.KindScalar}},
	}
}

func i03LoginSchema() *schema.Schema {
	field := &schema.FieldDef{
		Name: "login",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Auth"},
		Args: []*schema.ArgDef{{Name: "password", Type: i03JSONScalar()}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	return &schema.Schema{
		QueryType: qt,
		Types:     map[string]*schema.TypeDef{"Query": qt, "JSON": {Name: "JSON", Kind: schema.KindScalar}},
	}
}

// A backend whose result set tracks $ne / $in:[] → CRITICAL finding.
func TestI03_OperatorDifferential_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hasNe, _ := i03Op(r)
		if hasNe { // $ne matches everything → superset
			_, _ = io.WriteString(w, `{"data":{"users":[{"id":"1"},{"id":"2"},{"id":"3"}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"users":[]}}`) // control / $in:[] → empty
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i03FilterSchema()

	res, err := (&nosqlInjectionCheck{}).Run(context.Background(), cc)
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
	if f.Confidence != "confirmed" || f.CWE != "CWE-943" {
		t.Fatalf("classification = %q/%q, want confirmed/CWE-943", f.Confidence, f.CWE)
	}
	if !strings.Contains(f.Title, "users") || f.Fingerprint == "" {
		t.Fatalf("title/fingerprint not set: %q %q", f.Title, f.Fingerprint)
	}
	if res.ProbeCount < 3 {
		t.Fatalf("ProbeCount = %d, want >= 3", res.ProbeCount)
	}
}

// A backend that ignores operators (constant result) → no finding.
func TestI03_OperatorIgnored_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"users":[{"id":"1"}]}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i03FilterSchema()

	res, err := (&nosqlInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("operator-insensitive server must not fire, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason when no operator effect is observed")
	}
}

// A credential field where {$ne:null} logs in while a control is denied → confirmed bypass.
func TestI03_CredentialBypass_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hasNe, _ := i03Op(r)
		if hasNe { // operator bypass → authenticated
			_, _ = io.WriteString(w, `{"data":{"login":{"token":"abc123"}}}`)
			return
		}
		// control (wrong password string) → denied
		_, _ = io.WriteString(w, `{"errors":[{"message":"invalid credentials","extensions":{"code":"UNAUTHENTICATED"}}]}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i03LoginSchema()

	res, err := (&nosqlInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != CRITICAL {
		t.Fatalf("severity = %v, want CRITICAL", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Description), "authentication-bypass") {
		t.Fatalf("description should note the auth-bypass variant: %s", f.Description)
	}
}

// Mutation-only injectable points + AllowMutations=false → gated, no probes.
func TestI03_MutationOnly_Gated(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	field := &schema.FieldDef{
		Name: "setFilter",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Result"},
		Args: []*schema.ArgDef{{Name: "filter", Type: i03JSONScalar()}},
	}
	mt := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	s := &schema.Schema{MutationType: mt, Types: map[string]*schema.TypeDef{"Mutation": mt, "JSON": {Name: "JSON", Kind: schema.KindScalar}}}

	cc := newTestCheckContext(t, srv)
	cc.Schema = s
	cc.AllowMutations = false

	res, err := (&nosqlInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.ProbeCount != 0 || probed {
		t.Fatalf("gated mutation points must not be probed: findings=%d probes=%d probed=%v", len(res.Findings), res.ProbeCount, probed)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "mutation") {
		t.Fatalf("PassReason should mention mutation gating: %q", res.PassReason)
	}
}

// Malformed responses must never panic and must not produce a finding.
func TestI03_Malformed_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i03FilterSchema()

	res, err := (&nosqlInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("malformed responses must not produce a finding, got %+v", res.Findings)
	}
}

func TestI03_NoSchema_Skips(t *testing.T) {
	res, _ := (&nosqlInjectionCheck{}).Run(context.Background(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

func TestI03_Metadata(t *testing.T) {
	c := &nosqlInjectionCheck{}
	if c.ID() != "GQL-I03" {
		t.Fatalf("ID = %q, want GQL-I03", c.ID())
	}
	if c.Severity() != CRITICAL || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
