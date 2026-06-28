package checks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

func i06Var(r *http.Request, key string) string {
	body, _ := io.ReadAll(r.Body)
	var p struct {
		Variables map[string]any `json:"variables"`
	}
	_ = json.Unmarshal(body, &p)
	if v, ok := p.Variables[key].(string); ok {
		return v
	}
	return ""
}

// Marker echoed raw in an error message → MEDIUM firm finding.
func TestI06_ReflectedRaw_Finding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inj := i06Var(r, "inj")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":[{"message":"no such user: `+inj+`"}]}`) // raw echo
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	res, err := (&xssCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM || f.Confidence != "firm" || f.CWE != "CWE-79" {
		t.Fatalf("classification = %v/%q/%q, want MEDIUM/firm/CWE-79", f.Severity, f.Confidence, f.CWE)
	}
	if !strings.Contains(f.Title, "user") || f.Fingerprint == "" {
		t.Fatalf("title/fingerprint not set: %q %q", f.Title, f.Fingerprint)
	}
	if !strings.Contains(f.Description, "<svg/onload=alert(1)>") {
		t.Fatalf("description should include the unescaped reflected snippet: %s", f.Description)
	}
}

// Marker echoed HTML-escaped → no finding (correct encoding).
func TestI06_ReflectedEscaped_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		esc := strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(i06Var(r, "inj"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":[{"message":"no such user: `+esc+`"}]}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	res, _ := (&xssCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 {
		t.Fatalf("escaped reflection must not fire, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason when reflection is correctly encoded")
	}
}

// Non-JSON/binary response must not panic and must not fire.
func TestI06_NonJSON_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte{0x00, 0x01, 0xff, 0xfe, 'g', 'q', 'l', 's'})
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	res, err := (&xssCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("binary response must not fire, got %+v", res.Findings)
	}
}

// i06StoredSchema: query me: User{bio}; mutation updateBio(bio: String): User{bio}.
func i06StoredSchema() *schema.Schema {
	strType := &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}
	userType := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{{Name: "bio", Type: strType}}}
	me := &schema.FieldDef{Name: "me", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}}
	updateBio := &schema.FieldDef{
		Name: "updateBio",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
		Args: []*schema.ArgDef{{Name: "bio", Type: strType}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{me}}
	mt := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{updateBio}}
	return &schema.Schema{QueryType: qt, MutationType: mt, Types: map[string]*schema.TypeDef{"Query": qt, "Mutation": mt, "User": userType}}
}

// Stored path: write marker → read-back unescaped → finding; original restored.
func TestI06_Stored_Finding_AndRestore(t *testing.T) {
	var mu sync.Mutex
	bio := "original-bio"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "updateBio") {
			var p struct {
				Variables map[string]any `json:"variables"`
			}
			_ = json.Unmarshal(body, &p)
			mu.Lock()
			if v, ok := p.Variables["v"].(string); ok {
				bio = v
			}
			cur := bio
			mu.Unlock()
			_, _ = io.WriteString(w, `{"data":{"updateBio":{"bio":"`+cur+`"}}}`)
			return
		}
		mu.Lock()
		cur := bio
		mu.Unlock()
		_, _ = io.WriteString(w, `{"data":{"me":{"bio":"`+cur+`"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i06StoredSchema()
	cc.AllowMutations = true

	res, err := (&xssCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 stored finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	if !strings.Contains(res.Findings[0].Title, "stored") {
		t.Fatalf("title should mark the stored path: %s", res.Findings[0].Title)
	}
	mu.Lock()
	final := bio
	mu.Unlock()
	if final != "original-bio" {
		t.Fatalf("original value must be restored, got %q", final)
	}
}

// Without AllowMutations, the stored path is skipped and noted.
func TestI06_Stored_WriteGated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"me":{"bio":"x"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i06StoredSchema()
	cc.AllowMutations = false

	res, _ := (&xssCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 {
		t.Fatalf("stored path must be gated, got %+v", res.Findings)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "write-gated") {
		t.Fatalf("PassReason should note the stored path was write-gated: %q", res.PassReason)
	}
}

func TestI06_NoSchema_Skips(t *testing.T) {
	res, _ := (&xssCheck{}).Run(context.Background(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

func TestI06_Metadata(t *testing.T) {
	c := &xssCheck{}
	if c.ID() != "GQL-I06" {
		t.Fatalf("ID = %q, want GQL-I06", c.ID())
	}
	if c.Severity() != MEDIUM || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
