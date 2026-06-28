package checks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

func i08Inj(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var p struct {
		Variables struct {
			Inj string `json:"inj"`
		} `json:"variables"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Variables.Inj
}

// i08SchemaArg builds a query field `probe(<argName>: String): [Item]`.
func i08SchemaArg(field, argName string) *schema.Schema {
	strType := &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}
	f := &schema.FieldDef{
		Name: field,
		Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "Item"}},
		Args: []*schema.ArgDef{{Name: argName, Type: strType}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{f}}
	return &schema.Schema{QueryType: qt, Types: map[string]*schema.TypeDef{"Query": qt}}
}

var i08ArithRe = regexp.MustCompile(`(\d+)\*(\d+)`)

// SSTI: server evaluates a*b → confirmed.
func TestI08_SSTI_Confirmed(t *testing.T) {
	cc := i08Server(t, func(inj string) string {
		if m := i08ArithRe.FindStringSubmatch(inj); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			return `{"data":{"render":[{"out":"` + strconv.Itoa(a*b) + `"}]}}` // evaluated
		}
		return `{"data":{"render":[]}}`
	})
	cc.Schema = i08SchemaArg("render", "template")

	res, err := (&ldapXMLTemplateInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if findOne(res.Findings, "Template") == nil {
		t.Fatalf("expected an SSTI finding, got %+v", res.Findings)
	}
	f := findOne(res.Findings, "Template")
	if f.Severity != HIGH || f.Confidence != "confirmed" || f.CWE != "CWE-1336" {
		t.Fatalf("SSTI finding wrong: sev=%v conf=%q cwe=%q", f.Severity, f.Confidence, f.CWE)
	}
}

// SSTI: server echoes the payload literally → no finding.
func TestI08_SSTI_LiteralEcho_NoFinding(t *testing.T) {
	cc := i08Server(t, func(inj string) string {
		return `{"data":{"render":[{"out":"` + jsonSafe(inj) + `"}]}}` // literal echo
	})
	cc.Schema = i08SchemaArg("render", "template")

	res, _ := (&ldapXMLTemplateInjectionCheck{}).Run(context.Background(), cc)
	if findOne(res.Findings, "Template") != nil {
		t.Fatalf("literal echo must not fire SSTI, got %+v", res.Findings)
	}
}

// LDAP: wildcard returns a superset → confirmed.
func TestI08_LDAP_Confirmed(t *testing.T) {
	cc := i08Server(t, func(inj string) string {
		if inj == "*" {
			return `{"data":{"users":[{"id":"1"},{"id":"2"},{"id":"3"}]}}`
		}
		return `{"data":{"users":[]}}` // specific control → none
	})
	cc.Schema = i08SchemaArg("users", "uid")

	res, err := (&ldapXMLTemplateInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	f := findOne(res.Findings, "LDAP")
	if f == nil {
		t.Fatalf("expected an LDAP finding, got %+v", res.Findings)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-90" {
		t.Fatalf("LDAP finding wrong: conf=%q cwe=%q", f.Confidence, f.CWE)
	}
}

// XML: internal entity reflected/expanded → firm; assert no external entity sent.
func TestI08_XML_InternalEntity_Firm(t *testing.T) {
	var sawExternalEntity int32
	entRe := regexp.MustCompile(`<!ENTITY e "([^"]*)"`)
	cc := i08Server(t, func(inj string) string {
		if strings.Contains(strings.ToUpper(inj), "SYSTEM") || strings.Contains(inj, "file:") || strings.Contains(inj, "://") {
			atomic.StoreInt32(&sawExternalEntity, 1)
		}
		// Model an XML parser that expands the internal entity (drops &e;).
		if m := entRe.FindStringSubmatch(inj); m != nil && strings.Contains(inj, "&e;") {
			return `{"data":{"document":[{"content":"` + m[1] + `"}]}}` // expanded, no &e;
		}
		return `{"data":{"document":[]}}`
	})
	cc.Schema = i08SchemaArg("document", "xml")

	res, err := (&ldapXMLTemplateInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	f := findOne(res.Findings, "XML")
	if f == nil {
		t.Fatalf("expected an XML finding, got %+v", res.Findings)
	}
	if f.Confidence != "firm" || f.CWE != "CWE-91" {
		t.Fatalf("XML finding wrong: conf=%q cwe=%q", f.Confidence, f.CWE)
	}
	if atomic.LoadInt32(&sawExternalEntity) != 0 {
		t.Fatal("check must never send an external/system entity payload")
	}
}

// Non-JSON response must not panic and must not fire.
func TestI08_NonJSON_NoPanic(t *testing.T) {
	cc := i08Server(t, func(string) string { return "not json \x00\xff" })
	cc.Schema = i08SchemaArg("render", "template")
	res, err := (&ldapXMLTemplateInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("non-JSON must not fire, got %+v", res.Findings)
	}
}

// Mutation-only points + AllowMutations=false → gated.
func TestI08_MutationOnly_Gated(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cc := newTestCheckContext(t, srv)
	cc.Schema = i01MutationOnlySchema() // createUser(name: String)
	cc.AllowMutations = false

	res, _ := (&ldapXMLTemplateInjectionCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 || res.ProbeCount != 0 || probed {
		t.Fatalf("gated mutation points must not be probed: findings=%d probes=%d probed=%v", len(res.Findings), res.ProbeCount, probed)
	}
}

func TestI08_NoSchema_Skips(t *testing.T) {
	res, _ := (&ldapXMLTemplateInjectionCheck{}).Run(context.Background(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

func TestI08_Metadata(t *testing.T) {
	c := &ldapXMLTemplateInjectionCheck{}
	if c.ID() != "GQL-I08" {
		t.Fatalf("ID = %q, want GQL-I08", c.ID())
	}
	if c.Severity() != HIGH || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}

// ── helpers ──

// i08Server builds a CheckContext whose server responds to each injected value
// via respond(inj). Fingerprint/other probes (no "inj" variable) get a benign body.
func i08Server(t *testing.T, respond func(inj string) string) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inj := i08Inj(r)
		w.Header().Set("Content-Type", "application/json")
		if inj == "" {
			_, _ = io.WriteString(w, `{"data":{"_":[]}}`)
			return
		}
		_, _ = io.WriteString(w, respond(inj))
	}))
	t.Cleanup(srv.Close)
	return newTestCheckContext(t, srv)
}

func findOne(findings []Finding, classSubstr string) *Finding {
	for i := range findings {
		if strings.Contains(findings[i].Title, classSubstr) {
			return &findings[i]
		}
	}
	return nil
}

// jsonSafe escapes characters that would break a hand-built JSON string literal.
func jsonSafe(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
