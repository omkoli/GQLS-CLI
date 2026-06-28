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

// i07Row is a record in the test dataset.
type i07Row struct{ name, role string }

var i07Dataset = []i07Row{{"alice", "user"}, {"bob", "user"}, {"carol", "admin"}}

// i07Eval applies a tiny Hasura-style predicate (_eq/_or/_like, {} = all) to the
// dataset and returns the matching rows.
func i07Eval(pred map[string]any, rows []i07Row) []i07Row {
	if len(pred) == 0 {
		return rows
	}
	if orRaw, ok := pred["_or"]; ok {
		seen := map[string]bool{}
		var out []i07Row
		if list, ok := orRaw.([]any); ok {
			for _, sub := range list {
				if m, ok := sub.(map[string]any); ok {
					for _, r := range i07Eval(m, rows) {
						if !seen[r.name] {
							seen[r.name] = true
							out = append(out, r)
						}
					}
				}
			}
		}
		return out
	}
	// Column predicates ANDed.
	out := rows
	for col, condRaw := range pred {
		cond, ok := condRaw.(map[string]any)
		if !ok {
			continue
		}
		var next []i07Row
		for _, r := range out {
			val := r.name
			if col == "role" {
				val = r.role
			}
			if eq, ok := cond["_eq"].(string); ok && val == eq {
				next = append(next, r)
			} else if lk, ok := cond["_like"].(string); ok && (lk == "%" || strings.Contains(val, strings.Trim(lk, "%"))) {
				next = append(next, r)
			}
		}
		out = next
	}
	return out
}

func i07Pred(r *http.Request) map[string]any {
	body, _ := io.ReadAll(r.Body)
	var p struct {
		Variables struct {
			Inj map[string]any `json:"inj"`
		} `json:"variables"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Variables.Inj
}

func i07RowsJSON(rows []i07Row) string {
	parts := make([]string, len(rows))
	for i := range rows {
		parts[i] = `{"__typename":"User"}`
	}
	return `{"data":{"users":[` + strings.Join(parts, ",") + `]}}`
}

// i07FilterSchema: query users(where: user_bool_exp): [User], with a Hasura-style
// bool-exp exposing columns name/role and operators _and/_or/_not.
func i07FilterSchema() *schema.Schema {
	strCmp := &schema.TypeRef{Kind: schema.KindInputObject, Name: "String_comparison_exp"}
	boolExp := &schema.TypeDef{
		Name: "user_bool_exp", Kind: schema.KindInputObject,
		InputFields: []*schema.FieldDef{
			{Name: "_and", Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindInputObject, Name: "user_bool_exp"}}},
			{Name: "_or", Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindInputObject, Name: "user_bool_exp"}}},
			{Name: "_not", Type: &schema.TypeRef{Kind: schema.KindInputObject, Name: "user_bool_exp"}},
			{Name: "name", Type: strCmp},
			{Name: "role", Type: strCmp},
		},
	}
	cmp := &schema.TypeDef{Name: "String_comparison_exp", Kind: schema.KindInputObject, InputFields: []*schema.FieldDef{
		{Name: "_eq", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
		{Name: "_like", Type: &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}},
	}}
	users := &schema.FieldDef{
		Name: "users",
		Type: &schema.TypeRef{Kind: schema.KindList, OfType: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}},
		Args: []*schema.ArgDef{{Name: "where", Type: &schema.TypeRef{Kind: schema.KindInputObject, Name: "user_bool_exp"}}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{users}}
	return &schema.Schema{
		QueryType: qt,
		Types: map[string]*schema.TypeDef{
			"Query": qt, "user_bool_exp": boolExp, "String_comparison_exp": cmp,
		},
	}
}

// i07Server returns a handler: Hasura header (engineHeader), filter eval for
// GqlsInj requests honoring predicates (or ignoring them when ignore=true).
func i07Server(t *testing.T, engineHeader bool, ignore bool) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if engineHeader {
			w.Header().Set("X-Hasura-Role", "anonymous")
		}
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(string(body), "GqlsInj") {
			// Fingerprint probe: Hasura is signalled by the header (when set);
			// otherwise return a neutral error with no engine-distinctive wording.
			if engineHeader {
				_, _ = io.WriteString(w, `{"data":{"__typename":"q"}}`)
			} else {
				_, _ = io.WriteString(w, `{"errors":[{"message":"validation error"}]}`)
			}
			return
		}
		if ignore {
			_, _ = io.WriteString(w, i07RowsJSON(i07Dataset)) // same set regardless
			return
		}
		_, _ = io.WriteString(w, i07RowsJSON(i07Eval(i07Pred(r), i07Dataset)))
	}))
	t.Cleanup(srv.Close)
	return &CheckContext{Target: srv.URL, HTTPClient: fpProbeClient(), BaseHTTPClient: fpProbeClient()}
}

// Hasura engine + predicate-honoring server → HIGH confirmed (target surfaces admin).
func TestI07_Hasura_Confirmed(t *testing.T) {
	cc := i07Server(t, true, false)
	cc.Schema = i07FilterSchema()

	res, err := (&ormOperatorInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != Injection {
		t.Fatalf("severity/category = %v/%v, want HIGH/Injection", f.Severity, f.Category)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-943" {
		t.Fatalf("classification = %q/%q, want confirmed/CWE-943", f.Confidence, f.CWE)
	}
	if !strings.Contains(f.Title, "users") || f.Fingerprint == "" {
		t.Fatalf("title/fingerprint not set: %q %q", f.Title, f.Fingerprint)
	}
}

// Predicate-ignoring server → no finding.
func TestI07_IgnoresPredicates_NoFinding(t *testing.T) {
	cc := i07Server(t, true, true)
	cc.Schema = i07FilterSchema()

	res, _ := (&ormOperatorInjectionCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 {
		t.Fatalf("predicate-ignoring server must not fire, got %+v", res.Findings)
	}
}

// Non-matching engine (Apollo) → predicate set gated, PassReason notes it.
func TestI07_NonMatchingEngine_Gated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Apollo fingerprint signature for the probe docs.
		_, _ = io.WriteString(w, `{"errors":[{"message":"Cannot query field \"x\" on type \"Query\". Did you mean \"y\"?","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`)
	}))
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, HTTPClient: fpProbeClient(), BaseHTTPClient: fpProbeClient()}
	cc.Schema = i07FilterSchema()

	res, err := (&ormOperatorInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("non-matching engine must gate the predicate set, got %+v", res.Findings)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "gated") {
		t.Fatalf("PassReason should note engine gating: %q", res.PassReason)
	}
}

// Unknown engine → conservative widening subset still runs (firm on widening).
func TestI07_UnknownEngine_Conservative(t *testing.T) {
	cc := i07Server(t, false, false) // no Hasura header, generic probe responses
	cc.Schema = i07FilterSchema()

	res, err := (&ormOperatorInjectionCheck{}).Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("conservative subset should fire on widening, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Confidence != "firm" {
		t.Fatalf("conservative (widen-only) should be firm, got %q", res.Findings[0].Confidence)
	}
}

func TestI07_NoFilterArgs_PassReason(t *testing.T) {
	cc := i07Server(t, true, false)
	cc.Schema = sqliStringArgSchema() // user(id: String) — no filter input arg

	res, _ := (&ormOperatorInjectionCheck{}).Run(context.Background(), cc)
	if len(res.Findings) != 0 {
		t.Fatalf("no filter args → no findings, got %+v", res.Findings)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "filter") {
		t.Fatalf("PassReason should note no filter args: %q", res.PassReason)
	}
}

func TestI07_NoSchema_Skips(t *testing.T) {
	res, _ := (&ormOperatorInjectionCheck{}).Run(context.Background(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

func TestI07_Metadata(t *testing.T) {
	c := &ormOperatorInjectionCheck{}
	if c.ID() != "GQL-I07" {
		t.Fatalf("ID = %q, want GQL-I07", c.ID())
	}
	if c.Severity() != HIGH || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
