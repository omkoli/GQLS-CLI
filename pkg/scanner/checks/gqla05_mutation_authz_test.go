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

	"github.com/gqls-cli/gqls/pkg/schema"
)

// ── stateful test server ─────────────────────────────────────────────────────

var (
	mutIDValRe   = regexp.MustCompile(`\bid:\s*"([^"]*)"`)
	mutNameValRe = regexp.MustCompile(`\b(?:name|label):\s*"([^"]*)"`)
)

// mutServer is a tiny stateful GraphQL stub: id → field value, with a write
// authorization predicate.
type mutServer struct {
	mu    sync.Mutex
	state map[string]string
	allow func(token string) bool
	hits  atomic.Int32
}

func newMutServer(initial map[string]string, allow func(string) bool) *mutServer {
	return &mutServer{state: initial, allow: allow}
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	return ""
}

func (m *mutServer) handler(w http.ResponseWriter, r *http.Request) {
	m.hits.Add(1)
	q := bolaReadQuery(r)
	id := firstSubmatch(mutIDValRe, q)
	w.Header().Set("Content-Type", "application/json")

	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.HasPrefix(strings.TrimSpace(q), "mutation") {
		if m.allow == nil || !m.allow(tokenOf(r)) {
			_, _ = io.WriteString(w, `{"data":null,"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
			return
		}
		m.state[id] = firstSubmatch(mutNameValRe, q)
		_, _ = io.WriteString(w, `{"data":{"m":{"__typename":"User"}}}`)
		return
	}
	_, _ = io.WriteString(w, fmt.Sprintf(`{"data":{"user":{"id":%q,"name":%q,"label":%q}}}`, id, m.state[id], m.state[id]))
}

func (m *mutServer) get(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state[id]
}

// ── fixtures ─────────────────────────────────────────────────────────────────

func strArgNN(name string) *schema.ArgDef {
	return &schema.ArgDef{Name: name, Type: &schema.TypeRef{Kind: schema.KindNonNull, OfType: bolaScalar("String")}}
}

// mutAuthzSchema: Mutation{ updateUserName(id, name) } + Query{ user(id): User }.
func mutAuthzSchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")}, {Name: "name", Type: bolaScalar("String")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "updateUserName", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
			Args: []*schema.ArgDef{idArgNN(), strArgNN("name")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{"User": user, "Query": query, "Mutation": mutation}}
}

// mutAuthzDestructiveSchema: only a destructive-named mutation (would otherwise
// be a valid candidate).
func mutAuthzDestructiveSchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")}, {Name: "label", Type: bolaScalar("String")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "deleteUser", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
			Args: []*schema.ArgDef{idArgNN(), strArgNN("label")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{"User": user, "Query": query, "Mutation": mutation}}
}

func mutAuthzContext(url string, s *schema.Schema) *CheckContext {
	return &CheckContext{
		Target:         url,
		Schema:         s,
		Identities:     bflaIdentities(url),
		AllowMutations: true,
		AuthzSeeds:     map[string]string{"user": "42"},
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestMutAuthz_VulnerableAndRestored(t *testing.T) {
	ms := newMutServer(map[string]string{"42": "Alice"}, func(string) bool { return true })
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	res, err := (&mutAuthzCheck{}).Run(t.Context(), mutAuthzContext(srv.URL, mutAuthzSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != CRITICAL || f.Category != Authorization || f.CWE != "CWE-285" || f.OWASP != "API5:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "confirmed" {
		t.Fatalf("expected confirmed confidence, got %q", f.Confidence)
	}
	if !strings.Contains(f.Title, "updateUserName") {
		t.Fatalf("title should name the mutation: %s", f.Title)
	}
	if !strings.Contains(f.Description, "restored successfully") {
		t.Fatalf("description should record restore status: %s", f.Description)
	}
	if got := ms.get("42"); got != "Alice" {
		t.Fatalf("object was not restored to its original value: got %q", got)
	}
	if res.ProbeCount < 4 {
		t.Fatalf("expected >=4 probes (capture/attack/verify/restore), got %d", res.ProbeCount)
	}
}

func TestMutAuthz_Protected(t *testing.T) {
	// Only the owner (admin) may write; non-owners are forbidden.
	ms := newMutServer(map[string]string{"42": "Alice"}, func(tok string) bool { return tok == "admin" })
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	res, err := (&mutAuthzCheck{}).Run(t.Context(), mutAuthzContext(srv.URL, mutAuthzSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason explaining the clean result")
	}
	if got := ms.get("42"); got != "Alice" {
		t.Fatalf("object should be unchanged, got %q", got)
	}
}

func TestMutAuthz_DisabledByDefault(t *testing.T) {
	ms := newMutServer(map[string]string{"42": "Alice"}, func(string) bool { return true })
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	cc := mutAuthzContext(srv.URL, mutAuthzSchema())
	cc.AllowMutations = false // the default

	res, err := (&mutAuthzCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
	if ms.hits.Load() != 0 {
		t.Fatalf("disabled check must send zero requests; got %d", ms.hits.Load())
	}
}

func TestMutAuthz_DestructiveNotInvoked(t *testing.T) {
	ms := newMutServer(map[string]string{"42": "Alice"}, func(string) bool { return true })
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	// Destructive-named mutation, not allow-listed → no candidate, no requests.
	res, err := (&mutAuthzCheck{}).Run(t.Context(), mutAuthzContext(srv.URL, mutAuthzDestructiveSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if ms.hits.Load() != 0 {
		t.Fatalf("destructive mutation must not be probed; got %d requests", ms.hits.Load())
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason")
	}
}

func TestMutAuthz_NoIdentities(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql", Schema: mutAuthzSchema(), AllowMutations: true}
	res, err := (&mutAuthzCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}
