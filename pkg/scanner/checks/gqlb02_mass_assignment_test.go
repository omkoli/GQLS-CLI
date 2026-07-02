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

// ── stateful mass-assignment test server ─────────────────────────────────────

var (
	maIDRe      = regexp.MustCompile(`\bid:\s*"([^"]*)"`)
	maIsAdminRe = regexp.MustCompile(`isAdmin:\s*(true|false)`)
	maRoleRe    = regexp.MustCompile(`role:\s*"([^"]*)"`)
)

// maServer is a tiny stateful GraphQL stub. updateUser(id, input) can set
// isAdmin/role on the object; a query user(id) reads them back.
//   - honor=true : the resolver auto-binds the privileged input fields (vuln).
//   - honor=false: the resolver ignores the privileged input fields (safe).
type maServer struct {
	mu        sync.Mutex
	admin     map[string]bool
	role      map[string]string
	honor     bool
	hits      atomic.Int32
	mutations atomic.Int32
}

func newMAServer(honor bool, admin map[string]bool, role map[string]string) *maServer {
	return &maServer{admin: admin, role: role, honor: honor}
}

func (m *maServer) handler(w http.ResponseWriter, r *http.Request) {
	m.hits.Add(1)
	q := bolaReadQuery(r)
	id := firstSubmatch(maIDRe, q)
	w.Header().Set("Content-Type", "application/json")

	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.HasPrefix(strings.TrimSpace(q), "mutation") {
		m.mutations.Add(1)
		if m.honor {
			if am := maIsAdminRe.FindStringSubmatch(q); am != nil {
				m.admin[id] = am[1] == "true"
			}
			if rm := maRoleRe.FindStringSubmatch(q); rm != nil {
				m.role[id] = rm[1]
			}
		}
		_, _ = io.WriteString(w, `{"data":{"updateUser":{"__typename":"User"}}}`)
		return
	}
	_, _ = io.WriteString(w, fmt.Sprintf(`{"data":{"user":{"id":%q,"isAdmin":%t,"role":%q}}}`,
		id, m.admin[id], m.role[id]))
}

func (m *maServer) getAdmin(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.admin[id]
}

func (m *maServer) getRole(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.role[id]
}

// ── fixtures ─────────────────────────────────────────────────────────────────

func inputArgNN(name, inputType string) *schema.ArgDef {
	return &schema.ArgDef{Name: name, Type: &schema.TypeRef{Kind: schema.KindNonNull,
		OfType: &schema.TypeRef{Kind: schema.KindInputObject, Name: inputType}}}
}

// massAssignSchema: Mutation{ updateUser(id, input: UpdateUserInput) } +
// Query{ user(id): User }. UpdateUserInput carries privileged isAdmin/role.
func massAssignSchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")},
		{Name: "name", Type: bolaScalar("String")},
		{Name: "isAdmin", Type: bolaScalar("Boolean")},
		{Name: "role", Type: bolaScalar("String")},
	}}
	input := &schema.TypeDef{Name: "UpdateUserInput", Kind: schema.KindInputObject, InputFields: []*schema.FieldDef{
		{Name: "name", Type: bolaScalar("String")},
		{Name: "isAdmin", Type: bolaScalar("Boolean")},
		{Name: "role", Type: bolaScalar("String")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "updateUser", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
			Args: []*schema.ArgDef{idArgNN(), inputArgNN("input", "UpdateUserInput")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{
		"User": user, "UpdateUserInput": input, "Query": query, "Mutation": mutation}}
}

// massAssignRoleSchema: only a privileged String role field (no isAdmin) to
// exercise the string-sentinel path.
func massAssignRoleSchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")},
		{Name: "role", Type: bolaScalar("String")},
	}}
	input := &schema.TypeDef{Name: "ProfileInput", Kind: schema.KindInputObject, InputFields: []*schema.FieldDef{
		{Name: "role", Type: bolaScalar("String")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "updateProfile", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
			Args: []*schema.ArgDef{idArgNN(), inputArgNN("input", "ProfileInput")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{
		"User": user, "ProfileInput": input, "Query": query, "Mutation": mutation}}
}

// massAssignDestructiveSchema: the only candidate is a destructive-named flow.
func massAssignDestructiveSchema() *schema.Schema {
	user := &schema.TypeDef{Name: "User", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")},
		{Name: "isAdmin", Type: bolaScalar("Boolean")},
	}}
	input := &schema.TypeDef{Name: "PurgeInput", Kind: schema.KindInputObject, InputFields: []*schema.FieldDef{
		{Name: "isAdmin", Type: bolaScalar("Boolean")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "user", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"}, Args: []*schema.ArgDef{idArgNN()}},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "deleteUser", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "User"},
			Args: []*schema.ArgDef{idArgNN(), inputArgNN("input", "PurgeInput")}},
	}}
	return &schema.Schema{QueryType: query, MutationType: mutation, Types: map[string]*schema.TypeDef{
		"User": user, "PurgeInput": input, "Query": query, "Mutation": mutation}}
}

func massAssignContext(url string, s *schema.Schema) *CheckContext {
	return &CheckContext{
		Target:         url,
		Schema:         s,
		AllowMutations: true,
		HTTPClient:     aliasProbeClient(),
		AuthzSeeds:     map[string]string{"user": "42"},
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestMassAssign_VulnerableConfirmedAndRestored(t *testing.T) {
	ms := newMAServer(true, map[string]bool{"42": false}, map[string]string{"42": "user"})
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	res, err := (&massAssignCheck{}).Run(t.Context(), massAssignContext(srv.URL, massAssignSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != Authorization || f.CWE != "CWE-915" || f.OWASP != "API3:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "confirmed" {
		t.Fatalf("expected confirmed confidence, got %q", f.Confidence)
	}
	// Deterministic: with both isAdmin and role present, isAdmin is chosen first.
	if !strings.Contains(f.Title, "isAdmin") || !strings.Contains(f.Title, "updateUser") {
		t.Fatalf("title should name the field and mutation: %s", f.Title)
	}
	if !strings.Contains(f.Description, "restored successfully") {
		t.Fatalf("description should record restore status: %s", f.Description)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
	// The privileged field must have been reverted to its original value.
	if ms.getAdmin("42") {
		t.Fatalf("isAdmin should have been restored to false, got true")
	}
	if res.ProbeCount < 4 {
		t.Fatalf("expected >=4 probes (capture/inject/verify/restore), got %d", res.ProbeCount)
	}
}

func TestMassAssign_RoleStringConfirmed(t *testing.T) {
	ms := newMAServer(true, map[string]bool{}, map[string]string{"42": "user"})
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	res, err := (&massAssignCheck{}).Run(t.Context(), massAssignContext(srv.URL, massAssignRoleSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Confidence != "confirmed" || !strings.Contains(f.Title, "role") {
		t.Fatalf("expected confirmed role finding, got confidence=%q title=%q", f.Confidence, f.Title)
	}
	// A non-real (bogus) role sentinel must be used, never a real admin role.
	if !strings.Contains(string(f.ReproBody), "gqls-probe-role") {
		t.Fatalf("expected a non-real probe role in the request: %s", f.ReproBody)
	}
	if ms.getRole("42") != "user" {
		t.Fatalf("role should have been restored to 'user', got %q", ms.getRole("42"))
	}
}

func TestMassAssign_Protected(t *testing.T) {
	ms := newMAServer(false, map[string]bool{"42": false}, map[string]string{"42": "user"})
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	res, err := (&massAssignCheck{}).Run(t.Context(), massAssignContext(srv.URL, massAssignSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings when the server ignores privileged input, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason explaining the clean result")
	}
	if ms.getAdmin("42") {
		t.Fatalf("isAdmin must stay false on a protected server")
	}
}

func TestMassAssign_DisabledByDefault(t *testing.T) {
	ms := newMAServer(true, map[string]bool{"42": false}, map[string]string{"42": "user"})
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	cc := massAssignContext(srv.URL, massAssignSchema())
	cc.AllowMutations = false // the default

	res, err := (&massAssignCheck{}).Run(t.Context(), cc)
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

func TestMassAssign_DestructiveNotInvoked(t *testing.T) {
	ms := newMAServer(true, map[string]bool{"42": false}, map[string]string{})
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	res, err := (&massAssignCheck{}).Run(t.Context(), massAssignContext(srv.URL, massAssignDestructiveSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if ms.mutations.Load() != 0 {
		t.Fatalf("destructive-named mutation must not be invoked; got %d mutations", ms.mutations.Load())
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason")
	}
}

func TestMassAssign_MalformedResponseNoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{not valid json`)
	}))
	defer srv.Close()

	res, err := (&massAssignCheck{}).Run(t.Context(), massAssignContext(srv.URL, massAssignSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings on malformed responses, got %d", len(res.Findings))
	}
}

func TestMassAssign_NoCandidates(t *testing.T) {
	ms := newMAServer(true, map[string]bool{"42": false}, map[string]string{})
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer srv.Close()

	// mutAuthzSchema has updateUserName(id, name) — no privileged field.
	res, err := (&massAssignCheck{}).Run(t.Context(), massAssignContext(srv.URL, mutAuthzSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.PassReason == "" {
		t.Fatalf("expected clean pass with reason, got findings=%d pass=%q", len(res.Findings), res.PassReason)
	}
	if ms.mutations.Load() != 0 {
		t.Fatalf("no candidate should mean zero mutations; got %d", ms.mutations.Load())
	}
}
