package inject

import (
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

func nn(t *schema.TypeRef) *schema.TypeRef {
	return &schema.TypeRef{Kind: schema.KindNonNull, OfType: t}
}
func list(t *schema.TypeRef) *schema.TypeRef {
	return &schema.TypeRef{Kind: schema.KindList, OfType: t}
}
func scalar(name string) *schema.TypeRef { return &schema.TypeRef{Kind: schema.KindScalar, Name: name} }
func obj(name string) *schema.TypeRef    { return &schema.TypeRef{Kind: schema.KindObject, Name: name} }
func input(name string) *schema.TypeRef {
	return &schema.TypeRef{Kind: schema.KindInputObject, Name: name}
}

// fixtureSchema builds: query user(filter: UserFilter, id: ID!) : User and
// mutation createPost(input: PostInput!) : Post, with
// UserFilter{ name: String, tags: [String] } and PostInput{ title: String!, body: String }.
func fixtureSchema() *schema.Schema {
	userFilter := &schema.TypeDef{
		Name: "UserFilter", Kind: schema.KindInputObject,
		InputFields: []*schema.FieldDef{
			{Name: "name", Type: scalar("String")},
			{Name: "tags", Type: list(scalar("String"))},
		},
	}
	postInput := &schema.TypeDef{
		Name: "PostInput", Kind: schema.KindInputObject,
		InputFields: []*schema.FieldDef{
			{Name: "title", Type: nn(scalar("String"))},
			{Name: "body", Type: scalar("String")},
		},
	}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "user", Type: obj("User"), Args: []*schema.ArgDef{
			{Name: "filter", Type: input("UserFilter")},
			{Name: "id", Type: nn(scalar("ID"))},
		}},
	}}
	mutation := &schema.TypeDef{Name: "Mutation", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "createPost", Type: obj("Post"), Args: []*schema.ArgDef{
			{Name: "input", Type: nn(input("PostInput"))},
		}},
	}}
	return &schema.Schema{
		QueryType:    query,
		MutationType: mutation,
		Types: map[string]*schema.TypeDef{
			"Query": query, "Mutation": mutation, "UserFilter": userFilter, "PostInput": postInput,
		},
	}
}

func findPoint(points []Point, opKind, root, pathKey string) (Point, bool) {
	for _, p := range points {
		if p.OpKind == opKind && p.RootField == root && p.PathKey() == pathKey {
			return p, true
		}
	}
	return Point{}, false
}

func TestPoints_EnumeratesNestedInputAndList(t *testing.T) {
	pts := Points(fixtureSchema())

	cases := []struct {
		op, root, path, scalar string
	}{
		{"query", "user", "filter.name", "String"},
		{"query", "user", "filter.tags.0", "String"},
		{"query", "user", "id", "ID"},
		{"mutation", "createPost", "input.title", "String"},
		{"mutation", "createPost", "input.body", "String"},
	}
	for _, c := range cases {
		p, ok := findPoint(pts, c.op, c.root, c.path)
		if !ok {
			t.Fatalf("missing point %s %s %s; got %+v", c.op, c.root, c.path, pts)
		}
		if p.ScalarType != c.scalar {
			t.Errorf("%s scalar = %q, want %q", c.path, p.ScalarType, c.scalar)
		}
	}

	// id is required (NON_NULL), filter.name is optional.
	if p, _ := findPoint(pts, "query", "user", "id"); !p.Required || !p.NonNull {
		t.Errorf("id point should be Required and NonNull: %+v", p)
	}
	if p, _ := findPoint(pts, "query", "user", "filter.name"); p.Required {
		t.Errorf("filter.name should be optional (filter arg is nullable): %+v", p)
	}
}

func TestPoints_Deterministic(t *testing.T) {
	s := fixtureSchema()
	a, b := Points(s), Points(s)
	if len(a) != len(b) {
		t.Fatalf("len differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].OpKind != b[i].OpKind || a[i].RootField != b[i].RootField || a[i].PathKey() != b[i].PathKey() {
			t.Fatalf("order not deterministic at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestRender_NestedInjectionAndRequiredFilling(t *testing.T) {
	s := fixtureSchema()

	// Injecting filter.name must fill the required sibling arg `id` and keep the
	// payload in variables.
	p, _ := findPoint(Points(s), "query", "user", "filter.name")
	doc, vars := p.Render(s, "PAYLOAD' OR '1'='1")
	if !strings.Contains(doc, "$inj: String") {
		t.Fatalf("doc should declare a String variable: %s", doc)
	}
	if !strings.Contains(doc, "filter: { name: $inj }") {
		t.Fatalf("doc should inject at filter.name: %s", doc)
	}
	if !strings.Contains(doc, `id: "gqls"`) {
		t.Fatalf("doc should fill the required `id` arg with an example: %s", doc)
	}
	if !strings.Contains(doc, "{ __typename }") {
		t.Fatalf("doc should select __typename for the object return type: %s", doc)
	}
	if vars["inj"] != "PAYLOAD' OR '1'='1" {
		t.Fatalf("payload should be carried in variables, got %v", vars["inj"])
	}

	// Injecting the optional input field `body` must fill the required `title`.
	pb, _ := findPoint(Points(s), "mutation", "createPost", "input.body")
	docb, _ := pb.Render(s, "x")
	if !strings.HasPrefix(docb, "mutation ") {
		t.Fatalf("mutation op kind expected: %s", docb)
	}
	if !strings.Contains(docb, `title: "gqls"`) || !strings.Contains(docb, "body: $inj") {
		t.Fatalf("required title must be filled and body injected: %s", docb)
	}
}

func TestRender_ListAndNonNullVariable(t *testing.T) {
	s := fixtureSchema()
	p, _ := findPoint(Points(s), "query", "user", "filter.tags.0")
	doc, _ := p.Render(s, "x")
	if !strings.Contains(doc, "tags: [$inj]") {
		t.Fatalf("list element injection should render [$inj]: %s", doc)
	}

	// Required ID! leaf → non-null variable type.
	pid, _ := findPoint(Points(s), "query", "user", "id")
	docid, _ := pid.Render(s, "x")
	if !strings.Contains(docid, "$inj: ID!") {
		t.Fatalf("required leaf should declare a non-null variable: %s", docid)
	}
}

func TestCap(t *testing.T) {
	pts := Points(fixtureSchema())
	if got := Cap(pts, 2); len(got) != 2 {
		t.Fatalf("Cap(…,2) len = %d, want 2", len(got))
	}
	if got := Cap(pts, 0); len(got) != len(pts) {
		t.Fatalf("Cap(…,0) must not truncate")
	}
}

func TestPoints_NilSchema(t *testing.T) {
	if Points(nil) != nil {
		t.Fatal("Points(nil) should be nil")
	}
}
