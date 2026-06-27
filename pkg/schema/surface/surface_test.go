package surface

import (
	"reflect"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// nn wraps a named type in NON_NULL.
func nn(of *schema.TypeRef) *schema.TypeRef {
	return &schema.TypeRef{Kind: schema.KindNonNull, OfType: of}
}

func named(kind schema.TypeKind, name string) *schema.TypeRef {
	return &schema.TypeRef{Kind: kind, Name: name}
}

func fixtureSchema() *schema.Schema {
	idArg := &schema.ArgDef{Name: "id", Type: nn(named(schema.KindScalar, "ID"))}

	userType := &schema.TypeDef{
		Name: "User", Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "id", Type: named(schema.KindScalar, "ID")},
			{Name: "name", Type: named(schema.KindScalar, "String")},
			{Name: "email", Type: named(schema.KindScalar, "String"), SensitivityScore: 4, Tags: []string{"pii"}},
			{Name: "ssn", Type: named(schema.KindScalar, "String"), SensitivityScore: 10, Tags: []string{"pii"}},
		},
	}
	colorType := &schema.TypeDef{Name: "Color", Kind: schema.KindEnum, EnumValues: []string{"RED", "GREEN"}}
	nodeType := &schema.TypeDef{Name: "Node", Kind: schema.KindInterface}
	statsType := &schema.TypeDef{Name: "Stats", Kind: schema.KindObject}

	queryType := &schema.TypeDef{
		Name: "Query", Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "user", Type: named(schema.KindObject, "User"), Args: []*schema.ArgDef{idArg}},
			{Name: "users", Type: &schema.TypeRef{Kind: schema.KindList, OfType: named(schema.KindObject, "User")}},
			{Name: "node", Type: named(schema.KindInterface, "Node"), Args: []*schema.ArgDef{idArg}},
			{Name: "adminStats", Type: named(schema.KindObject, "Stats")},
		},
	}
	mutationType := &schema.TypeDef{
		Name: "Mutation", Kind: schema.KindObject,
		Fields: []*schema.FieldDef{
			{Name: "updateProfile", Type: named(schema.KindObject, "User"), Args: []*schema.ArgDef{idArg}},
			{Name: "deleteUser", Type: named(schema.KindScalar, "Boolean"), Args: []*schema.ArgDef{idArg}},
			{Name: "promoteToAdmin", Type: named(schema.KindObject, "User"), Args: []*schema.ArgDef{idArg}},
		},
	}

	return &schema.Schema{
		QueryType:    queryType,
		MutationType: mutationType,
		Types: map[string]*schema.TypeDef{
			"User": userType, "Color": colorType, "Node": nodeType,
			"Stats": statsType, "Query": queryType, "Mutation": mutationType,
		},
	}
}

func TestFetchers(t *testing.T) {
	got := Fetchers(fixtureSchema())
	// Expect node and user (sorted), each id-bearing single-object fetch.
	// "users" (list) and "adminStats" (no id arg) excluded.
	if len(got) != 2 {
		t.Fatalf("expected 2 fetchers, got %d: %+v", len(got), got)
	}
	if got[0].RootField != "node" || got[1].RootField != "user" {
		t.Fatalf("expected [node, user], got [%s, %s]", got[0].RootField, got[1].RootField)
	}
	if got[1].IDArg != "id" || got[1].IDArgType != "ID" || got[1].ReturnType != "User" {
		t.Fatalf("user fetcher fields wrong: %+v", got[1])
	}
}

func TestPrivilegedOps(t *testing.T) {
	got := PrivilegedOps(fixtureSchema())
	// adminStats (query), deleteUser (mutation), promoteToAdmin (mutation).
	// updateProfile is NOT privileged by name.
	var names []string
	for _, op := range got {
		names = append(names, op.Field)
	}
	want := []string{"adminStats", "deleteUser", "promoteToAdmin"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("privileged ops = %v, want %v", names, want)
	}
	if got[0].IsMutation {
		t.Fatal("adminStats should be a query (queries listed first)")
	}
	if len(got[0].Reasons) == 0 {
		t.Fatal("expected a privilege reason for adminStats")
	}
}

func TestSensitiveFieldsByType(t *testing.T) {
	got := SensitiveFieldsByType(fixtureSchema())
	user, ok := got["User"]
	if !ok {
		t.Fatal("expected User in sensitive map")
	}
	// Sorted by score desc: ssn(10) then email(4).
	if len(user) != 2 || user[0].Field != "ssn" || user[1].Field != "email" {
		t.Fatalf("user sensitive fields = %+v", user)
	}
	if _, ok := got["Stats"]; ok {
		t.Fatal("Stats has no sensitive fields and should be absent")
	}
}

func TestExampleValue(t *testing.T) {
	s := fixtureSchema()
	cases := []struct {
		t    *schema.TypeRef
		want string
	}{
		{nn(named(schema.KindScalar, "ID")), `"1"`},
		{named(schema.KindScalar, "String"), `"1"`},
		{named(schema.KindScalar, "Int"), "1"},
		{named(schema.KindScalar, "Float"), "1.0"},
		{named(schema.KindScalar, "Boolean"), "true"},
		{named(schema.KindEnum, "Color"), "RED"},
		{named(schema.KindObject, "User"), ""},
	}
	for _, c := range cases {
		if got := ExampleValue(c.t, s); got != c.want {
			t.Fatalf("ExampleValue(%s) = %q, want %q", c.t.String(), got, c.want)
		}
	}
}
