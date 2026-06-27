package authz

import (
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
)

func testClient() *transport.Client { return transport.NewClient(time.Second, 10, nil) }

func ids(specs ...[2]interface{}) []Identity {
	var out []Identity
	for _, s := range specs {
		out = append(out, Identity{Name: s[0].(string), Privilege: s[1].(int), Client: testClient()})
	}
	return out
}

func TestHasMultiple(t *testing.T) {
	if HasMultiple(nil) {
		t.Fatal("nil should not have multiple")
	}
	if HasMultiple(ids([2]interface{}{"a", 1})) {
		t.Fatal("single identity should not have multiple")
	}
	if !HasMultiple(ids([2]interface{}{"a", 1}, [2]interface{}{"b", 0})) {
		t.Fatal("two identities should have multiple")
	}
}

func TestByName(t *testing.T) {
	list := ids([2]interface{}{"admin", 100}, [2]interface{}{"user", 10})
	if got, ok := ByName(list, "user"); !ok || got.Privilege != 10 {
		t.Fatalf("ByName(user) = %+v, %v", got, ok)
	}
	if _, ok := ByName(list, "ghost"); ok {
		t.Fatal("ByName(ghost) should be false")
	}
}

func TestWithAnonymous(t *testing.T) {
	anon := testClient()

	// Empty stays empty (no anonymous-vs-anonymous testing).
	if got := WithAnonymous(nil, anon); len(got) != 0 {
		t.Fatalf("WithAnonymous(nil) should stay empty, got %d", len(got))
	}

	// One authenticated identity → anonymous appended.
	got := WithAnonymous(ids([2]interface{}{"admin", 100}), anon)
	if len(got) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(got))
	}
	if _, ok := ByName(got, AnonymousName); !ok {
		t.Fatal("anonymous identity should be appended")
	}

	// Already has anonymous → not duplicated.
	withAnon := []Identity{{Name: AnonymousName, Privilege: 0, Client: anon}, {Name: "admin", Privilege: 100, Client: anon}}
	got2 := WithAnonymous(withAnon, anon)
	count := 0
	for _, id := range got2 {
		if id.Name == AnonymousName {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 anonymous, got %d", count)
	}
}

func TestPairs_DeterministicOrdering(t *testing.T) {
	list := ids(
		[2]interface{}{"userB", 10},
		[2]interface{}{"admin", 100},
		[2]interface{}{"userA", 10},
		[2]interface{}{"anonymous", 0},
	)
	pairs := Pairs(list)

	// Expected order: sorted by Privilege desc, then Name asc:
	// admin(100), userA(10), userB(10), anonymous(0)
	want := [][2]string{
		{"admin", "userA"},
		{"admin", "userB"},
		{"admin", "anonymous"},
		{"userA", "userB"},
		{"userA", "anonymous"},
		{"userB", "anonymous"},
	}
	if len(pairs) != len(want) {
		t.Fatalf("expected %d pairs, got %d", len(want), len(pairs))
	}
	for i, w := range want {
		if pairs[i][0].Name != w[0] || pairs[i][1].Name != w[1] {
			t.Fatalf("pair %d = (%s,%s), want (%s,%s)", i, pairs[i][0].Name, pairs[i][1].Name, w[0], w[1])
		}
		if pairs[i][0].Privilege < pairs[i][1].Privilege {
			t.Fatalf("pair %d not ordered higher→lower privilege", i)
		}
	}

	// Determinism across repeated calls.
	again := Pairs(list)
	for i := range pairs {
		if pairs[i][0].Name != again[i][0].Name || pairs[i][1].Name != again[i][1].Name {
			t.Fatal("Pairs not deterministic across calls")
		}
	}
}

func TestPairs_TooFew(t *testing.T) {
	if Pairs(nil) != nil {
		t.Fatal("Pairs(nil) should be nil")
	}
	if Pairs(ids([2]interface{}{"a", 1})) != nil {
		t.Fatal("Pairs(single) should be nil")
	}
}
