package checks

import (
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
)

func tc() *transport.Client { return transport.NewClient(time.Second, 10, nil) }

func TestCheckContext_HasIdentities(t *testing.T) {
	cc := &CheckContext{}
	if cc.HasIdentities() {
		t.Fatal("empty context should not have identities")
	}

	cc.Identities = []Identity{{Name: "admin", Privilege: 100, Client: tc()}}
	if cc.HasIdentities() {
		t.Fatal("single identity should not satisfy HasIdentities")
	}

	cc.Identities = append(cc.Identities, Identity{Name: "anonymous", Privilege: 0, Client: tc()})
	if !cc.HasIdentities() {
		t.Fatal("two identities should satisfy HasIdentities")
	}
}

func TestCheckContext_IdentityPairsAndByName(t *testing.T) {
	cc := &CheckContext{Identities: []Identity{
		{Name: "userA", Privilege: 10, Client: tc()},
		{Name: "admin", Privilege: 100, Client: tc()},
		{Name: "anonymous", Privilege: 0, Client: tc()},
	}}

	pairs := cc.IdentityPairs()
	if len(pairs) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(pairs))
	}
	// First pair should be the two highest-privilege identities, owner first.
	if pairs[0][0].Name != "admin" || pairs[0][1].Name != "userA" {
		t.Fatalf("first pair = (%s,%s), want (admin,userA)", pairs[0][0].Name, pairs[0][1].Name)
	}

	if got, ok := cc.IdentityByName("admin"); !ok || got.Privilege != 100 {
		t.Fatalf("IdentityByName(admin) = %+v, %v", got, ok)
	}
	if _, ok := cc.IdentityByName("ghost"); ok {
		t.Fatal("IdentityByName(ghost) should be false")
	}
}

func TestAuthorizationCategoryExported(t *testing.T) {
	if string(Authorization) != "Authorization" {
		t.Fatalf("Authorization category = %q", Authorization)
	}
}
