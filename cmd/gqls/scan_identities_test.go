package main

import (
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/config"
	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/transport"
)

func TestBuildIdentities_AppendsAnonymousWithDistinctClients(t *testing.T) {
	anon := transport.NewClient(time.Second, 10, nil)
	cfg := &config.ScanConfig{
		Timeout:   time.Second,
		RateLimit: 10,
		Identities: []config.IdentityConfig{
			{Name: "admin", Privilege: 100, Headers: map[string]string{"Authorization": "Bearer A"}},
			{Name: "userB", Privilege: 10, Headers: map[string]string{"Authorization": "Bearer B"}},
		},
	}

	ids := buildIdentities(cfg, anon)
	if len(ids) != 3 {
		t.Fatalf("expected 3 identities (2 + anonymous), got %d", len(ids))
	}
	if _, ok := authz.ByName(ids, authz.AnonymousName); !ok {
		t.Fatal("anonymous identity should be appended")
	}

	// Each authenticated identity must have its own dedicated client (not shared,
	// and not the anonymous client).
	seen := map[*transport.Client]bool{}
	for _, id := range ids {
		if id.Name == authz.AnonymousName {
			if id.Client != anon {
				t.Fatal("anonymous identity should reuse the anonymous client")
			}
			continue
		}
		if id.Client == nil {
			t.Fatalf("identity %s has nil client", id.Name)
		}
		if id.Client == anon {
			t.Fatalf("identity %s must not reuse the anonymous client", id.Name)
		}
		if seen[id.Client] {
			t.Fatalf("identity %s shares a client with another identity", id.Name)
		}
		seen[id.Client] = true
	}
}

func TestBuildIdentities_NoneConfigured(t *testing.T) {
	anon := transport.NewClient(time.Second, 10, nil)
	cfg := &config.ScanConfig{Timeout: time.Second, RateLimit: 10}
	if ids := buildIdentities(cfg, anon); ids != nil {
		t.Fatalf("expected nil identities when none configured, got %d", len(ids))
	}
}
