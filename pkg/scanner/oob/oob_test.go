package oob

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewToken_UniqueAndFormatted(t *testing.T) {
	c := New("oob.example")
	host1, url1 := c.NewToken()
	host2, _ := c.NewToken()

	if host1 == host2 {
		t.Fatalf("tokens must be unique: %s == %s", host1, host2)
	}
	if !strings.HasSuffix(host1, ".oob.example") {
		t.Fatalf("host should be under the domain: %s", host1)
	}
	if url1 != "http://"+host1+"/" {
		t.Fatalf("fullURL mismatch: %s vs host %s", url1, host1)
	}
	// Label must be DNS-safe (lowercase alphanumerics + dots).
	for _, r := range host1 {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.') {
			t.Fatalf("host has a non-DNS-safe rune %q: %s", r, host1)
		}
	}
}

func TestPoll_DelegatesToPollFunc(t *testing.T) {
	c := New("oob.example")
	// Default: no backend → no interactions, no error.
	hits, err := c.Poll(context.Background(), "tok.oob.example", 0)
	if err != nil || len(hits) != 0 {
		t.Fatalf("default Poll should return no hits/err, got %v / %v", hits, err)
	}

	c.PollFunc = func(_ context.Context, token string, _ time.Duration) ([]Interaction, error) {
		return []Interaction{{Protocol: "dns", Host: token, SourceIP: "203.0.113.7"}}, nil
	}
	hits, err = c.Poll(context.Background(), "tok.oob.example", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Host != "tok.oob.example" || hits[0].Protocol != "dns" {
		t.Fatalf("PollFunc result not returned: %+v", hits)
	}
}

// Client must satisfy the Poller interface.
var _ Poller = (*Client)(nil)
