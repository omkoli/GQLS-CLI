// Package oob provides a minimal out-of-band (OOB) interaction client for blind
// injection and SSRF detection: it mints unique correlation tokens under an
// operator-supplied collaborator domain (interactsh / Burp-Collaborator style)
// and polls for DNS/HTTP callbacks correlated to those tokens.
//
// The polling backend is pluggable (Client.PollFunc) so operators can wire an
// interactsh-compatible endpoint and the test suite can stub it. It is consumed
// by GQL-I05 (SSRF) and GQL-I04 (OS command injection).
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Interaction is a single correlated out-of-band callback.
type Interaction struct {
	// Protocol is the callback protocol, e.g. "dns" or "http".
	Protocol string
	// Host is the full subdomain that was looked up / requested.
	Host string
	// SourceIP is the remote address that initiated the callback, when known.
	SourceIP string
	// RawID is a backend-specific interaction identifier, when available.
	RawID string
}

// Poller is the capability injection/SSRF checks consume: mint a unique token
// and later poll for correlated callbacks. *Client implements it; tests provide
// their own implementations.
type Poller interface {
	// NewToken mints a unique correlation token, returning the full host
	// (<label>.<domain>) and a fetch URL (http://<host>/) to inject.
	NewToken() (host, fullURL string)
	// Poll reports interactions correlated to token (the host returned by
	// NewToken), waiting up to wait for them to arrive. It honors ctx.
	Poll(ctx context.Context, token string, wait time.Duration) ([]Interaction, error)
}

// Client is the default OOB interaction client.
type Client struct {
	// Domain is the operator-supplied collaborator domain (via --oob-domain).
	Domain string
	// PollFunc, when set, performs the correlation poll against a real backend
	// (e.g. interactsh) or a test stub. When nil, Poll returns no interactions —
	// OOB is configured but no backend is wired, so blind callbacks cannot be
	// observed (in-band detection still applies).
	PollFunc func(ctx context.Context, token string, wait time.Duration) ([]Interaction, error)
}

// New returns a Client for the given collaborator domain.
func New(domain string) *Client { return &Client{Domain: domain} }

// NewToken mints a unique host under the client's domain and a fetch URL for it.
func (c *Client) NewToken() (host, fullURL string) {
	host = randomLabel() + "." + c.Domain
	fullURL = "http://" + host + "/"
	return host, fullURL
}

// Poll delegates to PollFunc when set; otherwise it returns no interactions.
func (c *Client) Poll(ctx context.Context, token string, wait time.Duration) ([]Interaction, error) {
	if c.PollFunc != nil {
		return c.PollFunc(ctx, token, wait)
	}
	return nil, nil
}

// Summary renders a compact, non-sensitive description of correlated callbacks
// (protocol and source IP) for embedding in a finding.
func Summary(hits []Interaction) string {
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		p := h.Protocol
		if p == "" {
			p = "callback"
		}
		if h.SourceIP != "" {
			p += " from " + h.SourceIP
		}
		parts = append(parts, p)
	}
	return fmt.Sprintf("%d callback(s): %s", len(hits), strings.Join(parts, ", "))
}

// randomLabel returns a DNS-label-safe, unique-enough token prefix.
func randomLabel() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a time-derived label; uniqueness is best-effort.
		return "gqls" + hex.EncodeToString([]byte(time.Now().Format("150405.000000")))
	}
	return "gqls" + hex.EncodeToString(b[:])
}
