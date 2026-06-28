package inject

import "context"

// OOBPoller correlates out-of-band (DNS/HTTP) callbacks to injected correlation
// tokens, for blind injection/SSRF detection. The concrete implementation —
// which talks to an interaction service such as a Collaborator-style listener —
// is provided by the SSRF foundation (GQL-I05); injection checks consume this
// interface and remain decoupled from the transport details. A nil poller means
// out-of-band probing is disabled.
type OOBPoller interface {
	// NewToken mints a unique correlation token (a DNS-label-safe string) used as
	// the subdomain of a probe URL/hostname.
	NewToken() string
	// Correlated reports whether a callback for token has been observed. It may
	// block briefly to poll the interaction service and must honor ctx.
	Correlated(ctx context.Context, token string) bool
}
