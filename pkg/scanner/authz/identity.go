// Package authz provides the core primitives for stateful GraphQL authorization
// testing: an operator-supplied multi-identity session model, a differential
// response oracle, and evidence redaction helpers.
//
// It depends only on pkg/transport and the standard library so that it can be
// imported by the checks package (and individual authz checks) without
// introducing an import cycle.
package authz

import (
	"sort"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// AnonymousName is the reserved identity name for the unauthenticated principal.
const AnonymousName = "anonymous"

// Identity is a single operator-supplied principal used for cross-identity
// authorization testing. Each Identity carries its own pre-configured HTTP
// client so a check can issue the same operation "as Alice", then "as Bob".
//
// Identities are never synthesized or brute-forced by the scanner; they are
// always provided by the operator (via --identity flags or the gqls.yaml
// `identities:` block). The anonymous identity (Privilege 0, no auth headers)
// is appended automatically when at least one authenticated identity exists.
type Identity struct {
	// Name is the operator-chosen label, e.g. "admin", "userA", "userB".
	Name string
	// Privilege ranks the identity; higher is more privileged. Anonymous is 0.
	// Used to order (owner, attacker) pairs for differential probes.
	Privilege int
	// Tenant is an optional tenant/org identifier used by cross-tenant checks.
	// Empty when not applicable.
	Tenant string
	// Client is the dedicated, rate-limited HTTP client carrying this identity's
	// headers (e.g. its Authorization token and any tenant header).
	Client *transport.Client
	// Headers is the resolved header set this identity carries. It lets checks
	// read and manipulate tenant-scoping headers (e.g. X-Tenant-Id) for
	// cross-tenant testing; it mirrors what Client injects. May be nil.
	Headers map[string]string
}

// HasMultiple reports whether ids contains at least two identities (including
// the auto-appended anonymous one), which is the minimum required for any
// differential authorization test.
func HasMultiple(ids []Identity) bool {
	return len(ids) >= 2
}

// ByName returns the identity with the given name, if present.
func ByName(ids []Identity, name string) (Identity, bool) {
	for _, id := range ids {
		if id.Name == name {
			return id, true
		}
	}
	return Identity{}, false
}

// WithAnonymous returns ids with an anonymous identity appended, but only when
// ids already contains at least one (authenticated) identity and does not
// already contain an identity named AnonymousName. anonClient is the bare,
// header-less transport client representing the unauthenticated principal.
//
// When ids is empty (no identities configured), it is returned unchanged so
// that authz checks cleanly skip rather than testing anonymous-vs-anonymous.
func WithAnonymous(ids []Identity, anonClient *transport.Client) []Identity {
	if len(ids) == 0 {
		return ids
	}
	if _, exists := ByName(ids, AnonymousName); exists {
		return ids
	}
	return append(ids, Identity{
		Name:      AnonymousName,
		Privilege: 0,
		Client:    anonClient,
	})
}

// Pairs returns every (higher-or-equal-privilege, lower-or-equal-privilege)
// ordered identity pair, suitable as (owner/victim, attacker) inputs to a
// differential authorization probe. The result is deterministic: identities
// are first sorted by Privilege descending, then by Name ascending, and every
// (i, j) with i < j in that order is emitted. Self-pairs are excluded.
//
// Example, for {admin(100), userA(10), userB(10), anonymous(0)}:
//
//	(admin,userA) (admin,userB) (admin,anonymous)
//	(userA,userB) (userA,anonymous) (userB,anonymous)
func Pairs(ids []Identity) [][2]Identity {
	if len(ids) < 2 {
		return nil
	}
	sorted := make([]Identity, len(ids))
	copy(sorted, ids)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Privilege != sorted[j].Privilege {
			return sorted[i].Privilege > sorted[j].Privilege
		}
		return sorted[i].Name < sorted[j].Name
	})

	var out [][2]Identity
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			out = append(out, [2]Identity{sorted[i], sorted[j]})
		}
	}
	return out
}
