// Package checks defines the core types, interfaces, and registry for scanner security checks.
package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/gqls-cli/gqls/pkg/domain"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// Type aliases re-export the domain types so that individual check files and
// tests in this package can reference them without importing pkg/domain directly.
// External packages (e.g. pkg/reporter) should import pkg/domain directly.
type (
	Severity    = domain.Severity
	Category    = domain.Category
	Finding     = domain.Finding
	PassProbe   = domain.PassProbe
	CheckResult = domain.CheckResult
	CurlRequest = domain.CurlRequest
)

// Severity constants re-exported from pkg/domain.
const (
	INFO     = domain.INFO
	LOW      = domain.LOW
	MEDIUM   = domain.MEDIUM
	HIGH     = domain.HIGH
	CRITICAL = domain.CRITICAL
)

// Category constants re-exported from pkg/domain.
const (
	InformationDisclosure = domain.InformationDisclosure
	DenialOfService       = domain.DenialOfService
	Authentication        = domain.Authentication
	Injection             = domain.Injection
)

// ParseSeverity delegates to domain.ParseSeverity.
var ParseSeverity = domain.ParseSeverity

// CheckContext bundles the shared resources passed to every check at runtime.
type CheckContext struct {
	// Target is the GraphQL endpoint URL.
	Target string
	// Schema is the parsed GraphQL schema; may be nil when schema extraction is skipped.
	Schema *schema.Schema
	// HTTPClient is the configured, rate-limited HTTP client. When --curl / --curl-file
	// is provided, this client carries the merged headers from both the curl command and
	// the --header flags. Injection-based checks (e.g. GQL-011) that need to reproduce
	// the original authenticated request context should use this client.
	HTTPClient *transport.Client
	// BaseHTTPClient is the HTTP client that carries only the --header flag values,
	// without any headers sourced from --curl / --curl-file. When no curl input was
	// provided it is identical to HTTPClient.
	//
	// Probing checks (GQL-002 through GQL-010, excluding injection checks) must use
	// this client so that their synthetic probes are not influenced by the
	// curl-file-specific authentication context.
	BaseHTTPClient *transport.Client
	// UnauthenticatedClient is a bare transport.Client with no default headers.
	// It is constructed once by the scan orchestrator with the same timeout and
	// rate-limit as the primary client. Checks that must probe without any
	// authentication headers (GQL-001, GQL-012) use this client instead of
	// constructing their own.
	UnauthenticatedClient *transport.Client
	// ParsedCurl contains the structured request data from a --curl / --curl-file
	// input. It is nil when no curl command was provided; checks must fall back to
	// cc.Target and cc.HTTPClient directly in that case.
	//
	// Checks requiring the full original HTTP context (Method, URL, Headers, Body)
	// — typically injection-based checks — should read from ParsedCurl and call
	// Clone before any modification. Checks that only require endpoint access
	// (introspection, batch, complexity, etc.) should use cc.Target with a freshly
	// generated GraphQL payload and must NOT reuse ParsedCurl.Body.
	ParsedCurl *CurlRequest
}

// ProbeClient returns the client that probing checks (GQL-002 through GQL-010,
// excluding injection-based checks) should use for their synthetic HTTP probes.
// It returns BaseHTTPClient when one has been configured, and falls back to
// HTTPClient otherwise (e.g. in tests or when no curl input was provided).
func (cc *CheckContext) ProbeClient() *transport.Client {
	if cc.BaseHTTPClient != nil {
		return cc.BaseHTTPClient
	}
	return cc.HTTPClient
}

// Check is the interface that every security check must implement.
type Check interface {
	// ID returns the globally unique identifier for this check (e.g. "GQL-001").
	ID() string
	// Name returns the short human-readable title of this check.
	Name() string
	// Category returns the vulnerability category this check targets.
	Category() Category
	// Severity returns the default severity level for findings from this check.
	Severity() Severity
	// RequiresSchema returns true if the check cannot run without a parsed schema.
	RequiresSchema() bool
	// Run executes the check against the target and returns the result.
	Run(ctx context.Context, c *CheckContext) (CheckResult, error)
}

// registry is the global list of registered checks.
var registry []Check

// Register adds a check to the global registry. Typically called from init().
func Register(c Check) {
	registry = append(registry, c)
}

// MustRegister adds a check to the global registry, panicking if c is nil.
// Typically called from init().
func MustRegister(c Check) {
	if c == nil {
		panic("checks: MustRegister called with nil Check")
	}
	Register(c)
}

// All returns a copy of the registered check list sorted by ID.
// Sorting in All() rather than at registration time guarantees a stable,
// ID-ordered result regardless of init() execution order across build tools.
func All() []Check {
	out := make([]Check, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID() < out[j].ID()
	})
	return out
}

// GenerateFingerprint returns a hex-encoded SHA-256 hash of the concatenated inputs,
// suitable for stable deduplication and false-positive suppression.
func GenerateFingerprint(checkID, target, evidenceKey string) string {
	h := sha256.New()
	h.Write([]byte(checkID))
	h.Write([]byte(target))
	h.Write([]byte(evidenceKey))
	return hex.EncodeToString(h.Sum(nil))
}
