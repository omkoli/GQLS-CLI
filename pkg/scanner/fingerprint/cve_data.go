package fingerprint

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gqls-cli/gqls/pkg/domain"
)

// Advisory describes a single known, published security advisory (CVE / GHSA)
// affecting a specific GraphQL engine and version range. Entries are
// hand-curated and dated: every Advisory is verified against the GitHub
// Advisory Database / NVD before being added, carries the upstream source URL,
// and records the date it was last verified. No advisory ID is ever invented —
// stale or unknown data degrades to a tentative finding (engine matches, version
// unconfirmed), never a fabricated CVE.
//
// Consumed by GQL-M02 (engine-specific known-CVE mapping).
type Advisory struct {
	// Engine is the engine name this advisory applies to. It must match the
	// fingerprint.Engine.Name produced by Identify (e.g. "Apollo Server").
	Engine string
	// VersionRange is a semver constraint over the affected versions, e.g.
	// ">=3.0.0 <3.7.5". Space-separated comparators are ANDed; "||" separates
	// alternative ranges (ORed). A bare version means exact match. See
	// VersionInRange for the supported grammar. Every entry's range must be
	// parseable (enforced by a data-integrity test).
	VersionRange string
	// ID is the verified CVE or GHSA identifier (never fabricated).
	ID string
	// Severity is the advisory's severity, applied to the emitted finding.
	Severity domain.Severity
	// Title is a short headline for the advisory.
	Title string
	// Summary explains the vulnerability (used in the finding description).
	Summary string
	// Remediation is the upstream fix guidance (upgrade to the fixed version).
	Remediation string
	// URL is the canonical advisory source (GitHub Advisory Database / NVD).
	URL string
	// CWE is the Common Weakness Enumeration id (e.g. "CWE-400"). Optional.
	CWE string
	// OWASP is the OWASP API Security Top 10 id. Optional; GQL-M02 defaults it
	// to "API9:2023" (Improper Inventory Management) when empty.
	OWASP string
	// VerifiedOn is the YYYY-MM-DD date this entry was last checked against the
	// upstream advisory database. Required for every entry.
	VerifiedOn string
}

// AdvisoryDatabaseURL is the canonical landing page for the GitHub Advisory
// Database; it is appended to every finding's references.
const AdvisoryDatabaseURL = "https://github.com/advisories"

// advisories is the curated, dated advisory table keyed by engine name. Each
// entry was verified against the GitHub Advisory Database / NVD on its
// VerifiedOn date. When adding an entry: confirm the ID exists upstream, copy
// the exact affected-version range, set the source URL, and stamp VerifiedOn.
var advisories = map[string][]Advisory{
	"Apollo Server": {
		{
			Engine:       "Apollo Server",
			VersionRange: ">=2.0.0 <2.25.4",
			ID:           "GHSA-2p3c-p3qw-69r4",
			Severity:     domain.MEDIUM,
			Title:        "CSRF via graphql-upload in Apollo Server 2",
			Summary: "The graphql-upload library bundled and enabled by default in Apollo Server 2 processes " +
				"GraphQL operations sent as multipart/form-data, which bypasses the CORS preflight check and " +
				"enables cross-site request forgery (CSRF) mutations against servers relying on cookies or " +
				"network-based access controls.",
			Remediation: "Upgrade Apollo Server to 2.25.4 or later (or migrate to Apollo Server 3+), or disable " +
				"file uploads. Require a non-simple custom header (e.g. a CSRF token) on all mutating requests.",
			URL:        "https://github.com/advisories/GHSA-2p3c-p3qw-69r4",
			CWE:        "CWE-352",
			OWASP:      "API8:2023",
			VerifiedOn: "2026-06-28",
		},
	},
	"graphql-js": {
		{
			Engine:       "graphql-js",
			VersionRange: ">=16.3.0 <16.8.1",
			ID:           "CVE-2023-26144",
			Severity:     domain.MEDIUM,
			Title:        "Denial of Service in graphql (OverlappingFieldsCanBeMerged)",
			Summary: "graphql-js is vulnerable to denial of service due to insufficient checks in the " +
				"OverlappingFieldsCanBeMergedRule validation, which exhibits quadratic time complexity when " +
				"processing large queries with many repeated fields sharing a response name, degrading server " +
				"performance.",
			Remediation: "Upgrade the graphql package to 16.8.1 or later.",
			URL:         "https://github.com/advisories/GHSA-9pv7-vfvm-6vr7",
			CWE:         "CWE-400",
			OWASP:       "API4:2023",
			VerifiedOn:  "2026-06-28",
		},
	},
	"graphql-ruby": {
		{
			Engine: "graphql-ruby",
			// Multiple maintained branches were patched; OR all affected ranges.
			VersionRange: ">=1.11.5 <1.11.11 || >=1.12.0 <1.12.25 || >=1.13.0 <1.13.24 || " +
				">=2.0.0 <2.0.32 || >=2.1.0 <2.1.15 || >=2.2.0 <2.2.17 || >=2.3.0 <2.3.21 || >=2.4.0 <2.4.13",
			ID:       "CVE-2025-27407",
			Severity: domain.CRITICAL,
			Title:    "Remote code execution loading a crafted GraphQL schema in graphql-ruby",
			Summary: "Loading a malicious schema definition via GraphQL::Schema.from_introspection (or " +
				"GraphQL::Schema::Loader.load) can result in remote code execution. Servers that build a schema " +
				"from an untrusted introspection result are affected.",
			Remediation: "Upgrade the graphql gem to a patched release for your branch (1.11.11, 1.12.25, " +
				"1.13.24, 2.0.32, 2.1.15, 2.2.17, 2.3.21, or 2.4.13 / later). Do not build schemas from " +
				"untrusted introspection responses.",
			URL:        "https://github.com/advisories/GHSA-q92j-grw3-h492",
			CWE:        "CWE-94",
			OWASP:      "API8:2023",
			VerifiedOn: "2026-06-28",
		},
	},
	"HotChocolate": {
		{
			Engine:       "HotChocolate",
			VersionRange: "<12.22.7 || >=13.0.0 <13.9.16 || >=14.0.0 <14.3.1 || >=15.0.0 <15.1.14",
			ID:           "CVE-2026-40324",
			Severity:     domain.HIGH,
			Title:        "Uncontrolled recursion (stack overflow) in HotChocolate Utf8GraphQLParser",
			Summary: "HotChocolate's Utf8GraphQLParser is a recursive-descent parser with no recursion-depth " +
				"limit, so a deeply nested GraphQL document (as small as ~40 KB) triggers an uncatchable " +
				"StackOverflowException that terminates the worker process — a denial of service.",
			Remediation: "Upgrade to HotChocolate 12.22.7, 13.9.16, 14.3.1, 15.1.14 or later, which add a " +
				"MaxAllowedRecursionDepth parser option that throws a catchable SyntaxException instead.",
			URL:        "https://github.com/advisories/GHSA-qr3m-xw4c-jqw3",
			CWE:        "CWE-674",
			OWASP:      "API4:2023",
			VerifiedOn: "2026-06-28",
		},
	},
	"Hasura": {
		{
			Engine: "Hasura",
			// The advisory documents v1.3.3 specifically; the upstream DB range is
			// "Unknown", so the table claims only the verified version.
			VersionRange: "=1.3.3",
			ID:           "CVE-2021-47713",
			Severity:     domain.HIGH,
			Title:        "Denial of service via deeply nested queries in Hasura GraphQL Engine 1.3.3",
			Summary: "Hasura GraphQL Engine 1.3.3 is vulnerable to denial of service: an unauthenticated " +
				"attacker can craft GraphQL queries with excessive nested fields to exhaust resources and " +
				"overwhelm the service.",
			Remediation: "Upgrade the Hasura GraphQL Engine to a current release and enable query depth/node " +
				"limits to bound query complexity.",
			URL:        "https://github.com/advisories/GHSA-c963-4j6g-xhmv",
			CWE:        "CWE-770",
			OWASP:      "API4:2023",
			VerifiedOn: "2026-06-28",
		},
	},
}

// Advisories returns the curated advisories for the given engine name (as
// produced by Identify). It returns nil when no advisories are catalogued for
// the engine. The returned slice is a copy, safe for the caller to mutate.
func Advisories(engine string) []Advisory {
	src := advisories[engine]
	if len(src) == 0 {
		return nil
	}
	out := make([]Advisory, len(src))
	copy(out, src)
	return out
}

// AllAdvisories returns every catalogued advisory across all engines. It is used
// by data-integrity tests and tooling.
func AllAdvisories() []Advisory {
	var out []Advisory
	for _, list := range advisories {
		out = append(out, list...)
	}
	return out
}

// ── semantic-version range matching ─────────────────────────────────────────

// semver is a parsed MAJOR.MINOR.PATCH version. Pre-release and build metadata
// (anything after '-' or '+') are dropped — sufficient for the curated ranges,
// which target released versions.
type semver struct{ major, minor, patch int }

// compare returns -1, 0, or 1 as a < b, a == b, or a > b.
func (a semver) compare(b semver) int {
	switch {
	case a.major != b.major:
		return cmpInt(a.major, b.major)
	case a.minor != b.minor:
		return cmpInt(a.minor, b.minor)
	default:
		return cmpInt(a.patch, b.patch)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// parseVersion parses "v3.7.5", "3.7", "16", "1.3.3-beta+exp" into a semver.
// Missing minor/patch components default to 0.
func parseVersion(s string) (semver, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	// Drop pre-release / build metadata.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return semver{}, fmt.Errorf("empty version")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return semver{}, fmt.Errorf("version %q has too many components", s)
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, fmt.Errorf("invalid version component %q in %q", p, s)
		}
		nums[i] = n
	}
	return semver{nums[0], nums[1], nums[2]}, nil
}

// comparator is a single "<op><version>" predicate within a range.
type comparator struct {
	op  string
	ver semver
}

func (c comparator) satisfied(v semver) bool {
	switch c.op {
	case ">":
		return v.compare(c.ver) > 0
	case ">=":
		return v.compare(c.ver) >= 0
	case "<":
		return v.compare(c.ver) < 0
	case "<=":
		return v.compare(c.ver) <= 0
	case "=", "==":
		return v.compare(c.ver) == 0
	default:
		return false
	}
}

// parseComparator parses one token such as ">=3.0.0", "<3.7.5", "=1.3.3", or a
// bare "1.3.3" (treated as "=1.3.3").
func parseComparator(tok string) (comparator, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return comparator{}, fmt.Errorf("empty comparator")
	}
	op := "="
	for _, candidate := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(tok, candidate) {
			op = candidate
			tok = strings.TrimSpace(tok[len(candidate):])
			break
		}
	}
	ver, err := parseVersion(tok)
	if err != nil {
		return comparator{}, err
	}
	return comparator{op: op, ver: ver}, nil
}

// parseConstraint parses a full range expression into OR-ed groups of AND-ed
// comparators. "||" separates alternatives; whitespace separates ANDed
// comparators within an alternative.
func parseConstraint(constraint string) ([][]comparator, error) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return nil, fmt.Errorf("empty version range")
	}
	var groups [][]comparator
	for _, alt := range strings.Split(constraint, "||") {
		var group []comparator
		for _, tok := range strings.Fields(alt) {
			c, err := parseComparator(tok)
			if err != nil {
				return nil, err
			}
			group = append(group, c)
		}
		if len(group) == 0 {
			return nil, fmt.Errorf("empty alternative in version range %q", constraint)
		}
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no comparators parsed from %q", constraint)
	}
	return groups, nil
}

// ValidateVersionRange reports whether constraint is a well-formed semver range.
// It is used by data-integrity tests to ensure every advisory has a parseable
// VersionRange.
func ValidateVersionRange(constraint string) error {
	_, err := parseConstraint(constraint)
	return err
}

// VersionInRange reports whether the given version satisfies the semver
// constraint. A version satisfies the constraint when it satisfies every
// comparator in at least one OR-ed alternative. An unparseable version or
// constraint returns (false, error) so callers can degrade safely.
func VersionInRange(version, constraint string) (bool, error) {
	v, err := parseVersion(version)
	if err != nil {
		return false, err
	}
	groups, err := parseConstraint(constraint)
	if err != nil {
		return false, err
	}
	for _, group := range groups {
		all := true
		for _, c := range group {
			if !c.satisfied(v) {
				all = false
				break
			}
		}
		if all {
			return true, nil
		}
	}
	return false, nil
}
