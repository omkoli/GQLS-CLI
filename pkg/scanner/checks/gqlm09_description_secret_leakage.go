package checks

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
)

// descriptionSecretLeakageCheck implements GQL-M09: it scans the schema's
// free-text channels — type/field/argument descriptions, deprecation reasons,
// and argument default values — for leaked secrets (credentials, tokens,
// private keys, connection strings) and internal hints (internal hosts/IPs,
// "remove in prod" notes). GQL-006 flags sensitive field *names*; M09 covers the
// description and default-value channels GQL-006 misses.
//
// Safety: read-only schema analysis (no requests). Matched secrets are redacted
// via authz.MaskValue — the finding reports the location and class, never the
// raw secret.
type descriptionSecretLeakageCheck struct{}

func init() {
	MustRegister(&descriptionSecretLeakageCheck{})
}

func (c *descriptionSecretLeakageCheck) ID() string { return "GQL-M09" }
func (c *descriptionSecretLeakageCheck) Name() string {
	return "Secrets/Hints Leaked in Schema Descriptions & Defaults"
}
func (c *descriptionSecretLeakageCheck) Category() Category   { return InformationDisclosure }
func (c *descriptionSecretLeakageCheck) Severity() Severity   { return LOW }
func (c *descriptionSecretLeakageCheck) RequiresSchema() bool { return true }

// m09Matcher is one secret/hint pattern with its danger class.
type m09Matcher struct {
	re       *regexp.Regexp
	class    string
	severity Severity
	redact   bool                    // redact the matched value in output
	valid    func(match string) bool // optional extra validation
}

// m09Matchers are evaluated against every scanned string. Concrete credentials
// and connection-strings-with-credentials are MEDIUM; internal hints are LOW.
var m09Matchers = []m09Matcher{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws-access-key", MEDIUM, true, nil},
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`), "github-token", MEDIUM, true, nil},
	{regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "slack-token", MEDIUM, true, nil},
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`), "private-key", MEDIUM, true, nil},
	{regexp.MustCompile(`(?i)\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|rediss|amqps?)://[^\s:@/]+:[^\s:@/]+@[^\s/]+`), "connection-string", MEDIUM, true, nil},
	{regexp.MustCompile(`(?i)bearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), "bearer-jwt", MEDIUM, true, nil},
	{regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[=:]\s*["']?[^\s"']{6,}`), "secret-assignment", MEDIUM, true, m09SecretAssignmentValid},
	{regexp.MustCompile(`\b[A-Za-z0-9+/=_\-]{32,}\b`), "high-entropy-token", LOW, true, m09LooksHighEntropy},

	{regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`), "internal-ip", LOW, true, nil},
	{regexp.MustCompile(`(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+(internal|local|corp|svc|intranet|lan)\b`), "internal-host", LOW, true, nil},
	{regexp.MustCompile(`(?i)(TODO|FIXME|XXX|HACK|remove (?:this |it )?(?:before|in|for) prod|do ?not expose|don'?t expose|internal[ -]only|internal[ -]use only|not for prod(?:uction)?|for internal use)`), "internal-note", LOW, false, nil},
}

// m09Hit records one matched location/class.
type m09Hit struct {
	location string // e.g. "User.password" or "Query.user(token)"
	channel  string // "description" / "deprecation reason" / "default value" / "argument description"
	class    string
	severity Severity
	masked   string
}

// m09MaxHits bounds the rendered detail list.
const m09MaxHits = 40

// Run executes the schema secret/hint leakage check.
func (c *descriptionSecretLeakageCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no schema available; GQL-M09 analyzes schema descriptions and defaults"
		return result, nil
	}

	var hits []m09Hit
	seen := map[string]bool{}
	scan := func(text, location, channel string) {
		for _, h := range m09Scan(text, location, channel) {
			key := h.location + "|" + h.channel + "|" + h.class
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, h)
		}
	}

	typeNames := make([]string, 0, len(cc.Schema.Types))
	for name := range cc.Schema.Types {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)

	for _, typeName := range typeNames {
		td := cc.Schema.Types[typeName]
		if td == nil || cc.Schema.IsBuiltinType(typeName) {
			continue
		}
		scan(td.Description, typeName, "description")
		for _, f := range append(append([]*schema.FieldDef{}, td.Fields...), td.InputFields...) {
			loc := typeName + "." + f.Name
			scan(f.Description, loc, "description")
			scan(f.DeprecationReason, loc, "deprecation reason")
			for _, a := range f.Args {
				argLoc := fmt.Sprintf("%s(%s)", loc, a.Name)
				scan(a.Description, argLoc, "argument description")
				if a.DefaultValue != nil {
					scan(*a.DefaultValue, argLoc, "default value")
				}
			}
		}
	}

	if len(hits) == 0 {
		result.PassReason = "No secrets or internal hints were found in schema descriptions, deprecation " +
			"reasons, or argument default values."
		return result, nil
	}

	// Deterministic ordering for output and fingerprint.
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].location != hits[j].location {
			return hits[i].location < hits[j].location
		}
		if hits[i].channel != hits[j].channel {
			return hits[i].channel < hits[j].channel
		}
		return hits[i].class < hits[j].class
	})

	severity := LOW
	locationSet := map[string]bool{}
	var details []string
	for _, h := range hits {
		if h.severity > severity {
			severity = h.severity
		}
		locationSet[h.location] = true
		if len(details) < m09MaxHits {
			details = append(details, fmt.Sprintf("%s [%s] — %s (%s)", h.location, h.channel, h.class, h.masked))
		}
	}
	truncNote := ""
	if len(hits) > m09MaxHits {
		truncNote = fmt.Sprintf(" … and %d more.", len(hits)-m09MaxHits)
	}

	locations := make([]string, 0, len(locationSet))
	for l := range locationSet {
		locations = append(locations, l)
	}
	sort.Strings(locations)

	cwe := "CWE-200"
	if severity >= MEDIUM {
		cwe = "CWE-540" // Inclusion of sensitive information in source code / artifacts.
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  severity,
		Category:  c.Category(),
		Title:     fmt.Sprintf("Secrets/Internal Hints in Schema Descriptions or Defaults — %d location(s)", len(locations)),
		Description: fmt.Sprintf(
			"The schema leaks secrets or internal hints through descriptions, deprecation reasons, or argument "+
				"default values. Matched values are redacted — only the location and class are reported. "+
				"Findings: %s%s",
			strings.Join(details, "; "), truncNote),
		Impact: "Leaked credentials or connection strings enable direct compromise; internal hosts and endpoints " +
			"aid reconnaissance and pivoting; \"remove in prod\" notes reveal unfinished or missing controls. " +
			"These ship to anyone who can read the schema via introspection or suggestion-based reconstruction.",
		Remediation: "Keep secrets and internal notes out of schema descriptions, deprecation reasons, and " +
			"default values; lint the schema in CI for secret patterns; and rotate any exposed credential " +
			"immediately.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		Confidence:  "firm",
		CWE:         cwe,
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "schema_secrets:"+strings.Join(locations, ",")),
	})
	return result, nil
}

// m09Scan returns the distinct class hits for one string at one location/channel.
func m09Scan(text, location, channel string) []m09Hit {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []m09Hit
	seenClass := map[string]bool{}
	for _, m := range m09Matchers {
		match := m.re.FindString(text)
		if match == "" {
			continue
		}
		if m.valid != nil && !m.valid(match) {
			continue
		}
		if seenClass[m.class] {
			continue
		}
		seenClass[m.class] = true
		out = append(out, m09Hit{
			location: location,
			channel:  channel,
			class:    m.class,
			severity: m.severity,
			masked:   m09Render(match, m.redact),
		})
	}
	return out
}

// m09Render redacts a matched value (secret/host) or truncates a non-secret hint.
func m09Render(match string, redact bool) string {
	if redact {
		return authz.MaskValue(match)
	}
	match = strings.TrimSpace(match)
	if len(match) > 60 {
		match = match[:60] + "…"
	}
	return fmt.Sprintf("%q", match)
}

// m09SecretAssignmentValid rejects assignments whose value looks like an ordinary
// word (e.g. "password: required"), requiring a digit or special character.
func m09SecretAssignmentValid(match string) bool {
	i := strings.IndexAny(match, "=:")
	if i < 0 {
		return false
	}
	val := strings.Trim(strings.TrimSpace(match[i+1:]), `"'`)
	if len(val) < 6 {
		return false
	}
	return strings.ContainsAny(val, "0123456789!@#$%^&*-_./+=")
}

// m09LooksHighEntropy requires the long token to mix letters and digits, to skip
// long all-alphabetic words and pure numbers.
func m09LooksHighEntropy(match string) bool {
	hasLetter, hasDigit := false, false
	for _, r := range match {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		}
	}
	return hasLetter && hasDigit
}
