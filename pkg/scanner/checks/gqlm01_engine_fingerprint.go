package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/fingerprint"
)

// engineFingerprintCheck implements GQL-M01: GraphQL engine fingerprinting. It
// identifies the backing engine (Apollo, Hasura, graphql-ruby, HotChocolate, …)
// from a small set of discriminator probes and emits an INFO finding with the
// result. The detection is a multiplier: it lets other checks tailor payloads
// and map engine-specific CVEs (GQL-M02).
type engineFingerprintCheck struct{}

func init() {
	MustRegister(&engineFingerprintCheck{})
}

func (c *engineFingerprintCheck) ID() string           { return "GQL-M01" }
func (c *engineFingerprintCheck) Name() string         { return "GraphQL Engine Fingerprint" }
func (c *engineFingerprintCheck) Category() Category   { return InformationDisclosure }
func (c *engineFingerprintCheck) Severity() Severity   { return INFO }
func (c *engineFingerprintCheck) RequiresSchema() bool { return false }

// Run executes the engine fingerprint check.
func (c *engineFingerprintCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	engine, evidence, probes := fingerprint.Identify(ctx, cc.ProbeClient(), cc.Target)
	result.ProbeCount += probes

	if probes == 0 {
		result.PassReason = "could not reach the endpoint to fingerprint the GraphQL engine"
		return result, nil
	}

	evParts := make([]string, 0, len(evidence))
	for _, e := range evidence {
		evParts = append(evParts, fmt.Sprintf("%s → %q", e.Probe, e.Signal))
	}
	evidenceStr := strings.Join(evParts, "; ")

	if !engine.Identified() {
		// Always emit (INFO) per the ticket: "unknown" is context, not a finding
		// to fail CI on, and carries no false attribution.
		result.Findings = append(result.Findings, Finding{
			CheckID:   c.ID(),
			CheckName: c.Name(),
			Severity:  INFO,
			Category:  InformationDisclosure,
			Title:     "GraphQL Engine Not Identified",
			Description: fmt.Sprintf(
				"The GraphQL engine could not be identified from the discriminator probes "+
					"(errors appear normalized, with no engine-distinctive wording or headers). Evidence: %s.",
				evidenceStr),
			Impact: "No engine-identifying signal was exposed — a good hardening posture. (Informational: " +
				"engine-specific CVE mapping and tailored payloads are unavailable for this target.)",
			Remediation: "No action required. Continue to normalize error messages and suppress " +
				"engine/version-identifying headers.",
			References: []string{
				"https://github.com/dolevf/graphw00f",
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			},
			Confidence:  "tentative",
			CWE:         "CWE-200",
			OWASP:       "API8:2023",
			Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "engine:unknown"),
		})
		return result, nil
	}

	vendor := engine.Vendor
	if vendor != "" {
		vendor = " (" + vendor + ")"
	}
	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  INFO,
		Category:  InformationDisclosure,
		Title:     "GraphQL Engine Identified — " + engine.Name,
		Description: fmt.Sprintf(
			"The backing GraphQL engine was identified as %s%s with %s confidence. Discriminating evidence: %s.",
			engine.Name, vendor, engine.Confidence, evidenceStr),
		Impact: "Engine identification narrows an attacker's exploit selection — engine-specific CVEs, " +
			"batching/introspection-defense behavior, and error oracles all follow from knowing the server.",
		Remediation: "Suppress engine-identifying error wording and headers in production; normalize error " +
			"messages; remove Server / X-Powered-By disclosure.",
		References: []string{
			"https://github.com/dolevf/graphw00f",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		Confidence:  engine.Confidence,
		CWE:         "CWE-200",
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "engine:"+engine.Name),
	})
	return result, nil
}
