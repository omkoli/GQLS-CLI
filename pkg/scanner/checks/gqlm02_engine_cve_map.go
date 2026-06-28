package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gqls-cli/gqls/pkg/scanner/fingerprint"
)

// engineCVEMapCheck implements GQL-M02: engine-specific known-CVE mapping. Once
// GQL-M01 has identified the backing engine (and, where detectable, its
// version), this check maps it against a curated, dated table of published
// advisories (CVEs / GHSAs) and emits one finding per applicable advisory.
//
// Safety: it never runs an exploit proof-of-concept. Version resolution is
// header-based only (a benign banner), and when a version cannot be confirmed
// the applicable advisories degrade to "tentative" rather than a fabricated or
// over-confident claim.
type engineCVEMapCheck struct{}

func init() {
	MustRegister(&engineCVEMapCheck{})
}

func (c *engineCVEMapCheck) ID() string           { return "GQL-M02" }
func (c *engineCVEMapCheck) Name() string         { return "Known Engine CVEs" }
func (c *engineCVEMapCheck) Category() Category   { return InformationDisclosure }
func (c *engineCVEMapCheck) Severity() Severity   { return INFO } // per-advisory severity is set on each finding
func (c *engineCVEMapCheck) RequiresSchema() bool { return false }

// Run executes the known-CVE mapping check.
func (c *engineCVEMapCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// 1. Identify the engine (GQL-M01 dependency).
	engine, _, probes := fingerprint.Identify(ctx, cc.ProbeClient(), cc.Target)
	result.ProbeCount += probes

	if !engine.Identified() {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "engine unknown; run GQL-M01 / cannot map CVEs"
		return result, nil
	}

	advs := fingerprint.Advisories(engine.Name)
	if len(advs) == 0 {
		result.PassReason = fmt.Sprintf(
			"no known advisories are catalogued for %s in the curated table", engine.Name)
		return result, nil
	}

	// 2. Resolve a version where possible (safe, header-based only).
	version, versionSource := c.resolveVersion(ctx, cc, engine.Name)
	if version != "" {
		result.ProbeCount++
	}
	versionKnown := version != ""

	// 3. Map each advisory; filter by version range when a version is known.
	skippedPatched := 0
	for _, adv := range advs {
		confidence := "tentative"
		var versionNote string

		switch {
		case versionKnown:
			inRange, err := fingerprint.VersionInRange(version, adv.VersionRange)
			switch {
			case err != nil:
				// Could not decide (unparseable) — degrade to tentative rather than drop.
				confidence = "tentative"
				versionNote = fmt.Sprintf(
					"detected version %s (from the %q header) could not be compared against the affected "+
						"range %q, so this advisory is reported tentatively",
					version, versionSource, adv.VersionRange)
			case inRange:
				confidence = "firm"
				versionNote = fmt.Sprintf(
					"detected version %s (from the %q header) falls within the affected range %s",
					version, versionSource, adv.VersionRange)
			default:
				// Version is known and outside the affected range → not applicable.
				skippedPatched++
				continue
			}
		default:
			confidence = "tentative"
			versionNote = "the running version could not be confirmed (no version banner), so this advisory " +
				"is reported tentatively — it applies only if the deployed version is in the affected range"
		}

		result.Findings = append(result.Findings, c.finding(cc, engine, adv, confidence, versionNote))
	}

	if len(result.Findings) == 0 {
		result.PassReason = fmt.Sprintf(
			"%s was identified at version %s, which is outside the affected range of all %d catalogued "+
				"advisor%s for this engine (likely patched)",
			engine.Name, version, len(advs), plural(len(advs), "y", "ies"))
	}
	return result, nil
}

// finding builds a single advisory finding.
func (c *engineCVEMapCheck) finding(
	cc *CheckContext, engine fingerprint.Engine, adv fingerprint.Advisory, confidence, versionNote string,
) Finding {
	cwe := adv.CWE
	if cwe == "" {
		cwe = "CWE-1395" // Dependency on a vulnerable third-party component.
	}
	owasp := adv.OWASP
	if owasp == "" {
		owasp = "API9:2023" // Improper Inventory Management.
	}

	vendor := ""
	if engine.Vendor != "" {
		vendor = " (" + engine.Vendor + ")"
	}

	description := fmt.Sprintf(
		"%s Detected engine: %s%s, with %s confidence via engine fingerprinting (GQL-M01). %s. Advisory: %s.",
		adv.Summary, engine.Name, vendor, engine.Confidence, capitalize(versionNote), adv.URL)

	impact := fmt.Sprintf(
		"If the deployed %s version is within %s, this advisory (%s, severity %s) applies and the engine is "+
			"exposed to the described vulnerability.",
		engine.Name, adv.VersionRange, adv.ID, adv.Severity.String())

	return Finding{
		CheckID:     c.ID(),
		CheckName:   c.Name(),
		Severity:    adv.Severity,
		Category:    c.Category(),
		Title:       fmt.Sprintf("%s — %s %s", adv.ID, engine.Name, adv.VersionRange),
		Description: description,
		Impact:      impact,
		Remediation: adv.Remediation,
		References: []string{
			adv.URL,
			fingerprint.AdvisoryDatabaseURL,
		},
		Confidence:  confidence,
		CWE:         cwe,
		OWASP:       owasp,
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "cve:"+adv.ID),
	}
}

// resolveVersion attempts a safe, header-only version probe. It sends a single
// benign `{ __typename }` request and extracts an engine-attributable version
// from the response headers. It returns ("","") when no version can be safely
// determined (the caller then degrades the findings to tentative).
func (c *engineCVEMapCheck) resolveVersion(ctx context.Context, cc *CheckContext, engineName string) (version, source string) {
	client := cc.ProbeClient()
	if client == nil {
		return "", ""
	}
	body, err := json.Marshal(map[string]string{"query": "{ __typename }"})
	if err != nil {
		return "", ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(body))
	if err != nil {
		return "", ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return "", ""
	}
	return fingerprint.VersionFromHeaders(engineName, resp.Headers)
}

// capitalize upper-cases the first rune of s (ASCII).
func capitalize(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}
