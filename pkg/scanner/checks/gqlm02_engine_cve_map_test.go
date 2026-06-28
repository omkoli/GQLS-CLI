package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/scanner/fingerprint"
)

// apolloDiscriminatorBody elicits the Apollo Server fingerprint (an Apollo error
// code plus "Did you mean" wording). It is reused across the M02 tests.
const apolloDiscriminatorBody = `{"errors":[{"message":"Cannot query field \"x\" on type \"Query\". Did you mean \"y\"?","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`

// apolloCSRFAdvisory is the single catalogued Apollo Server advisory id.
const apolloCSRFAdvisory = "GHSA-2p3c-p3qw-69r4"

func findByAdvisory(findings []Finding, id string) *Finding {
	for i := range findings {
		if strings.Contains(findings[i].Title, id) {
			return &findings[i]
		}
	}
	return nil
}

// Given an engine+version that falls in an advisory's range, the finding fires
// at the advisory's severity with firm confidence.
func TestM02_VersionInRange_FiresFirm(t *testing.T) {
	srv := fpServer(apolloDiscriminatorBody, map[string]string{"Server": "Apollo Server/2.25.3"})
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, err := (&engineCVEMapCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatalf("identified engine must not skip: %s", res.SkipReason)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 Apollo advisory finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := findByAdvisory(res.Findings, apolloCSRFAdvisory)
	if f == nil {
		t.Fatalf("expected %s finding, got titles: %v", apolloCSRFAdvisory, res.Findings[0].Title)
	}
	if f.Severity != MEDIUM {
		t.Fatalf("severity = %v, want MEDIUM (per advisory)", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Fatalf("confidence = %q, want firm (version in range)", f.Confidence)
	}
	if f.Category != InformationDisclosure {
		t.Fatalf("category = %v, want InformationDisclosure", f.Category)
	}
	if f.CWE != "CWE-352" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q, want CWE-352/API8:2023", f.CWE, f.OWASP)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
	if !strings.Contains(f.Description, "2.25.3") {
		t.Fatalf("description should record the detected version: %s", f.Description)
	}
	if !strings.Contains(f.Title, "Apollo Server") {
		t.Fatalf("title should name the engine: %s", f.Title)
	}
	// References must carry both the advisory URL and the advisory-database landing page.
	if !containsString(f.References, fingerprint.AdvisoryDatabaseURL) {
		t.Fatalf("references should include the advisory database URL: %v", f.References)
	}
	if !containsString(f.References, "https://github.com/advisories/"+apolloCSRFAdvisory) {
		t.Fatalf("references should include the specific advisory URL: %v", f.References)
	}
}

// Given an engine but no detectable version, applicable advisories fire as tentative.
func TestM02_EngineOnly_Tentative(t *testing.T) {
	srv := fpServer(apolloDiscriminatorBody, nil) // no version banner
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, err := (&engineCVEMapCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 tentative advisory finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Confidence != "tentative" {
		t.Fatalf("confidence = %q, want tentative (version unknown)", f.Confidence)
	}
	if f.Severity != MEDIUM {
		t.Fatalf("severity = %v, want MEDIUM (advisory severity preserved even when tentative)", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Description), "version could not be confirmed") {
		t.Fatalf("tentative description should note the unconfirmed version: %s", f.Description)
	}
}

// Given a version outside every advisory range (patched), the check fires nothing
// and explains why.
func TestM02_PatchedVersion_NoFindings(t *testing.T) {
	srv := fpServer(apolloDiscriminatorBody, map[string]string{"Server": "Apollo Server/2.25.4"})
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, err := (&engineCVEMapCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatal("identified engine must not skip")
	}
	if len(res.Findings) != 0 {
		t.Fatalf("patched version must not fire any advisory, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a pass reason explaining the version is outside affected ranges")
	}
}

// Given an unknown engine, the check skips.
func TestM02_UnknownEngine_Skips(t *testing.T) {
	srv := fpServer(`{"errors":[{"message":"Validation error"}]}`, nil)
	defer srv.Close()

	cc := &CheckContext{Target: srv.URL, BaseHTTPClient: fpProbeClient()}
	res, err := (&engineCVEMapCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.Ran {
		t.Fatalf("unknown engine must skip (Skipped=true, Ran=false), got Skipped=%v Ran=%v", res.Skipped, res.Ran)
	}
	if !strings.Contains(res.SkipReason, "engine unknown") {
		t.Fatalf("skip reason should mention unknown engine / GQL-M01: %q", res.SkipReason)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("skip must not emit findings, got %+v", res.Findings)
	}
}

// Data-integrity: every curated advisory has an ID, URL, VerifiedOn date, engine,
// prose, and a parseable version range. This enforces "no fabricated/empty CVEs".
func TestM02_AdvisoryDataIntegrity(t *testing.T) {
	all := fingerprint.AllAdvisories()
	if len(all) == 0 {
		t.Fatal("expected the curated advisory table to be non-empty")
	}
	for _, a := range all {
		label := a.ID
		if a.ID == "" {
			t.Errorf("advisory for %q has empty ID: %+v", a.Engine, a)
			label = a.Engine
		}
		if a.Engine == "" {
			t.Errorf("%s: empty Engine", label)
		}
		if a.URL == "" || !strings.HasPrefix(a.URL, "https://") {
			t.Errorf("%s: URL must be an https source, got %q", label, a.URL)
		}
		if a.VerifiedOn == "" {
			t.Errorf("%s: empty VerifiedOn", label)
		} else if _, err := time.Parse("2006-01-02", a.VerifiedOn); err != nil {
			t.Errorf("%s: VerifiedOn %q is not YYYY-MM-DD: %v", label, a.VerifiedOn, err)
		}
		if a.Title == "" || a.Summary == "" || a.Remediation == "" {
			t.Errorf("%s: Title/Summary/Remediation must all be populated", label)
		}
		if err := fingerprint.ValidateVersionRange(a.VersionRange); err != nil {
			t.Errorf("%s: VersionRange %q is not parseable: %v", label, a.VersionRange, err)
		}
		// The advisory must be retrievable by its declared engine name.
		if findByAdvisoryID(fingerprint.Advisories(a.Engine), a.ID) == nil {
			t.Errorf("%s: not retrievable via Advisories(%q) — engine key/field mismatch", label, a.Engine)
		}
	}
}

func TestM02_Metadata(t *testing.T) {
	c := &engineCVEMapCheck{}
	if c.ID() != "GQL-M02" {
		t.Fatalf("ID = %q, want GQL-M02", c.ID())
	}
	if c.Name() != "Known Engine CVEs" {
		t.Fatalf("Name = %q, want Known Engine CVEs", c.Name())
	}
	if c.Category() != InformationDisclosure {
		t.Fatalf("Category = %v, want InformationDisclosure", c.Category())
	}
	if c.RequiresSchema() {
		t.Fatal("RequiresSchema should be false")
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func findByAdvisoryID(list []fingerprint.Advisory, id string) *fingerprint.Advisory {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}
