package checks

import (
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

func strptr(s string) *string { return &s }

// A description with an AWS key + mongodb connection string, and a
// "remove in prod" deprecation reason → MEDIUM finding with redaction.
func TestM09_CredentialInDescription_MediumRedacted(t *testing.T) {
	const awsKey = "AKIAIOSFODNN7EXAMPLE"
	const mongo = "mongodb://admin:s3cr3tPass@db.internal:27017"
	s := &schema.Schema{
		Endpoint: "http://t/graphql",
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User", Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "token", Description: "example credential " + awsKey + " for testing"},
					{Name: "legacyConn", DeprecationReason: "internal only — remove before prod; use " + mongo},
				},
			},
		},
	}
	cc := &CheckContext{Target: "http://t/graphql", Schema: s}

	res, err := (&descriptionSecretLeakageCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM {
		t.Fatalf("severity = %v, want MEDIUM (concrete credential)", f.Severity)
	}
	if f.Confidence != "firm" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q, want firm/API8:2023", f.Confidence, f.OWASP)
	}
	if f.CWE != "CWE-540" {
		t.Fatalf("CWE = %q, want CWE-540 for concrete credential", f.CWE)
	}
	// Redaction: raw secrets must never appear in the finding text.
	blob := f.Title + "\n" + f.Description + "\n" + f.Impact
	if strings.Contains(blob, awsKey) {
		t.Fatalf("raw AWS key leaked into finding: %s", f.Description)
	}
	if strings.Contains(blob, "s3cr3tPass") {
		t.Fatalf("raw connection-string password leaked into finding: %s", f.Description)
	}
	// Classes and locations are reported.
	for _, want := range []string{"aws-access-key", "connection-string", "User.token", "User.legacyConn"} {
		if !strings.Contains(f.Description, want) {
			t.Fatalf("description missing %q: %s", want, f.Description)
		}
	}
}

// A "remove before prod" deprecation reason alone → LOW finding.
func TestM09_RemoveInProdNote_Low(t *testing.T) {
	s := &schema.Schema{
		Types: map[string]*schema.TypeDef{
			"Query": {Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
				{Name: "debugInfo", DeprecationReason: "internal only — remove before prod"},
			}},
		},
	}
	cc := &CheckContext{Target: "http://t/graphql", Schema: s}
	res, _ := (&descriptionSecretLeakageCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != LOW {
		t.Fatalf("severity = %v, want LOW (internal note)", res.Findings[0].Severity)
	}
	if !strings.Contains(res.Findings[0].Description, "internal-note") {
		t.Fatalf("description should list the internal-note class: %s", res.Findings[0].Description)
	}
}

// A secret in an argument default value → finding.
func TestM09_DefaultValueSecret_Fires(t *testing.T) {
	s := &schema.Schema{
		Types: map[string]*schema.TypeDef{
			"Query": {Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
				{Name: "connect", Args: []*schema.ArgDef{
					{Name: "dsn", DefaultValue: strptr("postgres://u:p4ss@10.0.0.5:5432/db")},
				}},
			}},
		},
	}
	cc := &CheckContext{Target: "http://t/graphql", Schema: s}
	res, _ := (&descriptionSecretLeakageCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM {
		t.Fatalf("severity = %v, want MEDIUM (connection string)", f.Severity)
	}
	if !strings.Contains(f.Description, "default value") || !strings.Contains(f.Description, "Query.connect(dsn)") {
		t.Fatalf("description should name the default-value location: %s", f.Description)
	}
	if strings.Contains(f.Description, "p4ss") {
		t.Fatalf("raw default-value secret leaked: %s", f.Description)
	}
}

// A clean schema → no finding + PassReason.
func TestM09_CleanSchema_NoFinding(t *testing.T) {
	s := &schema.Schema{
		Types: map[string]*schema.TypeDef{
			"User": {Name: "User", Kind: schema.KindObject, Description: "A registered user account.", Fields: []*schema.FieldDef{
				{Name: "id", Description: "Unique identifier."},
				{Name: "email", Description: "The user's email address.", DeprecationReason: "Use contact.email instead."},
			}},
		},
	}
	cc := &CheckContext{Target: "http://t/graphql", Schema: s}
	res, err := (&descriptionSecretLeakageCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("clean schema should produce no findings, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason for a clean schema")
	}
}

// Nil schema → skip (RequiresSchema is true, but Run must be nil-safe).
func TestM09_NilSchema_Skips(t *testing.T) {
	res, _ := (&descriptionSecretLeakageCheck{}).Run(t.Context(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

// The secret-assignment matcher must not fire on ordinary prose.
func TestM09_NoFalsePositiveOnProse(t *testing.T) {
	hits := m09Scan("The password field is required for login.", "X.y", "description")
	for _, h := range hits {
		if h.class == "secret-assignment" {
			t.Fatalf("prose 'password ... required' must not match secret-assignment: %+v", h)
		}
	}
}

func TestM09_Metadata(t *testing.T) {
	c := &descriptionSecretLeakageCheck{}
	if c.ID() != "GQL-M09" {
		t.Fatalf("ID = %q, want GQL-M09", c.ID())
	}
	if c.Severity() != LOW || c.Category() != InformationDisclosure || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
