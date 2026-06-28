package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// harvestedSchema builds a schema as the field-suggestion harvester would: object
// types whose fields carry only a name (no recovered type). nFields are spread
// across the given type names.
func harvestedSchema(typeNames []string, fieldsPerType int) *schema.Schema {
	s := &schema.Schema{
		Endpoint:         "http://target/graphql",
		ExtractionMethod: schema.MethodFieldSuggestion,
		Types:            map[string]*schema.TypeDef{},
		Metadata:         schema.ExtractionMetadata{IntrospectionEnabled: false, SuggestionsEnabled: true},
	}
	for _, tn := range typeNames {
		td := &schema.TypeDef{Name: tn, Kind: schema.KindObject}
		for i := 0; i < fieldsPerType; i++ {
			td.Fields = append(td.Fields, &schema.FieldDef{Name: fmt.Sprintf("%sField%d", strings.ToLower(tn), i)})
		}
		s.Types[tn] = td
	}
	return s
}

// Introspection disabled + >=5 fields harvested → MEDIUM finding with SDL.
func TestM05_Reconstructs_Medium(t *testing.T) {
	s := harvestedSchema([]string{"User", "Order"}, 3) // 6 fields total
	cc := &CheckContext{Target: "http://target/graphql", Schema: s}

	res, err := (&sdlReconstructionCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatalf("should not skip a non-trivial harvest: %s", res.SkipReason)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM || f.Category != InformationDisclosure {
		t.Fatalf("severity/category = %v/%v, want MEDIUM/InformationDisclosure", f.Severity, f.Category)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-200" || f.OWASP != "API8:2023" {
		t.Fatalf("classification = %q/%q/%q, want confirmed/CWE-200/API8:2023", f.Confidence, f.CWE, f.OWASP)
	}
	// SDL must contain valid-looking type declarations for the recovered types.
	for _, want := range []string{"type User {", "type Order {", "# partial"} {
		if !strings.Contains(f.Description, want) {
			t.Fatalf("description SDL missing %q:\n%s", want, f.Description)
		}
	}
	if !strings.Contains(f.Description, "2 type(s) and 6 field(s)") {
		t.Fatalf("description should report recovery stats: %s", f.Description)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
}

// Introspection enabled → skip (GQL-001 covers it).
func TestM05_IntrospectionEnabled_Skips(t *testing.T) {
	s := harvestedSchema([]string{"User", "Order"}, 3)
	s.ExtractionMethod = schema.MethodIntrospection
	s.Metadata.IntrospectionEnabled = true
	cc := &CheckContext{Target: "http://t/graphql", Schema: s}

	res, _ := (&sdlReconstructionCheck{}).Run(t.Context(), cc)
	if !res.Skipped || res.Ran {
		t.Fatalf("expected skip, got Skipped=%v Ran=%v", res.Skipped, res.Ran)
	}
	if !strings.Contains(res.SkipReason, "GQL-001") {
		t.Fatalf("skip reason should reference GQL-001: %q", res.SkipReason)
	}
}

// Trivial harvest (<5 fields) → no finding + PassReason.
func TestM05_TrivialHarvest_PassReason(t *testing.T) {
	s := harvestedSchema([]string{"User"}, 2) // 2 fields, below threshold
	cc := &CheckContext{Target: "http://t/graphql", Schema: s}

	res, _ := (&sdlReconstructionCheck{}).Run(t.Context(), cc)
	if len(res.Findings) != 0 {
		t.Fatalf("trivial harvest must not fire, got %+v", res.Findings)
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason for the trivial harvest")
	}
}

// Nil schema and non-suggestion extraction method both skip.
func TestM05_SkipsWhenNotApplicable(t *testing.T) {
	t.Run("nil schema", func(t *testing.T) {
		res, _ := (&sdlReconstructionCheck{}).Run(t.Context(), &CheckContext{Target: "http://t"})
		if !res.Skipped {
			t.Fatalf("nil schema should skip, got %+v", res)
		}
	})
	t.Run("schema-file method", func(t *testing.T) {
		s := harvestedSchema([]string{"User", "Order"}, 3)
		s.ExtractionMethod = schema.MethodSchemaFile
		res, _ := (&sdlReconstructionCheck{}).Run(t.Context(), &CheckContext{Target: "http://t", Schema: s})
		if !res.Skipped {
			t.Fatalf("non-suggestion method should skip, got %+v", res)
		}
	})
}

// The renderer is bounded and emits a truncation note past the type cap, and
// never panics on partial (nil-type) fields.
func TestM05_RendererBoundedAndPartialSafe(t *testing.T) {
	names := make([]string, 0, m05MaxTypes+10)
	for i := 0; i < m05MaxTypes+10; i++ {
		names = append(names, fmt.Sprintf("Type%03d", i))
	}
	s := harvestedSchema(names, 1)
	cc := &CheckContext{Target: "http://t/graphql", Schema: s}

	res, err := (&sdlReconstructionCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if !strings.Contains(f.Description, "truncated") {
		t.Fatalf("over-cap reconstruction should note truncation: %s", f.Description[:min(400, len(f.Description))])
	}
	// Bounded: rendered type count must not exceed the cap.
	if got := strings.Count(f.Description, "type Type"); got > m05MaxTypes {
		t.Fatalf("rendered %d types, exceeds cap %d", got, m05MaxTypes)
	}
}

func TestM05_Metadata(t *testing.T) {
	c := &sdlReconstructionCheck{}
	if c.ID() != "GQL-M05" {
		t.Fatalf("ID = %q, want GQL-M05", c.ID())
	}
	if c.Severity() != MEDIUM || c.Category() != InformationDisclosure || c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
