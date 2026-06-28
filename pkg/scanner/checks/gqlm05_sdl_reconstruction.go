package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// sdlReconstructionCheck implements GQL-M05: it turns a schema that gqls
// harvested from "Did you mean …" field suggestions (when introspection was
// disabled) into an explicit MEDIUM finding carrying a reconstructed SDL
// artifact — concretely demonstrating that disabling introspection did not hide
// the schema (the clairvoyance technique).
//
// Safety: read-only. It consumes the already-extracted schema (no new requests)
// and renders a bounded SDL artifact (the schema shape, never data).
type sdlReconstructionCheck struct{}

func init() {
	MustRegister(&sdlReconstructionCheck{})
}

func (c *sdlReconstructionCheck) ID() string           { return "GQL-M05" }
func (c *sdlReconstructionCheck) Name() string         { return "Schema Reconstructed via Field Suggestions" }
func (c *sdlReconstructionCheck) Category() Category   { return InformationDisclosure }
func (c *sdlReconstructionCheck) Severity() Severity   { return MEDIUM }
func (c *sdlReconstructionCheck) RequiresSchema() bool { return false } // reads cc.Schema/metadata directly

// m05MinFields is the minimum number of recovered fields for a reconstruction to
// be considered a meaningful schema disclosure.
const m05MinFields = 5

// Rendering bounds keep the SDL artifact from growing unbounded.
const (
	m05MaxTypes         = 50
	m05MaxFieldsPerType = 40
	m05MaxEnumValues    = 30
)

// Run executes the SDL-reconstruction check.
func (c *sdlReconstructionCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	s := cc.Schema
	if s == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no schema was extracted, so there is nothing to reconstruct"
		return result, nil
	}

	// Introspection on → GQL-001 already reports direct schema exposure.
	if s.Metadata.IntrospectionEnabled {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "introspection is enabled — the schema is exposed directly (covered by GQL-001), " +
			"not reconstructed from suggestions"
		return result, nil
	}

	// Only the suggestion/partial harvest paths constitute clairvoyance.
	if s.ExtractionMethod != schema.MethodFieldSuggestion && s.ExtractionMethod != schema.MethodPartial {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = fmt.Sprintf(
			"schema was not obtained via field suggestions (method=%q); SDL reconstruction does not apply",
			string(s.ExtractionMethod))
		return result, nil
	}

	typeCount, fieldCount := countRecovered(s)
	if fieldCount < m05MinFields {
		result.PassReason = fmt.Sprintf(
			"only %d field(s) across %d type(s) were recovered from suggestions — below the reconstruction "+
				"threshold (%d); not a meaningful schema disclosure",
			fieldCount, typeCount, m05MinFields)
		return result, nil
	}

	sdl, truncated := renderSDL(s)
	truncationNote := ""
	if truncated {
		truncationNote = fmt.Sprintf(
			" (artifact truncated to %d types / %d fields per type for brevity; the full schema is recoverable)",
			m05MaxTypes, m05MaxFieldsPerType)
	}

	description := fmt.Sprintf(
		"Introspection is disabled at %s, yet the schema was reconstructed from field-suggestion ("+
			"\"Did you mean …\") responses — the clairvoyance technique. %d type(s) and %d field(s) were "+
			"recovered%s. Reconstructed SDL:\n\n%s",
		cc.Target, typeCount, fieldCount, truncationNote, sdl)

	result.Findings = append(result.Findings, Finding{
		CheckID:     c.ID(),
		CheckName:   c.Name(),
		Severity:    c.Severity(),
		Category:    c.Category(),
		Title:       "Schema Reconstructed via Field Suggestions (introspection disabled but schema still exposed)",
		Description: description,
		Impact: "Attackers can map the full attack surface — types, fields, and arguments — despite " +
			"introspection being disabled, enabling targeted authorization, injection, and business-logic " +
			"attacks that the introspection lock-down was meant to prevent.",
		Remediation: "Disable field/\"Did you mean\" suggestions in production in addition to introspection " +
			"(graphql-js: enable NoSchemaIntrospectionCustomRule and disable suggestions; Apollo/Yoga: turn off " +
			"suggestions via the relevant plugin/flag). Treat schema confidentiality as defense-in-depth, not a " +
			"security control.",
		References: []string{
			"https://github.com/nikitastupin/clairvoyance",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		},
		Confidence:  "confirmed",
		CWE:         "CWE-200",
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "sdl_reconstruction"),
	})
	return result, nil
}

// countRecovered counts the non-builtin types and their fields in the schema.
func countRecovered(s *schema.Schema) (types, fields int) {
	for name, td := range s.Types {
		if td == nil || s.IsBuiltinType(name) {
			continue
		}
		types++
		fields += len(td.Fields) + len(td.InputFields)
	}
	return types, fields
}

// renderSDL renders the harvested schema to bounded SDL text. It marks
// partially-recovered fields/types with a "# partial" comment and is nil-safe on
// fields whose type was not recovered. It returns whether the output was
// truncated by the rendering bounds.
func renderSDL(s *schema.Schema) (sdl string, truncated bool) {
	var b strings.Builder
	b.WriteString("# Reconstructed from field suggestions (clairvoyance technique).\n")
	b.WriteString("# Introspection was disabled, but \"Did you mean …\" suggestions leaked the schema shape.\n")
	b.WriteString("# Entries marked \"# partial\" were inferred without full type information.\n\n")

	names := make([]string, 0, len(s.Types))
	for name, td := range s.Types {
		if td == nil || s.IsBuiltinType(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	if len(names) > m05MaxTypes {
		names = names[:m05MaxTypes]
		truncated = true
	}

	for _, name := range names {
		if renderTypeSDL(&b, s.Types[name]) {
			truncated = true
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n", truncated
}

// renderTypeSDL writes one type definition and returns whether its fields were truncated.
func renderTypeSDL(b *strings.Builder, td *schema.TypeDef) bool {
	switch td.Kind {
	case schema.KindScalar:
		fmt.Fprintf(b, "scalar %s\n", td.Name)
		return false
	case schema.KindUnion:
		if len(td.PossibleTypes) > 0 {
			fmt.Fprintf(b, "union %s = %s\n", td.Name, strings.Join(td.PossibleTypes, " | "))
		} else {
			fmt.Fprintf(b, "union %s # partial (members unknown)\n", td.Name)
		}
		return false
	case schema.KindEnum:
		fmt.Fprintf(b, "enum %s {\n", td.Name)
		vals := td.EnumValues
		truncated := false
		if len(vals) > m05MaxEnumValues {
			vals = vals[:m05MaxEnumValues]
			truncated = true
		}
		for _, v := range vals {
			fmt.Fprintf(b, "  %s\n", v)
		}
		if truncated {
			b.WriteString("  # … more values truncated\n")
		}
		b.WriteString("}\n")
		return truncated
	}

	keyword := "type"
	fields := td.Fields
	if td.Kind == schema.KindInputObject {
		keyword = "input"
		fields = td.InputFields
	} else if td.Kind == schema.KindInterface {
		keyword = "interface"
	}

	fmt.Fprintf(b, "%s %s {\n", keyword, td.Name)
	if len(fields) == 0 {
		b.WriteString("  # partial — no fields recovered\n")
		b.WriteString("}\n")
		return false
	}

	ordered := sortedFields(fields)
	truncated := false
	if len(ordered) > m05MaxFieldsPerType {
		ordered = ordered[:m05MaxFieldsPerType]
		truncated = true
	}
	for _, f := range ordered {
		renderFieldSDL(b, f)
	}
	if truncated {
		b.WriteString("  # … more fields truncated\n")
	}
	b.WriteString("}\n")
	return truncated
}

// renderFieldSDL writes one field, marking it "# partial" when its type was not recovered.
func renderFieldSDL(b *strings.Builder, f *schema.FieldDef) {
	args := ""
	if len(f.Args) > 0 {
		parts := make([]string, 0, len(f.Args))
		for _, a := range f.Args {
			at := a.Type.String()
			if at == "" {
				at = "Unknown"
			}
			parts = append(parts, fmt.Sprintf("%s: %s", a.Name, at))
		}
		args = "(" + strings.Join(parts, ", ") + ")"
	}
	if f.Type == nil || f.Type.String() == "" {
		fmt.Fprintf(b, "  %s%s # partial (type unknown)\n", f.Name, args)
		return
	}
	fmt.Fprintf(b, "  %s%s: %s\n", f.Name, args, f.Type.String())
}

// sortedFields returns a name-sorted copy of fields (does not mutate the input).
func sortedFields(fields []*schema.FieldDef) []*schema.FieldDef {
	out := make([]*schema.FieldDef, len(fields))
	copy(out, fields)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
