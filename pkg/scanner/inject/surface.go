// Package inject provides the shared GraphQL injection primitives consumed by
// the injection checks (GQL-I01..I08) and the refactored error-based GQL-011:
//
//   - an injection-point enumerator that walks the whole reachable input graph
//     into typed candidates (surface.go),
//   - a probe + differential oracle for boolean/error detection (oracle.go), and
//   - a statistical timing oracle for blind/time-based detection (timing.go).
//
// It ships capability only and produces no findings of its own.
package inject

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// Point is a single injectable leaf in the reachable input graph: a scalar/enum
// value reachable through a query or mutation argument, possibly nested inside
// input objects and lists.
type Point struct {
	// OpKind is "query" or "mutation".
	OpKind string
	// RootField is the root operation field name, e.g. "user" or "createPost".
	RootField string
	// Path is the argument/input path to the leaf, e.g. ["filter","name"] or
	// ["ids","0"] (list element index).
	Path []string
	// ScalarType is the leaf's named type: "String", "ID", "Int", an enum name,
	// or a custom scalar.
	ScalarType string
	// NonNull reports whether the leaf position itself is non-null (used to
	// declare the injection variable's type correctly).
	NonNull bool
	// Required reports whether the top-level argument (Path[0]) is required;
	// callers may prioritize required points.
	Required bool
	// ViaVariable reports whether the value is injected through a GraphQL
	// variable (the default and safest rendering).
	ViaVariable bool
}

// PathKey returns a stable dotted representation of the point's path.
func (p Point) PathKey() string { return strings.Join(p.Path, ".") }

// maxInputDepth bounds recursion into (possibly self-referential) input objects.
const maxInputDepth = 6

// Points enumerates every injectable scalar leaf reachable through the schema's
// query and mutation arguments. The result is deterministic: query points
// before mutation points, then by root field, then required-before-optional,
// then by path. A nil schema yields nil.
func Points(s *schema.Schema) []Point {
	if s == nil {
		return nil
	}
	var out []Point
	collect := func(opKind string, fields []*schema.FieldDef) {
		sorted := append([]*schema.FieldDef(nil), fields...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
		for _, f := range sorted {
			if f == nil {
				continue
			}
			args := append([]*schema.ArgDef(nil), f.Args...)
			sort.Slice(args, func(i, j int) bool { return args[i].Name < args[j].Name })
			for _, a := range args {
				if a == nil || a.Type == nil {
					continue
				}
				required := isNonNull(a.Type)
				walkType(s, opKind, f.Name, []string{a.Name}, a.Type, required, map[string]bool{}, 0, &out)
			}
		}
	}
	collect("query", s.QueryFields())
	collect("mutation", s.MutationFields())

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OpKind != out[j].OpKind {
			return opKindRank(out[i].OpKind) < opKindRank(out[j].OpKind) // queries before mutations
		}
		if out[i].RootField != out[j].RootField {
			return out[i].RootField < out[j].RootField
		}
		if out[i].Required != out[j].Required {
			return out[i].Required // required first
		}
		return out[i].PathKey() < out[j].PathKey()
	})
	return out
}

// walkType recurses a type, emitting a Point for each scalar/enum leaf.
func walkType(s *schema.Schema, opKind, rootField string, path []string, t *schema.TypeRef, required bool, visiting map[string]bool, depth int, out *[]Point) {
	if t == nil {
		return
	}
	nonNull := false
	if t.Kind == schema.KindNonNull {
		nonNull = true
		t = t.OfType
	}
	if t == nil {
		return
	}
	switch t.Kind {
	case schema.KindList:
		next := append(append([]string(nil), path...), "0")
		walkType(s, opKind, rootField, next, t.OfType, required, visiting, depth, out)
	case schema.KindScalar, schema.KindEnum:
		*out = append(*out, Point{
			OpKind:      opKind,
			RootField:   rootField,
			Path:        append([]string(nil), path...),
			ScalarType:  t.Name,
			NonNull:     nonNull,
			Required:    required,
			ViaVariable: true,
		})
	case schema.KindInputObject:
		if depth >= maxInputDepth || visiting[t.Name] {
			return
		}
		td := s.FindType(t.Name)
		if td == nil {
			return
		}
		visiting[t.Name] = true
		fields := append([]*schema.FieldDef(nil), td.InputFields...)
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		for _, inf := range fields {
			if inf == nil || inf.Type == nil {
				continue
			}
			next := append(append([]string(nil), path...), inf.Name)
			walkType(s, opKind, rootField, next, inf.Type, required, visiting, depth+1, out)
		}
		delete(visiting, t.Name)
	}
}

// Cap returns at most n points (n <= 0 means no cap). The input is assumed to be
// already sorted by Points, so the prefix keeps required/query points first.
func Cap(points []Point, n int) []Point {
	if n <= 0 || len(points) <= n {
		return points
	}
	return points[:n]
}

// Render builds a full operation document and variables map that injects value
// at this point, filling all other required arguments/input fields with benign
// ExampleValue defaults so the document validates. The string payload is coerced
// to the leaf's scalar type and placed in the variables map under the key "inj".
func (p Point) Render(s *schema.Schema, value string) (doc string, variables map[string]any) {
	return p.renderDoc(s), map[string]any{"inj": coerceValue(p.ScalarType, value)}
}

// RenderValue is like Render but injects value verbatim (no scalar coercion),
// so callers can inject non-string JSON values such as operator objects
// (e.g. {"$ne": null}) at a custom JSON/Object scalar leaf — used by NoSQL
// operator-injection probing.
func (p Point) RenderValue(s *schema.Schema, value any) (doc string, variables map[string]any) {
	return p.renderDoc(s), map[string]any{"inj": value}
}

// renderDoc builds the operation document (independent of the injected value).
func (p Point) renderDoc(s *schema.Schema) string {
	field := findRootField(s, p.OpKind, p.RootField)
	varType := p.ScalarType
	if varType == "" {
		varType = "String"
	}
	if p.NonNull {
		varType += "!"
	}
	args := ""
	if field != nil {
		args = renderArgs(s, field, p)
	} else {
		// Fallback: render just the targeted top-level arg.
		args = "(" + p.topArgName() + ": $inj)"
	}
	selection := ""
	if field != nil {
		selection = selectionFor(field.Type)
	}
	return fmt.Sprintf("%s GqlsInj($inj: %s) { %s%s%s }", p.OpKind, varType, p.RootField, args, selection)
}

func (p Point) topArgName() string {
	if len(p.Path) > 0 {
		return p.Path[0]
	}
	return "arg"
}

// renderArgs renders the root field's argument list: the targeted argument
// carries the injection variable at its leaf; other required arguments are
// filled with example literals; optional arguments are omitted.
func renderArgs(s *schema.Schema, field *schema.FieldDef, p Point) string {
	target := p.topArgName()
	args := append([]*schema.ArgDef(nil), field.Args...)
	sort.Slice(args, func(i, j int) bool { return args[i].Name < args[j].Name })

	var parts []string
	for _, a := range args {
		if a == nil || a.Type == nil {
			continue
		}
		switch {
		case a.Name == target:
			parts = append(parts, a.Name+": "+renderValue(s, a.Type, p.Path[1:], 0))
		case isNonNull(a.Type):
			parts = append(parts, a.Name+": "+exampleLiteral(s, a.Type, 0))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// renderValue descends remainingPath, placing $inj at the leaf and filling
// required sibling input fields with example literals.
func renderValue(s *schema.Schema, t *schema.TypeRef, remainingPath []string, depth int) string {
	t = unwrapNonNull(t)
	if t == nil {
		return "$inj"
	}
	if len(remainingPath) == 0 {
		return "$inj"
	}
	switch t.Kind {
	case schema.KindList:
		return "[" + renderValue(s, t.OfType, remainingPath[1:], depth) + "]"
	case schema.KindInputObject:
		td := s.FindType(t.Name)
		if td == nil || depth >= maxInputDepth {
			return "{}"
		}
		targetField := remainingPath[0]
		fields := append([]*schema.FieldDef(nil), td.InputFields...)
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		var parts []string
		for _, inf := range fields {
			if inf == nil || inf.Type == nil {
				continue
			}
			switch {
			case inf.Name == targetField:
				parts = append(parts, inf.Name+": "+renderValue(s, inf.Type, remainingPath[1:], depth+1))
			case isNonNull(inf.Type):
				parts = append(parts, inf.Name+": "+exampleLiteral(s, inf.Type, depth+1))
			}
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	default:
		return "$inj"
	}
}

// exampleLiteral builds a benign inline literal for a required argument/input
// field that is not the injection target, so the document validates.
func exampleLiteral(s *schema.Schema, t *schema.TypeRef, depth int) string {
	t = unwrapNonNull(t)
	if t == nil {
		return "null"
	}
	switch t.Kind {
	case schema.KindList:
		return "[]"
	case schema.KindEnum:
		if td := s.FindType(t.Name); td != nil && len(td.EnumValues) > 0 {
			return td.EnumValues[0]
		}
		return "null"
	case schema.KindInputObject:
		td := s.FindType(t.Name)
		if td == nil || depth >= maxInputDepth {
			return "{}"
		}
		fields := append([]*schema.FieldDef(nil), td.InputFields...)
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		var parts []string
		for _, inf := range fields {
			if inf != nil && inf.Type != nil && isNonNull(inf.Type) {
				parts = append(parts, inf.Name+": "+exampleLiteral(s, inf.Type, depth+1))
			}
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	default: // scalar
		return scalarExampleLiteral(t.Name)
	}
}

// scalarExampleLiteral returns a syntactically valid literal for a scalar type.
func scalarExampleLiteral(name string) string {
	switch name {
	case "Int":
		return "1"
	case "Float":
		return "1.0"
	case "Boolean":
		return "true"
	default: // String, ID, custom scalars
		return `"gqls"`
	}
}

// ExampleValue returns a benign Go value for a scalar type, suitable for use as
// a GraphQL variable value when filling non-targeted required fields.
func ExampleValue(scalarType string) any {
	switch scalarType {
	case "Int":
		return 1
	case "Float":
		return 1.0
	case "Boolean":
		return true
	default:
		return "gqls"
	}
}

// coerceValue converts the payload string into the appropriate JSON variable
// value for the leaf's scalar type. Non-numeric payloads fall back to a string,
// which is correct for String/ID/custom scalars (the realistic injection surface).
func coerceValue(scalarType, value string) any {
	switch scalarType {
	case "Int":
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return n
		}
	case "Float":
		if f, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			return f
		}
	case "Boolean":
		if b, err := strconv.ParseBool(strings.TrimSpace(value)); err == nil {
			return b
		}
	}
	return value
}

func findRootField(s *schema.Schema, opKind, name string) *schema.FieldDef {
	if s == nil {
		return nil
	}
	var fields []*schema.FieldDef
	if opKind == "mutation" {
		fields = s.MutationFields()
	} else {
		fields = s.QueryFields()
	}
	for _, f := range fields {
		if f != nil && f.Name == name {
			return f
		}
	}
	return nil
}

// selectionFor returns " { __typename }" for composite return types, else "".
func selectionFor(t *schema.TypeRef) string {
	u := t.Unwrap()
	if u == nil {
		return ""
	}
	switch u.Kind {
	case schema.KindObject, schema.KindInterface, schema.KindUnion:
		return " { __typename }"
	default:
		return ""
	}
}

// opKindRank orders query points before mutation points.
func opKindRank(op string) int {
	if op == "mutation" {
		return 1
	}
	return 0
}

func isNonNull(t *schema.TypeRef) bool { return t != nil && t.Kind == schema.KindNonNull }

func unwrapNonNull(t *schema.TypeRef) *schema.TypeRef {
	if t != nil && t.Kind == schema.KindNonNull {
		return t.OfType
	}
	return t
}
