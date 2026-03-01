// Package schema provides GraphQL schema representation types for the scanner.
package schema

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// ExtractionMethod indicates how the schema was obtained.
type ExtractionMethod string

const (
	MethodIntrospection   ExtractionMethod = "introspection"
	MethodFieldSuggestion ExtractionMethod = "field_suggestion"
	MethodSchemaFile      ExtractionMethod = "schema_file"
	MethodPartial         ExtractionMethod = "partial"
)

// ExtractionMetadata holds metadata about the extraction process.
type ExtractionMetadata struct {
	IntrospectionEnabled bool
	AuthRequired         bool
	EndpointDiscovered   bool
	DiscoveredPath       string
	SuggestionsEnabled   bool
	RawResponseSize      int
	ProbeCount           int
}

// TypeKind represents the kind of a GraphQL type.
type TypeKind string

const (
	KindObject      TypeKind = "OBJECT"
	KindScalar      TypeKind = "SCALAR"
	KindEnum        TypeKind = "ENUM"
	KindInputObject TypeKind = "INPUT_OBJECT"
	KindInterface   TypeKind = "INTERFACE"
	KindUnion       TypeKind = "UNION"
	KindList        TypeKind = "LIST"
	KindNonNull     TypeKind = "NON_NULL"
)

// Schema holds a parsed and enriched GraphQL schema.
type Schema struct {
	Endpoint         string
	ExtractedAt      time.Time
	ExtractionMethod ExtractionMethod
	Types            map[string]*TypeDef
	QueryType        *TypeDef
	MutationType     *TypeDef
	SubscriptionType *TypeDef
	Directives       []DirectiveDef
	Raw              json.RawMessage
	Metadata         ExtractionMetadata
}

// TypeDef represents a single GraphQL type definition.
type TypeDef struct {
	Name             string
	Kind             TypeKind
	Fields           []*FieldDef
	InputFields      []*FieldDef
	Interfaces       []string
	PossibleTypes    []string
	EnumValues       []string
	Description      string
	IsDeprecated     bool
	SensitivityScore int
	Tags             []string
}

// FieldDef represents a field within a GraphQL type.
type FieldDef struct {
	Name              string
	Type              *TypeRef
	Args              []*ArgDef
	IsDeprecated      bool
	DeprecationReason string
	Description       string
	SensitivityScore  int
	Tags              []string
}

// TypeRef is a potentially-wrapped reference to a named GraphQL type.
type TypeRef struct {
	Kind   TypeKind
	Name   string
	OfType *TypeRef
}

// ArgDef represents a single argument of a GraphQL field or directive.
// DefaultValue is nil when the argument has no default (required argument) and
// non-nil (possibly pointing to "") when an explicit default was declared.
type ArgDef struct {
	Name         string
	Type         *TypeRef
	DefaultValue *string
	Description  string
}

// DirectiveDef represents a GraphQL directive definition.
type DirectiveDef struct {
	Name        string
	Description string
	Locations   []string
	Args        []*ArgDef
}

// QueryFields returns all fields on the query type, nil-safe.
func (s *Schema) QueryFields() []*FieldDef {
	if s == nil || s.QueryType == nil {
		return nil
	}
	return s.QueryType.Fields
}

// MutationFields returns all fields on the mutation type, nil-safe.
func (s *Schema) MutationFields() []*FieldDef {
	if s == nil || s.MutationType == nil {
		return nil
	}
	return s.MutationType.Fields
}

// SubscriptionFields returns all fields on the subscription type, nil-safe.
func (s *Schema) SubscriptionFields() []*FieldDef {
	if s == nil || s.SubscriptionType == nil {
		return nil
	}
	return s.SubscriptionType.Fields
}

// FindType looks up a type by name, returning nil if not found.
func (s *Schema) FindType(name string) *TypeDef {
	if s == nil || s.Types == nil {
		return nil
	}
	return s.Types[name]
}

// SensitiveFields returns all fields across all types with SensitivityScore > 0,
// sorted by score descending.
func (s *Schema) SensitiveFields() []*FieldDef {
	if s == nil {
		return nil
	}
	var out []*FieldDef
	for _, t := range s.Types {
		for _, f := range t.Fields {
			if f.SensitivityScore > 0 {
				out = append(out, f)
			}
		}
		for _, f := range t.InputFields {
			if f.SensitivityScore > 0 {
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SensitivityScore > out[j].SensitivityScore
	})
	return out
}

// urlArgNames is the set of argument names that indicate a URL-like parameter.
var urlArgNames = map[string]bool{
	"url":      true,
	"uri":      true,
	"link":     true,
	"href":     true,
	"webhook":  true,
	"redirect": true,
	"callback": true,
	"src":      true,
	"endpoint": true,
	"target":   true,
}

// URLArgFields returns all fields where any arg name matches known URL-like parameter names.
func (s *Schema) URLArgFields() []*FieldDef {
	if s == nil {
		return nil
	}
	var out []*FieldDef
	for _, t := range s.Types {
		for _, f := range t.Fields {
			for _, arg := range f.Args {
				if urlArgNames[strings.ToLower(arg.Name)] {
					out = append(out, f)
					break
				}
			}
		}
	}
	return out
}

// builtinTypes is the set of GraphQL built-in type names.
var builtinTypes = map[string]bool{
	"__Schema":            true,
	"__Type":              true,
	"__Field":             true,
	"__InputValue":        true,
	"__EnumValue":         true,
	"__Directive":         true,
	"__DirectiveLocation": true, // ENUM returned by some servers (Apollo, Hasura)
	"String":              true,
	"Int":                 true,
	"Float":               true,
	"Boolean":             true,
	"ID":                  true,
}

// IsBuiltinType returns true for GraphQL built-in type names.
func (s *Schema) IsBuiltinType(name string) bool {
	return builtinTypes[name]
}

// Unwrap follows the OfType chain until it reaches a named type, returning that TypeRef.
func (t *TypeRef) Unwrap() *TypeRef {
	if t == nil {
		return nil
	}
	current := t
	for current.OfType != nil {
		current = current.OfType
	}
	return current
}

// String returns a human-readable type string, e.g. [User!]!
func (t *TypeRef) String() string {
	if t == nil {
		return ""
	}
	switch t.Kind {
	case KindNonNull:
		if t.OfType != nil {
			return t.OfType.String() + "!"
		}
		return "!"
	case KindList:
		if t.OfType != nil {
			return "[" + t.OfType.String() + "]"
		}
		return "[]"
	default:
		return t.Name
	}
}
