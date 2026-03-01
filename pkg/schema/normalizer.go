package schema

import (
	"encoding/json"
	"fmt"
	"time"
)

// rawIntrospectionResponse is the top-level JSON shape returned by a GraphQL introspection query.
type rawIntrospectionResponse struct {
	Data struct {
		Schema *rawSchema `json:"__schema"`
	} `json:"data"`
}

// rawSchema mirrors the __schema introspection object.
type rawSchema struct {
	QueryType        *rawNamedRef   `json:"queryType"`
	MutationType     *rawNamedRef   `json:"mutationType"`
	SubscriptionType *rawNamedRef   `json:"subscriptionType"`
	Types            []rawType      `json:"types"`
	Directives       []rawDirective `json:"directives"`
}

// rawNamedRef is a JSON object with only a "name" field, used for queryType etc.
type rawNamedRef struct {
	Name string `json:"name"`
}

// rawType mirrors a __Type introspection object.
type rawType struct {
	Kind          string        `json:"kind"`
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	Fields        []rawField    `json:"fields"`
	InputFields   []rawInputVal `json:"inputFields"`
	Interfaces    []rawTypeRef  `json:"interfaces"`
	EnumValues    []rawEnumVal  `json:"enumValues"`
	PossibleTypes []rawTypeRef  `json:"possibleTypes"`
}

// rawField mirrors a __Field introspection object.
type rawField struct {
	Name              string        `json:"name"`
	Description       string        `json:"description"`
	Args              []rawInputVal `json:"args"`
	Type              rawTypeRef    `json:"type"`
	IsDeprecated      bool          `json:"isDeprecated"`
	DeprecationReason string        `json:"deprecationReason"`
}

// rawInputVal mirrors a __InputValue introspection object.
// DefaultValue is a pointer so that JSON null (no default) can be distinguished from
// an explicit empty-string default ("").
type rawInputVal struct {
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Type         rawTypeRef `json:"type"`
	DefaultValue *string    `json:"defaultValue"`
}

// rawTypeRef mirrors the recursive __Type reference (kind/name/ofType).
type rawTypeRef struct {
	Kind   string      `json:"kind"`
	Name   string      `json:"name"`
	OfType *rawTypeRef `json:"ofType"`
}

// rawEnumVal mirrors a __EnumValue introspection object.
type rawEnumVal struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	IsDeprecated      bool   `json:"isDeprecated"`
	DeprecationReason string `json:"deprecationReason"`
}

// rawDirective mirrors a __Directive introspection object.
type rawDirective struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Locations   []string      `json:"locations"`
	Args        []rawInputVal `json:"args"`
}

// Normalize parses a full GraphQL introspection response into the internal Schema model.
// It returns an error on any malformed input rather than panicking.
func Normalize(raw json.RawMessage) (*Schema, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("normalizer: empty raw message")
	}

	var resp rawIntrospectionResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("normalizer: failed to unmarshal introspection response: %w", err)
	}

	if resp.Data.Schema == nil {
		return nil, fmt.Errorf("normalizer: missing __schema in response data")
	}

	rs := resp.Data.Schema
	s := &Schema{
		ExtractedAt:      time.Now(),
		ExtractionMethod: MethodIntrospection,
		Types:            make(map[string]*TypeDef),
		Raw:              raw,
		Metadata: ExtractionMetadata{
			IntrospectionEnabled: true,
			RawResponseSize:      len(raw),
		},
	}

	// Convert all types, filtering out built-in types.
	for i := range rs.Types {
		rt := &rs.Types[i]
		if builtinTypes[rt.Name] {
			continue
		}
		td := normalizeType(rt)
		s.Types[td.Name] = td
	}

	// Wire up root types by resolving the stored name against the types map.
	if rs.QueryType != nil && rs.QueryType.Name != "" {
		s.QueryType = s.Types[rs.QueryType.Name]
	}
	if rs.MutationType != nil && rs.MutationType.Name != "" {
		s.MutationType = s.Types[rs.MutationType.Name]
	}
	if rs.SubscriptionType != nil && rs.SubscriptionType.Name != "" {
		s.SubscriptionType = s.Types[rs.SubscriptionType.Name]
	}

	// Convert directives.
	for i := range rs.Directives {
		s.Directives = append(s.Directives, normalizeDirective(&rs.Directives[i]))
	}

	// Classify all types and fields for sensitivity scoring.
	for _, td := range s.Types {
		for _, f := range td.Fields {
			ClassifyField(f)
		}
		for _, f := range td.InputFields {
			ClassifyField(f)
		}
		ClassifyType(td)
	}

	return s, nil
}

// normalizeType converts a rawType into a TypeDef.
func normalizeType(rt *rawType) *TypeDef {
	td := &TypeDef{
		Name:        rt.Name,
		Kind:        TypeKind(rt.Kind),
		Description: rt.Description,
	}

	for i := range rt.Fields {
		td.Fields = append(td.Fields, normalizeField(&rt.Fields[i]))
	}

	for i := range rt.InputFields {
		td.InputFields = append(td.InputFields, normalizeInputField(&rt.InputFields[i]))
	}

	for i := range rt.Interfaces {
		inner := NormalizeTypeRef(rt.Interfaces[i])
		if inner != nil {
			unwrapped := inner.Unwrap()
			if unwrapped != nil && unwrapped.Name != "" {
				td.Interfaces = append(td.Interfaces, unwrapped.Name)
			}
		}
	}

	for i := range rt.PossibleTypes {
		inner := NormalizeTypeRef(rt.PossibleTypes[i])
		if inner != nil {
			unwrapped := inner.Unwrap()
			if unwrapped != nil && unwrapped.Name != "" {
				td.PossibleTypes = append(td.PossibleTypes, unwrapped.Name)
			}
		}
	}

	for i := range rt.EnumValues {
		// Only collect the enum value name; do NOT propagate individual enum-value
		// deprecation to TypeDef.IsDeprecated.  A type is not deprecated because one
		// of its values is — the type is still in use and should not be skipped by
		// consumers (e.g. buildMaximalQuery) that honour TypeDef.IsDeprecated.
		td.EnumValues = append(td.EnumValues, rt.EnumValues[i].Name)
	}

	return td
}

// normalizeField converts a rawField into a FieldDef.
func normalizeField(rf *rawField) *FieldDef {
	fd := &FieldDef{
		Name:              rf.Name,
		Description:       rf.Description,
		IsDeprecated:      rf.IsDeprecated,
		DeprecationReason: rf.DeprecationReason,
		Type:              NormalizeTypeRef(rf.Type),
	}
	for i := range rf.Args {
		fd.Args = append(fd.Args, normalizeArg(&rf.Args[i]))
	}
	return fd
}

// normalizeInputField converts a rawInputVal into a FieldDef (for input types).
func normalizeInputField(rv *rawInputVal) *FieldDef {
	return &FieldDef{
		Name:        rv.Name,
		Description: rv.Description,
		Type:        NormalizeTypeRef(rv.Type),
	}
}

// normalizeArg converts a rawInputVal into an ArgDef.
func normalizeArg(rv *rawInputVal) *ArgDef {
	return &ArgDef{
		Name:         rv.Name,
		Description:  rv.Description,
		Type:         NormalizeTypeRef(rv.Type),
		DefaultValue: rv.DefaultValue,
	}
}

// normalizeDirective converts a rawDirective into a DirectiveDef.
func normalizeDirective(rd *rawDirective) DirectiveDef {
	dd := DirectiveDef{
		Name:        rd.Name,
		Description: rd.Description,
		Locations:   rd.Locations,
	}
	for i := range rd.Args {
		dd.Args = append(dd.Args, normalizeArg(&rd.Args[i]))
	}
	return dd
}

// NormalizeTypeRef recursively converts a rawTypeRef into a TypeRef.
// It handles arbitrarily nested OfType chains.
func NormalizeTypeRef(raw rawTypeRef) *TypeRef {
	tr := &TypeRef{
		Kind: TypeKind(raw.Kind),
		Name: raw.Name,
	}
	if raw.OfType != nil {
		child := NormalizeTypeRef(*raw.OfType)
		tr.OfType = child
	}
	return tr
}
