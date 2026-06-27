// Package surface walks a parsed GraphQL schema into typed authorization test
// candidates: object fetchers (BOLA/IDOR), privileged operations (BFLA), and
// sensitive fields (BOPLA). Authz checks consume these candidates instead of
// re-walking the schema with ad-hoc logic.
//
// It depends only on pkg/schema.
package surface

import (
	"regexp"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// ObjectFetcher is a root query field that retrieves a single object by an
// id-like argument — the candidate shape for BOLA / IDOR and cross-tenant tests.
type ObjectFetcher struct {
	// RootField is the field name on the query root, e.g. "user", "order", "node".
	RootField string
	// IsMutation is true when the fetcher is a mutation (rare for read-fetchers).
	IsMutation bool
	// IDArg is the id-like argument name, e.g. "id".
	IDArg string
	// IDArgType is the named scalar type of the id argument, e.g. "ID", "Int".
	IDArgType string
	// ReturnType is the named object type the fetcher returns, e.g. "User".
	ReturnType string
}

// PrivilegedOp is an operation flagged as privileged — the candidate shape for
// BFLA (a lower-privilege identity reaching an admin-only operation).
type PrivilegedOp struct {
	// Field is the operation field name.
	Field string
	// IsMutation distinguishes privileged mutations from privileged queries.
	IsMutation bool
	// Reasons explains why the operation was flagged privileged.
	Reasons []string
}

// SensitiveField is a schema field carrying a sensitivity score — the candidate
// shape for BOPLA (field-level authorization / excessive data exposure).
type SensitiveField struct {
	// ParentType is the owning type name.
	ParentType string
	// Field is the field name.
	Field string
	// Score is the field's sensitivity score (higher is more sensitive).
	Score int
	// Tags are the sensitivity tags (e.g. "pii", "financial", "credential").
	Tags []string
	// SelectionPath is the selection needed to request the field (the field name).
	SelectionPath string
}

// idArgRe matches identifier-like argument names.
var idArgRe = regexp.MustCompile(`(?i)^(id|_id|.*Id|nodeId|uuid|guid|slug|key|number|ref)$`)

// privilegedNameRe matches operation names that imply privileged functionality.
var privilegedNameRe = regexp.MustCompile(`(?i)(admin|delete|remove|destroy|purge|wipe|drop|grant|revoke|promote|demote|impersonate|role|permission|disable|enable|ban|unban|refund|payout|invite|approve|reject|publish|unpublish|config|setting|sudo|root|superuser)`)

// privilegedTags is the set of sensitivity tags that imply a privileged surface.
var privilegedTags = map[string]bool{
	"privileged": true,
	"credential": true,
}

// Fetchers returns the object-fetcher candidates on the query root: fields that
// take an id-like scalar argument and return a single object (not a list).
// The result is sorted by RootField for deterministic iteration.
func Fetchers(s *schema.Schema) []ObjectFetcher {
	if s == nil {
		return nil
	}
	var out []ObjectFetcher
	for _, f := range s.QueryFields() {
		if f == nil {
			continue
		}
		idArg := firstIDArg(f)
		if idArg == nil {
			continue
		}
		named, isList := namedReturn(f.Type)
		if isList || named == nil {
			continue // collection field, not a single-object fetch
		}
		if !isObjectKind(s, named) {
			continue
		}
		out = append(out, ObjectFetcher{
			RootField:  f.Name,
			IsMutation: false,
			IDArg:      idArg.Name,
			IDArgType:  argTypeName(idArg),
			ReturnType: named.Name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RootField < out[j].RootField })
	return out
}

// PrivilegedOps returns the privileged operation candidates across queries and
// mutations. The result is sorted (queries before mutations, then by name).
func PrivilegedOps(s *schema.Schema) []PrivilegedOp {
	if s == nil {
		return nil
	}
	var out []PrivilegedOp
	add := func(fields []*schema.FieldDef, isMutation bool) {
		for _, f := range fields {
			if f == nil {
				continue
			}
			reasons := privilegeReasons(s, f)
			if len(reasons) == 0 {
				continue
			}
			out = append(out, PrivilegedOp{Field: f.Name, IsMutation: isMutation, Reasons: reasons})
		}
	}
	add(s.QueryFields(), false)
	add(s.MutationFields(), true)
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsMutation != out[j].IsMutation {
			return !out[i].IsMutation // queries first
		}
		return out[i].Field < out[j].Field
	})
	return out
}

// SensitiveFieldsByType groups every field with a positive sensitivity score by
// its parent type name. Each group is sorted by Score descending, then Field.
func SensitiveFieldsByType(s *schema.Schema) map[string][]SensitiveField {
	out := map[string][]SensitiveField{}
	if s == nil {
		return out
	}
	for _, t := range s.Types {
		if t == nil || s.IsBuiltinType(t.Name) {
			continue
		}
		var group []SensitiveField
		collect := func(fields []*schema.FieldDef) {
			for _, f := range fields {
				if f == nil || f.SensitivityScore <= 0 {
					continue
				}
				group = append(group, SensitiveField{
					ParentType:    t.Name,
					Field:         f.Name,
					Score:         f.SensitivityScore,
					Tags:          f.Tags,
					SelectionPath: f.Name,
				})
			}
		}
		collect(t.Fields)
		collect(t.InputFields)
		if len(group) == 0 {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			if group[i].Score != group[j].Score {
				return group[i].Score > group[j].Score
			}
			return group[i].Field < group[j].Field
		})
		out[t.Name] = group
	}
	return out
}

// ExampleValue synthesizes a schema-valid GraphQL literal for a (typically
// required) argument type, so probes pass input validation. Strings/IDs and
// unknown scalars yield `"1"`; Int → 1; Float → 1.0; Boolean → true; enums yield
// their first value (unquoted). Object/list types yield an empty string, which
// the caller should treat as "cannot synthesize".
func ExampleValue(t *schema.TypeRef, s *schema.Schema) string {
	named := t.Unwrap()
	if named == nil {
		return `"1"`
	}
	kind := named.Kind
	if kind == "" && s != nil {
		if td := s.FindType(named.Name); td != nil {
			kind = td.Kind
		}
	}
	switch named.Name {
	case "Int":
		return "1"
	case "Float":
		return "1.0"
	case "Boolean":
		return "true"
	case "ID", "String":
		return `"1"`
	}
	switch kind {
	case schema.KindEnum:
		if s != nil {
			if td := s.FindType(named.Name); td != nil && len(td.EnumValues) > 0 {
				return td.EnumValues[0]
			}
		}
		return `"1"`
	case schema.KindObject, schema.KindInputObject, schema.KindInterface, schema.KindUnion, schema.KindList:
		return "" // cannot synthesize a literal for a composite type
	default:
		// Custom scalar — treat as a string.
		return `"1"`
	}
}

// firstIDArg returns the first id-like scalar argument of f, or nil.
func firstIDArg(f *schema.FieldDef) *schema.ArgDef {
	// Deterministic: scan args in declared order.
	for _, a := range f.Args {
		if a == nil {
			continue
		}
		if idArgRe.MatchString(a.Name) {
			return a
		}
	}
	return nil
}

// argTypeName returns the named (unwrapped) type name of an argument.
func argTypeName(a *schema.ArgDef) string {
	if a == nil || a.Type == nil {
		return ""
	}
	if u := a.Type.Unwrap(); u != nil {
		return u.Name
	}
	return ""
}

// namedReturn unwraps a return TypeRef to its named type, reporting whether a
// LIST wrapper was present anywhere in the chain.
func namedReturn(t *schema.TypeRef) (named *schema.TypeRef, isList bool) {
	cur := t
	for cur != nil {
		if cur.Kind == schema.KindList {
			isList = true
		}
		if cur.OfType == nil {
			return cur, isList
		}
		cur = cur.OfType
	}
	return nil, isList
}

// isObjectKind reports whether the named type resolves to an object/interface/union.
func isObjectKind(s *schema.Schema, named *schema.TypeRef) bool {
	switch named.Kind {
	case schema.KindObject, schema.KindInterface, schema.KindUnion:
		return true
	case schema.KindScalar, schema.KindEnum, schema.KindInputObject:
		return false
	}
	if s != nil {
		if td := s.FindType(named.Name); td != nil {
			switch td.Kind {
			case schema.KindObject, schema.KindInterface, schema.KindUnion:
				return true
			}
		}
	}
	return false
}

// privilegeReasons returns the reasons a field is considered privileged, or nil.
func privilegeReasons(s *schema.Schema, f *schema.FieldDef) []string {
	var reasons []string
	if privilegedNameRe.MatchString(f.Name) {
		reasons = append(reasons, "operation name implies privileged functionality")
	}
	for _, tag := range f.Tags {
		if privilegedTags[tag] {
			reasons = append(reasons, "field tagged "+tag)
			break
		}
	}
	// Return type carries a privileged/credential sensitivity tag.
	if named, _ := namedReturn(f.Type); named != nil && s != nil {
		if td := s.FindType(named.Name); td != nil {
			for _, tag := range td.Tags {
				if privilegedTags[tag] {
					reasons = append(reasons, "returns "+tag+"-tagged type "+td.Name)
					break
				}
			}
		}
	}
	return dedupe(reasons)
}

// dedupe removes duplicate strings preserving order.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}
