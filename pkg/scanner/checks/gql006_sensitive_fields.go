package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// sensitiveFieldsCheck implements GQL-006: Sensitive Fields Exposed in Schema.
type sensitiveFieldsCheck struct{}

func init() {
	MustRegister(&sensitiveFieldsCheck{})
}

func (c *sensitiveFieldsCheck) ID() string           { return "GQL-006" }
func (c *sensitiveFieldsCheck) Name() string         { return "Sensitive Fields Exposed in Schema" }
func (c *sensitiveFieldsCheck) Category() Category   { return InformationDisclosure }
func (c *sensitiveFieldsCheck) Severity() Severity   { return INFO }
func (c *sensitiveFieldsCheck) RequiresSchema() bool { return true }

// sensitiveFieldHit holds a single sensitive field with its type context and reachability info.
type sensitiveFieldHit struct {
	TypeName            string
	TypeKind            schema.TypeKind
	Field               *schema.FieldDef
	Score               int
	Tags                []string
	AccessPath          string   // e.g. "User.password"
	ReachableVia        []string // all query paths that reach this type
	IsDirectlyQueryable bool     // type is a direct return type of Query or Mutation
}

// typeGroup aggregates all sensitive hits for a single GraphQL type.
type typeGroup struct {
	TypeName    string
	TypeKind    schema.TypeKind
	Hits        []sensitiveFieldHit
	MaxScore    int
	MaxSeverity Severity
	AllTags     []string // deduplicated union of all tags across hits
	AccessPaths []string // deduplicated access paths to this type
}

// Run executes the GQL-006 sensitive fields schema analysis.
// It makes zero HTTP requests — all logic operates on the extracted schema.
func (c *sensitiveFieldsCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true, ProbeCount: 0}

	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "schema_required_for_field_analysis"
		return result, nil
	}

	reachability := BuildReachabilityMap(cc.Schema)

	// Determine which types are direct return types of Query or Mutation fields.
	directlyQueryable := make(map[string]bool)
	for _, f := range cc.Schema.QueryFields() {
		if f.Type != nil {
			if name := f.Type.Unwrap().Name; name != "" {
				directlyQueryable[name] = true
			}
		}
	}
	for _, f := range cc.Schema.MutationFields() {
		if f.Type != nil {
			if name := f.Type.Unwrap().Name; name != "" {
				directlyQueryable[name] = true
			}
		}
	}

	// Collect sensitive field hits grouped by type name.
	groups := make(map[string]*typeGroup)
	for typeName, typeDef := range cc.Schema.Types {
		if cc.Schema.IsBuiltinType(typeName) {
			continue
		}
		for _, field := range typeDef.Fields {
			if field.SensitivityScore < 7 {
				continue
			}
			paths := reachability[typeName]
			isDirect := directlyQueryable[typeName]
			hit := sensitiveFieldHit{
				TypeName:            typeName,
				TypeKind:            typeDef.Kind,
				Field:               field,
				Score:               field.SensitivityScore,
				Tags:                append([]string(nil), field.Tags...),
				AccessPath:          typeName + "." + field.Name,
				ReachableVia:        paths,
				IsDirectlyQueryable: isDirect,
			}
			if _, ok := groups[typeName]; !ok {
				groups[typeName] = &typeGroup{
					TypeName:    typeName,
					TypeKind:    typeDef.Kind,
					AccessPaths: deduplicateStrings(paths),
				}
			}
			groups[typeName].Hits = append(groups[typeName].Hits, hit)
		}
	}

	// Build one Finding per typeGroup.
	for _, group := range groups {
		tagSet := make(map[string]bool)
		maxSev := INFO
		maxScore := 0
		for _, hit := range group.Hits {
			sev := hitSeverity(hit)
			if sev > maxSev {
				maxSev = sev
			}
			if hit.Score > maxScore {
				maxScore = hit.Score
			}
			for _, tag := range hit.Tags {
				tagSet[tag] = true
			}
		}
		group.MaxSeverity = maxSev
		group.MaxScore = maxScore
		for tag := range tagSet {
			group.AllTags = append(group.AllTags, tag)
		}
		sort.Strings(group.AllTags)

		result.Findings = append(result.Findings, Finding{
			CheckID:      "GQL-006",
			CheckName:    "Sensitive Fields Exposed in Schema",
			Severity:     group.MaxSeverity,
			Category:     InformationDisclosure,
			Title:        fmt.Sprintf("Sensitive fields on type %q (%d field(s))", group.TypeName, len(group.Hits)),
			Description:  buildDescription(*group),
			Impact:       buildImpact(*group),
			Remediation:  buildRemediation(*group),
			References: []string{
				"https://owasp.org/www-project-api-security/",
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			},
			ReproRequest: nil,
			ReproBody:    nil,
			Fingerprint:  GenerateFingerprint("GQL-006", cc.Target, group.TypeName),
		})
	}

	// Sort: severity descending, then type name alphabetically for deterministic output.
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Severity != result.Findings[j].Severity {
			return result.Findings[i].Severity > result.Findings[j].Severity
		}
		return result.Findings[i].Title < result.Findings[j].Title
	})

	if len(result.Findings) == 0 {
		result.PassReason = "No sensitive fields were detected in the schema. All types reachable from the Query and Mutation roots were scanned; none contained fields matching credential, PII, financial, or privileged patterns with a sensitivity score ≥ 7."
	}

	return result, nil
}

// BuildReachabilityMap performs a BFS from Query and Mutation root types, returning
// a map of type name → access paths. Depth is capped at 5 to prevent infinite loops
// on circular schemas. Exported to allow direct testing.
func BuildReachabilityMap(s *schema.Schema) map[string][]string {
	result := make(map[string][]string)
	if s == nil {
		return result
	}

	type qitem struct {
		typeName string
		path     string
		depth    int
	}

	// expanded tracks types whose fields we have already enqueued, preventing
	// re-expansion and breaking circular references.
	expanded := make(map[string]bool)
	queue := make([]qitem, 0, 32)

	// Seed from Query root fields.
	for _, f := range s.QueryFields() {
		if f.Type == nil {
			continue
		}
		name := f.Type.Unwrap().Name
		if name == "" || s.IsBuiltinType(name) {
			continue
		}
		queue = append(queue, qitem{typeName: name, path: "Query." + f.Name, depth: 1})
	}

	// Seed from Mutation root fields.
	for _, f := range s.MutationFields() {
		if f.Type == nil {
			continue
		}
		name := f.Type.Unwrap().Name
		if name == "" || s.IsBuiltinType(name) {
			continue
		}
		queue = append(queue, qitem{typeName: name, path: "Mutation." + f.Name, depth: 1})
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		// Always record this access path, even for types we've already expanded.
		result[item.typeName] = append(result[item.typeName], item.path)

		// Only expand a type's fields once, and only within the depth limit.
		if expanded[item.typeName] || item.depth >= 5 {
			continue
		}
		expanded[item.typeName] = true

		typeDef := s.FindType(item.typeName)
		if typeDef == nil {
			continue
		}
		for _, f := range typeDef.Fields {
			if f.Type == nil {
				continue
			}
			childName := f.Type.Unwrap().Name
			if childName == "" || s.IsBuiltinType(childName) {
				continue
			}
			queue = append(queue, qitem{
				typeName: childName,
				path:     item.path + "." + f.Name,
				depth:    item.depth + 1,
			})
		}
	}

	return result
}

// hitSeverity maps a sensitiveFieldHit's score and reachability to a Severity.
func hitSeverity(hit sensitiveFieldHit) Severity {
	reachable := len(hit.ReachableVia) > 0

	if hit.Score >= 10 {
		if hit.IsDirectlyQueryable {
			return HIGH
		}
		if reachable {
			return MEDIUM
		}
		return LOW
	}

	// Score 7–9.
	if hit.IsDirectlyQueryable {
		return MEDIUM
	}
	if reachable {
		return LOW
	}
	return INFO
}

// buildDescription produces the formatted, column-aligned description block for a finding.
func buildDescription(group typeGroup) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Type: %s (%s)\n", group.TypeName, group.TypeKind))
	if len(group.AccessPaths) > 0 {
		sb.WriteString(fmt.Sprintf("Reachable via: %s\n", strings.Join(group.AccessPaths, ", ")))
	} else {
		sb.WriteString("Reachable via: (not reachable from Query or Mutation roots)\n")
	}
	sb.WriteString("\nSensitive fields detected:\n\n")

	// Sort hits: score descending, then field name alphabetically.
	hits := make([]sensitiveFieldHit, len(group.Hits))
	copy(hits, group.Hits)
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Field.Name < hits[j].Field.Name
	})

	// Compute column widths for aligned output.
	maxNameLen := 10
	maxTagLen := 12
	for _, h := range hits {
		if n := len(h.Field.Name); n > maxNameLen {
			maxNameLen = n
		}
		tagStr := "[" + strings.Join(h.Tags, ",") + "]"
		if n := len(tagStr); n > maxTagLen {
			maxTagLen = n
		}
	}

	for _, h := range hits {
		sev := hitSeverity(h)
		tagStr := "[" + strings.Join(h.Tags, ",") + "]"
		sb.WriteString(fmt.Sprintf("  %-*s  %-*s  score: %-2d  severity: %s\n",
			maxNameLen, h.Field.Name,
			maxTagLen, tagStr,
			h.Score,
			sev.String(),
		))
		if h.Field.Type != nil {
			sb.WriteString(fmt.Sprintf("    Type: %s\n", h.Field.Type.String()))
		}
		sb.WriteString(fmt.Sprintf("    Note: %s\n", fieldNote(h)))
		if h.Field.Description != "" && len(h.Field.Description) < 100 {
			sb.WriteString(fmt.Sprintf("    Description: %s\n", h.Field.Description))
		}
		sb.WriteString("\n")
	}

	return strings.TrimRight(sb.String(), "\n")
}

// buildImpact generates a plain-English paragraph for a CISO or engineering manager.
func buildImpact(group typeGroup) string {
	hasTag := func(tag string) bool {
		for _, t := range group.AllTags {
			if t == tag {
				return true
			}
		}
		return false
	}

	fieldList := func(max int) string {
		hits := make([]sensitiveFieldHit, len(group.Hits))
		copy(hits, group.Hits)
		sort.Slice(hits, func(i, j int) bool {
			return hits[i].Score > hits[j].Score
		})
		names := make([]string, 0, max)
		for _, h := range hits {
			names = append(names, h.Field.Name)
			if len(names) >= max {
				break
			}
		}
		return strings.Join(names, ", ")
	}

	var impact string
	switch {
	case hasTag("credential"):
		impact = fmt.Sprintf(
			"The %s type exposes credential fields (%s) in the GraphQL schema. "+
				"If introspection is enabled or field names are leaked via suggestions, an attacker "+
				"can identify these fields and target them for extraction, brute force, or injection attacks.",
			group.TypeName, fieldList(5),
		)
	case hasTag("pii"):
		impact = fmt.Sprintf(
			"The %s type exposes personally identifiable information (%s). "+
				"Exposure of PII fields in the schema — even without successful data extraction — "+
				"may constitute a compliance finding under GDPR, CCPA, or HIPAA depending on your jurisdiction.",
			group.TypeName, fieldList(5),
		)
	case hasTag("financial"):
		impact = fmt.Sprintf(
			"The %s type exposes financial data fields (%s). "+
				"Schema exposure of financial fields signals to attackers where to focus "+
				"authorization bypass and injection attempts. PCI-DSS scope may be affected.",
			group.TypeName, fieldList(5),
		)
	default:
		impact = fmt.Sprintf(
			"The %s type exposes %d field(s) that match sensitive data patterns. "+
				"These fields represent elevated-risk targets for data extraction attacks.",
			group.TypeName, len(group.Hits),
		)
	}

	if anyDirectlyQueryable(group.Hits) {
		impact += " This type is directly accessible from the Query root, meaning these fields" +
			" are one level of authorization bypass away from being exposed."
	}

	return impact
}

// buildRemediation generates the three-section remediation guidance.
func buildRemediation(group typeGroup) string {
	// Collect credential/PII field names for the "rarely needed" reminder.
	var rareFields []string
	seen := make(map[string]bool)
	for _, h := range group.Hits {
		for _, tag := range h.Tags {
			if (tag == "credential" || tag == "pii") && !seen[h.Field.Name] {
				rareFields = append(rareFields, h.Field.Name)
				seen[h.Field.Name] = true
				break
			}
		}
	}

	// Top fields by score descending (max 3) for monitoring guidance.
	topHits := make([]sensitiveFieldHit, len(group.Hits))
	copy(topHits, group.Hits)
	sort.Slice(topHits, func(i, j int) bool {
		return topHits[i].Score > topHits[j].Score
	})
	topFields := make([]string, 0, 3)
	for _, h := range topHits {
		topFields = append(topFields, h.Field.Name)
		if len(topFields) >= 3 {
			break
		}
	}

	if len(rareFields) == 0 {
		rareFields = topFields
	}
	if len(rareFields) > 3 {
		rareFields = rareFields[:3]
	}

	exampleField := "sensitiveField"
	if len(topFields) > 0 {
		exampleField = topFields[0]
	}
	rareList := strings.Join(rareFields, ", ")
	topList := strings.Join(topFields, ", ")

	return fmt.Sprintf(
		"IMMEDIATE:\n"+
			"  Review whether each flagged field needs to be in the GraphQL schema at all.\n"+
			"  Fields like %s are rarely needed by API consumers\n"+
			"  and should be removed from the schema if not required.\n"+
			"\n"+
			"FIELD-LEVEL AUTHORIZATION:\n"+
			"  Implement field-level authorization checks on all sensitive fields.\n"+
			"  These should verify the requesting user has explicit permission to read\n"+
			"  each sensitive field — not just permission to query the parent type.\n"+
			"\n"+
			"  Apollo Server example:\n"+
			"    const resolvers = {\n"+
			"      %s: {\n"+
			"        %s: (parent, args, context) => {\n"+
			"          if (!context.user?.isAdmin) throw new ForbiddenError('Access denied');\n"+
			"          return parent.%s;\n"+
			"        }\n"+
			"      }\n"+
			"    }\n"+
			"\n"+
			"MONITORING:\n"+
			"  Add logging and alerting on access to sensitive fields.\n"+
			"  Unusual access patterns (bulk queries, unauthenticated access, off-hours access)\n"+
			"  on fields like %s should trigger security alerts.",
		rareList,
		group.TypeName,
		exampleField,
		exampleField,
		topList,
	)
}

// anyDirectlyQueryable returns true if any hit in the slice is directly queryable.
func anyDirectlyQueryable(hits []sensitiveFieldHit) bool {
	for _, h := range hits {
		if h.IsDirectlyQueryable {
			return true
		}
	}
	return false
}

// fieldNote returns a human-readable explanation of why a field was flagged.
func fieldNote(hit sensitiveFieldHit) string {
	for _, tag := range hit.Tags {
		switch tag {
		case "credential":
			return "Field name matches credential pattern"
		case "pii":
			return "Field name matches PII pattern"
		case "financial":
			return "Field name matches financial data pattern"
		case "privileged":
			return "Field name matches privileged access pattern"
		case "sensitive":
			return "Field name suggests internal/private data"
		}
	}
	return fmt.Sprintf("Field name has sensitivity score %d", hit.Score)
}

// deduplicateStrings returns a copy of s with duplicates removed, preserving order.
func deduplicateStrings(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
