package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSchemaCheckContext builds a CheckContext for schema-only checks (no HTTP client needed).
func newSchemaCheckContext(target string, s *schema.Schema) *CheckContext {
	return &CheckContext{
		Target: target,
		Schema: s,
	}
}

// --- Metadata ---

func TestGQL006_Metadata(t *testing.T) {
	chk := &sensitiveFieldsCheck{}
	assert.Equal(t, "GQL-006", chk.ID())
	assert.Equal(t, "Sensitive Fields Exposed in Schema", chk.Name())
	assert.Equal(t, INFO, chk.Severity())
	assert.Equal(t, InformationDisclosure, chk.Category())
	assert.True(t, chk.RequiresSchema())
}

// --- Skip behaviour ---

func TestGQL006_RequiresSchema_SkipsWhenNil(t *testing.T) {
	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", nil))

	require.NoError(t, err)
	assert.True(t, result.Skipped)
	assert.False(t, result.Ran)
	assert.Equal(t, "schema_required_for_field_analysis", result.SkipReason)
	assert.Empty(t, result.Findings)
}

// --- Credential fields ---

func TestGQL006_CredentialField_ProducesHighSeverity(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "id", SensitivityScore: 0},
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	assert.True(t, result.Ran)
	assert.False(t, result.Skipped)
	require.Len(t, result.Findings, 1, "expected exactly one finding")

	f := result.Findings[0]
	assert.Equal(t, HIGH, f.Severity, "credential field + directly queryable should be HIGH")
	assert.Contains(t, f.Title, "User")
	assert.Contains(t, f.Description, "password")
	assert.Equal(t, 0, result.ProbeCount)
}

// --- Unreachable type severity ---

func TestGQL006_UnreachableType_LowerSeverity(t *testing.T) {
	// User has a score-10 field but is NOT reachable from Query.
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "health", Type: &schema.TypeRef{Name: "HealthStatus"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"HealthStatus": {
				Name:   "HealthStatus",
				Kind:   schema.KindObject,
				Fields: []*schema.FieldDef{{Name: "ok", SensitivityScore: 0}},
			},
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, LOW, result.Findings[0].Severity, "score 10 + not reachable should be LOW")
}

// --- Grouping ---

func TestGQL006_MultipleFieldsSameType_GroupedIntoOneFinding(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
					{Name: "ssn", SensitivityScore: 10, Tags: []string{"pii"}},
					{Name: "salary", SensitivityScore: 8, Tags: []string{"financial"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "all fields from one type should produce exactly one finding")

	f := result.Findings[0]
	assert.Equal(t, HIGH, f.Severity, "max score in group is 10 (directly queryable) → HIGH")
	assert.Contains(t, f.Description, "password")
	assert.Contains(t, f.Description, "ssn")
	assert.Contains(t, f.Description, "salary")
}

// --- Sub-threshold filtering ---

func TestGQL006_SubThresholdFields_NotIncluded(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "email", SensitivityScore: 4},
					{Name: "phone", SensitivityScore: 5},
					{Name: "createdAt", SensitivityScore: 0},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	assert.Empty(t, result.Findings, "all scores below threshold of 7 should produce no findings")
}

// --- Impact text ---

func TestGQL006_PII_Impact_ContainsComplianceLanguage(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "ssn", SensitivityScore: 10, Tags: []string{"pii"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	impact := result.Findings[0].Impact
	hasCompliance := strings.Contains(impact, "GDPR") ||
		strings.Contains(impact, "CCPA") ||
		strings.Contains(impact, "HIPAA")
	assert.True(t, hasCompliance, "PII impact should mention GDPR, CCPA, or HIPAA; got: %s", impact)
}

func TestGQL006_Financial_Impact_ContainsPCI(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "payment", Type: &schema.TypeRef{Name: "PaymentInfo"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"PaymentInfo": {
				Name: "PaymentInfo",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "cardNumber", SensitivityScore: 10, Tags: []string{"financial"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Contains(t, result.Findings[0].Impact, "PCI")
}

// --- Sort order ---

func TestGQL006_Findings_SortedBySeverityDescending(t *testing.T) {
	// AdminType: directly queryable, adminToken score 10 → HIGH
	// ReportType: reachable (not direct) via admin.reports, salary score 8 → LOW
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "admin", Type: &schema.TypeRef{Name: "AdminType"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"AdminType": {
				Name: "AdminType",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "adminToken", SensitivityScore: 10, Tags: []string{"credential"}},
					{Name: "reports", Type: &schema.TypeRef{Name: "ReportType"}},
				},
			},
			"ReportType": {
				Name: "ReportType",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "salary", SensitivityScore: 8, Tags: []string{"financial"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 2)
	assert.Equal(t, HIGH, result.Findings[0].Severity, "first finding should be HIGH")
	assert.Equal(t, LOW, result.Findings[1].Severity, "second finding should be LOW")
}

// --- BuildReachabilityMap: direct ---

func TestGQL006_BuildReachabilityMap_DirectQueryable(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name:   "User",
				Kind:   schema.KindObject,
				Fields: []*schema.FieldDef{{Name: "id", SensitivityScore: 0}},
			},
		},
	}

	reachability := BuildReachabilityMap(s)

	paths, ok := reachability["User"]
	require.True(t, ok, "User should be in the reachability map")
	assert.Contains(t, paths, "Query.user")
}

// --- BuildReachabilityMap: nested type ---

func TestGQL006_BuildReachabilityMap_NestedType(t *testing.T) {
	// Query.organization → Organization.members → User
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "organization", Type: &schema.TypeRef{Name: "Organization"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"Organization": {
				Name: "Organization",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "members", Type: &schema.TypeRef{Name: "User"}},
				},
			},
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	reachability := BuildReachabilityMap(s)

	paths, ok := reachability["User"]
	require.True(t, ok, "User should be reachable")
	require.NotEmpty(t, paths)

	var hasOrgPath bool
	for _, p := range paths {
		if strings.Contains(p, "Query.organization") {
			hasOrgPath = true
			break
		}
	}
	assert.True(t, hasOrgPath, "User access path should contain Query.organization; got: %v", paths)

	// User is NOT directly queryable — verify via finding severity.
	// score 10 + reachable but not direct → MEDIUM (not HIGH).
	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, MEDIUM, result.Findings[0].Severity,
		"reachable-but-not-direct type with score 10 should be MEDIUM")
}

// --- Circular schema ---

func TestGQL006_CircularSchema_NoInfiniteLoop(t *testing.T) {
	// User.friends → User (circular).
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "friends", Type: &schema.TypeRef{Name: "User"}, SensitivityScore: 0},
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	// Must terminate (no infinite loop).
	reachability := BuildReachabilityMap(s)

	_, ok := reachability["User"]
	assert.True(t, ok, "User should be in the reachability map despite circular reference")
}

// --- Description field filtering ---

func TestGQL006_DescriptionFormat_ColumnAligned(t *testing.T) {
	// password (score 10, above threshold) and email (score 4, below threshold).
	// Only password should appear in the description.
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
					{Name: "email", SensitivityScore: 4},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	desc := result.Findings[0].Description
	assert.Contains(t, desc, "password", "above-threshold field should appear in description")
	assert.NotContains(t, desc, "email", "below-threshold field must NOT appear in description")
}

// --- No sensitive fields ---

func TestGQL006_NoSensitiveFields_NoFindings(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "id", SensitivityScore: 0},
					{Name: "name", SensitivityScore: 0},
					{Name: "title", SensitivityScore: 0},
					{Name: "createdAt", SensitivityScore: 0},
					{Name: "updatedAt", SensitivityScore: 0},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	assert.True(t, result.Ran, "check should have run (not skipped)")
	assert.False(t, result.Skipped)
	assert.Empty(t, result.Findings)
}

// --- ProbeCount ---

func TestGQL006_ProbeCount_IsZero(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	assert.Equal(t, 0, result.ProbeCount, "GQL-006 makes zero HTTP requests")
}

// --- Fingerprint ---

func TestGQL006_Fingerprint_StableAndNonEmpty(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	ctx := newSchemaCheckContext("http://example.com/graphql", s)

	r1, _ := chk.Run(context.Background(), ctx)
	r2, _ := chk.Run(context.Background(), ctx)

	require.Len(t, r1.Findings, 1)
	require.Len(t, r2.Findings, 1)
	assert.NotEmpty(t, r1.Findings[0].Fingerprint)
	assert.Len(t, r1.Findings[0].Fingerprint, 64, "fingerprint should be a 64-char hex SHA-256")
	assert.Equal(t, r1.Findings[0].Fingerprint, r2.Findings[0].Fingerprint,
		"fingerprint must be stable across runs")
}

// --- hitSeverity unit tests ---

func TestGQL006_HitSeverity_Score10DirectlyQueryable_IsHigh(t *testing.T) {
	hit := sensitiveFieldHit{
		Score:               10,
		IsDirectlyQueryable: true,
		ReachableVia:        []string{"Query.user"},
	}
	assert.Equal(t, HIGH, hitSeverity(hit))
}

func TestGQL006_HitSeverity_Score10ReachableNotDirect_IsMedium(t *testing.T) {
	hit := sensitiveFieldHit{
		Score:               10,
		IsDirectlyQueryable: false,
		ReachableVia:        []string{"Query.org.members"},
	}
	assert.Equal(t, MEDIUM, hitSeverity(hit))
}

func TestGQL006_HitSeverity_Score10NotReachable_IsLow(t *testing.T) {
	hit := sensitiveFieldHit{
		Score:               10,
		IsDirectlyQueryable: false,
		ReachableVia:        nil,
	}
	assert.Equal(t, LOW, hitSeverity(hit))
}

func TestGQL006_HitSeverity_Score8DirectlyQueryable_IsMedium(t *testing.T) {
	hit := sensitiveFieldHit{
		Score:               8,
		IsDirectlyQueryable: true,
		ReachableVia:        []string{"Query.user"},
	}
	assert.Equal(t, MEDIUM, hitSeverity(hit))
}

func TestGQL006_HitSeverity_Score8ReachableNotDirect_IsLow(t *testing.T) {
	hit := sensitiveFieldHit{
		Score:               8,
		IsDirectlyQueryable: false,
		ReachableVia:        []string{"Query.org.members"},
	}
	assert.Equal(t, LOW, hitSeverity(hit))
}

func TestGQL006_HitSeverity_Score7NotReachable_IsInfo(t *testing.T) {
	hit := sensitiveFieldHit{
		Score:               7,
		IsDirectlyQueryable: false,
		ReachableVia:        nil,
	}
	assert.Equal(t, INFO, hitSeverity(hit))
}

// --- Remediation content ---

func TestGQL006_Remediation_ContainsThreeSections(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	rem := result.Findings[0].Remediation
	assert.Contains(t, rem, "IMMEDIATE:")
	assert.Contains(t, rem, "FIELD-LEVEL AUTHORIZATION:")
	assert.Contains(t, rem, "MONITORING:")
}

// --- References ---

func TestGQL006_References_ContainOWASP(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	refs := result.Findings[0].References
	require.NotEmpty(t, refs)
	var hasOWASP bool
	for _, r := range refs {
		if strings.Contains(r, "owasp.org") {
			hasOWASP = true
			break
		}
	}
	assert.True(t, hasOWASP, "references should include an OWASP link")
}

// --- Multiple types ---

func TestGQL006_MultipleTypes_ProduceSeparateFindings(t *testing.T) {
	s := &schema.Schema{
		QueryType: &schema.TypeDef{
			Name: "Query",
			Fields: []*schema.FieldDef{
				{Name: "user", Type: &schema.TypeRef{Name: "User"}},
				{Name: "payment", Type: &schema.TypeRef{Name: "PaymentInfo"}},
			},
		},
		Types: map[string]*schema.TypeDef{
			"User": {
				Name: "User",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
				},
			},
			"PaymentInfo": {
				Name: "PaymentInfo",
				Kind: schema.KindObject,
				Fields: []*schema.FieldDef{
					{Name: "cardNumber", SensitivityScore: 10, Tags: []string{"financial"}},
				},
			},
		},
	}

	chk := &sensitiveFieldsCheck{}
	result, err := chk.Run(context.Background(), newSchemaCheckContext("http://example.com/graphql", s))

	require.NoError(t, err)
	assert.Len(t, result.Findings, 2, "one finding per type")
}
