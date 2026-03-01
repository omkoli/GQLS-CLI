package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSensitiveTagsFor_Password(t *testing.T) {
	score, tags := SensitiveTagsFor("password")
	assert.Equal(t, 10, score)
	assert.Contains(t, tags, "credential")
}

func TestSensitiveTagsFor_Email(t *testing.T) {
	score, tags := SensitiveTagsFor("email")
	assert.Equal(t, 4, score)
	assert.Contains(t, tags, "pii")
}

func TestSensitiveTagsFor_Benign(t *testing.T) {
	score, tags := SensitiveTagsFor("createdAt")
	assert.Equal(t, 0, score)
	assert.Empty(t, tags)
}

func TestSensitiveTagsFor_CreditCard(t *testing.T) {
	score, tags := SensitiveTagsFor("creditCardNumber")
	assert.Equal(t, 10, score)
	assert.Contains(t, tags, "financial")
}

func TestSensitiveTagsFor_Token(t *testing.T) {
	score, tags := SensitiveTagsFor("accessToken")
	assert.Equal(t, 10, score)
	assert.Contains(t, tags, "credential")
}

func TestSensitiveTagsFor_SSN(t *testing.T) {
	score, tags := SensitiveTagsFor("ssn")
	assert.Equal(t, 10, score)
	assert.Contains(t, tags, "pii")
}

func TestSensitiveTagsFor_Salary(t *testing.T) {
	score, tags := SensitiveTagsFor("salary")
	assert.Equal(t, 8, score)
	assert.Contains(t, tags, "financial")
}

func TestClassifyType_PropagatesFromFields(t *testing.T) {
	// A type whose name is benign but has a field with score 10.
	td := &TypeDef{
		Name: "SomeRecord",
		Fields: []*FieldDef{
			{Name: "password", SensitivityScore: 10, Tags: []string{"credential"}},
		},
	}
	ClassifyType(td)
	// Type should get score = max(0, 10 - 2) = 8.
	assert.Equal(t, 8, td.SensitivityScore)
	assert.Contains(t, td.Tags, "credential")
}

func TestClassifyType_PropagatesNotBelowThreshold(t *testing.T) {
	// Field with score 7 should NOT propagate to type.
	td := &TypeDef{
		Name: "ARecord",
		Fields: []*FieldDef{
			{Name: "adminName", SensitivityScore: 7, Tags: []string{"privileged"}},
		},
	}
	ClassifyType(td)
	// adminName scores 7, which is < 8, so no propagation.
	// Type name "ARecord" scores 0. After ClassifyField, field score set.
	assert.Equal(t, 0, td.SensitivityScore, "fields scoring < 8 should not propagate to type")
}

func TestClassifyField_ChecksDescription(t *testing.T) {
	// Field name is neutral but description contains "password".
	fd := &FieldDef{
		Name:        "data",
		Description: "The hashed password for this account",
	}
	ClassifyField(fd)
	assert.Greater(t, fd.SensitivityScore, 0, "description matching pattern should set score > 0")
	assert.Contains(t, fd.Tags, "credential")
}

func TestClassifyField_NoMutation_WhenBenign(t *testing.T) {
	fd := &FieldDef{
		Name:        "createdAt",
		Description: "Timestamp when the record was created",
	}
	ClassifyField(fd)
	assert.Equal(t, 0, fd.SensitivityScore)
	assert.Empty(t, fd.Tags)
}

func TestClassifyField_HighestScoreWins(t *testing.T) {
	// "email" (4) vs "password" in description (10) → score should be 10.
	fd := &FieldDef{
		Name:        "email",
		Description: "password field",
	}
	ClassifyField(fd)
	assert.Equal(t, 10, fd.SensitivityScore)
}
