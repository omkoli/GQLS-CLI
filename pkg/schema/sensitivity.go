package schema

import (
	"regexp"
	"strings"
)

// sensitivityRule maps a compiled regex pattern to a tag and a score.
type sensitivityRule struct {
	pattern *regexp.Regexp
	tag     string
	score   int
}

// sensitivityRules is the ordered table of sensitivity patterns.
var sensitivityRules = []sensitivityRule{
	{regexp.MustCompile(`(?i)password|passwd|pwd`), "credential", 10},
	{regexp.MustCompile(`(?i)token|apikey|api_key|secret|private_key`), "credential", 10},
	{regexp.MustCompile(`(?i)ssn|social.?security`), "pii", 10},
	{regexp.MustCompile(`(?i)credit.?card|card.?number|cvv|ccv|pan`), "financial", 10},
	{regexp.MustCompile(`(?i)salary|compensation|wage|income`), "financial", 8},
	{regexp.MustCompile(`(?i)dob|date.?of.?birth|birthday`), "pii", 7},
	{regexp.MustCompile(`(?i)admin|superuser|root`), "privileged", 7},
	{regexp.MustCompile(`(?i)internal|private|debug|backdoor`), "sensitive", 6},
	{regexp.MustCompile(`(?i)phone|mobile|cell`), "pii", 5},
	{regexp.MustCompile(`(?i)address|location|coordinates|lat|lng`), "pii", 4},
	{regexp.MustCompile(`(?i)email`), "pii", 4},
	{regexp.MustCompile(`(?i)ip.?address|ip_addr`), "pii", 4},
}

// SensitiveTagsFor returns the maximum sensitivity score and all matching tags for
// the given name string. It is a pure function with no side effects.
func SensitiveTagsFor(name string) (score int, tags []string) {
	tagSet := make(map[string]bool)
	for _, rule := range sensitivityRules {
		if rule.pattern.MatchString(name) {
			if rule.score > score {
				score = rule.score
			}
			tagSet[rule.tag] = true
		}
	}
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return score, tags
}

// ClassifyField mutates f.SensitivityScore and f.Tags in place.
// It checks the field name and description against all sensitivity patterns
// and takes the maximum score found.
func ClassifyField(f *FieldDef) {
	if f == nil {
		return
	}
	nameScore, nameTags := SensitiveTagsFor(f.Name)
	descScore, descTags := SensitiveTagsFor(f.Description)

	maxScore := nameScore
	tagSet := make(map[string]bool)
	for _, t := range nameTags {
		tagSet[t] = true
	}

	if descScore > maxScore {
		maxScore = descScore
	}
	for _, t := range descTags {
		tagSet[t] = true
	}

	if maxScore > f.SensitivityScore {
		f.SensitivityScore = maxScore
	}

	existingTags := make(map[string]bool)
	for _, t := range f.Tags {
		existingTags[t] = true
	}
	for tag := range tagSet {
		if !existingTags[tag] {
			f.Tags = append(f.Tags, tag)
		}
	}
	sortTags(f.Tags)
}

// ClassifyType mutates t.SensitivityScore and t.Tags in place.
// It checks the type name, and also propagates high-scoring fields:
// if any field scores >= 8, the type gets score = max(type_score, field_score - 2).
func ClassifyType(t *TypeDef) {
	if t == nil {
		return
	}
	nameScore, nameTags := SensitiveTagsFor(t.Name)
	tagSet := make(map[string]bool)
	for _, tag := range nameTags {
		tagSet[tag] = true
	}

	maxScore := nameScore

	// Propagate from fields.
	allFields := append(t.Fields, t.InputFields...)
	for _, f := range allFields {
		if f == nil {
			continue
		}
		if f.SensitivityScore >= 8 {
			propagated := f.SensitivityScore - 2
			if propagated > maxScore {
				maxScore = propagated
			}
			for _, tag := range f.Tags {
				tagSet[tag] = true
			}
		}
	}

	if maxScore > t.SensitivityScore {
		t.SensitivityScore = maxScore
	}

	existingTags := make(map[string]bool)
	for _, tag := range t.Tags {
		existingTags[tag] = true
	}
	for tag := range tagSet {
		if !existingTags[tag] {
			t.Tags = append(t.Tags, tag)
		}
	}
	sortTags(t.Tags)
}

// sortTags sorts a slice of tags in-place for deterministic output.
func sortTags(tags []string) {
	// simple insertion sort for small slices
	for i := 1; i < len(tags); i++ {
		for j := i; j > 0 && strings.Compare(tags[j-1], tags[j]) > 0; j-- {
			tags[j-1], tags[j] = tags[j], tags[j-1]
		}
	}
}
