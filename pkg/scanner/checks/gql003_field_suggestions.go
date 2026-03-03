package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// fieldSuggestionPatterns mirrors those in schema/harvester for extracting field names from errors.
var fieldSuggestionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Did you mean "([^"]+)"\?`),
	regexp.MustCompile(`Did you mean '([^']+)'\?`),
	regexp.MustCompile(`did you mean "([^"]+)"`),
	regexp.MustCompile(`Suggestions: \[([^\]]+)\]`),
	regexp.MustCompile(`Perhaps you meant: ([a-zA-Z_][a-zA-Z0-9_]*)`),
}

// fieldSuggestionSeeds is the set of root-level field names used as probe seeds.
var fieldSuggestionSeeds = []string{
	"user", "users", "me", "account", "admin",
	"order", "product", "settings", "health", "viewer",
}

type fieldSuggestionsCheck struct{}

func init() {
	Register(&fieldSuggestionsCheck{})
}

func (c *fieldSuggestionsCheck) ID() string           { return "GQL-003" }
func (c *fieldSuggestionsCheck) Name() string         { return "Schema Exposed via Field Suggestions" }
func (c *fieldSuggestionsCheck) Category() Category   { return InformationDisclosure }
func (c *fieldSuggestionsCheck) Severity() Severity   { return MEDIUM }
func (c *fieldSuggestionsCheck) RequiresSchema() bool { return false }

func (c *fieldSuggestionsCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID()}

	// First, check if introspection is enabled.
	// If it is, skip this check since GQL-001 already covers that case.
	const probeQuery = `{"query":"{ __schema { queryType { name } } }"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target,
		bytes.NewBufferString(probeQuery))
	if err != nil {
		result.Error = err
		return result, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		result.Error = err
		return result, nil
	}

	var parsed struct {
		Data struct {
			Schema *json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err == nil && parsed.Data.Schema != nil {
		// Introspection is enabled; skip this check
		result.Skipped = true
		result.SkipReason = "Introspection is enabled on this endpoint. GQL-001 already covers full schema exposure via introspection, making GQL-003 (field suggestion hints) redundant."
		return result, nil
	}

	// Introspection is disabled; proceed with the field suggestions check.
	result.Ran = true

	// Probe with typo queries and collect any field suggestions returned in errors.
	discovered, passProbes := c.harvestSuggestions(ctx, cc)
	if len(discovered) == 0 {
		result.PassReason = "Field suggestion hints are suppressed. Typo-based probes on common root field name seeds (user, users, me, account, admin, order, product, settings, health, viewer) returned no 'Did you mean?' suggestions in error messages — schema field names cannot be reconstructed via this technique."
		result.PassProbes = passProbes
		return result, nil
	}

	fieldList := strings.Join(discovered, ", ")
	if len(discovered) > 10 {
		fieldList = strings.Join(discovered[:10], ", ") + fmt.Sprintf(" … and %d more", len(discovered)-10)
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  c.Severity(),
		Category:  c.Category(),
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s leaks schema field names through 'Did you mean?' error messages despite introspection being disabled. "+
				"%d field name(s) were recovered via typo probing: %s.",
			cc.Target, len(discovered), fieldList,
		),
		Impact: "An attacker can reconstruct a partial schema by iteratively submitting typo queries and collecting suggestion hints, " +
			"effectively bypassing introspection controls and mapping the API surface without any special privileges. " +
			"This technique affects servers that believe they are protected by disabling introspection.",
		Remediation: "Disable field suggestion hints in your GraphQL server. " +
			"Apollo Server: configure a custom `formatError` function that strips suggestion text from error messages. " +
			"graphql-js: replace the built-in `didYouMean` helper or suppress it via a custom validation rule. " +
			"Yoga/Envelop: use `useMaskedErrors()` to suppress verbose error details in production.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://graphql.org/learn/best-practices/#error-handling",
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
		},
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "field_suggestions_enabled"),
	})

	return result, nil
}

// harvestSuggestions sends a single typo variant per seed and collects all unique field names
// returned in GraphQL suggestion error messages. It also returns a PassProbe for every request
// that was successfully sent, to support no-finding explanations in reports.
func (c *fieldSuggestionsCheck) harvestSuggestions(ctx context.Context, cc *CheckContext) ([]string, []PassProbe) {
	seen := make(map[string]bool)
	var results []string
	var passProbes []PassProbe

	for _, seed := range fieldSuggestionSeeds {
		select {
		case <-ctx.Done():
			return results, passProbes
		default:
		}

		// Append "z" to turn a valid field name into a near-miss typo that triggers suggestions.
		typo := seed + "z"
		query := fmt.Sprintf(`{ %s { id } }`, typo)
		payload, err := json.Marshal(map[string]string{"query": query})
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := cc.ProbeClient().Do(req)
		if err != nil {
			continue
		}

		passProbes = append(passProbes, PassProbe{
			Label:   fmt.Sprintf("Field suggestion probe — seed %q, typo query: { %s { id } }", seed, typo),
			Request: resp.Request,
			Body:    payload,
		})

		for _, name := range extractFieldSuggestions(resp.Body) {
			if !seen[name] {
				seen[name] = true
				results = append(results, name)
			}
		}
	}

	return results, passProbes
}

// extractFieldSuggestions parses a GraphQL error response and returns all suggested field names.
func extractFieldSuggestions(body []byte) []string {
	if len(body) == 0 {
		return nil
	}

	var resp struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var results []string

	for _, e := range resp.Errors {
		for _, pat := range fieldSuggestionPatterns {
			matches := pat.FindStringSubmatch(e.Message)
			if len(matches) < 2 {
				continue
			}
			name := matches[1]
			if !seen[name] {
				seen[name] = true
				results = append(results, name)
			}
		}
	}

	return results
}
