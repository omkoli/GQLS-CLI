package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type playgroundCheck struct{}

func init() {
	Register(&playgroundCheck{})
}

func (c *playgroundCheck) ID() string           { return "GQL-004" }
func (c *playgroundCheck) Name() string         { return "GraphQL Playground Exposed" }
func (c *playgroundCheck) Category() Category   { return InformationDisclosure }
func (c *playgroundCheck) Severity() Severity   { return MEDIUM }
func (c *playgroundCheck) RequiresSchema() bool { return false }

// playgroundSignatures maps a lowercase HTML needle to the human-readable product name.
var playgroundSignatures = []struct {
	needle string
	name   string
}{
	{"graphiql", "GraphiQL"},
	{"apollo-sandbox", "Apollo Sandbox"},
	{"embeddable-sandbox", "Apollo Sandbox"},
	{"apollographql.com/docs/apollo-server/testing/graphql-playground", "Apollo Playground"},
	{"graphql-playground", "GraphQL Playground"},
	{"graphql playground", "GraphQL Playground"},
}

func (c *playgroundCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cc.Target, nil)
	if err != nil {
		result.Error = err
		return result, nil
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		result.Error = err
		return result, nil
	}

	lower := strings.ToLower(string(resp.Body))

	seen := make(map[string]bool)
	for _, sig := range playgroundSignatures {
		if strings.Contains(lower, sig.needle) && !seen[sig.name] {
			seen[sig.name] = true
			result.Findings = append(result.Findings, Finding{
				CheckID:     c.ID(),
				CheckName:   c.Name(),
				Severity:    c.Severity(),
				Category:    c.Category(),
				Description: fmt.Sprintf("%s is exposed at %s. The interactive query editor is accessible without authentication.", sig.name, cc.Target),
				Impact:      "Any visitor can explore, construct, and execute GraphQL queries directly in a browser. Combined with introspection this gives a complete attack surface map.",
				Remediation: "Disable playground UIs before deploying to production. Apollo Server: set `playground: false` (v2) or remove the Sandbox plugin (v4). Restrict the route by IP or require authentication if the UI is needed for internal use.",
				References: []string{
					"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
					"https://www.apollographql.com/docs/apollo-server/security/introspection/",
				},
				ReproRequest: resp.Request,
				Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, sig.name),
			})
		}
	}

	if len(result.Findings) == 0 {
		result.PassReason = "No interactive GraphQL playground UI was detected. The HTTP GET response contained no signatures for GraphiQL, Apollo Sandbox, Apollo Playground, or GraphQL Playground — the endpoint does not appear to serve a browser-accessible query editor."
		result.PassProbes = []PassProbe{
			{
				Label:   "Playground detection probe — HTTP GET with Accept: text/html",
				Request: resp.Request,
				Body:    nil,
			},
		}
	}

	return result, nil
}
