package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type introspectionCheck struct{}

func init() {
	Register(&introspectionCheck{})
}

func (c *introspectionCheck) ID() string           { return "GQL-001" }
func (c *introspectionCheck) Name() string         { return "Introspection Enabled" }
func (c *introspectionCheck) Category() Category   { return InformationDisclosure }
func (c *introspectionCheck) Severity() Severity   { return HIGH }
func (c *introspectionCheck) RequiresSchema() bool { return false }

func (c *introspectionCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	const probeQuery = `{"query":"{ __schema { queryType { name } } }"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target,
		bytes.NewBufferString(probeQuery))
	if err != nil {
		result.Error = err
		return result, nil
	}
	req.Header.Set("Content-Type", "application/json")

	// Always probe introspection without credentials. GQL-001's threat model is
	// "can an unauthenticated attacker access the full schema?", so auth tokens,
	// session cookies, and API keys must never influence the outcome regardless of
	// how the scan was invoked. UnauthenticatedClient is constructed once by the
	// scan orchestrator with no default headers; fall back to HTTPClient only in
	// test environments that do not populate the field.
	client := cc.UnauthenticatedClient
	if client == nil {
		client = cc.HTTPClient
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		return result, nil
	}

	var parsed struct {
		Data struct {
			Schema *json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil || parsed.Data.Schema == nil {
		result.PassReason = "Introspection is disabled. The server did not return schema data in response to the `{ __schema { queryType { name } } }` probe — the full schema cannot be enumerated via standard introspection."
		result.PassProbes = []PassProbe{
			{
				Label:   `Introspection probe — { __schema { queryType { name } } }`,
				Request: resp.Request,
				Body:    []byte(probeQuery),
			},
		}
		return result, nil
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:     c.ID(),
		CheckName:   c.Name(),
		Severity:    c.Severity(),
		Category:    c.Category(),
		Description: fmt.Sprintf("GraphQL introspection is enabled at %s. The complete schema — every type, field, mutation, and subscription — is publicly queryable.", cc.Target),
		Impact:      "An attacker can enumerate the entire API surface, discover undocumented or internal fields, and precisely target sensitive operations without any guesswork.",
		Remediation: "Disable introspection in production environments. Apollo Server: set `introspection: false`. graphql-java: use `GraphQL.Builder#instrumentation`. Yoga/Envelop: use `useDisableIntrospection()` plugin.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://www.apollographql.com/docs/apollo-server/security/introspection/",
		},
		ReproRequest: resp.Request,
		ReproBody:    []byte(probeQuery),
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "introspection_enabled"),
	})

	return result, nil
}
