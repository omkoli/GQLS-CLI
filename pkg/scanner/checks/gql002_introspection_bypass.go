package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type introspectionBypassCheck struct{}

func init() {
	Register(&introspectionBypassCheck{})
}

func (c *introspectionBypassCheck) ID() string           { return "GQL-002" }
func (c *introspectionBypassCheck) Name() string         { return "Introspection Bypass via __type" }
func (c *introspectionBypassCheck) Category() Category   { return InformationDisclosure }
func (c *introspectionBypassCheck) Severity() Severity   { return HIGH }
func (c *introspectionBypassCheck) RequiresSchema() bool { return false }

func (c *introspectionBypassCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// Only meaningful when __schema introspection is actually blocked.
	// If full introspection is on, GQL-001 is the relevant finding.
	const schemaProbe = `{"query":"{ __schema { queryType { name } } }"}`
	schemaReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target,
		bytes.NewBufferString(schemaProbe))
	if err != nil {
		result.Error = err
		return result, nil
	}
	schemaReq.Header.Set("Content-Type", "application/json")

	schemaResp, err := cc.ProbeClient().Do(schemaReq)
	if err != nil {
		result.Error = err
		return result, nil
	}

	var schemaParsed struct {
		Data struct {
			Schema *json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(schemaResp.Body, &schemaParsed); err == nil && schemaParsed.Data.Schema != nil {
		// Full introspection is on — GQL-001 covers this.
		result.Skipped = true
		result.SkipReason = "full introspection is enabled (covered by GQL-001)"
		return result, nil
	}

	// __schema is blocked. Probe __type — some servers block __schema but leave
	// __type open, allowing iterative type-by-type schema reconstruction.
	const bypassQuery = `{"query":"query TypeProbe { __type(name: \"Query\") { name fields { name type { name kind } } } }"}`
	bypassReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target,
		bytes.NewBufferString(bypassQuery))
	if err != nil {
		return result, nil
	}
	bypassReq.Header.Set("Content-Type", "application/json")

	bypassResp, err := cc.ProbeClient().Do(bypassReq)
	if err != nil {
		return result, nil
	}

	var bypassParsed struct {
		Data struct {
			Type *json.RawMessage `json:"__type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bypassResp.Body, &bypassParsed); err != nil || bypassParsed.Data.Type == nil {
		result.PassReason = "Introspection bypass via `__type` is not possible. The server blocked both `__schema` and `__type` meta-field queries — iterative type-by-type schema reconstruction is not available."
		result.PassProbes = []PassProbe{
			{
				Label:   `Schema probe (blocked) — { __schema { queryType { name } } }`,
				Request: schemaResp.Request,
				Body:    []byte(schemaProbe),
			},
			{
				Label:   `Bypass probe via __type (blocked) — query TypeProbe { __type(name: "Query") { ... } }`,
				Request: bypassResp.Request,
				Body:    []byte(bypassQuery),
			},
		}
		return result, nil
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:     c.ID(),
		CheckName:   c.Name(),
		Severity:    c.Severity(),
		Category:    c.Category(),
		Description: fmt.Sprintf("GraphQL introspection bypass via __type is possible at %s. Although __schema introspection appears disabled, the server responds to __type queries, allowing partial schema enumeration.", cc.Target),
		Impact:      "An attacker can probe individual types and their fields using __type queries, progressively mapping the API schema without triggering standard introspection blocks.",
		Remediation: "Ensure that field-level introspection meta-fields (__type, __field, __enumValue, etc.) are also blocked, not just __schema. Use a deny-list approach or an allow-list of permitted query shapes.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://www.apollographql.com/docs/apollo-server/security/introspection/",
		},
		ReproRequest: bypassResp.Request,
		ReproBody:    []byte(bypassQuery),
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "introspection_bypass_type_probe"),
	})

	return result, nil
}
