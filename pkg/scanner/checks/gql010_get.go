package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Misconfiguration is the vulnerability category for security misconfigurations.
const Misconfiguration Category = "Misconfiguration"

type getQueriesCheck struct{}

func init() {
	MustRegister(&getQueriesCheck{})
}

func (c *getQueriesCheck) ID() string           { return "GQL-010" }
func (c *getQueriesCheck) Name() string         { return "GraphQL GET Queries Enabled" }
func (c *getQueriesCheck) Category() Category   { return Misconfiguration }
func (c *getQueriesCheck) Severity() Severity   { return MEDIUM }
func (c *getQueriesCheck) RequiresSchema() bool { return false }

func (c *getQueriesCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	targetURL, err := url.Parse(cc.Target)
	if err != nil {
		result.Error = fmt.Errorf("parsing target URL: %w", err)
		return result, nil
	}

	q := targetURL.Query()
	q.Set("query", "{__typename}")
	targetURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		result.Error = fmt.Errorf("constructing GET request: %w", err)
		return result, nil
	}

	// Use the base client so curl-file headers (e.g. auth tokens) are not sent
	// with this probe. The base client already injects any --header flag values.
	resp, err := cc.ProbeClient().Do(req)
	result.ProbeCount++
	if err != nil {
		result.Error = fmt.Errorf("GET probe request: %w", err)
		return result, nil
	}

	// 405 Method Not Allowed or 400 Bad Request → endpoint rejects GET queries.
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusBadRequest {
		result.PassReason = fmt.Sprintf(
			"server responded HTTP %d; GET queries are not accepted",
			resp.StatusCode,
		)
		result.PassProbes = []PassProbe{{
			Label:   "GET probe — ?query={__typename}",
			Request: resp.Request,
		}}
		return result, nil
	}

	// Require a valid GraphQL JSON body with a non-null "data" field.
	var parsed struct {
		Data json.RawMessage `json:"data"`
	}
	if jsonErr := json.Unmarshal(resp.Body, &parsed); jsonErr != nil ||
		len(parsed.Data) == 0 ||
		string(parsed.Data) == "null" {
		result.PassReason = "response does not contain a valid GraphQL \"data\" field; GET queries appear unsupported"
		result.PassProbes = []PassProbe{{
			Label:   "GET probe — ?query={__typename}",
			Request: resp.Request,
		}}
		return result, nil
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  MEDIUM,
		Category:  Misconfiguration,
		Title:     "GraphQL GET Queries Enabled",
		Description: fmt.Sprintf(
			"The endpoint at %s accepted a GraphQL query via HTTP GET "+
				"(?query={__typename}) and returned a valid GraphQL response "+
				"containing a non-null \"data\" field.",
			cc.Target,
		),
		Impact: "Accepting queries over GET exposes the API to CSRF attacks because browsers " +
			"submit GET requests cross-origin without CORS preflight checks. Query strings are " +
			"also recorded by proxies, CDNs, and web servers, leaking query contents in access " +
			"logs. Caching layers may store authenticated responses and replay them to " +
			"unauthenticated users.",
		Remediation: "Restrict GraphQL operations to HTTP POST only. " +
			"In Apollo Server set allowGet: false (verify it has not been overridden). " +
			"In express-graphql, route only POST requests to the GraphQL handler. " +
			"Configure reverse proxies (nginx, HAProxy, AWS ALB) to return HTTP 405 for " +
			"GET requests targeting the GraphQL endpoint. " +
			"As a defence-in-depth measure, require the Content-Type: application/json " +
			"header, which browsers cannot set cross-origin without a CORS preflight.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://graphql.org/learn/serving-over-http/#get-request",
			"https://owasp.org/www-community/attacks/csrf",
		},
		ReproRequest: resp.Request,
		ReproBody:    nil, // GET requests carry no body.
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "get_queries_enabled"),
	})

	return result, nil
}
