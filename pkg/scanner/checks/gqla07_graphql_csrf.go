package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// graphqlCSRFCheck implements GQL-A07: GraphQL CSRF. It detects whether the
// endpoint accepts operations over request shapes a browser can forge cross-site
// without a CORS preflight — GET requests and POSTs with a "simple" content-type
// (text/plain, application/x-www-form-urlencoded) — and without requiring a CSRF
// token. This is exactly the class Apollo Server's csrfPrevention defends against.
type graphqlCSRFCheck struct{}

func init() {
	MustRegister(&graphqlCSRFCheck{})
}

func (c *graphqlCSRFCheck) ID() string { return "GQL-A07" }
func (c *graphqlCSRFCheck) Name() string {
	return "GraphQL CSRF (State Change via GET / Simple Content-Type)"
}
func (c *graphqlCSRFCheck) Category() Category   { return Authorization }
func (c *graphqlCSRFCheck) Severity() Severity   { return HIGH }
func (c *graphqlCSRFCheck) RequiresSchema() bool { return false }

// csrfCanary is a non-mutating operation used to demonstrate transport
// acceptance of a CSRF-able request shape.
const csrfCanary = "{ __typename }"

// csrfRejectRe matches responses that indicate the server rejected a
// browser-forgeable shape (Apollo csrfPrevention / preflight enforcement).
var csrfRejectRe = regexp.MustCompile(`(?i)(this operation has been blocked as a potential csrf|require[sd]? .*preflight|non-?preflight|csrf|apollo-require-preflight)`)

// csrfVector is one browser-forgeable request shape.
type csrfVector struct {
	label       string
	method      string
	contentType string
	// build returns the request URL and body for the given GraphQL document.
	build func(target, doc string) (string, []byte)
}

// csrfVectors are the browser-forgeable shapes, in deterministic order.
var csrfVectors = []csrfVector{
	{
		label: "GET ?query=", method: http.MethodGet, contentType: "",
		build: func(target, doc string) (string, []byte) {
			u, err := url.Parse(target)
			if err != nil {
				return target, nil
			}
			q := u.Query()
			q.Set("query", doc)
			u.RawQuery = q.Encode()
			return u.String(), nil
		},
	},
	{
		label: "POST text/plain", method: http.MethodPost, contentType: "text/plain",
		build: func(target, doc string) (string, []byte) {
			body, _ := json.Marshal(map[string]string{"query": doc})
			return target, body
		},
	},
	{
		label: "POST application/x-www-form-urlencoded", method: http.MethodPost,
		contentType: "application/x-www-form-urlencoded",
		build: func(target, doc string) (string, []byte) {
			return target, []byte("query=" + url.QueryEscape(doc))
		},
	},
}

// Run executes the GraphQL CSRF check.
func (c *graphqlCSRFCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}
	client := cc.ProbeClient()

	// ── Baseline: confirm the normal POST application/json path works ─────────
	jsonBody, _ := json.Marshal(map[string]string{"query": csrfCanary})
	baseResp, _, berr := c.send(ctx, client, http.MethodPost, cc.Target, "application/json", jsonBody)
	result.ProbeCount++
	if berr != nil || !csrfAccepted(baseResp) {
		result.PassReason = "endpoint did not respond to the JSON baseline probe (cannot assess CSRF)"
		return result, nil
	}

	// ── Probe each browser-forgeable shape with the non-mutating canary ───────
	var (
		accepted    []string
		passProbes  []PassProbe
		reproReq    *http.Request
		reproBody   []byte
		firstVecIdx = -1
	)
	for vi := range csrfVectors {
		if ctx.Err() != nil {
			break
		}
		v := csrfVectors[vi]
		u, body := v.build(cc.Target, csrfCanary)
		resp, sentBody, err := c.send(ctx, client, v.method, u, v.contentType, body)
		result.ProbeCount++
		if err != nil || resp == nil {
			continue
		}
		if csrfAccepted(resp) {
			accepted = append(accepted, v.label)
			if firstVecIdx == -1 {
				firstVecIdx = vi
				reproReq = resp.Request
				reproBody = sentBody
			}
		} else {
			passProbes = append(passProbes, PassProbe{
				Label:   fmt.Sprintf("CSRF vector rejected: %s", v.label),
				Request: resp.Request,
				Body:    sentBody,
			})
		}
	}

	if len(accepted) == 0 {
		result.PassReason = "the server rejected every browser-forgeable request shape " +
			"(GET / text/plain / form-encoded); it enforces a JSON content-type or CSRF preflight"
		result.PassProbes = passProbes
		return result, nil
	}

	// ── Optional: upgrade to "confirmed" by executing a real mutation over a
	//    CSRF-able shape — only when writes are explicitly allowed ──────────────
	confidence := "firm"
	mutationNote := "a non-mutating query executed over the shape(s) above"
	if cc.AllowMutations {
		if m, ok := safeNoArgMutation(cc.Schema); ok {
			doc := fmt.Sprintf("mutation { %s%s }", m.Name, mutSelectionSet(m.Type, cc.Schema))
			v := csrfVectors[firstVecIdx]
			u, body := v.build(cc.Target, doc)
			if resp, sentBody, err := c.send(ctx, client, v.method, u, v.contentType, body); err == nil && csrfAccepted(resp) {
				confidence = "confirmed"
				mutationNote = fmt.Sprintf("the state-changing mutation %q executed over %s", m.Name, v.label)
				reproReq = resp.Request
				reproBody = sentBody
			}
			result.ProbeCount++
		}
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  Authorization,
		Title:     "GraphQL CSRF — operations accepted over browser-forgeable request shapes",
		Description: fmt.Sprintf(
			"The endpoint executed GraphQL operations over browser-forgeable request shape(s) [%s] without "+
				"requiring a CSRF token or CORS preflight; %s. A malicious page can cause a victim's browser "+
				"to submit these requests cross-site using the victim's cookies.",
			strings.Join(accepted, ", "), mutationNote),
		Impact: "A malicious web page can make a victim's browser submit authenticated GraphQL operations " +
			"cross-site using the victim's session cookies, performing actions as the victim (CSRF) — account " +
			"changes, data modification, or privileged actions depending on the exposed operations.",
		Remediation: "Enable CSRF prevention (e.g. Apollo `csrfPrevention: true`): require an " +
			"`application/json` content-type and reject simple content-types; require a custom header " +
			"(e.g. `Apollo-Require-Preflight` / `X-CSRF-Token`) that forces a CORS preflight; never accept " +
			"mutations over GET; use SameSite cookies and anti-CSRF tokens for cookie-authenticated GraphQL.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
			"https://www.apollographql.com/docs/apollo-server/security/cors#preventing-cross-site-request-forgery-csrf",
			"https://cwe.mitre.org/data/definitions/352.html",
		},
		Confidence:   confidence,
		CWE:          "CWE-352",
		OWASP:        "API8:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "graphql_csrf"),
		ReproRequest: reproReq,
		ReproBody:    reproBody,
	})
	return result, nil
}

// send issues a single request of the given shape and returns the response and
// the request body bytes.
func (c *graphqlCSRFCheck) send(ctx context.Context, client *transport.Client, method, target, contentType string, body []byte) (*transport.Response, []byte, error) {
	if client == nil {
		return nil, body, fmt.Errorf("nil client")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, body, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, body, err
	}
	return resp, body, nil
}

// csrfAccepted reports whether a response indicates the operation executed over
// the tested shape: HTTP 200 with a non-null data object and no CSRF/preflight
// rejection error.
func csrfAccepted(resp *transport.Response) bool {
	if resp == nil || resp.StatusCode != 200 {
		return false
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return false
	}
	for _, e := range env.Errors {
		if csrfRejectRe.MatchString(e.Message) {
			return false
		}
	}
	return env.Data != nil && strings.TrimSpace(string(env.Data)) != "null"
}

// safeNoArgMutation returns a non-destructive mutation that takes no required
// arguments, suitable for a (write-gated) CSRF impact demonstration.
func safeNoArgMutation(s *schema.Schema) (*schema.FieldDef, bool) {
	if s == nil {
		return nil, false
	}
	muts := make([]*schema.FieldDef, len(s.MutationFields()))
	copy(muts, s.MutationFields())
	sort.Slice(muts, func(i, j int) bool { return muts[i].Name < muts[j].Name })
	for _, m := range muts {
		if m == nil || a05DestructiveRe.MatchString(m.Name) || hasRequiredArgs(m) {
			continue
		}
		return m, true
	}
	return nil, false
}
