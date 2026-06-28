package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// subscriptionAuthzCheck implements GQL-A09: subscription authorization bypass.
// It detects when a GraphQL subscription delivers data over WebSocket to an
// under-privileged (anonymous) client even though the equivalent data is
// authorization-protected over HTTP — i.e. the WS path skips the authz applied
// to queries.
type subscriptionAuthzCheck struct{}

func init() {
	MustRegister(&subscriptionAuthzCheck{})
}

func (c *subscriptionAuthzCheck) ID() string { return "GQL-A09" }
func (c *subscriptionAuthzCheck) Name() string {
	return "Subscription Authorization Bypass (WebSocket)"
}
func (c *subscriptionAuthzCheck) Category() Category   { return Authorization }
func (c *subscriptionAuthzCheck) Severity() Severity   { return HIGH }
func (c *subscriptionAuthzCheck) RequiresSchema() bool { return true }

const (
	maxSubscriptions = 3
	wsWaitWindow     = 3 * time.Second
)

// Run executes the subscription authorization check.
func (c *subscriptionAuthzCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	subs := cc.Schema.SubscriptionFields()
	if len(subs) == 0 {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no subscription type in the schema (nothing to test for subscription authz)"
		return result, nil
	}
	if len(subs) > maxSubscriptions {
		subs = subs[:maxSubscriptions]
	}

	wsURL, derr := deriveWSURL(cc)
	if derr != nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "could not derive a WebSocket URL from the target: " + derr.Error()
		return result, nil
	}

	priv, hasPriv := highestPrivilegeOpt(cc.Identities)
	var (
		passProbes  []PassProbe
		reachable   bool
		comparisons int
	)

	for si := range subs {
		if ctx.Err() != nil {
			break
		}
		sub := subs[si]

		// ── HTTP control: is the equivalent data authz-protected for anonymous?
		authzExpected, controlNote := c.httpAuthzExpected(ctx, cc, sub, &result)
		if !authzExpected {
			passProbes = append(passProbes, PassProbe{
				Label: fmt.Sprintf("subscription %q: %s — not an A09 case", sub.Name, controlNote),
			})
			continue
		}

		// ── WS probe as anonymous (no auth) ───────────────────────────────────
		subDoc := buildSubscribeDoc(cc.Schema, sub)
		anon := transport.Subscribe(ctx, wsURL, nil, subDoc, wsWaitWindow)
		result.ProbeCount++
		if anon.Err == nil {
			reachable = true
		}
		comparisons++

		// ── Optional privileged baseline (confirms the subscription yields data
		//    for an authorized principal) ───────────────────────────────────────
		if hasPriv {
			_ = transport.Subscribe(ctx, wsURL, priv.Headers, subDoc, wsWaitWindow)
			result.ProbeCount++
		}

		switch {
		case anon.NextPayload != nil:
			// Confirmed: anonymous received streamed data the HTTP path denies it.
			result.Findings = append(result.Findings,
				c.finding(cc, sub, wsURL, subDoc, anon, "confirmed"))
		case anon.Acked && anon.Subscribed && !anon.Errored && wsRejectCode(anon.CloseCode) == 0:
			// Firm: the WS path accepted an anonymous subscription (no auth error)
			// but no data arrived within the window.
			result.Findings = append(result.Findings,
				c.finding(cc, sub, wsURL, subDoc, anon, "firm"))
		default:
			passProbes = append(passProbes, PassProbe{
				Label: fmt.Sprintf("subscription %q: WS rejected anonymous (acked=%v close=%d errored=%v) — authz enforced",
					sub.Name, anon.Acked, anon.CloseCode, anon.Errored),
			})
		}
	}

	if len(result.Findings) > 0 {
		return result, nil
	}

	result.PassProbes = passProbes
	switch {
	case comparisons == 0:
		result.PassReason = "no subscription had an HTTP-equivalent that is authz-protected for anonymous users; " +
			"subscription authz could not be differentially assessed"
	case !reachable:
		result.PassReason = "the WebSocket endpoint was unreachable for every subscription probe"
	default:
		result.PassReason = fmt.Sprintf(
			"tested %d subscription(s) over WebSocket; the subscription transport enforced authorization "+
				"(anonymous connections were rejected or delivered no data)", comparisons)
	}
	return result, nil
}

// httpAuthzExpected reports whether the data backing the subscription is
// authorization-protected for anonymous users over HTTP. It queries a related
// query field (same name, else same return type) as the unauthenticated client.
func (c *subscriptionAuthzCheck) httpAuthzExpected(ctx context.Context, cc *CheckContext,
	sub *schema.FieldDef, result *CheckResult) (bool, string) {

	related := relatedQueryField(cc.Schema, sub)
	if related == nil {
		return false, "no related HTTP query field found to establish the authz baseline"
	}
	query := buildRelatedQuery(cc.Schema, related)
	client := cc.UnauthenticatedClient
	if client == nil {
		client = cc.ProbeClient()
	}
	resp, _, err := gqlPost(ctx, client, cc.Target, query)
	result.ProbeCount++
	if err != nil || resp == nil {
		return false, "the HTTP authz baseline probe did not return a response"
	}
	switch authz.Classify(resp) {
	case authz.ClassAuthDenied:
		return true, "HTTP-equivalent query is denied to anonymous"
	case authz.ClassSuccess:
		return false, "HTTP-equivalent query is public (anonymous already permitted)"
	default:
		return false, "HTTP authz baseline was inconclusive"
	}
}

// finding builds the subscription-authz finding.
func (c *subscriptionAuthzCheck) finding(cc *CheckContext, sub *schema.FieldDef, wsURL, subDoc string,
	res transport.WSResult, confidence string) Finding {

	redacted := authz.RedactLeak(nil, &transport.Response{Body: res.NextPayload})
	if redacted == "" {
		redacted = "(no scalar payload received)"
	}
	proof := "the WebSocket path delivered a `next` data message to an anonymous client"
	if confidence == "firm" {
		proof = "the WebSocket path accepted an anonymous subscription (connection_ack + subscribe with no auth error), though no data arrived within the wait window"
	}

	reproFrames := fmt.Sprintf("// %s\n{\"type\":\"connection_init\"}\n{\"id\":\"1\",\"type\":\"subscribe\",\"payload\":{\"query\":%q}}",
		wsURL, subDoc)
	var reproReq *http.Request
	if r, err := http.NewRequest(http.MethodGet, wsURL, nil); err == nil {
		reproReq = r
	}

	return Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  Authorization,
		Title: fmt.Sprintf("Subscription Authorization Bypass — %s delivered over WebSocket without query-level authz",
			sub.Name),
		Description: fmt.Sprintf(
			"The HTTP-equivalent access to %q's data is denied to anonymous users, but %s over the %q "+
				"subprotocol. Subscriptions bypass the authorization enforced on queries. Delivered payload "+
				"(redacted): %s.",
			sub.Name, proof, res.Subprotocol, redacted),
		Impact: "Unauthorized clients can stream data — including real-time sensitive or owner-scoped data — " +
			"via subscriptions that bypass the authorization enforced on queries, enabling continuous data " +
			"exfiltration and privacy breaches.",
		Remediation: "Enforce authentication at the WebSocket connection_init handshake and authorization at " +
			"the subscription resolver, mirroring the query/middleware authz on the subscription path. Validate " +
			"the principal on every published event, not only at subscribe time, and reject unauthenticated " +
			"connection_init.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md",
			"https://cwe.mitre.org/data/definitions/285.html",
		},
		Confidence:   confidence,
		CWE:          "CWE-285",
		OWASP:        "API5:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "sub_authz:"+sub.Name),
		ReproRequest: reproReq,
		ReproBody:    []byte(reproFrames),
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// deriveWSURL returns the WebSocket URL: the explicit override when set,
// otherwise the target with http→ws / https→wss.
func deriveWSURL(cc *CheckContext) (string, error) {
	if cc.WSURL != "" {
		return cc.WSURL, nil
	}
	t := cc.Target
	switch {
	case strings.HasPrefix(t, "https://"):
		return "wss://" + strings.TrimPrefix(t, "https://"), nil
	case strings.HasPrefix(t, "http://"):
		return "ws://" + strings.TrimPrefix(t, "http://"), nil
	case strings.HasPrefix(t, "ws://"), strings.HasPrefix(t, "wss://"):
		return t, nil
	default:
		return "", fmt.Errorf("unsupported target scheme in %q", t)
	}
}

// relatedQueryField finds a query field related to the subscription: one with
// the same name, else one returning the same named type.
func relatedQueryField(s *schema.Schema, sub *schema.FieldDef) *schema.FieldDef {
	if fd := queryFieldByName(s, sub.Name); fd != nil {
		return fd
	}
	subNamed, _ := unwrapNamed(sub.Type)
	if subNamed == nil {
		return nil
	}
	for _, fd := range s.QueryFields() {
		if fd == nil {
			continue
		}
		if named, _ := unwrapNamed(fd.Type); named != nil && named.Name == subNamed.Name {
			return fd
		}
	}
	return nil
}

// buildRelatedQuery builds an HTTP query for the related field, synthesizing
// required args and selecting __typename for object returns.
func buildRelatedQuery(s *schema.Schema, fd *schema.FieldDef) string {
	args := opArgs(fd, s)
	return fmt.Sprintf("query { %s%s%s }", fd.Name, args, mutSelectionSet(fd.Type, s))
}

// buildSubscribeDoc builds a minimal subscribe document for the subscription
// field, synthesizing required args and selecting __typename for object returns.
func buildSubscribeDoc(s *schema.Schema, sub *schema.FieldDef) string {
	args := opArgs(sub, s)
	return fmt.Sprintf("subscription { %s%s%s }", sub.Name, args, mutSelectionSet(sub.Type, s))
}

// highestPrivilegeOpt returns the most privileged identity, if any are configured.
func highestPrivilegeOpt(ids []Identity) (Identity, bool) {
	if len(ids) == 0 {
		return Identity{}, false
	}
	return highestPrivilege(ids), true
}

// wsRejectCode returns a non-zero auth-rejection close code (4401/4403), else 0.
func wsRejectCode(code int) int {
	if code == 4401 || code == 4403 {
		return code
	}
	return 0
}
