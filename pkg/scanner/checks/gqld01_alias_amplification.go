package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// aliasCount is the fixed number of aliases sent in the amplified probe. It is a
// bounded constant (Safety): the check detects whether the server accepts an
// amplified document, it must never attempt to take the target down.
const aliasCount = 100

// aliasLimitRejectionPattern matches response bodies that indicate the amplified
// query was rejected or capped by an alias / document-cost limiter rather than
// executed. A match means the protection appears to be enforced, so no finding
// is produced.
var aliasLimitRejectionPattern = regexp.MustCompile(`(?i)alias|too many|complexity|cost|query .*too large|limit exceeded`)

// aliasAmplificationCheck implements GQL-D01: Alias-Based Query Amplification.
//
// GraphQL lets a client request the same field many times under different alias
// keys; each alias forces a separate resolver execution. Without an alias /
// document-cost limit, one HTTP request multiplies server work N×, bypassing
// per-request rate limiting and brute-force protections (OWASP API4:2023).
type aliasAmplificationCheck struct{}

func init() {
	MustRegister(&aliasAmplificationCheck{})
}

func (c *aliasAmplificationCheck) ID() string           { return "GQL-D01" }
func (c *aliasAmplificationCheck) Name() string         { return "Alias-Based Query Amplification" }
func (c *aliasAmplificationCheck) Category() Category   { return DenialOfService }
func (c *aliasAmplificationCheck) Severity() Severity   { return HIGH }
func (c *aliasAmplificationCheck) RequiresSchema() bool { return false }

// Run executes GQL-D01 against the target endpoint.
//
// It sends exactly two probes: a 1-alias control to establish a live baseline,
// then a single aliasCount-alias amplified probe. A finding fires when the
// amplified probe is executed in full (HTTP 200, a data object, and every alias
// key echoed back, with no limit/validation rejection), or when the amplified
// probe times out / returns 5xx after a fast control 200 (unresponsiveness is
// itself a positive DoS signal).
func (c *aliasAmplificationCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	field, selection := pickAmplifiableField(cc.Schema)

	// ── Control probe (1 alias) ──────────────────────────────────────────────
	controlQuery := buildAliasedQuery("c", 1, field, selection)
	ctlStatus, ctlBody, ctlReq, ctlPayload, ctlErr := c.probe(ctx, cc, controlQuery)
	result.ProbeCount++

	controlOK := ctlErr == nil && ctlStatus == http.StatusOK && bytes.Contains(ctlBody, []byte(`"data"`))
	if !controlOK {
		result.PassReason = fmt.Sprintf(
			"endpoint did not respond to baseline probe (control query returned %s); "+
				"alias amplification was not assessed",
			describeControlFailure(ctlStatus, ctlErr),
		)
		if ctlReq != nil {
			result.PassProbes = append(result.PassProbes, PassProbe{
				Label:   "alias-control (1 alias)",
				Request: ctlReq,
				Body:    ctlPayload,
			})
		}
		return result, nil
	}

	// ── Amplified probe (aliasCount aliases) ─────────────────────────────────
	amplifiedQuery := buildAliasedQuery("a", aliasCount, field, selection)
	ampStatus, ampBody, ampReq, ampPayload, ampErr := c.probe(ctx, cc, amplifiedQuery)
	result.ProbeCount++

	// A timeout / network failure on the amplified probe — but NOT a parent
	// context cancellation — is itself a positive DoS signal because the control
	// returned a fast 200.
	if ampErr != nil {
		if ctx.Err() != nil {
			result.Error = fmt.Errorf("alias amplification probe cancelled: %w", ampErr)
			return result, nil
		}
		result.Findings = append(result.Findings, c.finding(cc, ampReq, ampPayload,
			amplifiedUnresponsiveDescription(field, fmt.Sprintf("the request did not complete (%v)", ampErr)),
		))
		return result, nil
	}

	// A 5xx under bounded aliasing (control was fast 200) is likewise positive.
	if ampStatus >= http.StatusInternalServerError {
		result.Findings = append(result.Findings, c.finding(cc, ampReq, ampPayload,
			amplifiedUnresponsiveDescription(field, fmt.Sprintf("the server returned HTTP %d", ampStatus)),
		))
		return result, nil
	}

	echoed := countAliasKeys(ampBody, aliasCount)
	hasData := bytes.Contains(ampBody, []byte(`"data"`))
	rejected := aliasLimitRejectionPattern.Match(ampBody)

	if ampStatus == http.StatusOK && hasData && echoed == aliasCount && !rejected {
		result.Findings = append(result.Findings, c.finding(cc, ampReq, ampPayload,
			amplifiedAcceptedDescription(field, echoed),
		))
		return result, nil
	}

	// ── Protected: limit / validation rejection or incomplete execution ──────
	result.PassReason = "Endpoint rejected or limited a 100-alias query (alias/document-cost limiting appears enforced)."
	result.PassProbes = []PassProbe{
		{Label: "alias-control (1 alias)", Request: ctlReq, Body: ctlPayload},
		{Label: fmt.Sprintf("alias-amplified (%d aliases)", aliasCount), Request: ampReq, Body: ampPayload},
	}
	return result, nil
}

// probe marshals query into a GraphQL POST body and sends it via the probe
// client. It returns the response status and body, the constructed request, and
// the JSON payload. The request and payload are returned even on a transport
// error so callers can still build repro / pass records (e.g. on a timeout).
func (c *aliasAmplificationCheck) probe(
	ctx context.Context, cc *CheckContext, query string,
) (statusCode int, body []byte, req *http.Request, payload []byte, err error) {
	payload, err = json.Marshal(map[string]string{"query": query})
	if err != nil {
		return 0, nil, nil, nil, err
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, nil, payload, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return 0, nil, req, payload, err
	}
	return resp.StatusCode, resp.Body, resp.Request, payload, nil
}

// finding builds a HIGH GQL-D01 finding with the shared metadata and the given
// description.
func (c *aliasAmplificationCheck) finding(cc *CheckContext, req *http.Request, body []byte, description string) Finding {
	return Finding{
		CheckID:      c.ID(),
		CheckName:    c.Name(),
		Severity:     HIGH,
		Category:     DenialOfService,
		Title:        "No Alias Limit — Query Amplification Possible",
		Description:  description,
		Impact:       aliasImpact,
		Remediation:  aliasRemediation,
		References:   aliasReferences,
		ReproRequest: req,
		ReproBody:    body,
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "alias_amplification"),
	}
}

// pickAmplifiableField selects a Query field suitable for alias amplification
// and the selection set (possibly empty) that must follow each alias so the
// resulting document is valid GraphQL.
//
// Preference: the first root Query field taking no required arguments and
// returning a leaf (scalar/enum) — a leaf needs no sub-selection, keeping the
// amplified document minimal. An object/interface/union field is accepted as a
// fallback with a "{ __typename }" sub-selection so the query stays valid. When
// no schema is available (or no field qualifies) it falls back to the
// always-valid meta-field __typename, which still exercises document parsing and
// validation per alias.
func pickAmplifiableField(s *schema.Schema) (field, selection string) {
	if s == nil {
		return "__typename", ""
	}

	var compositeField string
	for _, f := range s.QueryFields() {
		if f == nil || f.Name == "" || f.Type == nil || fieldHasRequiredArg(f) {
			continue
		}
		ret := f.Type.Unwrap()
		if ret == nil {
			continue
		}
		switch returnKind(s, ret) {
		case schema.KindScalar, schema.KindEnum:
			return f.Name, ""
		case schema.KindObject, schema.KindInterface, schema.KindUnion:
			if compositeField == "" {
				compositeField = f.Name
			}
		}
	}
	if compositeField != "" {
		return compositeField, " { __typename }"
	}
	return "__typename", ""
}

// returnKind resolves the kind of an unwrapped return type, preferring the
// schema's own type definition and falling back to the kind carried on the type
// reference (which is populated for built-in scalars not present in the type map).
func returnKind(s *schema.Schema, ret *schema.TypeRef) schema.TypeKind {
	if t := s.FindType(ret.Name); t != nil {
		return t.Kind
	}
	return ret.Kind
}

// fieldHasRequiredArg reports whether the field declares at least one required
// argument — a NON_NULL argument with no default value. Such fields cannot be
// invoked with a bare alias and are skipped during field selection.
func fieldHasRequiredArg(f *schema.FieldDef) bool {
	for _, a := range f.Args {
		if a == nil || a.Type == nil {
			continue
		}
		if a.Type.Kind == schema.KindNonNull && a.DefaultValue == nil {
			return true
		}
	}
	return false
}

// buildAliasedQuery builds a GraphQL operation that requests field n times under
// the alias keys prefix0..prefix(n-1), each followed by the (possibly empty)
// selection set, e.g. buildAliasedQuery("a", 3, "__typename", "") →
// "query { a0: __typename a1: __typename a2: __typename }".
func buildAliasedQuery(prefix string, n int, field, selection string) string {
	var sb strings.Builder
	sb.WriteString("query {")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, " %s%d: %s%s", prefix, i, field, selection)
	}
	sb.WriteString(" }")
	return sb.String()
}

// countAliasKeys returns how many of the alias keys "a0".."a(n-1)" appear as
// quoted JSON keys in body. The keys are matched with both surrounding quotes so
// that "a1" is not counted as present merely because "a10" is.
func countAliasKeys(body []byte, n int) int {
	count := 0
	for i := 0; i < n; i++ {
		if bytes.Contains(body, []byte(fmt.Sprintf(`"a%d"`, i))) {
			count++
		}
	}
	return count
}

// describeControlFailure renders a short human description of why the control
// probe was not a clean HTTP 200 with a data object.
func describeControlFailure(status int, err error) string {
	switch {
	case err != nil:
		return fmt.Sprintf("error: %v", err)
	case status != http.StatusOK:
		return fmt.Sprintf("HTTP %d", status)
	default:
		return "HTTP 200 without a data object"
	}
}

func amplifiedAcceptedDescription(field string, echoed int) string {
	return fmt.Sprintf(
		"The endpoint accepted and executed a single GraphQL operation containing %d field "+
			"aliases (a0..a%d), all targeting the field %q. The response echoed back %d distinct "+
			"alias keys, proving the server performed a separate resolver execution for every alias "+
			"rather than collapsing, capping, or rejecting the duplicated selections.\n\n"+
			"GraphQL permits the same field to be requested many times under different alias keys in "+
			"one document. With no alias or document-cost limit, a single HTTP request multiplies "+
			"server-side work N× — here %d×.",
		aliasCount, aliasCount-1, field, echoed, aliasCount,
	)
}

func amplifiedUnresponsiveDescription(field, outcome string) string {
	return fmt.Sprintf(
		"A control query using a single alias of the field %q returned a fast HTTP 200, but an "+
			"otherwise identical query carrying %d aliases (a0..a%d) did not complete normally: %s. "+
			"A bounded %d-alias document driving the server to time out or error is itself a positive "+
			"resource-consumption signal — the server became unresponsive under aliasing instead of "+
			"enforcing an alias / document-cost limit.",
		field, aliasCount, aliasCount-1, outcome, aliasCount,
	)
}

const aliasImpact = "A single HTTP request can amplify resolver and database work N× by repeating the " +
	"same field under many alias keys. Because the amplification happens inside one request, it " +
	"bypasses per-request rate limiting and brute-force / OTP protections (for example, aliasing a " +
	"login or verify-code field 100× in one document), and can drive CPU, memory, and downstream " +
	"quota exhaustion, leading to denial of service."

const aliasRemediation = "Enforce a maximum alias count and/or a maximum operation cost at the validation " +
	"layer, before execution. For graphql-js / Apollo use graphql-no-alias or Apollo operation-cost " +
	"limits; for general cost control use graphql-query-complexity (assign per-field costs and cap the " +
	"document total). Apply cost-based rate limiting (limiting the summed operation cost) rather than " +
	"counting HTTP requests, so a single amplified request cannot bypass the limit."

var aliasReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://portswigger.net/web-security/graphql",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
}
