package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// aliasAuthBypassCheck implements GQL-A06: authentication rate-limit / brute-force
// bypass via aliases. It checks whether an authentication-style operation can be
// invoked many times in a single request by aliasing it, which defeats
// per-request rate limiting and account-lockout protections.
type aliasAuthBypassCheck struct{}

func init() {
	MustRegister(&aliasAuthBypassCheck{})
}

func (c *aliasAuthBypassCheck) ID() string { return "GQL-A06" }
func (c *aliasAuthBypassCheck) Name() string {
	return "Auth Bypass via Aliases (Rate-Limit/Brute-Force Bypass)"
}
func (c *aliasAuthBypassCheck) Category() Category   { return Authorization }
func (c *aliasAuthBypassCheck) Severity() Severity   { return HIGH }
func (c *aliasAuthBypassCheck) RequiresSchema() bool { return false }

// aliasAuthCount is the bounded number of aliased attempts (well below DoS levels;
// this is an authz/throttling test, not a denial-of-service probe).
const aliasAuthCount = 20

// authOpRe matches authentication-style mutation names.
var authOpRe = regexp.MustCompile(`(?i)(login|sign_?in|authenticate|verify_?otp|verify_?code|reset_?password|redeem|token|mfa|2fa|otp)`)

// credEmailRe / credSecretRe classify auth arguments so the check sends clearly
// invalid, non-existent credentials.
var (
	credEmailRe  = regexp.MustCompile(`(?i)(email|username|user|login|account|phone)`)
	credSecretRe = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|otp|code|pin|mfa)`)
)

// aliasLimitRe matches errors that indicate the server limited or rejected the
// multi-alias document (the protected signal). It must not match ordinary
// authentication-failure errors.
var aliasLimitRe = regexp.MustCompile(`(?i)(too many|rate.?limit|throttl|locked|lockout|\balias|complexity|cost|max(imum)?[ _-]?(operations|aliases|depth)|exceeded|abuse)`)

// authOp describes the operation to alias.
type authOp struct {
	field     string           // field name (for the fingerprint / messages)
	fieldDef  *schema.FieldDef // non-nil for schema-driven arg synthesis
	snippet   string           // verbatim "field(args) {sel}" when operator-supplied
	selection string           // selection suffix for the schema path
}

// Run executes the alias auth-bypass check.
func (c *aliasAuthBypassCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	op, ok := resolveAuthOp(cc)
	if !ok {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no authentication-style operation found to test alias brute-force; " +
			"supply one with --authz-login-op (e.g. --authz-login-op 'login')"
		return result, nil
	}

	client := cc.ProbeClient()

	// ── Control: a single attempt confirms the endpoint is live ───────────────
	controlDoc := buildAliasedAuthDoc(op, cc.Schema, 1)
	controlResp, _, cerr := gqlPost(ctx, client, cc.Target, controlDoc)
	result.ProbeCount++
	if cerr != nil || controlResp == nil {
		result.PassReason = "endpoint did not respond to the baseline authentication probe (cannot assess alias bypass)"
		return result, nil
	}

	// ── Aliased: N attempts in one request ────────────────────────────────────
	aliasedDoc := buildAliasedAuthDoc(op, cc.Schema, aliasAuthCount)
	aliasedResp, aliasedBody, aerr := gqlPost(ctx, client, cc.Target, aliasedDoc)
	result.ProbeCount++
	if aerr != nil || aliasedResp == nil {
		result.PassReason = fmt.Sprintf(
			"the %d-alias authentication document did not return a usable response "+
				"(server may have dropped/limited the oversized request)", aliasAuthCount)
		result.PassProbes = append(result.PassProbes, PassProbe{
			Label: "control (single attempt)", Request: controlResp.Request, Body: nil,
		})
		return result, nil
	}

	executed, limited := analyzeAliasedAuth(aliasedResp, aliasAuthCount)

	// ── Decision ──────────────────────────────────────────────────────────────
	if executed == aliasAuthCount && !limited {
		result.Findings = append(result.Findings, Finding{
			CheckID:   c.ID(),
			CheckName: c.Name(),
			Severity:  HIGH,
			Category:  Authorization,
			Title:     "Authentication Rate-Limit Bypass via Aliases",
			Description: fmt.Sprintf(
				"All %d aliased %q attempts executed in a single request (alias keys a0..a%d were all present "+
					"in the response), and the server applied no alias/operation/rate limit. Each alias triggers "+
					"a separate authentication attempt, so one HTTP request performs %d attempts — defeating "+
					"per-request rate limiting and account-lockout protections. Deliberately invalid, "+
					"non-existent credentials were used.",
				aliasAuthCount, op.field, aliasAuthCount-1, aliasAuthCount),
			Impact: "Attackers can perform credential stuffing, password/OTP brute-forcing, and coupon/code " +
				"guessing at N times the intended rate per request, defeating rate limits and lockouts; this " +
				"enables account takeover and code/coupon brute-forcing.",
			Remediation: "Enforce a maximum alias/operation count per document at the validation layer " +
				"(e.g. graphql-no-alias, operation-cost limits). Apply attempt-based (not request-based) rate " +
				"limiting and lockouts keyed on the authentication action itself, and deduplicate repeated " +
				"operations within a request.",
			References: []string{
				"https://portswigger.net/web-security/graphql",
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
				"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
				"https://cwe.mitre.org/data/definitions/307.html",
			},
			Confidence:   "firm",
			CWE:          "CWE-307",
			OWASP:        "API4:2023",
			Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "alias_auth_bypass:"+op.field),
			ReproRequest: aliasedResp.Request,
			ReproBody:    aliasedBody,
		})
		return result, nil
	}

	// ── Clean / protected ─────────────────────────────────────────────────────
	if limited {
		result.PassReason = fmt.Sprintf(
			"the server limited or rejected the %d-alias authentication document "+
				"(alias/operation limiting appears enforced)", aliasAuthCount)
	} else {
		result.PassReason = fmt.Sprintf(
			"only %d of %d aliased authentication attempts executed in one request "+
				"(the server did not run every aliased attempt)", executed, aliasAuthCount)
	}
	result.PassProbes = append(result.PassProbes, PassProbe{
		Label:   fmt.Sprintf("aliased %d-attempt authentication document", aliasAuthCount),
		Request: aliasedResp.Request, Body: aliasedBody,
	})
	return result, nil
}

// analyzeAliasedAuth returns how many of the n aliases (a0..a{n-1}) are present
// in the response data, and whether the server emitted a limit/rejection error.
func analyzeAliasedAuth(resp *transport.Response, n int) (executed int, limited bool) {
	var env struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return 0, false
	}
	for _, e := range env.Errors {
		if aliasLimitRe.MatchString(e.Message) {
			limited = true
		}
	}
	if resp.StatusCode != 200 {
		// A non-200 to a bounded aliased document is treated as a rejection.
		limited = true
	}
	for i := 0; i < n; i++ {
		if _, ok := env.Data[fmt.Sprintf("a%d", i)]; ok {
			executed++
		}
	}
	return executed, limited
}

// resolveAuthOp determines the authentication operation to alias: the operator
// flag wins; otherwise a schema mutation whose name looks authentication-related.
func resolveAuthOp(cc *CheckContext) (authOp, bool) {
	if flag := strings.TrimSpace(cc.AuthzLoginOp); flag != "" {
		if strings.Contains(flag, "(") {
			// Verbatim snippet: "login(email: \"x\", password: \"y\") { token }".
			field := strings.TrimSpace(flag[:strings.IndexByte(flag, '(')])
			return authOp{field: field, snippet: flag}, true
		}
		// Bare field name — synthesize args from the schema when available.
		if cc.Schema != nil {
			if fd := mutationFieldByName(cc.Schema, flag); fd != nil {
				return authOp{field: flag, fieldDef: fd, selection: mutSelectionSet(fd.Type, cc.Schema)}, true
			}
		}
		// No schema: alias the bare field (valid only if it takes no args).
		return authOp{field: flag, snippet: flag}, true
	}

	if cc.Schema != nil {
		muts := make([]*schema.FieldDef, len(cc.Schema.MutationFields()))
		copy(muts, cc.Schema.MutationFields())
		sort.Slice(muts, func(i, j int) bool { return muts[i].Name < muts[j].Name })
		for _, m := range muts {
			if m != nil && authOpRe.MatchString(m.Name) {
				return authOp{field: m.Name, fieldDef: m, selection: mutSelectionSet(m.Type, cc.Schema)}, true
			}
		}
	}
	return authOp{}, false
}

// buildAliasedAuthDoc builds a mutation aliasing op count times (a0..a{count-1}),
// each carrying distinct, clearly-invalid credentials when schema-driven.
func buildAliasedAuthDoc(op authOp, s *schema.Schema, count int) string {
	aliases := make([]string, 0, count)
	for i := 0; i < count; i++ {
		var call string
		if op.fieldDef != nil {
			call = fmt.Sprintf("%s(%s)%s", op.field, buildInvalidAuthArgs(op.fieldDef, s, i), op.selection)
		} else {
			call = op.snippet
		}
		aliases = append(aliases, fmt.Sprintf("a%d: %s", i, call))
	}
	return "mutation { " + strings.Join(aliases, " ") + " }"
}

// buildInvalidAuthArgs renders the field's required arguments with deliberately
// invalid, non-existent credential values, varied per attempt index.
func buildInvalidAuthArgs(fd *schema.FieldDef, s *schema.Schema, i int) string {
	var parts []string
	for _, a := range fd.Args {
		if a == nil || !argRequired(a) {
			continue
		}
		u := a.Type.Unwrap()
		switch {
		case u != nil && u.Name == "String":
			parts = append(parts, fmt.Sprintf("%s: %q", a.Name, invalidCredValue(a.Name, i)))
		default:
			if ev := surface.ExampleValue(a.Type, s); ev != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
			}
		}
	}
	return strings.Join(parts, ", ")
}

// invalidCredValue returns a clearly-invalid sentinel credential for an argument.
func invalidCredValue(argName string, i int) string {
	switch {
	case credEmailRe.MatchString(argName):
		return fmt.Sprintf("gqls-nouser-%d@invalid.example", i)
	case credSecretRe.MatchString(argName):
		return fmt.Sprintf("gqls-invalid-%d", i)
	default:
		return fmt.Sprintf("gqls-invalid-%d", i)
	}
}
