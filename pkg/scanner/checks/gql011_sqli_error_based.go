package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gqls-cli/gqls/pkg/scanner/inject"
)

// sqliErrorBasedCheck implements GQL-011: SQL Injection (Error-Based, Conservative).
//
// It enumerates injectable string-typed leaves across the whole reachable input
// graph via inject.Points (nested input objects and list elements included),
// fires a small table of error-based payloads at each, and flags only when a
// known database-error signal appears in the response. It is the single-shot,
// "tentative" error oracle; GQL-I01 provides the confirmed boolean-differential.
type sqliErrorBasedCheck struct{}

func init() {
	MustRegister(&sqliErrorBasedCheck{})
}

func (c *sqliErrorBasedCheck) ID() string           { return "GQL-011" }
func (c *sqliErrorBasedCheck) Name() string         { return "SQL Injection (Error-Based)" }
func (c *sqliErrorBasedCheck) Category() Category   { return Injection }
func (c *sqliErrorBasedCheck) Severity() Severity   { return HIGH }
func (c *sqliErrorBasedCheck) RequiresSchema() bool { return false }

// sqliMaxPoints bounds how many injection points are probed.
const sqliMaxPoints = 25

// sqliPayloadEntry pairs a human-readable label with a SQL injection probe string.
type sqliPayloadEntry struct {
	label   string
	payload string
}

// sqliProbes is the ordered list of 5 classic error-based SQL injection payloads.
var sqliProbes = []sqliPayloadEntry{
	{"single_quote", `'`},
	{"double_single_quote", `''`},
	{"or_true", `' OR '1'='1`},
	{"backslash", `\`},
	{"mssql_convert", `' AND 1=CONVERT(int, 'a')--`},
}

// dbErrorPatterns matches known database engine error strings.
// The list is intentionally conservative to avoid flagging generic application errors
// or GraphQL validation messages.
var dbErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQLSTATE`),
	regexp.MustCompile(`(?i)\bmysql\b`),
	regexp.MustCompile(`(?i)\bpostgres(ql)?\b`),
	regexp.MustCompile(`(?i)\bsqlite\b`),
	regexp.MustCompile(`ORA-\d`),
	regexp.MustCompile(`(?i)SQL syntax.{0,30}error`),
	regexp.MustCompile(`(?i)unknown column`),
	regexp.MustCompile(`(?i)quoted string not terminated`),
	regexp.MustCompile(`(?i)syntax error at or near`),
	regexp.MustCompile(`(?i)unterminated quoted string`),
}

// sqliStringLike reports whether a scalar type carries injectable string text.
// Error-based payloads are string literals, so numeric/boolean leaves (which the
// GraphQL type system would reject) are excluded.
func sqliStringLike(scalarType string) bool {
	switch scalarType {
	case "Int", "Float", "Boolean":
		return false
	default: // String, ID, custom scalars
		return true
	}
}

// buildProbeReq constructs the HTTP request for a SQL injection probe.
//
// When a curl command was provided (cc.ParsedCurl != nil), the probe uses the
// original HTTP method and URL from that context — preserving the exact transport
// semantics of the real client request. The body is always replaced with the
// generated SQL injection payload; the original body is never replayed.
//
// When no curl input was provided, the probe falls back to HTTP POST against
// cc.Target. In both cases all authentication headers flow through cc.HTTPClient,
// which has them baked in from the resolved scan configuration.
func (c *sqliErrorBasedCheck) buildProbeReq(ctx context.Context, cc *CheckContext, body []byte) (*http.Request, error) {
	method := http.MethodPost
	target := cc.Target

	if cc.ParsedCurl != nil {
		clone := cc.ParsedCurl.Clone()
		method = clone.Method
		target = clone.URL
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// Run executes GQL-011 by injecting the error-based payload table into every
// string-typed injection point (query points always; mutation points only with
// --authz-allow-mutations). It flags only when a database error indicator
// appears; generic GraphQL validation errors are not flagged.
func (c *sqliErrorBasedCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	points := inject.Points(cc.Schema)
	var targets []inject.Point
	mutationGated := false
	for _, p := range points {
		if !sqliStringLike(p.ScalarType) {
			continue
		}
		if p.OpKind == "mutation" && !cc.AllowMutations {
			mutationGated = true
			continue
		}
		targets = append(targets, p)
	}
	targets = inject.Cap(targets, sqliMaxPoints)

	if len(targets) == 0 {
		result.PassReason = "no injectable String/ID arguments identified in query or mutation fields"
		if mutationGated {
			result.PassReason += " (mutation injection points were skipped; pass --authz-allow-mutations to include them)"
		}
		return result, nil
	}

	var passProbes []PassProbe

	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		found := false
		for _, pl := range sqliProbes {
			doc, vars := tgt.Render(cc.Schema, pl.payload)
			body, err := json.Marshal(map[string]any{"query": doc, "variables": vars})
			if err != nil {
				continue
			}

			req, err := c.buildProbeReq(ctx, cc, body)
			if err != nil {
				continue
			}

			resp, err := cc.HTTPClient.Do(req)
			result.ProbeCount++
			if err != nil {
				continue
			}

			if matched, ok := inject.ErrorSignal(resp.Body, dbErrorPatterns); ok {
				evidenceKey := fmt.Sprintf("%s.%s.%s", tgt.OpKind, tgt.RootField, tgt.PathKey())
				result.Findings = append(result.Findings, Finding{
					CheckID:   c.ID(),
					CheckName: c.Name(),
					Severity:  HIGH,
					Category:  Injection,
					Title: fmt.Sprintf(
						"SQL Injection (error-based) in %s field %q argument path %q",
						tgt.OpKind, tgt.RootField, tgt.PathKey(),
					),
					Description: fmt.Sprintf(
						"A SQL injection payload injected into %s field %q (argument path %q) triggered a "+
							"database error indicator (%q) in the server response, suggesting that unsanitised "+
							"input reaches a SQL query.",
						tgt.OpKind, tgt.RootField, tgt.PathKey(), matched,
					),
					Impact: "An attacker can leverage error-based SQL injection to enumerate the " +
						"database structure, extract sensitive data, and potentially write or delete " +
						"records depending on database user permissions.",
					Remediation: "Use parameterised queries or prepared statements for every database " +
						"interaction. Never interpolate user-supplied values into SQL strings. " +
						"Suppress verbose database error messages in production responses. " +
						"Apply allow-list input validation as defence-in-depth.",
					References: []string{
						"https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
						"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
						"https://portswigger.net/web-security/sql-injection/error-based",
					},
					ReproRequest: resp.Request,
					ReproBody:    body,
					Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, evidenceKey),
				})
				found = true
				break // one finding per injection point
			}

			passProbes = append(passProbes, PassProbe{
				Label: fmt.Sprintf("SQLi probe (%s): %s %s[%s]",
					pl.label, tgt.OpKind, tgt.RootField, tgt.PathKey()),
				Request: resp.Request,
				Body:    body,
			})
		}
		_ = found
	}

	if len(result.Findings) == 0 {
		result.PassReason = "no database error indicators observed in responses to SQL injection probes"
		result.PassProbes = passProbes
	}

	return result, nil
}
