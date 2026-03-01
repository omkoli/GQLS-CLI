package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// sqliErrorBasedCheck implements GQL-011: SQL Injection (Error-Based, Conservative).
type sqliErrorBasedCheck struct{}

func init() {
	MustRegister(&sqliErrorBasedCheck{})
}

func (c *sqliErrorBasedCheck) ID() string           { return "GQL-011" }
func (c *sqliErrorBasedCheck) Name() string         { return "SQL Injection (Error-Based)" }
func (c *sqliErrorBasedCheck) Category() Category   { return Injection }
func (c *sqliErrorBasedCheck) Severity() Severity   { return HIGH }
func (c *sqliErrorBasedCheck) RequiresSchema() bool { return false }

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

// containsDBError reports whether body includes any known database error indicator.
func containsDBError(body []byte) bool {
	for _, re := range dbErrorPatterns {
		if re.Match(body) {
			return true
		}
	}
	return false
}

// sqliInjectTarget describes a field/argument pair to probe.
type sqliInjectTarget struct {
	fieldName string
	argName   string
	argType   string // unwrapped scalar name, e.g. "String"
	isQuery   bool   // true → Query root, false → Mutation root
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
		// Clone before reading to document intent and protect against future
		// modifications; we only read Method and URL here.
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

// Run executes GQL-011 by injecting 5 SQL payloads into the first injectable
// String argument of one query field and one mutation field (when a schema is
// available). It flags only when a database error indicator appears in the
// response body; generic GraphQL validation errors are not flagged.
func (c *sqliErrorBasedCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	targets := sqliCollectTargets(cc.Schema)
	if len(targets) == 0 {
		result.PassReason = "no injectable String arguments identified in query or mutation fields"
		return result, nil
	}

	var passProbes []PassProbe

	for _, tgt := range targets {
		opType := "query"
		if !tgt.isQuery {
			opType = "mutation"
		}

		for _, pl := range sqliProbes {
			body, err := sqliProbeBody(tgt.fieldName, tgt.argName, tgt.argType, pl.payload, tgt.isQuery)
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

			if containsDBError(resp.Body) {
				evidenceKey := fmt.Sprintf("%s.%s.%s", opType, tgt.fieldName, tgt.argName)
				result.Findings = append(result.Findings, Finding{
					CheckID:   c.ID(),
					CheckName: c.Name(),
					Severity:  HIGH,
					Category:  Injection,
					Title: fmt.Sprintf(
						"SQL Injection (error-based) in %s field %q argument %q",
						opType, tgt.fieldName, tgt.argName,
					),
					Description: fmt.Sprintf(
						"Payload %q injected into %s field %q (argument %q) triggered a database "+
							"error indicator in the server response, suggesting that unsanitised input "+
							"reaches a SQL query.",
						pl.payload, opType, tgt.fieldName, tgt.argName,
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
				// One finding per target field is sufficient; move to the next target.
				break
			}

			passProbes = append(passProbes, PassProbe{
				Label:   fmt.Sprintf("SQLi probe (%s): %s %s(%s=%q)", pl.label, opType, tgt.fieldName, tgt.argName, pl.payload),
				Request: resp.Request,
				Body:    body,
			})
		}
	}

	if len(result.Findings) == 0 {
		result.PassReason = "no database error indicators observed in responses to SQL injection probes"
		result.PassProbes = passProbes
	}

	return result, nil
}

// sqliCollectTargets returns up to two inject targets: the first query field and
// the first mutation field that each have a String-typed argument.
func sqliCollectTargets(s *schema.Schema) []sqliInjectTarget {
	var out []sqliInjectTarget
	if s == nil {
		return out
	}
	if f, a := sqliFirstStringArg(s.QueryFields()); f != nil {
		out = append(out, sqliInjectTarget{
			fieldName: f.Name,
			argName:   a.Name,
			argType:   a.Type.Unwrap().Name,
			isQuery:   true,
		})
	}
	if f, a := sqliFirstStringArg(s.MutationFields()); f != nil {
		out = append(out, sqliInjectTarget{
			fieldName: f.Name,
			argName:   a.Name,
			argType:   a.Type.Unwrap().Name,
			isQuery:   false,
		})
	}
	return out
}

// sqliFirstStringArg scans fields for the first field that has a String-typed
// argument, returning both the field and the matching argument definition.
func sqliFirstStringArg(fields []*schema.FieldDef) (*schema.FieldDef, *schema.ArgDef) {
	for _, f := range fields {
		for _, a := range f.Args {
			if a.Type == nil {
				continue
			}
			if u := a.Type.Unwrap(); u != nil && u.Name == "String" {
				return f, a
			}
		}
	}
	return nil, nil
}

// sqliProbeBody builds a GraphQL request body that injects payload into the
// named argument via a GraphQL variable, keeping the injection out of the
// query document itself to avoid document-level parse errors.
func sqliProbeBody(fieldName, argName, argType, payload string, isQuery bool) ([]byte, error) {
	opType := "query"
	if !isQuery {
		opType = "mutation"
	}
	gqlQuery := fmt.Sprintf(
		`%s SQLiProbe($v0: %s) { %s(%s: $v0) { __typename } }`,
		opType, argType, fieldName, argName,
	)
	return json.Marshal(map[string]interface{}{
		"query":     gqlQuery,
		"variables": map[string]interface{}{"v0": payload},
	})
}
