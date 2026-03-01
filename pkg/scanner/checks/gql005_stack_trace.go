package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type leakPattern struct {
	pattern     *regexp.Regexp
	category    string
	severity    Severity
	description string
}

var stackTraceProbes = []struct {
	label  string
	query  string
	intent string
}{
	{
		label:  "type_error",
		query:  `{ __typename { invalid } }`,
		intent: "type mismatch — __typename is a scalar, not an object",
	},
	{
		label:  "syntax_error",
		query:  `{ 99invalid { id } }`,
		intent: "syntax error — field name cannot start with a digit",
	},
	{
		label:  "null_coercion",
		query:  `query ($id: ID!) { __typename }`,
		intent: "missing required variable — triggers variable coercion error",
	},
	{
		label:  "undefined_fragment",
		query:  `{ ...UndefinedFragment }`,
		intent: "undefined fragment reference",
	},
	{
		label:  "duplicate_fields",
		query:  `{ __typename __typename __typename __typename __typename }`,
		intent: "some servers error on excessive duplicate fields",
	},
}

var leakPatterns = []leakPattern{
	// File system paths
	{regexp.MustCompile(`(?i)/(?:var|home|usr|opt|app|srv|etc)/[a-z0-9_\-./]+\.(?:js|ts|go|py|rb|java)`), "file_path", HIGH, "Server-side source file path exposed"},
	{regexp.MustCompile(`(?i)[A-Z]:\\[a-zA-Z0-9_\-\\]+\.(?:js|ts|go|py|rb|java)`), "file_path", HIGH, "Windows server-side file path exposed"},

	// Stack frame patterns
	{regexp.MustCompile(`at Object\.<anonymous>`), "stack_frame", HIGH, "Node.js stack trace exposed"},
	{regexp.MustCompile(`at [A-Za-z]+\.[A-Za-z]+ \([^)]+:\d+:\d+\)`), "stack_frame", HIGH, "Node.js stack frame with line numbers exposed"},
	{regexp.MustCompile(`Traceback \(most recent call last\)`), "stack_frame", HIGH, "Python traceback exposed"},
	{regexp.MustCompile(`goroutine \d+ \[running\]`), "stack_frame", HIGH, "Go goroutine stack trace exposed"},
	{regexp.MustCompile(`(?i)Exception in thread`), "stack_frame", HIGH, "Java exception stack trace exposed"},
	{regexp.MustCompile(`(?i)RuntimeException|NullPointerException`), "stack_frame", MEDIUM, "Java exception class name exposed"},

	// Library/version info
	{regexp.MustCompile(`graphql-js/\d+\.\d+`), "version", LOW, "graphql-js version exposed"},
	{regexp.MustCompile(`apollo-server/\d+\.\d+`), "version", LOW, "Apollo Server version exposed"},
	{regexp.MustCompile(`express/\d+\.\d+`), "version", LOW, "Express.js version exposed"},

	// Database errors
	{regexp.MustCompile(`(?i)syntax error at or near`), "database", HIGH, "PostgreSQL error message exposed"},
	{regexp.MustCompile(`(?i)You have an error in your SQL syntax`), "database", HIGH, "MySQL error message exposed"},
	{regexp.MustCompile(`(?i)ORA-\d{5}`), "database", HIGH, "Oracle database error exposed"},
	{regexp.MustCompile(`(?i)MongoDB.*Exception`), "database", HIGH, "MongoDB exception exposed"},
	{regexp.MustCompile(`(?i)Sequelize.*Error|TypeORM.*Error`), "database", MEDIUM, "ORM error class exposed"},

	// Internal hostnames / IPs
	{regexp.MustCompile(`(?i)connect ECONNREFUSED (\d{1,3}\.){3}\d{1,3}`), "internal_host", HIGH, "Internal IP address in connection error"},
	{regexp.MustCompile(`(?i)getaddrinfo.*\.internal|\.local|\.corp`), "internal_host", HIGH, "Internal hostname exposed in DNS error"},
}

type stackTraceCheck struct{}

func init() {
	Register(&stackTraceCheck{})
}

func (c *stackTraceCheck) ID() string           { return "GQL-005" }
func (c *stackTraceCheck) Name() string         { return "Stack Trace / Debug Info in Error Responses" }
func (c *stackTraceCheck) Category() Category   { return InformationDisclosure }
func (c *stackTraceCheck) Severity() Severity   { return MEDIUM }
func (c *stackTraceCheck) RequiresSchema() bool { return false }

func (c *stackTraceCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	type matchEntry struct {
		matched     string // truncated to 200 chars
		description string
		severity    Severity
		category    string
	}

	// allMatches maps probeLabel → all pattern matches across every category.
	// One Finding is emitted per probe label, aggregating all matched categories.
	allMatches := make(map[string][]matchEntry)
	// Store the first request/body per probe for reproduction info.
	probeRequests := make(map[string]*http.Request)
	probeBodies := make(map[string][]byte)

	// Determine the HTTP method and target URL for all probes once before the loop.
	// When curl input was provided, use its method and URL to reproduce the original
	// request environment (Rule 1: full context for context-dependent error probes).
	// The malformed-query bodies are always generated fresh; the curl body is never
	// replayed. Fallback to POST against cc.Target when no curl input was given (Rule 3).
	method, target := http.MethodPost, cc.Target
	if cc.ParsedCurl != nil {
		// Clone before reading: documents intent and protects against future mutations
		// that might otherwise affect subsequent iterations.
		clone := cc.ParsedCurl.Clone()
		method = clone.Method
		target = clone.URL
	}

	for _, probe := range stackTraceProbes {
		select {
		case <-ctx.Done():
			return result, nil
		default:
		}

		payload, err := json.Marshal(map[string]string{"query": probe.query})
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := cc.ProbeClient().Do(req)
		if err != nil {
			continue
		}

		// Always record this probe's request so it can be included in PassProbes
		// when no findings are produced, giving readers verifiable evidence of what was tested.
		probeRequests[probe.label] = resp.Request
		probeBodies[probe.label] = payload

		// Scan the entire response body (not just error messages) against all leak patterns.
		body := resp.Body
		for _, lp := range leakPatterns {
			locs := lp.pattern.FindAllIndex(body, -1)
			for _, loc := range locs {
				matched := string(body[loc[0]:loc[1]])
				if len(matched) > 200 {
					matched = matched[:200]
				}
				allMatches[probe.label] = append(allMatches[probe.label], matchEntry{
					matched:     matched,
					description: lp.description,
					severity:    lp.severity,
					category:    lp.category,
				})
			}
		}
	}

	// Sort probe labels for deterministic finding order.
	labels := make([]string, 0, len(allMatches))
	for k := range allMatches {
		labels = append(labels, k)
	}
	sort.Strings(labels)

	// Generate exactly ONE Finding per probe label. All categories matched by
	// that probe are aggregated: severity = highest across all matches,
	// impact/remediation = from the highest-severity category.
	for _, label := range labels {
		entries := allMatches[label]

		highest := INFO
		highestCat := ""
		seenDescs := make(map[string]bool)
		seenCats := make(map[string]bool)
		var uniqueDescs []string
		var uniqueCats []string
		var samples []string

		for _, e := range entries {
			if e.severity > highest {
				highest = e.severity
				highestCat = e.category
			}
			if !seenDescs[e.description] {
				seenDescs[e.description] = true
				uniqueDescs = append(uniqueDescs, e.description)
			}
			if !seenCats[e.category] {
				seenCats[e.category] = true
				uniqueCats = append(uniqueCats, e.category)
			}
			samples = append(samples, fmt.Sprintf("%q", e.matched))
		}

		sampleText := strings.Join(samples, ", ")
		if len(samples) > 3 {
			sampleText = strings.Join(samples[:3], ", ") + fmt.Sprintf(" … and %d more", len(samples)-3)
		}

		result.Findings = append(result.Findings, Finding{
			CheckID:   c.ID(),
			CheckName: c.Name(),
			Severity:  highest,
			Category:  c.Category(),
			Description: fmt.Sprintf(
				"The GraphQL server at %s leaked debug information in its error response to a %s probe (%s). "+
					"Detected categories: %s. Signals: %s. Sample matched text: %s",
				cc.Target, label, stackTraceProbeIntent(label),
				strings.Join(uniqueCats, ", "),
				strings.Join(uniqueDescs, "; "),
				sampleText,
			),
			Impact:      stackTraceImpact(highestCat),
			Remediation: stackTraceRemediation(highestCat),
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
				"https://graphql.org/learn/best-practices/#error-handling",
			},
			ReproRequest: probeRequests[label],
			ReproBody:    probeBodies[label],
			// Fingerprint is stable: one per (check, target, probe). Adding a
			// delimiter avoids theoretical collisions with future probe labels.
			Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "probe:"+label),
		})
	}

	if len(result.Findings) == 0 {
		result.PassReason = "No debug information leaked in error responses. All 5 malformed query probes (type error, syntax error, null coercion, undefined fragment, duplicate fields) returned clean error messages with no file paths, stack traces, version strings, database errors, or internal hostnames."
		// Build PassProbes in the same order as stackTraceProbes for deterministic output.
		for _, probe := range stackTraceProbes {
			if req, ok := probeRequests[probe.label]; ok {
				result.PassProbes = append(result.PassProbes, PassProbe{
					Label:   fmt.Sprintf("Probe %q — %s", probe.label, probe.intent),
					Request: req,
					Body:    probeBodies[probe.label],
				})
			}
		}
	}

	return result, nil
}

func stackTraceProbeIntent(label string) string {
	for _, p := range stackTraceProbes {
		if p.label == label {
			return p.intent
		}
	}
	return label
}

func stackTraceImpact(category string) string {
	switch category {
	case "file_path":
		return "Exposed server-side file paths reveal the technology stack, directory structure, and exact source file locations, " +
			"enabling targeted attacks such as path traversal or identification of exploitable library versions."
	case "stack_frame":
		return "Stack traces expose internal code structure, function call chains, and exact line numbers, " +
			"allowing an attacker to map application internals and craft targeted exploits against specific code paths."
	case "version":
		return "Library version strings allow attackers to identify known CVEs affecting the exact versions in use " +
			"and target publicly documented vulnerabilities."
	case "database":
		return "Database error messages reveal the database engine, schema fragments, or query syntax, " +
			"which can aid SQL injection refinement or targeted database fingerprinting."
	case "internal_host":
		return "Internal IP addresses and hostnames expose the server's private network topology, " +
			"enabling reconnaissance of internal services or facilitating server-side request forgery (SSRF) attacks."
	default:
		return "Verbose debug information in error responses reduces attacker effort by revealing implementation details that should remain server-side."
	}
}

func stackTraceRemediation(category string) string {
	switch category {
	case "file_path", "stack_frame":
		return "Configure your GraphQL server to suppress detailed error messages in production. " +
			"Apollo Server: set NODE_ENV=production or use a custom formatError function that strips stack traces. " +
			"graphql-js: catch resolver errors and return sanitised messages. " +
			"Yoga/Envelop: use useMaskedErrors() to replace verbose errors with generic messages."
	case "version":
		return "Remove version identifiers from error responses and HTTP headers. " +
			"Use a custom error formatter to strip library-specific strings. " +
			"Setting NODE_ENV=production suppresses version info in many frameworks."
	case "database":
		return "Catch database exceptions at the resolver or data-access layer and return generic error messages. " +
			"Never propagate raw database error objects into GraphQL responses. " +
			"Use an ORM-level error handler to translate database errors into sanitised application errors."
	case "internal_host":
		return "Wrap all network calls in error handlers that return generic messages on connection failure. " +
			"Never include hostnames, IPs, or connection strings in user-facing error responses. " +
			"Use a service mesh or API gateway to abstract internal network topology from external clients."
	default:
		return "Enable production error masking in your GraphQL server to prevent verbose debug information from reaching clients."
	}
}
