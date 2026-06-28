// Package fingerprint identifies the backing GraphQL engine (Apollo, Hasura,
// graphql-ruby, HotChocolate, …) from a small set of discriminator probes,
// graphw00f-style. The result is consumed by GQL-M01 (engine fingerprint) and
// can be reused by other checks to tailor payloads and map engine-specific CVEs.
package fingerprint

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// Engine describes an identified GraphQL server implementation.
type Engine struct {
	// Name is the engine identifier, e.g. "Apollo Server", or "unknown".
	Name string
	// Vendor is a human-readable platform/vendor hint.
	Vendor string
	// Confidence is "firm" (distinctive signal) or "tentative".
	Confidence string
}

// Identified reports whether an engine (other than "unknown") was determined.
func (e Engine) Identified() bool { return e.Name != "" && e.Name != "unknown" }

// Evidence records what discriminating signal matched.
type Evidence struct {
	// Probe is the probe document (or "headers") that produced the signal.
	Probe string
	// Signal is the matched wording/header (truncated, for the report).
	Signal string
}

// probeDocs are the bounded discriminator queries. They are deliberately
// invalid/edge-case to elicit engine-distinctive error wording.
var probeDocs = []string{
	"{ __typename }", // valid baseline (read headers)
	"query { gqls_probe_nonexistent_field_zzz }",      // unknown field → "Cannot query field…"
	"query @gqls_probe_fake_directive { __typename }", // unknown directive
	"query {", // malformed → parse-error wording
}

type probeResult struct {
	doc  string
	resp *transport.Response
	body string
}

// Identify sends the discriminator probes and returns the best-matching engine,
// the supporting evidence, and the number of probes sent. A nil client or an
// unreachable target yields ("unknown", 0 or n probes).
func Identify(ctx context.Context, client *transport.Client, target string) (Engine, []Evidence, int) {
	var results []probeResult
	probes := 0
	for _, doc := range probeDocs {
		if ctx.Err() != nil {
			break
		}
		resp, body := send(ctx, client, target, doc)
		probes++
		results = append(results, probeResult{doc: doc, resp: resp, body: body})
	}

	for _, m := range matchers {
		if ev, ok := m.match(results); ok {
			return m.engine, []Evidence{ev}, probes
		}
	}
	return Engine{Name: "unknown", Confidence: "tentative"},
		[]Evidence{{Probe: "all probes", Signal: "no distinctive engine signal matched (errors appear normalized)"}},
		probes
}

func send(ctx context.Context, client *transport.Client, target, doc string) (*transport.Response, string) {
	if client == nil {
		return nil, ""
	}
	body, err := json.Marshal(map[string]string{"query": doc})
	if err != nil {
		return nil, ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil, ""
	}
	return resp, string(resp.Body)
}

// ── matchers ─────────────────────────────────────────────────────────────────

type matcher struct {
	engine Engine
	match  func(results []probeResult) (Evidence, bool)
}

var didYouMeanRe = regexp.MustCompile(`(?i)did you mean`)

// apolloErrorCodes are Apollo Server / graphql-js extensions.code values.
var apolloErrorCodes = map[string]bool{
	"GRAPHQL_VALIDATION_FAILED": true,
	"GRAPHQL_PARSE_FAILED":      true,
	"BAD_USER_INPUT":            true,
	"PERSISTED_QUERY_NOT_FOUND": true,
	"INTROSPECTION_DISABLED":    true,
}

// matchers are evaluated in priority order; the first to match wins. The most
// distinctive (firm) signals come first; generic graphql-js/graphql-core/gqlparser
// fallbacks come last so they never shadow a specific engine.
var matchers = []matcher{
	{
		engine: Engine{Name: "Hasura", Vendor: "Hasura GraphQL Engine", Confidence: "firm"},
		match: func(rs []probeResult) (Evidence, bool) {
			if ev, ok := headerFind(rs, func(h http.Header) (string, bool) {
				for k := range h {
					if strings.HasPrefix(strings.ToLower(k), "x-hasura") {
						return k, true
					}
				}
				return "", false
			}); ok {
				return ev, true
			}
			return bodyFind(rs, regexp.MustCompile(`(?i)(query_root|mutation_root|subscription_root|not found in type)`))
		},
	},
	{
		engine: Engine{Name: "AWS AppSync", Vendor: "Amazon Web Services", Confidence: "firm"},
		match: func(rs []probeResult) (Evidence, bool) {
			if ev, ok := bodyFind(rs, regexp.MustCompile(`"errorType"\s*:`)); ok {
				return ev, true
			}
			return headerFind(rs, func(h http.Header) (string, bool) {
				if v := h.Get("x-amzn-RequestId"); v != "" {
					return "x-amzn-RequestId", true
				}
				if v := h.Get("x-amzn-ErrorType"); v != "" {
					return "x-amzn-ErrorType", true
				}
				return "", false
			})
		},
	},
	{
		engine: Engine{Name: "graphql-ruby", Vendor: "Ruby", Confidence: "firm"},
		match: func(rs []probeResult) (Evidence, bool) {
			return bodyFind(rs, regexp.MustCompile(`(?i)(doesn't exist on type|can't be applied to|is missing required arguments)`))
		},
	},
	{
		engine: Engine{Name: "HotChocolate", Vendor: ".NET / ChilliCream", Confidence: "firm"},
		match: func(rs []probeResult) (Evidence, bool) {
			return bodyFind(rs, regexp.MustCompile("(?i)(The field `[^`]+` does not exist on the type|does not exist on the type `|Unexpected token while parsing|HotChocolate)"))
		},
	},
	{
		engine: Engine{Name: "Apollo Server", Vendor: "Apollo GraphQL (graphql-js)", Confidence: "firm"},
		match: func(rs []probeResult) (Evidence, bool) {
			var ev Evidence
			hasCode := false
			for _, r := range rs {
				if code, ok := extractErrorCode(r.body); ok && apolloErrorCodes[code] {
					hasCode = true
					ev = Evidence{Probe: r.doc, Signal: "extensions.code=" + code}
				}
			}
			didYouMean := false
			for _, r := range rs {
				if didYouMeanRe.MatchString(r.body) {
					didYouMean = true
				}
			}
			if hasCode && didYouMean {
				return ev, true
			}
			return Evidence{}, false
		},
	},
	{
		engine: Engine{Name: "graphql-js", Vendor: "Apollo / Yoga / Express-GraphQL (Node.js)", Confidence: "tentative"},
		match: func(rs []probeResult) (Evidence, bool) {
			return bodyFind(rs, didYouMeanRe)
		},
	},
	{
		engine: Engine{Name: "graphql-core", Vendor: "Graphene / Ariadne / Strawberry (Python)", Confidence: "tentative"},
		match: func(rs []probeResult) (Evidence, bool) {
			return bodyFind(rs, regexp.MustCompile(`(?i)Syntax Error GraphQL`))
		},
	},
	{
		engine: Engine{Name: "gqlgen", Vendor: "Go (gqlparser)", Confidence: "tentative"},
		match: func(rs []probeResult) (Evidence, bool) {
			return bodyFind(rs, regexp.MustCompile(`(?i)expected at least one definition`))
		},
	},
}

// extractErrorCode returns the first errors[].extensions.code in a GraphQL body.
func extractErrorCode(body string) (string, bool) {
	var env struct {
		Errors []struct {
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if json.Unmarshal([]byte(body), &env) != nil {
		return "", false
	}
	for _, e := range env.Errors {
		if e.Extensions.Code != "" {
			return e.Extensions.Code, true
		}
	}
	return "", false
}

// bodyFind returns evidence for the first probe body matching re.
func bodyFind(results []probeResult, re *regexp.Regexp) (Evidence, bool) {
	for _, r := range results {
		if m := re.FindString(r.body); m != "" {
			return Evidence{Probe: r.doc, Signal: truncate(m, 120)}, true
		}
	}
	return Evidence{}, false
}

// headerFind returns evidence for the first response whose headers satisfy pred.
func headerFind(results []probeResult, pred func(http.Header) (string, bool)) (Evidence, bool) {
	for _, r := range results {
		if r.resp == nil {
			continue
		}
		if sig, ok := pred(r.resp.Headers); ok {
			return Evidence{Probe: "headers", Signal: sig}, true
		}
	}
	return Evidence{}, false
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
