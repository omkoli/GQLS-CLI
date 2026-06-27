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

// maxPageProbe is the large page size requested in the abuse probe. It is a
// bounded constant (Safety): deliberately moderate (10k, not millions) so the
// check detects a missing maximum without trying to exhaust the target.
const maxPageProbe = 10000

// maxPaginationCandidates bounds how many list fields are probed per run so the
// total request volume stays small (≤ maxPaginationCandidates × 2 probes).
const maxPaginationCandidates = 2

// paginationArgNames is the set of recognized integer pagination argument names
// (compared case-insensitively).
var paginationArgNames = map[string]bool{
	"first":    true,
	"last":     true,
	"limit":    true,
	"count":    true,
	"take":     true,
	"pagesize": true,
	"perpage":  true,
	"size":     true,
}

// paginationLimitRejectionPattern matches response bodies that indicate the
// large page request was rejected or clamped by an amount/page-size limit. A
// match means amount limiting appears to be enforced for that field.
var paginationLimitRejectionPattern = regexp.MustCompile(
	`(?i)maximum|exceeds|too large|limit|must be (less|fewer)|cannot request more than`,
)

// listArgumentAbuseCheck implements GQL-D05: Unbounded List/Pagination Argument.
//
// GraphQL list fields that accept first/last/limit/count/take (etc.) without an
// enforced maximum let a client request enormous result sets in one query,
// exhausting memory/DB/serialization resources — the OWASP GraphQL Cheat Sheet
// "Amount limiting" control (OWASP API4:2023).
type listArgumentAbuseCheck struct{}

func init() {
	MustRegister(&listArgumentAbuseCheck{})
}

func (c *listArgumentAbuseCheck) ID() string           { return "GQL-D05" }
func (c *listArgumentAbuseCheck) Name() string         { return "Unbounded List/Pagination Argument" }
func (c *listArgumentAbuseCheck) Category() Category   { return DenialOfService }
func (c *listArgumentAbuseCheck) Severity() Severity   { return HIGH }
func (c *listArgumentAbuseCheck) RequiresSchema() bool { return true }

// paginationCandidate is a schema-derived list field plus the pagination
// argument and minimal selection set used to probe it.
type paginationCandidate struct {
	field     string
	arg       string
	selection string // e.g. "{ __typename }", "{ edges { __typename } }", or "" for a scalar list
}

// paginationProbeResult captures the outcome of a single pagination probe.
type paginationProbeResult struct {
	status  int
	body    []byte
	req     *http.Request
	payload []byte
	err     error
}

// Run executes GQL-D05 against the target endpoint.
//
// It finds up to maxPaginationCandidates paginated list fields in the schema and,
// for each, sends a small control page (arg: 1) then a large abuse page
// (arg: maxPageProbe). A per-field HIGH finding fires when the large page is
// honored without a max-page rejection (a near-max returned count, or a much
// larger response for scalar lists), or when the abuse probe times out / 5xx
// after a fast control.
func (c *listArgumentAbuseCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// Defensive guard: although RequiresSchema()=true means the runner skips this
	// check when the schema is nil, a direct call must not panic.
	candidates := findPaginationCandidates(cc.Schema, maxPaginationCandidates)
	if len(candidates) == 0 {
		result.PassReason = "No list fields with a recognized pagination argument were found in the schema."
		return result, nil
	}

	probedCount := 0
	for _, cand := range candidates {
		if ctx.Err() != nil {
			break
		}

		// ── Control probe (small page) ───────────────────────────────────────
		control := c.probe(ctx, cc, buildPaginationQuery(cand.field, cand.arg, 1, cand.selection))
		result.ProbeCount++
		controlOK := control.err == nil && control.status == http.StatusOK && bytes.Contains(control.body, []byte(`"data"`))
		if !controlOK {
			// Skip the field — its control did not yield a baseline (it likely
			// requires additional arguments). Record the probe for transparency.
			if control.req != nil {
				result.PassProbes = append(result.PassProbes, PassProbe{
					Label: fmt.Sprintf("pagination-control %s(%s: 1) — skipped, no baseline (%s)",
						cand.field, cand.arg, describeControlFailure(control.status, control.err)),
					Request: control.req,
					Body:    control.payload,
				})
			}
			continue
		}
		probedCount++

		if ctx.Err() != nil {
			break
		}

		// ── Abuse probe (large page) ─────────────────────────────────────────
		abuse := c.probe(ctx, cc, buildPaginationQuery(cand.field, cand.arg, maxPageProbe, cand.selection))
		result.ProbeCount++

		// Timeout / network failure (not cancellation) on the abuse probe is a
		// positive signal — the control already returned a fast 200.
		if abuse.err != nil {
			if ctx.Err() != nil {
				break
			}
			result.Findings = append(result.Findings, c.finding(cc, cand, abuse,
				paginationUnresponsiveDescription(cand, fmt.Sprintf("the request did not complete (%v)", abuse.err), len(control.body))))
			continue
		}
		if abuse.status >= http.StatusInternalServerError {
			result.Findings = append(result.Findings, c.finding(cc, cand, abuse,
				paginationUnresponsiveDescription(cand, fmt.Sprintf("the server returned HTTP %d", abuse.status), len(control.body))))
			continue
		}

		sc := len(control.body)
		sa := len(abuse.body)
		hasData := bytes.Contains(abuse.body, []byte(`"data"`))
		limited := paginationLimitRejectionPattern.Match(abuse.body)
		honored, itemCount := pageHonored(cand, sc, sa, abuse.body)

		if abuse.status == http.StatusOK && hasData && !limited && honored {
			result.Findings = append(result.Findings, c.finding(cc, cand, abuse,
				paginationHonoredDescription(cand, sc, sa, itemCount)))
			continue
		}

		// Not vulnerable for this field — record both probes.
		result.PassProbes = append(result.PassProbes,
			PassProbe{
				Label:   fmt.Sprintf("pagination-control %s(%s: 1)", cand.field, cand.arg),
				Request: control.req, Body: control.payload,
			},
			PassProbe{
				Label:   fmt.Sprintf("pagination-abuse %s(%s: %d)", cand.field, cand.arg, maxPageProbe),
				Request: abuse.req, Body: abuse.payload,
			},
		)
	}

	if len(result.Findings) == 0 {
		if probedCount == 0 {
			result.PassReason = fmt.Sprintf(
				"Found %d paginated field(s), but their control probes did not return a usable baseline "+
					"(they likely require additional arguments); pagination limits were not assessed.",
				len(candidates),
			)
		} else {
			result.PassReason = "All paginated fields enforced a maximum page size (or rejected first:10000)."
		}
	}

	return result, nil
}

// probe marshals query into a GraphQL POST body, sends it via the probe client,
// and records the status, body, request, and payload. The request and payload
// are populated even on a transport error so callers can still build repro /
// pass records (e.g. on a timeout).
func (c *listArgumentAbuseCheck) probe(ctx context.Context, cc *CheckContext, query string) paginationProbeResult {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return paginationProbeResult{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		return paginationProbeResult{payload: payload, err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	if err != nil {
		return paginationProbeResult{req: req, payload: payload, err: err}
	}
	return paginationProbeResult{
		status:  resp.StatusCode,
		body:    resp.Body,
		req:     resp.Request,
		payload: payload,
	}
}

// finding builds a HIGH GQL-D05 finding for a single vulnerable field, with a
// field-specific fingerprint.
func (c *listArgumentAbuseCheck) finding(cc *CheckContext, cand paginationCandidate, abuse paginationProbeResult, description string) Finding {
	return Finding{
		CheckID:      c.ID(),
		CheckName:    c.Name(),
		Severity:     HIGH,
		Category:     DenialOfService,
		Title:        fmt.Sprintf("Unbounded Pagination on %q (arg %q)", cand.field, cand.arg),
		Description:  description,
		Impact:       paginationImpact,
		Remediation:  paginationRemediation,
		References:   paginationReferences,
		ReproRequest: abuse.req,
		ReproBody:    abuse.payload,
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "pagination_"+cand.field),
	}
}

// findPaginationCandidates returns up to max paginated list fields from the
// schema, deterministically in schema order. It is nil-safe.
func findPaginationCandidates(s *schema.Schema, max int) []paginationCandidate {
	var out []paginationCandidate
	for _, f := range s.QueryFields() {
		if f == nil || f.Name == "" || f.Type == nil {
			continue
		}
		arg := paginationArgFor(f)
		if arg == "" {
			continue
		}
		selection, ok := paginationSelection(s, f)
		if !ok {
			continue
		}
		out = append(out, paginationCandidate{field: f.Name, arg: arg, selection: selection})
		if len(out) >= max {
			break
		}
	}
	return out
}

// paginationArgFor returns the name of the first integer-typed pagination
// argument on f, or "" when none is present.
func paginationArgFor(f *schema.FieldDef) string {
	for _, a := range f.Args {
		if a == nil {
			continue
		}
		if paginationArgNames[strings.ToLower(a.Name)] && argIsInteger(a) {
			return a.Name
		}
	}
	return ""
}

// argIsInteger reports whether the argument's (unwrapped) type is the built-in
// Int scalar.
func argIsInteger(a *schema.ArgDef) bool {
	if a == nil || a.Type == nil {
		return false
	}
	return a.Type.Unwrap().Name == "Int"
}

// paginationSelection determines the minimal selection set needed to probe a
// list/connection field and reports whether the field is a usable candidate.
//
//   - Plain list of objects ([User])     → "{ __typename }"
//   - Plain list of scalars/enums ([Int]) → ""        (leaf list)
//   - Connection object with edges/nodes  → "{ edges { __typename } }" (or nodes)
func paginationSelection(s *schema.Schema, f *schema.FieldDef) (string, bool) {
	if typeRefContainsList(f.Type) {
		named := f.Type.Unwrap()
		switch returnKind(s, named) {
		case schema.KindScalar, schema.KindEnum:
			return "", true
		default:
			return "{ __typename }", true
		}
	}

	// Connection heuristic: an object return type exposing an edges/nodes list.
	named := f.Type.Unwrap()
	t := s.FindType(named.Name)
	if t == nil || t.Kind != schema.KindObject {
		return "", false
	}
	for _, sub := range t.Fields {
		if sub == nil || sub.Type == nil {
			continue
		}
		low := strings.ToLower(sub.Name)
		if (low == "edges" || low == "nodes") && typeRefContainsList(sub.Type) {
			switch returnKind(s, sub.Type.Unwrap()) {
			case schema.KindScalar, schema.KindEnum:
				return fmt.Sprintf("{ %s }", sub.Name), true
			default:
				return fmt.Sprintf("{ %s { __typename } }", sub.Name), true
			}
		}
	}
	return "", false
}

// typeRefContainsList reports whether any node in the type reference's wrapper
// chain is a LIST.
func typeRefContainsList(t *schema.TypeRef) bool {
	for cur := t; cur != nil; cur = cur.OfType {
		if cur.Kind == schema.KindList {
			return true
		}
	}
	return false
}

// buildPaginationQuery builds a query invoking field with arg set to value and
// the given selection set appended (omitted for scalar leaf lists).
func buildPaginationQuery(field, arg string, value int, selection string) string {
	if selection == "" {
		return fmt.Sprintf("query { %s(%s: %d) }", field, arg, value)
	}
	return fmt.Sprintf("query { %s(%s: %d) %s }", field, arg, value, selection)
}

// pageHonored reports whether the abuse response is evidence the large page was
// honored, and the approximate returned item count. For countable selections
// (one __typename per item) it requires a near-max returned count, which avoids
// false positives from servers that silently clamp to a smaller maximum. For
// scalar leaf lists (uncountable) it falls back to a response-size ratio.
func pageHonored(cand paginationCandidate, controlSize, abuseSize int, abuseBody []byte) (bool, int) {
	if strings.Contains(cand.selection, "__typename") {
		itemCount := bytes.Count(abuseBody, []byte("__typename"))
		return itemCount >= maxPageProbe/2, itemCount
	}
	return controlSize > 0 && abuseSize >= 5*controlSize, 0
}

func paginationHonoredDescription(cand paginationCandidate, controlSize, abuseSize, itemCount int) string {
	evidence := fmt.Sprintf("the response grew from %d bytes (at %s: 1) to %d bytes", controlSize, cand.arg, abuseSize)
	if strings.Contains(cand.selection, "__typename") {
		evidence = fmt.Sprintf("the response returned ~%d items and grew from %d to %d bytes",
			itemCount, controlSize, abuseSize)
	}
	return fmt.Sprintf(
		"The list field %q accepts the pagination argument %q with no enforced server-side maximum. "+
			"Requesting `%s: %d` was honored without a max-page rejection — %s. A single request can thus "+
			"force the server to load, serialize, and transfer an arbitrarily large result set.",
		cand.field, cand.arg, cand.arg, maxPageProbe, evidence,
	)
}

func paginationUnresponsiveDescription(cand paginationCandidate, outcome string, controlSize int) string {
	return fmt.Sprintf(
		"A control request for a single-item page of the list field %q (%s: 1) returned a fast HTTP 200 "+
			"(%d bytes), but requesting `%s: %d` did not complete normally: %s. A large page request driving "+
			"the server to time out or error indicates no enforced maximum page size.",
		cand.field, cand.arg, controlSize, cand.arg, maxPageProbe, outcome,
	)
}

const paginationImpact = "A single request can force the server to load, serialize, and transfer a very large " +
	"dataset, exhausting memory, database, and bandwidth resources and producing slow-loris-style " +
	"amplification. The same primitive also enables bulk data scraping, since one legitimate-looking query " +
	"returns an unbounded result set."

const paginationRemediation = "Enforce a server-side maximum page size (e.g. cap first/limit ≤ 100) and reject " +
	"or clamp larger values. Prefer cursor-based pagination with a hard ceiling, and add query-cost analysis " +
	"that weights requested list sizes so an expensive page is rejected before execution."

var paginationReferences = []string{
	"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
	"https://graphql.org/learn/pagination/",
}
