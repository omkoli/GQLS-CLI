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

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// crossTenantCheck implements GQL-A04: Cross-Tenant Isolation Failure.
//
// It is BOLA (GQL-A01) specialized to the multi-tenant boundary: it has an
// identity in tenant A attempt to read an object owned by an identity in tenant
// B, via three vectors — requesting B's object id directly, manipulating a
// tenant header, and manipulating a tenant argument — and flags when tenant A
// receives tenant B's object.
type crossTenantCheck struct{}

func init() {
	MustRegister(&crossTenantCheck{})
}

func (c *crossTenantCheck) ID() string           { return "GQL-A04" }
func (c *crossTenantCheck) Name() string         { return "Cross-Tenant Isolation Failure" }
func (c *crossTenantCheck) Category() Category   { return Authorization }
func (c *crossTenantCheck) Severity() Severity   { return CRITICAL }
func (c *crossTenantCheck) RequiresSchema() bool { return true }

const (
	maxXTenantFetchers = 5
	maxXTenantPairs    = 6
)

// vector identifies the crossing technique used for a finding.
type xtVector struct {
	key   string // short token for the fingerprint
	label string // human-readable description
}

var (
	vectorObjectID = xtVector{"object-id", "object-id crossing"}
	vectorHeader   = xtVector{"tenant-header", "tenant header manipulation"}
	vectorArg      = xtVector{"tenant-arg", "tenant argument manipulation"}
)

// knownTenantHeaders lists tenant-scoping header names (HTTP-canonical form).
var knownTenantHeaders = []string{
	"X-Tenant-Id", "X-Tenant", "X-Org-Id", "X-Organization-Id",
	"X-Account", "X-Account-Id", "X-Workspace-Id", "Tenant-Id",
}

// tenantArgRe matches tenant-scoping argument names.
var tenantArgRe = regexp.MustCompile(`(?i)^(tenant_?id|org(anization)?_?id|account_?id|workspace_?id|tenant|org)$`)

// Run executes the cross-tenant isolation check.
func (c *crossTenantCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: preconditions — need ≥2 identities in different tenants ───────
	tenantIdents := identitiesWithTenant(cc.Identities)
	if countDistinctTenants(tenantIdents) < 2 {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "cross-tenant testing requires two operator-supplied identities in different " +
			"tenants; set tenant: on each --identity (e.g. --identity 'name=a;tenant=t1;header=...')"
		return result, nil
	}

	fetchers := surface.Fetchers(cc.Schema)
	if len(fetchers) == 0 {
		result.PassReason = "no id-bearing object fetchers found in the schema (nothing to test for cross-tenant access)"
		return result, nil
	}
	if len(fetchers) > maxXTenantFetchers {
		fetchers = fetchers[:maxXTenantFetchers]
	}

	tenantHeader := detectTenantHeader(tenantIdents)
	pairs := tenantPairs(tenantIdents)

	var (
		passProbes  []PassProbe
		victimCache = map[string]string{}
		fired       = map[string]bool{} // vector.key|fetcher -> finding already emitted
		comparisons int
		discovered  bool
	)

	for fi := range fetchers {
		if ctx.Err() != nil {
			break
		}
		f := fetchers[fi]

		for pi := range pairs {
			if ctx.Err() != nil {
				break
			}
			attacker := pairs[pi][0]
			victim := pairs[pi][1]

			// Discover an object the victim (tenant B) legitimately owns.
			cacheKey := victim.Name + "|" + f.RootField
			victimObjID, cached := victimCache[cacheKey]
			if !cached {
				victimObjID = discoverOwnerObjectID(ctx, cc, victim, f, &result)
				victimCache[cacheKey] = victimObjID
			}
			if victimObjID == "" {
				continue
			}
			discovered = true

			idLit := formatIDLiteral(f.IDArgType, victimObjID)
			victimTenant := strings.TrimSpace(victim.Tenant)

			// When the fetcher carries a tenant-scoping argument it is typically
			// required, so every request must supply it. The victim's baseline (and
			// the attacker's "arg crossing") therefore carry the victim's tenant in
			// that argument; this is itself the tenant-argument manipulation vector.
			tenantArg, hasTenantArg := tenantArgOf(cc.Schema, f)
			var extraArgs []string
			vector1 := vectorObjectID
			if hasTenantArg && victimTenant != "" {
				extraArgs = []string{fmt.Sprintf("%s: %q", tenantArg, victimTenant)}
				vector1 = vectorArg
			}

			query, idField := buildTenantCrossQuery(cc.Schema, f, idLit, extraArgs)
			idPath := "data." + f.RootField + "." + idField

			// Victim baseline: confirm the victim can read its own object.
			victimResp, _, verr := gqlPost(ctx, victim.Client, cc.Target, query)
			result.ProbeCount++
			if verr != nil || victimResp == nil || authz.Classify(victimResp) != authz.ClassSuccess {
				continue
			}

			// ── Attempt 1: id / tenant-argument crossing ───────────────────
			if !fired[vector1.key+"|"+f.RootField] {
				aResp, aBody, aerr := gqlPost(ctx, attacker.Client, cc.Target, query)
				result.ProbeCount++
				if aerr == nil && aResp != nil {
					comparisons++
					if leaked, fin := c.evaluate(cc, f, attacker, victim, vector1, victimResp, aResp, aBody, idPath); leaked {
						result.Findings = append(result.Findings, fin)
						fired[vector1.key+"|"+f.RootField] = true
					} else {
						passProbes = append(passProbes, xtPass(f, attacker, victim, vector1, aResp, aBody))
					}
				}
			}

			// ── Attempt 2: tenant-header manipulation ──────────────────────
			// Only meaningful when there is a tenant header and no tenant argument
			// already crossing the boundary (otherwise the header would be a
			// redundant second selector on the same query).
			if tenantHeader != "" && !hasTenantArg && !fired[vectorHeader.key+"|"+f.RootField] {
				victimHeaderVal := victim.Headers[tenantHeader]
				if victimHeaderVal == "" {
					victimHeaderVal = victimTenant
				}
				if victimHeaderVal != "" {
					aResp, aBody, aerr := gqlPostHeaders(ctx, attacker.Client, cc.Target, query,
						map[string]string{tenantHeader: victimHeaderVal})
					result.ProbeCount++
					if aerr == nil && aResp != nil {
						comparisons++
						if leaked, fin := c.evaluate(cc, f, attacker, victim, vectorHeader, victimResp, aResp, aBody, idPath); leaked {
							result.Findings = append(result.Findings, fin)
							fired[vectorHeader.key+"|"+f.RootField] = true
						} else {
							passProbes = append(passProbes, xtPass(f, attacker, victim, vectorHeader, aResp, aBody))
						}
					}
				}
			}
		}
	}

	if len(result.Findings) > 0 {
		return result, nil
	}

	result.PassProbes = passProbes
	if !discovered {
		result.PassReason = "could not establish any victim-tenant object id to test; " +
			"provide --authz-seed 'field=id' or ensure a viewer/list query exposes an id"
	} else {
		result.PassReason = fmt.Sprintf(
			"performed %d cross-tenant comparison(s); tenant isolation appears enforced "+
				"(no identity reached another tenant's object via id, header, or argument manipulation)",
			comparisons)
	}
	return result, nil
}

// evaluate decides whether an attacker response constitutes a cross-tenant leak
// (attacker received the victim's object) and, if so, builds the finding.
func (c *crossTenantCheck) evaluate(cc *CheckContext, f surface.ObjectFetcher, attacker, victim Identity,
	v xtVector, victimResp, attackerResp *transport.Response, aBody []byte, idPath string) (bool, Finding) {

	diff := authz.Compare(victimResp, attackerResp, idPath)
	if diff.AttackerClass != authz.ClassSuccess || !diff.SameObject {
		return false, Finding{}
	}

	redacted := authz.RedactLeak(diff.LeakedFields, attackerResp)
	if redacted == "" {
		redacted = "(no scalar fields returned)"
	}

	return true, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  CRITICAL,
		Category:  Authorization,
		Title: fmt.Sprintf("Cross-Tenant Isolation Failure — tenant %q reached tenant %q data via %s",
			attacker.Tenant, victim.Tenant, v.label),
		Description: fmt.Sprintf(
			"Identity %q (tenant %q) retrieved an object owned by identity %q (tenant %q) via %s on "+
				"%s(%s). Both responses returned the same object id, proving the tenant boundary was crossed. "+
				"Leaked fields (redacted): %s.",
			attacker.Name, attacker.Tenant, victim.Name, victim.Tenant, v.label,
			f.RootField, f.IDArg, redacted),
		Impact: "A customer/tenant can read (and, combined with mutation-side flaws, modify) another " +
			"tenant's data — a total multi-tenant isolation breach, mass cross-organization data " +
			"exfiltration, and severe compliance/contractual exposure.",
		Remediation: "Scope every data access by the authenticated principal's tenant at the data layer " +
			"(mandatory tenant predicate / row-level security). Never trust a client-supplied tenant id or " +
			"tenant header for authorization; validate that requested object ids belong to the caller's " +
			"tenant; add tenant-isolation assertions to integration tests.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/639.html",
		},
		Confidence:   "confirmed",
		CWE:          "CWE-639",
		OWASP:        "API1:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "xtenant:"+v.key+":"+f.RootField),
		ReproRequest: attackerResp.Request,
		ReproBody:    aBody,
	}
}

// xtPass builds a transparency pass-probe for a non-leaking crossing attempt.
func xtPass(f surface.ObjectFetcher, attacker, victim Identity, v xtVector, resp *transport.Response, body []byte) PassProbe {
	return PassProbe{
		Label: fmt.Sprintf("cross-tenant %s via %s: tenant %q did not reach tenant %q's object (isolation enforced)",
			f.RootField, v.label, attacker.Tenant, victim.Tenant),
		Request: resp.Request,
		Body:    body,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// identitiesWithTenant returns the identities that carry a non-empty tenant.
func identitiesWithTenant(ids []Identity) []Identity {
	var out []Identity
	for _, id := range ids {
		if strings.TrimSpace(id.Tenant) != "" {
			out = append(out, id)
		}
	}
	return out
}

// countDistinctTenants returns the number of distinct tenant labels.
func countDistinctTenants(ids []Identity) int {
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id.Tenant] = true
	}
	return len(seen)
}

// tenantPairs returns ordered (attacker, victim) identity pairs in different
// tenants, deterministically ordered and capped.
func tenantPairs(ids []Identity) [][2]Identity {
	sorted := make([]Identity, len(ids))
	copy(sorted, ids)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Tenant != sorted[j].Tenant {
			return sorted[i].Tenant < sorted[j].Tenant
		}
		return sorted[i].Name < sorted[j].Name
	})
	var out [][2]Identity
	for i := range sorted {
		for j := range sorted {
			if sorted[i].Tenant == sorted[j].Tenant {
				continue
			}
			out = append(out, [2]Identity{sorted[i], sorted[j]})
			if len(out) >= maxXTenantPairs {
				return out
			}
		}
	}
	return out
}

// detectTenantHeader returns the first known tenant header present on any
// identity, or "".
func detectTenantHeader(ids []Identity) string {
	for _, name := range knownTenantHeaders {
		for _, id := range ids {
			if _, ok := id.Headers[name]; ok {
				return name
			}
		}
	}
	return ""
}

// tenantArgOf returns the name of a tenant-scoping argument on the fetcher's
// field, if present.
func tenantArgOf(s *schema.Schema, f surface.ObjectFetcher) (string, bool) {
	fd := queryFieldByName(s, f.RootField)
	if fd == nil {
		return "", false
	}
	for _, a := range fd.Args {
		if a != nil && tenantArgRe.MatchString(a.Name) {
			return a.Name, true
		}
	}
	return "", false
}

// buildTenantCrossQuery builds a single-object fetch query for f using idLit as
// the id argument, plus any extraArgs (e.g. a tenant argument). It skips id and
// tenant args when synthesizing other required arguments.
func buildTenantCrossQuery(s *schema.Schema, f surface.ObjectFetcher, idLit string, extraArgs []string) (query, idField string) {
	sel, idField := buildSelection(s, f.ReturnType)
	parts := []string{fmt.Sprintf("%s: %s", f.IDArg, idLit)}
	parts = append(parts, extraArgs...)

	if fd := queryFieldByName(s, f.RootField); fd != nil {
		for _, a := range fd.Args {
			if a == nil || a.Name == f.IDArg || tenantArgRe.MatchString(a.Name) {
				continue
			}
			if argRequired(a) {
				if ev := surface.ExampleValue(a.Type, s); ev != "" {
					parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
				}
			}
		}
	}
	query = fmt.Sprintf("query { %s(%s) %s }", f.RootField, strings.Join(parts, ", "), sel)
	return query, idField
}

// gqlPostHeaders sends a GraphQL POST with additional request headers that
// override the client's defaults (the transport client only force-overrides
// Authorization, so explicitly-set headers like a tenant header are preserved).
func gqlPostHeaders(ctx context.Context, client *transport.Client, target, query string, extra map[string]string) (*transport.Response, []byte, error) {
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, body, fmt.Errorf("nil client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, body, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, body, err
	}
	return resp, body, nil
}
