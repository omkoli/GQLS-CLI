package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gqls-cli/gqls/pkg/scanner/authz"
	"github.com/gqls-cli/gqls/pkg/scanner/inject"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/schema/surface"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// userEnumerationCheck implements GQL-B04: User/Identifier Enumeration via
// differential errors and timing. Auth-flow operations (login, password-reset,
// signup, userExists) leak whether an account exists when they return a
// different error message/code/shape — or take measurably longer (password
// hashing runs only for existing users) — for one identifier versus another.
//
// The check is read-only: it sends only clearly-invalid, non-existent probe
// identifiers (never a real/configured credential) and never triggers a real
// account lockout. It compares two should-be-negative identifiers — a well-formed
// non-existent address and a malformed one — that a safe API would answer
// identically. A differential response (after redacting the echoed identifiers)
// or a robust timing gap between them is the enumeration oracle.
type userEnumerationCheck struct{}

func init() {
	MustRegister(&userEnumerationCheck{})
}

func (c *userEnumerationCheck) ID() string           { return "GQL-B04" }
func (c *userEnumerationCheck) Name() string         { return "User/Identifier Enumeration" }
func (c *userEnumerationCheck) Category() Category   { return Authorization }
func (c *userEnumerationCheck) Severity() Severity   { return MEDIUM }
func (c *userEnumerationCheck) RequiresSchema() bool { return false }

const (
	// enumTimingSamples is the interleaved sample count for the timing oracle.
	enumTimingSamples = 7
	// enumTimingFloor is the absolute latency gap required to call a timing
	// oracle (well below a SQL-sleep floor, tuned for a password-hash gap).
	enumTimingFloor = 25 * time.Millisecond
)

// enumOpRe matches enumeration-prone operation names.
var enumOpRe = regexp.MustCompile(`(?i)(login|signin|reset_?password|forgot_?password|signup|register|user_?exists|check_?email|account)`)

// enumOp is the resolved operation to probe.
type enumOp struct {
	isMutation bool
	field      string
	fieldDef   *schema.FieldDef
	emailArg   string // the identifier-bearing argument varied between probes
}

// Run executes the user-enumeration check.
func (c *userEnumerationCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	// ── Step 1: locate an enumeration-prone operation ─────────────────────────
	op, ok := resolveEnumOp(cc)
	if !ok {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no enumeration-prone operation with an identifier argument found; " +
			"provide a schema exposing a login/reset/signup/userExists-style operation, or name one with " +
			"--authz-login-op"
		return result, nil
	}

	client := cc.HTTPClient
	if client == nil {
		client = cc.ProbeClient()
	}
	if client == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "no HTTP client available to send enumeration probes"
		return result, nil
	}

	// ── Step 2: two clearly non-existent probe identifiers (safe negatives) ───
	// They share a random token so partial echoes redact cleanly.
	token := newBizProbeCode()
	wellFormed := "gqls-nouser-" + token + "@invalid.example"
	malformed := "gqls-not-an-email-" + token
	redact := []string{wellFormed, malformed, token}

	// ── Step 3a: message/code/shape differential (one sample each) ────────────
	docWF := buildEnumDoc(op, cc.Schema, wellFormed)
	docMF := buildEnumDoc(op, cc.Schema, malformed)

	respWF, bodyWF, errWF := gqlPost(ctx, client, cc.Target, docWF)
	result.ProbeCount++
	respMF, _, _ := gqlPost(ctx, client, cc.Target, docMF)
	result.ProbeCount++

	probeWF := analyzeEnumResp(respWF, redact)
	probeMF := analyzeEnumResp(respMF, redact)
	msgDiff := probeWF.ok && probeMF.ok && probeWF.sig != probeMF.sig

	// ── Step 3b: timing differential ──────────────────────────────────────────
	// A safe design answers both identically and in equal time; a hash-on-existing
	// oracle makes the well-formed (plausible) identifier the slower branch.
	control := func(ctx context.Context) (time.Duration, error) {
		resp, _, err := gqlPost(ctx, client, cc.Target, docMF)
		result.ProbeCount++
		if err != nil {
			return 0, err
		}
		if resp == nil {
			return 0, fmt.Errorf("no response")
		}
		return resp.Latency, nil
	}
	payload := func(ctx context.Context) (time.Duration, error) {
		resp, _, err := gqlPost(ctx, client, cc.Target, docWF)
		result.ProbeCount++
		if err != nil {
			return 0, err
		}
		if resp == nil {
			return 0, fmt.Errorf("no response")
		}
		return resp.Latency, nil
	}
	timing := inject.TimingOracle(ctx, control, payload, enumTimingSamples, enumTimingFloor)

	// ── Step 4: decide ────────────────────────────────────────────────────────
	switch {
	case timing.Effect:
		result.Findings = append(result.Findings, c.finding(cc, op, "timing", "confirmed",
			enumTimingDetail(timing, probeWF, probeMF, msgDiff), respWF, bodyWF))
		return result, nil

	case msgDiff:
		result.Findings = append(result.Findings, c.finding(cc, op, "message", "firm",
			fmt.Sprintf("the two probes returned different responses (well-formed → %s; malformed → %s) "+
				"after redacting the probe identifiers — the operation's responses encode which inputs it "+
				"treats as accounts", probeWF.summary, probeMF.summary), respWF, bodyWF))
		return result, nil
	}

	// ── Clean / safe design ────────────────────────────────────────────────────
	if errWF == nil && respWF != nil {
		result.PassProbes = append(result.PassProbes, PassProbe{
			Label:   fmt.Sprintf("enumeration probe %s (well-formed vs malformed non-existent id): %s", op.field, probeWF.summary),
			Request: respWF.Request, Body: bodyWF,
		})
	}
	result.PassReason = fmt.Sprintf(
		"%s answered two non-existent probe identifiers identically (control median %s vs payload median %s over "+
			"%d samples, no robust gap) — no enumeration oracle observed",
		op.field, timing.ControlMedian, timing.PayloadMedian, timing.Samples)
	return result, nil
}

// finding builds the MEDIUM enumeration finding for the given channel.
func (c *userEnumerationCheck) finding(cc *CheckContext, op enumOp, channel, confidence, detail string,
	resp *transport.Response, body []byte) Finding {

	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  MEDIUM,
		Category:  Authorization,
		Title:     fmt.Sprintf("User Enumeration — %s reveals account existence via %s", op.field, channel),
		Description: fmt.Sprintf(
			"The %s operation %q lets an attacker tell whether an account exists: %s. Only clearly-invalid, "+
				"non-existent probe identifiers were used (a well-formed gqls-nouser-…@invalid.example and a "+
				"malformed gqls-not-an-email-… sentinel), so no real account was touched and no lockout was "+
				"triggered. Echoed data is redacted.",
			enumOpKind(op), op.field, detail),
		Impact: "Attackers can confirm which emails/usernames have accounts, building target lists for credential " +
			"stuffing, phishing, and account-takeover chains — and disclosing account existence is itself a " +
			"privacy violation.",
		Remediation: "Return generic, identical responses for existing and non-existing accounts (same message, " +
			"code, and shape); use constant-time handling (always perform a dummy password hash on the reject " +
			"path); and apply rate limiting / CAPTCHA on authentication and reset flows.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages",
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
			"https://cwe.mitre.org/data/definitions/204.html",
		},
		Confidence:  confidence,
		CWE:         "CWE-204",
		OWASP:       "API1:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "enum:"+op.field+":"+channel),
		ReproBody:   body,
	}
	if resp != nil {
		f.ReproRequest = resp.Request
	}
	return f
}

// enumTimingDetail renders the timing-channel evidence, noting a corroborating
// message differential when one was also present.
func enumTimingDetail(t inject.TimingResult, wf, mf enumProbe, msgDiff bool) string {
	d := fmt.Sprintf("the well-formed identifier was robustly slower than the malformed one "+
		"(payload median %s vs control median %s, ±MAD %s over %d samples), consistent with server-side work "+
		"(e.g. a password hash) performed only for plausible/existing accounts",
		t.PayloadMedian, t.ControlMedian, t.MAD, t.Samples)
	if msgDiff {
		d += fmt.Sprintf("; the responses also differed (well-formed → %s; malformed → %s)", wf.summary, mf.summary)
	}
	return d
}

// ── operation resolution ─────────────────────────────────────────────────────

// resolveEnumOp resolves the operation to probe: an operator-named bare field
// (with schema) wins; otherwise a schema mutation, then query, whose name looks
// enumeration-prone and that carries an identifier-bearing argument.
func resolveEnumOp(cc *CheckContext) (enumOp, bool) {
	s := cc.Schema
	if flag := strings.TrimSpace(cc.AuthzLoginOp); flag != "" && !strings.Contains(flag, "(") && s != nil {
		if fd := mutationFieldByName(s, flag); fd != nil {
			if ea := emailArgOf(fd); ea != "" {
				return enumOp{isMutation: true, field: flag, fieldDef: fd, emailArg: ea}, true
			}
		}
		if fd := queryFieldByName(s, flag); fd != nil {
			if ea := emailArgOf(fd); ea != "" {
				return enumOp{isMutation: false, field: flag, fieldDef: fd, emailArg: ea}, true
			}
		}
	}
	if s == nil {
		return enumOp{}, false
	}
	if op, ok := firstEnumOp(s.MutationFields(), true); ok {
		return op, true
	}
	if op, ok := firstEnumOp(s.QueryFields(), false); ok {
		return op, true
	}
	return enumOp{}, false
}

// firstEnumOp returns the first (name-sorted) enumeration-prone field with an
// identifier argument.
func firstEnumOp(fields []*schema.FieldDef, isMutation bool) (enumOp, bool) {
	fs := make([]*schema.FieldDef, len(fields))
	copy(fs, fields)
	sort.Slice(fs, func(i, j int) bool { return fs[i].Name < fs[j].Name })
	for _, fd := range fs {
		if fd == nil || !enumOpRe.MatchString(fd.Name) {
			continue
		}
		if ea := emailArgOf(fd); ea != "" {
			return enumOp{isMutation: isMutation, field: fd.Name, fieldDef: fd, emailArg: ea}, true
		}
	}
	return enumOp{}, false
}

// emailArgOf returns the first identifier-bearing argument (email/username/…).
func emailArgOf(fd *schema.FieldDef) string {
	for _, a := range fd.Args {
		if a != nil && credEmailRe.MatchString(a.Name) {
			return a.Name
		}
	}
	return ""
}

// enumOpKind returns "mutation" or "query" for messaging.
func enumOpKind(op enumOp) string {
	if op.isMutation {
		return "mutation"
	}
	return "query"
}

// ── document building ────────────────────────────────────────────────────────

// buildEnumDoc builds the operation document setting the identifier argument to
// the given probe id, secret arguments to a fixed invalid password, and other
// required arguments to example values.
func buildEnumDoc(op enumOp, s *schema.Schema, identifier string) string {
	opType := "query"
	if op.isMutation {
		opType = "mutation"
	}
	sel := ""
	if op.fieldDef != nil {
		sel = mutSelectionSet(op.fieldDef.Type, s)
	}
	args := buildEnumArgs(op, s, identifier)
	if args == "" {
		return fmt.Sprintf("%s { %s%s }", opType, op.field, sel)
	}
	return fmt.Sprintf("%s { %s(%s)%s }", opType, op.field, args, sel)
}

// buildEnumArgs renders the operation's arguments: the identifier argument
// carries the probe id, credential/secret arguments a fixed invalid value, and
// other required arguments example values.
func buildEnumArgs(op enumOp, s *schema.Schema, identifier string) string {
	if op.fieldDef == nil {
		return ""
	}
	var parts []string
	for _, a := range op.fieldDef.Args {
		if a == nil {
			continue
		}
		switch {
		case a.Name == op.emailArg:
			parts = append(parts, fmt.Sprintf("%s: %q", a.Name, identifier))
		case !argRequired(a):
			continue
		case isStringArg(a) && credSecretRe.MatchString(a.Name):
			parts = append(parts, fmt.Sprintf("%s: %q", a.Name, "gqls-invalid-password"))
		default:
			if ev := surface.ExampleValue(a.Type, s); ev != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", a.Name, ev))
			}
		}
	}
	return strings.Join(parts, ", ")
}

// isStringArg reports whether an argument's named type is String.
func isStringArg(a *schema.ArgDef) bool {
	if a == nil || a.Type == nil {
		return false
	}
	u := a.Type.Unwrap()
	return u != nil && u.Name == "String"
}

// ── response differential ────────────────────────────────────────────────────

// enumProbe is a normalized fingerprint of one probe response.
type enumProbe struct {
	sig     string // canonical signature for differential comparison
	summary string // short, redacted human description for the finding
	ok      bool
}

// analyzeEnumResp builds a redacted signature (status + class + sorted error
// messages/codes + gross data shape) so two probes can be compared without the
// echoed identifiers themselves causing a spurious difference.
func analyzeEnumResp(resp *transport.Response, redact []string) enumProbe {
	if resp == nil {
		return enumProbe{}
	}
	red := func(str string) string {
		for _, t := range redact {
			if t != "" {
				str = strings.ReplaceAll(str, t, "<ID>")
			}
		}
		return str
	}

	env := decodeEnumEnvelope(resp.Body)
	msgs := make([]string, 0, len(env.Errors))
	codes := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		msgs = append(msgs, red(e.Message))
		if e.Extensions.Code != "" {
			codes = append(codes, red(e.Extensions.Code))
		}
	}
	sort.Strings(msgs)
	sort.Strings(codes)

	dataState := "null"
	if t := strings.TrimSpace(string(env.Data)); t != "" && t != "null" {
		dataState = "present"
	}

	cls := authz.Classify(resp)
	sig := fmt.Sprintf("%d|%s|%v|%v|%s", resp.StatusCode, cls, msgs, codes, dataState)

	summary := fmt.Sprintf("HTTP %d, %s", resp.StatusCode, cls)
	switch {
	case len(msgs) > 0:
		summary += fmt.Sprintf(", error %q", truncateStr(msgs[0], 80))
	default:
		summary += ", data " + dataState
	}
	return enumProbe{sig: sig, summary: summary, ok: true}
}

// enumEnvelope is the minimal GraphQL envelope the differential needs.
type enumEnvelope struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

func decodeEnumEnvelope(body []byte) enumEnvelope {
	var env enumEnvelope
	_ = json.Unmarshal(body, &env)
	return env
}

// truncateStr bounds a string for evidence output.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
