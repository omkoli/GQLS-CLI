package checks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gqls-cli/gqls/pkg/scanner/inject"
	"github.com/gqls-cli/gqls/pkg/schema"
)

// xssCheck implements GQL-I06: it detects where GraphQL surfaces XSS payloads
// unencoded — through error/field reflection (reflected) and rich-text fields
// that store and return markup unescaped (stored). It reasons about the raw JSON
// response bytes: whether an injected, self-attributing marker re-emerges with
// HTML-significant characters unescaped, not about browser execution.
//
// Safety: the marker is inert and self-identifying. The stored path is
// write-gated (--authz-allow-mutations) and uses capture→write→read-back→restore
// — it never writes without first capturing the original, and restores it.
type xssCheck struct{}

func init() {
	MustRegister(&xssCheck{})
}

func (c *xssCheck) ID() string           { return "GQL-I06" }
func (c *xssCheck) Name() string         { return "Cross-Site Scripting (Reflected/Stored via GraphQL)" }
func (c *xssCheck) Category() Category   { return Injection }
func (c *xssCheck) Severity() Severity   { return MEDIUM }
func (c *xssCheck) RequiresSchema() bool { return true }

// i06MaxPoints bounds the reflected-path injection points probed.
const i06MaxPoints = 25

// i06MarkerHTML is the HTML-significant core of the marker; its raw presence
// (with `<`) signals an unescaped reflection.
const i06MarkerHTML = "<svg/onload=alert(1)>"

// i06RichTextRe matches field/arg names likely rendered as rich text/HTML.
var i06RichTextRe = regexp.MustCompile(`(?i)(bio|description|comment|content|body|message|about|note|summary|title|text)`)

// Run executes the XSS reflection check.
func (c *xssCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	if cc.Schema == nil {
		result.Ran = false
		result.Skipped = true
		result.SkipReason = "schema required to enumerate injection points"
		return result, nil
	}

	// ── Reflected path: inject the marker at query points; flag unescaped echoes.
	var queryPts []inject.Point
	for _, p := range inject.Points(cc.Schema) {
		if p.OpKind == "query" && i01StringLike(p.ScalarType) {
			queryPts = append(queryPts, p)
		}
	}
	for _, tgt := range inject.Cap(queryPts, i06MaxPoints) {
		if ctx.Err() != nil {
			break
		}
		marker, nonceTok := i06NewMarker()
		doc, vars := tgt.Render(cc.Schema, marker)
		resp, body, err := inject.Send(ctx, cc.HTTPClient, cc.Target, doc, vars)
		result.ProbeCount++
		if err != nil || resp == nil {
			continue
		}
		if i06UnescapedReflection(resp.Body, nonceTok) {
			result.Findings = append(result.Findings, c.finding(cc, tgt.RootField, tgt.PathKey(), "reflected",
				i06Snippet(resp.Body, nonceTok), resp.Request, body))
		}
	}

	// ── Stored path (opt-in): capture → write marker → read-back → restore.
	storedSkipped := ""
	if cc.AllowMutations {
		c.probeStored(ctx, cc, &result)
	} else if i06HasMutationRichText(cc.Schema) {
		storedSkipped = " The stored-XSS path was skipped (write-gated): pass --authz-allow-mutations to test it."
	}

	if len(result.Findings) == 0 {
		result.PassReason = "no unencoded reflection of the XSS marker was observed: injected markers were either " +
			"absent from responses or returned with HTML-significant characters correctly escaped." + storedSkipped
	}
	return result, nil
}

// probeStored runs a single safe capture→write→read-back→restore cycle against a
// discoverable rich-text mutation paired with a no-argument getter. It never
// writes unless it first captures the original value, and always restores it.
func (c *xssCheck) probeStored(ctx context.Context, cc *CheckContext, result *CheckResult) {
	mut, arg, retType, ok := i06FindRichTextMutation(cc.Schema)
	if !ok {
		return
	}
	getter, ok := i06FindGetter(cc.Schema, retType, arg)
	if !ok {
		return
	}

	getterDoc := fmt.Sprintf("{ %s { %s } }", getter, arg)

	// 1. Capture the original value. Never write without a successful capture.
	capResp, _, err := inject.Send(ctx, cc.HTTPClient, cc.Target, getterDoc, nil)
	result.ProbeCount++
	if err != nil || capResp == nil {
		return
	}
	original, ok := i06ExtractField(capResp.Body, getter, arg)
	if !ok {
		return // cannot safely restore → do not write
	}

	marker, nonceTok := i06NewMarker()
	writeDoc := fmt.Sprintf("mutation GqlsXSS($v: String) { %s(%s: $v) { %s } }", mut, arg, arg)

	// 2. Write the marker.
	if _, _, err := inject.Send(ctx, cc.HTTPClient, cc.Target, writeDoc, map[string]any{"v": marker}); err == nil {
		result.ProbeCount++
	} else {
		result.ProbeCount++
		return
	}

	// 3. Read back via the getter.
	rbResp, rbBody, err := inject.Send(ctx, cc.HTTPClient, cc.Target, getterDoc, nil)
	result.ProbeCount++
	stored := err == nil && rbResp != nil && i06UnescapedReflection(rbResp.Body, nonceTok)

	// 4. Restore the original value (always, regardless of outcome).
	if _, _, rerr := inject.Send(ctx, cc.HTTPClient, cc.Target, writeDoc, map[string]any{"v": original}); rerr == nil {
		result.ProbeCount++
	} else {
		result.ProbeCount++
	}

	if stored {
		result.Findings = append(result.Findings, c.finding(cc, mut, arg, "stored",
			i06Snippet(rbResp.Body, nonceTok), rbResp.Request, rbBody))
	}
}

func (c *xssCheck) finding(cc *CheckContext, rootField, pathKey, kind, snippet string, reproReq *http.Request, reproBody []byte) Finding {
	f := Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  MEDIUM,
		Category:  Injection,
		Title:     fmt.Sprintf("Potential XSS — unencoded %s reflection via %s arg %s", kind, rootField, pathKey),
		Description: fmt.Sprintf(
			"An inert XSS marker injected at %s field %q (argument path %q) was %s back with HTML-significant "+
				"characters unescaped (raw `<`/`>`), e.g. %q. This is exploitable only if a consuming client "+
				"renders the value as HTML, which the scanner cannot prove from the JSON response alone.",
			cc.Target, rootField, pathKey, kind, snippet),
		Impact: "If a client renders the reflected value as HTML, an attacker can run script in the victim's " +
			"browser: session theft, account takeover, and arbitrary actions as the victim.",
		Remediation: "Apply context-aware output encoding at the HTML sink; sanitize rich text on input/output " +
			"with an allow-list; set the correct Content-Type; apply a Content-Security-Policy; and never echo raw " +
			"user input in error messages.",
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/79.html",
		},
		ReproBody:   reproBody,
		Confidence:  "firm",
		CWE:         "CWE-79",
		OWASP:       "API8:2023",
		Fingerprint: GenerateFingerprint(c.ID(), cc.Target, "xss:"+rootField+"/"+pathKey),
	}
	if reproReq != nil {
		f.ReproRequest = reproReq
	}
	return f
}

// i06NewMarker returns a unique, inert marker and its attribution nonce token.
func i06NewMarker() (marker, nonceTok string) {
	var b [6]byte
	_, _ = rand.Read(b[:])
	nonceTok = "gqls" + hex.EncodeToString(b[:])
	return nonceTok + i06MarkerHTML, nonceTok
}

// i06UnescapedReflection reports whether the body reflects this probe's marker
// with the raw `<` intact (i.e., the nonce is immediately followed by "<svg").
// HTML-encoded (&lt;svg) or JSON-unicode-escaped (<svg) reflections do not
// match and are correctly encoded.
func i06UnescapedReflection(body []byte, nonceTok string) bool {
	return bytes.Contains(body, []byte(nonceTok+"<svg"))
}

// i06Snippet returns a short, truncated window around the reflected marker.
func i06Snippet(body []byte, nonceTok string) string {
	idx := bytes.Index(body, []byte(nonceTok))
	if idx < 0 {
		return nonceTok + i06MarkerHTML
	}
	end := idx + len(nonceTok) + len(i06MarkerHTML)
	if end > len(body) {
		end = len(body)
	}
	return string(body[idx:end])
}

// i06ExtractField parses data.<getter>.<field> as a string.
func i06ExtractField(body []byte, getter, field string) (string, bool) {
	var env struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", false
	}
	obj, ok := env.Data[getter]
	if !ok {
		return "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(obj, &fields); err != nil {
		return "", false
	}
	raw, ok := fields[field]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// i06FindRichTextMutation finds a mutation with a rich-text-named String arg
// whose return type is an object exposing that same field, and with no other
// required arguments (so it is safe to call with just the rich-text arg).
func i06FindRichTextMutation(s *schema.Schema) (mutation, arg, retType string, ok bool) {
	for _, m := range s.MutationFields() {
		if m == nil || m.Type == nil {
			continue
		}
		ret := m.Type.Unwrap()
		if ret == nil || ret.Kind != schema.KindObject {
			continue
		}
		td := s.FindType(ret.Name)
		if td == nil {
			continue
		}
		for _, a := range m.Args {
			if a == nil || a.Type == nil {
				continue
			}
			if !i06RichTextRe.MatchString(strings.ToLower(a.Name)) {
				continue
			}
			if u := a.Type.Unwrap(); u == nil || (u.Name != "String" && u.Name != "ID") {
				continue
			}
			if !i06TypeHasField(td, a.Name) {
				continue
			}
			if i06HasOtherRequiredArg(m, a.Name) {
				continue
			}
			return m.Name, a.Name, ret.Name, true
		}
	}
	return "", "", "", false
}

// i06FindGetter finds a query field returning retType (object) with no required
// arguments, used to capture/read-back the field.
func i06FindGetter(s *schema.Schema, retType, field string) (string, bool) {
	for _, q := range s.QueryFields() {
		if q == nil || q.Type == nil {
			continue
		}
		u := q.Type.Unwrap()
		if u == nil || u.Kind != schema.KindObject || u.Name != retType {
			continue
		}
		if i06HasOtherRequiredArg(q, "") {
			continue
		}
		return q.Name, true
	}
	return "", false
}

func i06TypeHasField(td *schema.TypeDef, name string) bool {
	for _, f := range td.Fields {
		if f != nil && f.Name == name {
			return true
		}
	}
	return false
}

// i06HasOtherRequiredArg reports whether f has a required (NON_NULL) argument
// other than except.
func i06HasOtherRequiredArg(f *schema.FieldDef, except string) bool {
	for _, a := range f.Args {
		if a == nil || a.Name == except {
			continue
		}
		if a.Type != nil && a.Type.Kind == schema.KindNonNull {
			return true
		}
	}
	return false
}

// i06HasMutationRichText reports whether any mutation exposes a rich-text-named
// String arg (used to note when the stored path was skipped for write-gating).
func i06HasMutationRichText(s *schema.Schema) bool {
	_, _, _, ok := i06FindRichTextMutation(s)
	return ok
}
