package authz

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// RedactLeak renders a compact, secret-masked preview of the scalar leaf values
// found in a response's `data` object, suitable for embedding in a finding's
// Description as evidence. Actual sensitive values are masked so that raw PII or
// tokens never appear in scanner output.
//
// When fields is non-empty, only those leaf keys are included; otherwise every
// scalar leaf under `data` is included. The output is deterministic
// (alphabetical by key) and bounded in length.
func RedactLeak(fields []string, resp *transport.Response) string {
	if resp == nil {
		return ""
	}
	var top struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &top); err != nil || len(top.Data) == 0 {
		return ""
	}

	want := make(map[string]bool, len(fields))
	for _, f := range fields {
		// Accept both bare keys and dotted paths (use the final segment).
		seg := f
		if i := strings.LastIndex(f, "."); i >= 0 {
			seg = f[i+1:]
		}
		want[seg] = true
	}

	pairs := collectScalars(top.Data, want)
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	strSort(keys)

	const maxPairs = 12
	var b strings.Builder
	n := 0
	for _, k := range keys {
		if n >= maxPairs {
			b.WriteString(", …")
			break
		}
		if n > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s: %s", k, MaskValue(pairs[k]))
		n++
	}
	return b.String()
}

// collectScalars walks raw JSON and collects scalar leaves keyed by their field
// name. When want is non-empty, only matching keys are collected.
func collectScalars(raw json.RawMessage, want map[string]bool) map[string]string {
	out := map[string]string{}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return out
	}
	var walk func(node interface{})
	walk = func(node interface{}) {
		switch t := node.(type) {
		case map[string]interface{}:
			for k, val := range t {
				if s := scalarString(val); s != "" {
					if len(want) == 0 || want[k] {
						out[k] = s
					}
					continue
				}
				walk(val)
			}
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// MaskValue returns a redacted preview of a sensitive value. Emails keep the
// first character of the local part; other strings keep their first character.
// The real value is never returned in full.
func MaskValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return `""`
	}
	if at := strings.IndexByte(v, '@'); at > 0 {
		return fmt.Sprintf("%q", string(v[0])+"***@***")
	}
	if len(v) <= 1 {
		return `"***"`
	}
	return fmt.Sprintf("%q", string(v[0])+"***")
}
