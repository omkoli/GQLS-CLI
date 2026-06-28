package inject

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// Send POSTs a GraphQL operation (doc + variables) as JSON to target using
// client. It returns the response, the exact request body sent (for
// reproduction), and any transport error. It does not count probes — the caller
// owns ProbeCount.
func Send(ctx context.Context, client *transport.Client, target, doc string, variables map[string]any) (*transport.Response, []byte, error) {
	payload := map[string]any{"query": doc}
	if variables != nil {
		payload["variables"] = variables
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, body, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	return resp, body, err
}

// ErrorSignal returns the first substring of body matching any pattern, and
// whether one matched. It generalizes per-check engine-error tables (e.g. the
// SQL-error patterns in GQL-011). It never panics on malformed input.
func ErrorSignal(body []byte, patterns []*regexp.Regexp) (matched string, ok bool) {
	for _, re := range patterns {
		if re == nil {
			continue
		}
		if m := re.Find(body); m != nil {
			return string(m), true
		}
	}
	return "", false
}

// BodyEquivalent reports whether two responses are equivalent for differential
// comparison: same status code and the same normalized GraphQL envelope (data +
// error messages). It is the basis for boolean-true-vs-false comparison (I01)
// and enumeration oracles. Two nil responses are equivalent; one nil is not.
func BodyEquivalent(a, b *transport.Response) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.StatusCode != b.StatusCode {
		return false
	}
	return normalizeEnvelope(a.Body) == normalizeEnvelope(b.Body)
}

// normalizeEnvelope produces a canonical string for a GraphQL response body:
// the re-marshaled `data` object plus the sorted set of error messages. JSON
// re-marshaling canonicalizes object key order; this makes the comparison robust
// to insignificant formatting differences. Malformed bodies fall back to their
// trimmed raw bytes.
func normalizeEnvelope(body []byte) string {
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return string(bytes.TrimSpace(body))
	}

	dataCanon := canonicalJSON(env.Data)
	msgs := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		msgs = append(msgs, e.Message)
	}
	// Error message order is not significant for equivalence.
	sortStrings(msgs)

	out, _ := json.Marshal(struct {
		Data   string   `json:"data"`
		Errors []string `json:"errors"`
	}{Data: dataCanon, Errors: msgs})
	return string(out)
}

// canonicalJSON re-marshals raw JSON so that object keys are emitted in sorted
// order (Go's encoding/json sorts map keys), yielding a stable representation.
func canonicalJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "null"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
