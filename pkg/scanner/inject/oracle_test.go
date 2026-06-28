package inject

import (
	"regexp"
	"testing"

	"github.com/gqls-cli/gqls/pkg/transport"
)

func resp(status int, body string) *transport.Response {
	return &transport.Response{StatusCode: status, Body: []byte(body)}
}

func TestBodyEquivalent(t *testing.T) {
	cases := []struct {
		name string
		a, b *transport.Response
		want bool
	}{
		{"identical", resp(200, `{"data":{"user":{"id":1}}}`), resp(200, `{"data":{"user":{"id":1}}}`), true},
		{"key order insensitive", resp(200, `{"data":{"a":1,"b":2}}`), resp(200, `{"data":{"b":2,"a":1}}`), true},
		{"different data", resp(200, `{"data":{"rows":[1,2,3]}}`), resp(200, `{"data":{"rows":[]}}`), false},
		{"different status", resp(200, `{"data":{}}`), resp(500, `{"data":{}}`), false},
		{"error set equal regardless of order", resp(200, `{"errors":[{"message":"a"},{"message":"b"}]}`), resp(200, `{"errors":[{"message":"b"},{"message":"a"}]}`), true},
		{"error set differs", resp(200, `{"errors":[{"message":"a"}]}`), resp(200, `{"errors":[{"message":"z"}]}`), false},
		{"both nil", nil, nil, true},
		{"one nil", nil, resp(200, `{}`), false},
		{"malformed equal raw", resp(200, `not json`), resp(200, `not json`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BodyEquivalent(c.a, c.b); got != c.want {
				t.Fatalf("BodyEquivalent = %v, want %v", got, c.want)
			}
		})
	}
}

func TestErrorSignal(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)SQLSTATE`),
		regexp.MustCompile(`ORA-\d`),
	}
	if m, ok := ErrorSignal([]byte(`{"errors":[{"message":"SQLSTATE 42000"}]}`), patterns); !ok || m != "SQLSTATE" {
		t.Fatalf("expected SQLSTATE match, got (%q,%v)", m, ok)
	}
	if _, ok := ErrorSignal([]byte(`{"data":{"ok":true}}`), patterns); ok {
		t.Fatal("clean body should not match")
	}
	// Malformed / empty input must not panic.
	if _, ok := ErrorSignal([]byte("\x00\xff not json"), patterns); ok {
		t.Fatal("binary noise should not match these patterns")
	}
	if _, ok := ErrorSignal(nil, patterns); ok {
		t.Fatal("nil body should not match")
	}
}
