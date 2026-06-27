package authz

import (
	"strings"
	"testing"
)

func TestMaskValue(t *testing.T) {
	cases := map[string]string{
		"":                   `""`,
		"x":                  `"***"`,
		"victim@example.com": `"v***@***"`,
		"111-22-3333":        `"1***"`,
		"secret":             `"s***"`,
	}
	for in, want := range cases {
		if got := MaskValue(in); got != want {
			t.Fatalf("MaskValue(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestRedactLeak_MasksValues(t *testing.T) {
	r := resp(200, `{"data":{"user":{"id":"42","email":"victim@x.com","ssn":"111-22-3333"}}}`)
	out := RedactLeak(nil, r)

	// Raw sensitive values must never appear.
	for _, raw := range []string{"victim@x.com", "111-22-3333"} {
		if strings.Contains(out, raw) {
			t.Fatalf("RedactLeak leaked raw value %q in %q", raw, out)
		}
	}
	// Field names should be present.
	for _, name := range []string{"email", "ssn", "id"} {
		if !strings.Contains(out, name) {
			t.Fatalf("RedactLeak missing field name %q in %q", name, out)
		}
	}
}

func TestRedactLeak_FieldFilter(t *testing.T) {
	r := resp(200, `{"data":{"user":{"id":"42","email":"a@b.c","ssn":"111"}}}`)
	out := RedactLeak([]string{"data.user.ssn"}, r)
	if !strings.Contains(out, "ssn") {
		t.Fatalf("expected ssn in filtered output, got %q", out)
	}
	if strings.Contains(out, "email") {
		t.Fatalf("did not expect email in filtered output, got %q", out)
	}
}

func TestRedactLeak_Empty(t *testing.T) {
	if got := RedactLeak(nil, nil); got != "" {
		t.Fatalf("RedactLeak(nil) = %q, want empty", got)
	}
	if got := RedactLeak(nil, resp(200, `{`)); got != "" {
		t.Fatalf("RedactLeak(malformed) = %q, want empty", got)
	}
}
