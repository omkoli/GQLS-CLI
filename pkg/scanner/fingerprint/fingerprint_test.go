package fingerprint

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
)

func fpClient() *transport.Client { return transport.NewClient(2*time.Second, 50, nil) }

// engineServer returns a server that replies with the given body (and optional
// headers) to every request — emulating an engine's distinctive error wording.
func engineServer(body string, headers map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		_, _ = io.WriteString(w, body)
	}))
}

func TestIdentify_Engines(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		headers map[string]string
		want    string
		conf    string
	}{
		{
			name: "Apollo",
			body: `{"errors":[{"message":"Cannot query field \"x\" on type \"Query\". Did you mean \"y\"?","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`,
			want: "Apollo Server", conf: "firm",
		},
		{
			name: "Hasura (body)",
			body: `{"errors":[{"message":"field \"x\" not found in type: 'query_root'","extensions":{"code":"validation-failed"}}]}`,
			want: "Hasura", conf: "firm",
		},
		{
			name:    "Hasura (header)",
			body:    `{"errors":[{"message":"validation failed"}]}`,
			headers: map[string]string{"x-hasura-role": "anonymous"},
			want:    "Hasura", conf: "firm",
		},
		{
			name: "HotChocolate",
			body: "{\"errors\":[{\"message\":\"The field `x` does not exist on the type `Query`.\"}]}",
			want: "HotChocolate", conf: "firm",
		},
		{
			name: "graphql-ruby",
			body: `{"errors":[{"message":"Field 'x' doesn't exist on type 'Query'"}]}`,
			want: "graphql-ruby", conf: "firm",
		},
		{
			name: "AWS AppSync",
			body: `{"errors":[{"errorType":"ValidationException","message":"Validation error"}]}`,
			want: "AWS AppSync", conf: "firm",
		},
		{
			name: "graphql-js generic (Did you mean, no Apollo code)",
			body: `{"errors":[{"message":"Cannot query field \"x\" on type \"Query\". Did you mean \"y\"?"}]}`,
			want: "graphql-js", conf: "tentative",
		},
		{
			name: "unknown (normalized)",
			body: `{"errors":[{"message":"Validation error"}]}`,
			want: "unknown", conf: "tentative",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := engineServer(c.body, c.headers)
			defer srv.Close()

			eng, ev, probes := Identify(t.Context(), fpClient(), srv.URL)
			if eng.Name != c.want {
				t.Fatalf("Identify = %q, want %q (evidence: %+v)", eng.Name, c.want, ev)
			}
			if eng.Confidence != c.conf {
				t.Fatalf("confidence = %q, want %q", eng.Confidence, c.conf)
			}
			if probes < 1 || probes > 6 {
				t.Fatalf("probe count %d out of bound [1,6]", probes)
			}
			if len(ev) == 0 {
				t.Fatal("expected evidence to be captured")
			}
		})
	}
}

func TestIdentify_Deterministic(t *testing.T) {
	srv := engineServer(`{"errors":[{"message":"Cannot query field \"x\". Did you mean?","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`, nil)
	defer srv.Close()
	e1, _, p1 := Identify(t.Context(), fpClient(), srv.URL)
	e2, _, p2 := Identify(t.Context(), fpClient(), srv.URL)
	if e1 != e2 || p1 != p2 {
		t.Fatalf("Identify not deterministic: %+v/%d vs %+v/%d", e1, p1, e2, p2)
	}
}

func TestIdentify_Unreachable(t *testing.T) {
	srv := engineServer(`{}`, nil)
	url := srv.URL
	srv.Close() // make unreachable
	eng, _, _ := Identify(t.Context(), fpClient(), url)
	if eng.Identified() {
		t.Fatalf("unreachable endpoint should not identify an engine, got %q", eng.Name)
	}
}

func TestIdentify_NilClient(t *testing.T) {
	eng, _, probes := Identify(t.Context(), nil, "http://example.com/graphql")
	if eng.Identified() || probes != len(probeDocs) {
		t.Fatalf("nil client: got %q, probes=%d", eng.Name, probes)
	}
}
