package checks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ── test server (HTTP control + graphql-transport-ws subscription) ───────────

// subServer serves the HTTP authz control (anonymous denied) and a WebSocket
// subscription endpoint. wsAcceptAnon controls whether anonymous WS connections
// are accepted; wsSendNext controls whether a data frame is pushed; supportWS
// controls whether the WebSocket upgrade is handled at all.
func subServer(wsAcceptAnon, wsSendNext, supportWS bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if supportWS && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"graphql-transport-ws"}})
			if err != nil {
				return
			}
			defer conn.Close(websocket.StatusInternalError, "")
			ctx := r.Context()
			if !wsAcceptAnon && r.Header.Get("Authorization") == "" {
				conn.Close(websocket.StatusCode(4401), "unauthorized")
				return
			}
			for {
				_, data, rerr := conn.Read(ctx)
				if rerr != nil {
					return
				}
				var m map[string]interface{}
				if json.Unmarshal(data, &m) != nil {
					continue
				}
				switch m["type"] {
				case "connection_init":
					_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"connection_ack"}`))
				case "subscribe":
					if wsSendNext {
						_ = conn.Write(ctx, websocket.MessageText,
							[]byte(`{"id":"1","type":"next","payload":{"data":{"secretFeed":{"id":"1","value":"topsecret"}}}}`))
					}
					_ = conn.Write(ctx, websocket.MessageText, []byte(`{"id":"1","type":"complete"}`))
					conn.Close(websocket.StatusNormalClosure, "")
					return
				}
			}
		}

		// HTTP path: the related query is denied to anonymous (no Authorization).
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			_, _ = io.WriteString(w, `{"data":null,"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"secretFeed":{"__typename":"Secret"}}}`)
	}))
}

func subAuthzSchema(withSub bool) *schema.Schema {
	secret := &schema.TypeDef{Name: "Secret", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "id", Type: bolaScalar("ID")}, {Name: "value", Type: bolaScalar("String")},
	}}
	query := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{
		{Name: "secretFeed", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Secret"}},
	}}
	s := &schema.Schema{QueryType: query, Types: map[string]*schema.TypeDef{"Secret": secret, "Query": query}}
	if withSub {
		sub := &schema.TypeDef{Name: "Subscription", Kind: schema.KindObject, Fields: []*schema.FieldDef{
			{Name: "secretFeed", Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Secret"}},
		}}
		s.SubscriptionType = sub
		s.Types["Subscription"] = sub
	}
	return s
}

func subAuthzContext(url string, withSub bool) *CheckContext {
	return &CheckContext{
		Target:                url,
		Schema:                subAuthzSchema(withSub),
		UnauthenticatedClient: transport.NewClient(3*time.Second, 50, nil),
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestSubAuthz_Vulnerable(t *testing.T) {
	srv := subServer(true, true, true) // accept anon, push data, support WS
	defer srv.Close()

	res, err := (&subscriptionAuthzCheck{}).Run(t.Context(), subAuthzContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != Authorization || f.CWE != "CWE-285" || f.OWASP != "API5:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "confirmed" || !strings.Contains(f.Title, "secretFeed") {
		t.Fatalf("expected confirmed finding naming the subscription, got %q / %q", f.Confidence, f.Title)
	}
	if strings.Contains(f.Description, "topsecret") {
		t.Fatalf("delivered payload must be redacted in the finding: %s", f.Description)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
}

func TestSubAuthz_Enforced(t *testing.T) {
	srv := subServer(false, false, true) // reject anon WS (close 4401)
	defer srv.Close()

	res, err := (&subscriptionAuthzCheck{}).Run(t.Context(), subAuthzContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (WS authz enforced), got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason")
	}
}

func TestSubAuthz_NoSubscriptions(t *testing.T) {
	srv := subServer(true, true, true)
	defer srv.Close()

	res, err := (&subscriptionAuthzCheck{}).Run(t.Context(), subAuthzContext(srv.URL, false))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
}

func TestSubAuthz_WSUnreachable(t *testing.T) {
	srv := subServer(true, true, false) // HTTP works, WS upgrade not handled
	defer srv.Close()

	res, err := (&subscriptionAuthzCheck{}).Run(t.Context(), subAuthzContext(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings when WS is unreachable, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason (recorded, not a crash)")
	}
}
