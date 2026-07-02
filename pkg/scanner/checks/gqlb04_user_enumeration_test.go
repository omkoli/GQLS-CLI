package checks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// ── enumeration test server ──────────────────────────────────────────────────

var enumEmailRe = regexp.MustCompile(`email:\s*"([^"]*)"`)

// enumServer records every identifier it is sent and answers per mode:
//   - "message": distinct error text for the well-formed vs malformed identifier.
//   - "timing":  identical text, but sleeps only for the well-formed identifier.
//   - "generic": identical response for every identifier (the safe design).
type enumServer struct {
	mu     sync.Mutex
	mode   string
	emails []string
	hits   atomic.Int32
}

func (s *enumServer) handler(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	q := bolaReadQuery(r)
	email := firstSubmatch(enumEmailRe, q)
	s.mu.Lock()
	s.emails = append(s.emails, email)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	wellFormed := strings.Contains(email, "@")

	switch s.mode {
	case "message":
		if wellFormed {
			_, _ = io.WriteString(w, `{"data":{"login":null},"errors":[{"message":"invalid password"}]}`)
		} else {
			_, _ = io.WriteString(w, `{"data":{"login":null},"errors":[{"message":"user not found"}]}`)
		}
	case "timing":
		if wellFormed {
			time.Sleep(60 * time.Millisecond) // password hash runs only for plausible users
		}
		_, _ = io.WriteString(w, `{"data":{"login":null},"errors":[{"message":"invalid credentials"}]}`)
	default: // generic / safe
		_, _ = io.WriteString(w, `{"data":{"login":null},"errors":[{"message":"invalid credentials"}]}`)
	}
}

func (s *enumServer) seenEmails() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.emails...)
}

func enumContext(url string, s *schema.Schema) *CheckContext {
	return &CheckContext{Target: url, Schema: s, BaseHTTPClient: aliasProbeClient()}
}

// assertOnlySentinels fails if any recorded identifier is not a gqls probe
// sentinel — the check must never send a real/configured identifier.
func assertOnlySentinels(t *testing.T, emails []string) {
	t.Helper()
	if len(emails) == 0 {
		t.Fatal("expected the check to send probe identifiers")
	}
	for _, e := range emails {
		if !strings.HasPrefix(e, "gqls-nouser-") && !strings.HasPrefix(e, "gqls-not-an-email-") {
			t.Fatalf("non-sentinel identifier was sent: %q", e)
		}
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestUserEnum_MessageChannel(t *testing.T) {
	es := &enumServer{mode: "message"}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()

	res, err := (&userEnumerationCheck{}).Run(t.Context(), enumContext(srv.URL, aliasAuthSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != MEDIUM || f.Category != Authorization || f.CWE != "CWE-204" || f.OWASP != "API1:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "firm" {
		t.Fatalf("expected firm confidence for the message channel, got %q", f.Confidence)
	}
	if !strings.Contains(f.Title, "login") || !strings.Contains(f.Title, "message") {
		t.Fatalf("title should name the op and channel: %s", f.Title)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}
	// Repro must show the clearly-invalid sentinels and never a real credential.
	body := string(f.ReproBody)
	if !strings.Contains(body, "gqls-nouser-") || !strings.Contains(body, "gqls-invalid-password") {
		t.Fatalf("expected invalid sentinels in the probe body: %s", body)
	}
	assertOnlySentinels(t, es.seenEmails())
}

func TestUserEnum_TimingChannel(t *testing.T) {
	es := &enumServer{mode: "timing"}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()

	res, err := (&userEnumerationCheck{}).Run(t.Context(), enumContext(srv.URL, aliasAuthSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Confidence != "confirmed" {
		t.Fatalf("expected confirmed confidence for a robust timing oracle, got %q", f.Confidence)
	}
	if !strings.Contains(f.Title, "timing") {
		t.Fatalf("title should reference the timing channel: %s", f.Title)
	}
	if f.CWE != "CWE-204" || f.OWASP != "API1:2023" || f.Severity != MEDIUM {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	assertOnlySentinels(t, es.seenEmails())
}

func TestUserEnum_GenericNoFinding(t *testing.T) {
	es := &enumServer{mode: "generic"}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()

	res, err := (&userEnumerationCheck{}).Run(t.Context(), enumContext(srv.URL, aliasAuthSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings for identical generic responses, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason explaining the clean result")
	}
	assertOnlySentinels(t, es.seenEmails())
}

func TestUserEnum_NoOpSkipped(t *testing.T) {
	es := &enumServer{mode: "generic"}
	srv := httptest.NewServer(http.HandlerFunc(es.handler))
	defer srv.Close()

	// bolaFixtureSchema exposes user/users only — no enumeration-prone op.
	res, err := (&userEnumerationCheck{}).Run(t.Context(), enumContext(srv.URL, bolaFixtureSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
	if es.hits.Load() != 0 {
		t.Fatalf("a skipped check must send zero requests; got %d", es.hits.Load())
	}
}

func TestUserEnum_NoSchemaNoFlagSkipped(t *testing.T) {
	res, err := (&userEnumerationCheck{}).Run(t.Context(), &CheckContext{Target: "http://example.com/graphql"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason when no op can be resolved, got %+v", res)
	}
}
