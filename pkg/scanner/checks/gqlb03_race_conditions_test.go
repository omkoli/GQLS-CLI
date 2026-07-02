package checks

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
	"github.com/gqls-cli/gqls/pkg/transport"
)

// ── stateful, race-detector-clean redeem server ──────────────────────────────

// raceServer models a one-time redeemCoupon flow. All shared state is accessed
// under a mutex, so the server itself has no Go data race; the vulnerability is
// a *logical* TOCTOU — in the non-atomic mode the "check" and "act" happen in
// separate critical sections with a gap between them, so a parallel burst can
// pass the check before any writer sets the used flag.
type raceServer struct {
	mu           sync.Mutex
	used         bool
	count        int
	atomicGuard  bool // check-and-act under one lock ⇒ exactly one success
	scalarReturn bool // return a bare Boolean instead of a { balance } object
	hits         atomic.Int32
	mutations    atomic.Int32
}

func (s *raceServer) writeSuccess(w http.ResponseWriter, c int) {
	if s.scalarReturn {
		_, _ = io.WriteString(w, `{"data":{"redeemCoupon":true}}`)
		return
	}
	_, _ = io.WriteString(w, fmt.Sprintf(`{"data":{"redeemCoupon":{"balance":%d,"__typename":"Redemption"}}}`, c))
}

func (s *raceServer) writeAlreadyRedeemed(w http.ResponseWriter) {
	_, _ = io.WriteString(w, `{"data":{"redeemCoupon":null},"errors":[{"message":"coupon already redeemed"}]}`)
}

func (s *raceServer) handler(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	q := bolaReadQuery(r)
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(strings.TrimSpace(q), "mutation") {
		_, _ = io.WriteString(w, `{"data":{}}`)
		return
	}
	s.mutations.Add(1)

	if s.atomicGuard {
		// Check-and-act atomically: only the first request wins.
		s.mu.Lock()
		if s.used {
			s.mu.Unlock()
			s.writeAlreadyRedeemed(w)
			return
		}
		s.used = true
		s.count++
		c := s.count
		s.mu.Unlock()
		s.writeSuccess(w, c)
		return
	}

	// Non-atomic: check, then a gap, then act — a classic TOCTOU window.
	s.mu.Lock()
	seen := s.used
	s.mu.Unlock()
	if seen {
		s.writeAlreadyRedeemed(w)
		return
	}
	time.Sleep(25 * time.Millisecond) // widen the window so the burst races through
	s.mu.Lock()
	s.used = true
	s.count++
	c := s.count
	s.mu.Unlock()
	s.writeSuccess(w, c)
}

func raceContext(url string, s *schema.Schema) *CheckContext {
	return &CheckContext{
		Target:         url,
		Schema:         s,
		AllowMutations: true,
		HTTPClient:     transport.NewClient(5*time.Second, 50, nil),
	}
}

// ── tests (run these under `go test -race`) ──────────────────────────────────

func TestRace_VulnerableConfirmed(t *testing.T) {
	rs := &raceServer{} // non-atomic, object return with a balance effect field
	srv := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer srv.Close()

	res, err := (&raceCheck{}).Run(t.Context(), raceContext(srv.URL, bizFlowSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	f := res.Findings[0]
	if f.Severity != HIGH || f.Category != BusinessLogic || f.CWE != "CWE-362" || f.OWASP != "API6:2023" {
		t.Fatalf("unexpected finding metadata: %+v", f)
	}
	if f.Confidence != "confirmed" {
		t.Fatalf("expected confirmed confidence (balances proved over-consumption), got %q", f.Confidence)
	}
	if !strings.Contains(f.Title, "redeemCoupon") || !strings.Contains(f.Title, "parallel") {
		t.Fatalf("title should describe the parallel over-application: %s", f.Title)
	}
	if f.Fingerprint == "" || res.ProbeCount < raceBurstSize {
		t.Fatalf("fingerprint/probe count wrong: fp=%q probes=%d", f.Fingerprint, res.ProbeCount)
	}
	if !strings.Contains(string(f.ReproBody), "gqls-probe-") {
		t.Fatalf("expected a bogus probe identifier in the request: %s", f.ReproBody)
	}
	if got := rs.mutations.Load(); got != raceBurstSize {
		t.Fatalf("expected %d parallel mutations, got %d", raceBurstSize, got)
	}
}

func TestRace_FirmWhenNoEffectField(t *testing.T) {
	rs := &raceServer{scalarReturn: true} // non-atomic, bare Boolean return
	srv := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer srv.Close()

	res, err := (&raceCheck{}).Run(t.Context(), raceContext(srv.URL, bizFlowScalarSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (pass: %q)", len(res.Findings), res.PassReason)
	}
	if res.Findings[0].Confidence != "firm" {
		t.Fatalf("expected firm confidence (no readable effect field), got %q", res.Findings[0].Confidence)
	}
}

func TestRace_AtomicGuard(t *testing.T) {
	rs := &raceServer{atomicGuard: true}
	srv := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer srv.Close()

	res, err := (&raceCheck{}).Run(t.Context(), raceContext(srv.URL, bizFlowSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings against an atomic guard, got %d", len(res.Findings))
	}
	if res.PassReason == "" {
		t.Fatal("expected a PassReason explaining the clean result")
	}
	// The burst was still fired (all K requests sent), but only one won.
	if got := rs.mutations.Load(); got != raceBurstSize {
		t.Fatalf("expected %d parallel mutations, got %d", raceBurstSize, got)
	}
}

func TestRace_DisabledByDefault(t *testing.T) {
	rs := &raceServer{}
	srv := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer srv.Close()

	cc := raceContext(srv.URL, bizFlowSchema())
	cc.AllowMutations = false // the default

	res, err := (&raceCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason, got %+v", res)
	}
	if rs.hits.Load() != 0 {
		t.Fatalf("disabled check must send zero requests; got %d", rs.hits.Load())
	}
}

func TestRace_NoCandidate(t *testing.T) {
	rs := &raceServer{}
	srv := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer srv.Close()

	// mutAuthzSchema exposes updateUserName — not a limited-quantity flow.
	res, err := (&raceCheck{}).Run(t.Context(), raceContext(srv.URL, mutAuthzSchema()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.PassReason == "" {
		t.Fatalf("expected clean pass with reason, got findings=%d pass=%q", len(res.Findings), res.PassReason)
	}
	if rs.mutations.Load() != 0 {
		t.Fatalf("no candidate should mean zero mutations; got %d", rs.mutations.Load())
	}
}

func TestRace_NoSchemaSkipped(t *testing.T) {
	cc := &CheckContext{Target: "http://example.com/graphql", AllowMutations: true}
	res, err := (&raceCheck{}).Run(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.SkipReason == "" {
		t.Fatalf("expected Skipped with reason when schema is nil, got %+v", res)
	}
}
