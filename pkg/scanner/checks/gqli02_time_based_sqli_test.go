package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func i02BodyContainsSleep(r *http.Request) bool {
	body, _ := io.ReadAll(r.Body)
	low := strings.ToLower(string(body))
	return strings.Contains(low, "sleep(") || strings.Contains(low, "pg_sleep(") || strings.Contains(low, "waitfor delay")
}

// A backend that sleeps when a sleep token is present → CRITICAL finding.
func TestI02_TimeBased_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i02BodyContainsSleep(r) {
			time.Sleep(200 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"user":{"__typename":"User"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	chk := &timeBasedSQLiCheck{floor: 80 * time.Millisecond, samples: 5}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != CRITICAL || f.Category != Injection {
		t.Fatalf("severity/category = %v/%v, want CRITICAL/Injection", f.Severity, f.Category)
	}
	if f.Confidence != "confirmed" || f.CWE != "CWE-89" {
		t.Fatalf("classification = %q/%q, want confirmed/CWE-89", f.Confidence, f.CWE)
	}
	// MySQL family is tried first → fires first → exactly 2·samples probes.
	if res.ProbeCount != 2*5 {
		t.Fatalf("ProbeCount = %d, want %d (2·samples for the firing point)", res.ProbeCount, 2*5)
	}
	if !strings.Contains(f.Description, "median") {
		t.Fatalf("description should report medians: %s", f.Description)
	}
	if !strings.Contains(f.Title, "user") || f.Fingerprint == "" {
		t.Fatalf("title/fingerprint not set: %q %q", f.Title, f.Fingerprint)
	}
}

// Constant-latency backend → no finding (Effect=false).
func TestI02_ConstantLatency_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"user":{"__typename":"User"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	chk := &timeBasedSQLiCheck{floor: 80 * time.Millisecond, samples: 5}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("constant latency must not fire, got %+v", res.Findings)
	}
	if res.PassReason == "" || len(res.PassProbes) == 0 {
		t.Fatalf("expected PassReason and recorded median PassProbes, got reason=%q probes=%d", res.PassReason, len(res.PassProbes))
	}
}

// Jittery backend (small payload-independent delays) → no finding (no FP).
func TestI02_Jitter_NoFinding(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Deterministic small jitter, uncorrelated with the payload: 0,5,10,15,20ms.
		d := time.Duration(atomic.AddInt64(&n, 1)%5) * 5 * time.Millisecond
		time.Sleep(d)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"user":{"__typename":"User"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = sqliStringArgSchema()

	chk := &timeBasedSQLiCheck{floor: 80 * time.Millisecond, samples: 7}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("jitter without a real delay must not fire, got %+v", res.Findings)
	}
}

// Mutation-only points + AllowMutations=false → gated, no probes.
func TestI02_MutationOnly_Gated(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i01MutationOnlySchema()
	cc.AllowMutations = false

	chk := &timeBasedSQLiCheck{floor: 80 * time.Millisecond, samples: 5}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.ProbeCount != 0 || probed {
		t.Fatalf("gated mutation points must not be probed: findings=%d probes=%d probed=%v", len(res.Findings), res.ProbeCount, probed)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "mutation") {
		t.Fatalf("PassReason should mention mutation write-gating: %q", res.PassReason)
	}
}

func TestI02_NoSchema_Skips(t *testing.T) {
	res, _ := (&timeBasedSQLiCheck{}).Run(context.Background(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

func TestI02_Metadata(t *testing.T) {
	c := &timeBasedSQLiCheck{}
	if c.ID() != "GQL-I02" {
		t.Fatalf("ID = %q, want GQL-I02", c.ID())
	}
	if c.Severity() != CRITICAL || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
	// Defaults resolve sensibly on the zero-value instance.
	if c.sleepDur() != 5*time.Second || c.floorDur() != 2500*time.Millisecond || c.sampleCount() != 7 || c.pointCap() != 8 {
		t.Fatalf("defaults wrong: sleep=%v floor=%v samples=%d cap=%d", c.sleepDur(), c.floorDur(), c.sampleCount(), c.pointCap())
	}
}
