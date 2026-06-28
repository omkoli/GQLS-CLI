package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gqls-cli/gqls/pkg/schema"
)

// i04HostSchema returns a query with a shell-suggestive String arg ("host").
func i04HostSchema() *schema.Schema {
	strType := &schema.TypeRef{Kind: schema.KindScalar, Name: "String"}
	field := &schema.FieldDef{
		Name: "resolve",
		Type: &schema.TypeRef{Kind: schema.KindObject, Name: "Result"},
		Args: []*schema.ArgDef{{Name: "host", Type: strType}},
	}
	qt := &schema.TypeDef{Name: "Query", Kind: schema.KindObject, Fields: []*schema.FieldDef{field}}
	return &schema.Schema{QueryType: qt, Types: map[string]*schema.TypeDef{"Query": qt}}
}

func i04WantsSleep(r *http.Request) bool {
	body, _ := io.ReadAll(r.Body)
	low := strings.ToLower(string(body))
	return strings.Contains(low, "sleep") || strings.Contains(low, "ping -c")
}

// fakeOOBPoller is a stub for the I05-supplied OOB poller.
type fakeOOBPoller struct {
	n   int
	hit bool
}

func (f *fakeOOBPoller) NewToken() string                            { f.n++; return fmt.Sprintf("tok%d", f.n) }
func (f *fakeOOBPoller) Correlated(_ context.Context, _ string) bool { return f.hit }

// Time-based oracle confirms command injection → CRITICAL.
func TestI04_TimeBased_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i04WantsSleep(r) {
			time.Sleep(200 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"resolve":{"__typename":"Result"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i04HostSchema()

	chk := &osCommandInjectionCheck{floor: 80 * time.Millisecond, samples: 5}
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
	if f.Confidence != "confirmed" || f.CWE != "CWE-78" {
		t.Fatalf("classification = %q/%q, want confirmed/CWE-78", f.Confidence, f.CWE)
	}
	if res.ProbeCount != 2*5 {
		t.Fatalf("ProbeCount = %d, want %d (2·samples for the firing point)", res.ProbeCount, 2*5)
	}
	if !strings.Contains(f.Description, "time-based") || f.Fingerprint == "" {
		t.Fatalf("description/fingerprint not set: %q %q", f.Description, f.Fingerprint)
	}
}

// Constant latency, no OOB → no finding; PassReason notes OOB was skipped.
func TestI04_ConstantLatency_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"resolve":{"__typename":"Result"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i04HostSchema()

	chk := &osCommandInjectionCheck{floor: 80 * time.Millisecond, samples: 5}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("constant latency must not fire, got %+v", res.Findings)
	}
	if !strings.Contains(strings.ToLower(res.PassReason), "out-of-band probing was skipped") {
		t.Fatalf("PassReason should note OOB was skipped: %q", res.PassReason)
	}
}

// OOB callback correlation → confirmed finding.
func TestI04_OOB_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Constant latency, no shell error → only the OOB path can fire.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"resolve":{"__typename":"Result"}}}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i04HostSchema()
	cc.OOBDomain = "oob.example"
	cc.OOBPoller = &fakeOOBPoller{hit: true}

	chk := &osCommandInjectionCheck{floor: 80 * time.Millisecond, samples: 5}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 OOB finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Confidence != "confirmed" || f.Severity != CRITICAL {
		t.Fatalf("OOB finding should be confirmed/CRITICAL, got %q/%v", f.Confidence, f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Description), "out-of-band") || !strings.Contains(f.Description, "oob.example") {
		t.Fatalf("description should reference the OOB callback: %s", f.Description)
	}
}

// Verbose shell error, constant latency → firm error-based finding.
func TestI04_ErrorBased_Firm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":[{"message":"sh: 1: gqls: not found"}]}`)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i04HostSchema()

	chk := &osCommandInjectionCheck{floor: 80 * time.Millisecond, samples: 5}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Confidence != "firm" {
		t.Fatalf("error-only finding should be firm, got %q", f.Confidence)
	}
	if !strings.Contains(strings.ToLower(f.Description), "shell error") {
		t.Fatalf("description should mention the shell error signal: %s", f.Description)
	}
}

// Mutation-only points + AllowMutations=false → gated, no probes.
func TestI04_MutationOnly_Gated(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := newTestCheckContext(t, srv)
	cc.Schema = i01MutationOnlySchema()
	cc.AllowMutations = false

	chk := &osCommandInjectionCheck{floor: 80 * time.Millisecond, samples: 5}
	res, err := chk.Run(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.ProbeCount != 0 || probed {
		t.Fatalf("gated mutation points must not be probed: findings=%d probes=%d probed=%v", len(res.Findings), res.ProbeCount, probed)
	}
}

func TestI04_NoSchema_Skips(t *testing.T) {
	res, _ := (&osCommandInjectionCheck{}).Run(context.Background(), &CheckContext{Target: "http://t"})
	if !res.Skipped {
		t.Fatalf("nil schema should skip, got %+v", res)
	}
}

func TestI04_Metadata(t *testing.T) {
	c := &osCommandInjectionCheck{}
	if c.ID() != "GQL-I04" {
		t.Fatalf("ID = %q, want GQL-I04", c.ID())
	}
	if c.Severity() != CRITICAL || c.Category() != Injection || !c.RequiresSchema() {
		t.Fatalf("metadata mismatch: sev=%v cat=%v reqSchema=%v", c.Severity(), c.Category(), c.RequiresSchema())
	}
}
