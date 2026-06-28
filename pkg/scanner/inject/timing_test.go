package inject

import (
	"context"
	"testing"
	"time"
)

// seqSampler returns successive durations from ds, cycling if exhausted.
func seqSampler(ds ...time.Duration) Sampler {
	i := 0
	return func(ctx context.Context) (time.Duration, error) {
		d := ds[i%len(ds)]
		i++
		return d, nil
	}
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestTimingOracle_DetectsSleep(t *testing.T) {
	control := seqSampler(ms(100))
	payload := seqSampler(ms(100) + 5*time.Second) // ~5s injected sleep
	res := TimingOracle(context.Background(), control, payload, 7, 0)
	if !res.Effect {
		t.Fatalf("expected Effect=true for a 5s payload sleep: %+v", res)
	}
	if res.Samples != 7 {
		t.Fatalf("expected 7 sample pairs, got %d", res.Samples)
	}
}

func TestTimingOracle_NoEffectEqualLatency(t *testing.T) {
	res := TimingOracle(context.Background(), seqSampler(ms(120)), seqSampler(ms(120)), 7, 0)
	if res.Effect {
		t.Fatalf("equal latency must not report an effect: %+v", res)
	}
}

func TestTimingOracle_NoFalsePositiveOnJitter(t *testing.T) {
	// Both branches jitter around ~100ms; the small delta is well under the floor.
	control := seqSampler(ms(90), ms(110), ms(95), ms(105), ms(100), ms(108), ms(92))
	payload := seqSampler(ms(100), ms(112), ms(96), ms(107), ms(101), ms(109), ms(93))
	res := TimingOracle(context.Background(), control, payload, 7, 0)
	if res.Effect {
		t.Fatalf("jitter without a real delay must not report an effect: %+v", res)
	}
}

func TestTimingOracle_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := TimingOracle(ctx, seqSampler(ms(100)), seqSampler(ms(5000)), 7, 0)
	if res.Effect {
		t.Fatalf("cancelled context should not produce an effect: %+v", res)
	}
}

func TestMedianAndMAD(t *testing.T) {
	if got := median([]time.Duration{ms(10), ms(30), ms(20)}); got != ms(20) {
		t.Fatalf("median = %v, want 20ms", got)
	}
	if got := median([]time.Duration{ms(10), ms(20)}); got != ms(15) {
		t.Fatalf("even median = %v, want 15ms", got)
	}
	if got := medianAbsoluteDeviation([]time.Duration{ms(10), ms(20), ms(30)}, ms(20)); got != ms(10) {
		t.Fatalf("MAD = %v, want 10ms", got)
	}
}
