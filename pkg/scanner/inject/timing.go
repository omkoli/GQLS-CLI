package inject

import (
	"context"
	"sort"
	"time"
)

// Sampler measures the latency of a single request. It returns the elapsed time
// and any error; erroring samples are discarded.
type Sampler func(ctx context.Context) (time.Duration, error)

// TimingResult reports the outcome of a statistical timing comparison.
type TimingResult struct {
	// Effect is true only when the payload is robustly slower than control.
	Effect bool
	// ControlMedian / PayloadMedian are the median latencies of each branch.
	ControlMedian time.Duration
	PayloadMedian time.Duration
	// MAD is the median absolute deviation of the control samples (the jitter
	// scale used as the robustness threshold).
	MAD time.Duration
	// Samples is the number of successful (control, payload) sample pairs.
	Samples int
}

// timingK is the robustness multiplier: the payload median must exceed the
// control median by more than k control-MADs.
const timingK = 3.0

// DefaultTimingFloor is the absolute minimum delta required, independent of
// jitter, so a tiny-but-consistent difference never reports an effect. It is
// tuned for the multi-second sleeps used by time-based injection payloads (≥2.5s
// for a 5s SLEEP). Callers pass their own floor matched to their injected delay
// (e.g. half the sleep duration); a non-positive floor selects this default.
const DefaultTimingFloor = 2500 * time.Millisecond

// TimingOracle interleaves up to `samples` control and payload measurements
// (default 7) and reports an effect only when the payload branch is robustly
// slower: payloadMedian > controlMedian + k·controlMAD AND the absolute delta
// exceeds floor (DefaultTimingFloor when floor <= 0). Interleaving cancels slow
// drift; the median+MAD test rejects jitter. It aborts early on ctx cancellation.
func TimingOracle(ctx context.Context, control, payload Sampler, samples int, floor time.Duration) TimingResult {
	if samples <= 0 {
		samples = 7
	}
	if floor <= 0 {
		floor = DefaultTimingFloor
	}
	var controls, payloads []time.Duration
	for i := 0; i < samples; i++ {
		if ctx.Err() != nil {
			break
		}
		if d, err := control(ctx); err == nil {
			controls = append(controls, d)
		}
		if ctx.Err() != nil {
			break
		}
		if d, err := payload(ctx); err == nil {
			payloads = append(payloads, d)
		}
	}

	cm := median(controls)
	pm := median(payloads)
	mad := medianAbsoluteDeviation(controls, cm)

	res := TimingResult{
		ControlMedian: cm,
		PayloadMedian: pm,
		MAD:           mad,
		Samples:       min(len(controls), len(payloads)),
	}
	if len(controls) == 0 || len(payloads) == 0 {
		return res
	}
	threshold := cm + time.Duration(timingK*float64(mad))
	res.Effect = pm > threshold && (pm-cm) >= floor
	return res
}

// median returns the median of ds (0 for an empty slice).
func median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), ds...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

// medianAbsoluteDeviation returns median(|d - center|) over ds.
func medianAbsoluteDeviation(ds []time.Duration, center time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	devs := make([]time.Duration, len(ds))
	for i, d := range ds {
		if d >= center {
			devs[i] = d - center
		} else {
			devs[i] = center - d
		}
	}
	return median(devs)
}
