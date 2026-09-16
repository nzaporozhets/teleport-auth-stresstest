package ramp

import (
	"testing"
	"time"
)

func TestGeneratorHealth_Exceeds(t *testing.T) {
	h := GeneratorHealth{CPUPercent: 90, Goroutines: 50, OpenFDs: 10, EphemeralConns: 5}

	exceeded, reasons := h.Exceeds(GeneratorThresholds{MaxCPUPercent: 80})
	if !exceeded || len(reasons) != 1 {
		t.Errorf("Exceeds(MaxCPUPercent=80) = %v, %v; want exceeded with 1 reason", exceeded, reasons)
	}

	exceeded, reasons = h.Exceeds(GeneratorThresholds{MaxCPUPercent: 95, MaxGoroutines: 100})
	if exceeded || len(reasons) != 0 {
		t.Errorf("Exceeds within limits = %v, %v; want not exceeded", exceeded, reasons)
	}

	// A zero threshold means "don't check this metric" — must not
	// spuriously trigger just because the reading is also zero-ish or
	// the threshold is unset.
	exceeded, _ = GeneratorHealth{}.Exceeds(GeneratorThresholds{})
	if exceeded {
		t.Error("all-zero thresholds must never trigger")
	}
}

func TestWorst_TakesMaxPerField(t *testing.T) {
	a := GeneratorHealth{CPUPercent: 10, Goroutines: 100, OpenFDs: 5, EphemeralConns: 1}
	b := GeneratorHealth{CPUPercent: 50, Goroutines: 20, OpenFDs: 50, EphemeralConns: 2}

	got := WorstHealth(a, b)
	want := GeneratorHealth{CPUPercent: 50, Goroutines: 100, OpenFDs: 50, EphemeralConns: 2}
	if got != want {
		t.Errorf("WorstHealth(a, b) = %+v, want %+v", got, want)
	}
}

// TestOSHealthSampler_DoesNotPanic exercises the real /proc-based
// sampler on this Linux sandbox. It can't assert exact values (host-
// dependent), but it proves the sampler works end-to-end here and
// degrades gracefully rather than erroring.
func TestOSHealthSampler_DoesNotPanic(t *testing.T) {
	s := NewOSHealthSampler()
	first := s.Sample()
	if first.Goroutines <= 0 {
		t.Errorf("Goroutines = %d, want > 0", first.Goroutines)
	}
	if first.OpenFDs <= 0 {
		t.Errorf("OpenFDs = %d, want > 0 on this Linux sandbox", first.OpenFDs)
	}

	time.Sleep(50 * time.Millisecond)
	second := s.Sample()
	if second.CPUPercent < 0 {
		t.Errorf("CPUPercent = %v, want >= 0", second.CPUPercent)
	}
}

func TestReadProcessCPUTime_Succeeds(t *testing.T) {
	d, err := readProcessCPUTime()
	if err != nil {
		t.Fatalf("readProcessCPUTime: %v", err)
	}
	if d < 0 {
		t.Errorf("cpu time = %v, want >= 0", d)
	}
}
