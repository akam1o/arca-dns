package metrics

import (
	"sync"
	"testing"
)

func TestHistogramCloneIndependence(t *testing.T) {
	h := NewHistogram([]float64{0.1, 1})
	h.Observe(0.05)

	clone := h.Clone()
	h.Observe(0.5)

	if clone.count != 1 {
		t.Fatalf("clone count changed after original observe: got %d, want 1", clone.count)
	}
	if clone.counts[0] != 1 || clone.counts[1] != 0 {
		t.Fatalf("clone bucket counts changed after original observe: got %v", clone.counts)
	}
}

func TestControllerMetricsRenderConcurrentSigningObserve(t *testing.T) {
	metrics := NewControllerMetrics()
	metrics.ObserveSigningDuration("success", 0.01)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				metrics.ObserveSigningDuration("success", 0.01)
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		_ = metrics.Render(0)
	}

	close(done)
	wg.Wait()
}
