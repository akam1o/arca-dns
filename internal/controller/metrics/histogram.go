package metrics

import (
	"fmt"
	"sort"
)

// Histogram is a minimal Prometheus-compatible histogram implementation.
// It is intentionally dependency-free (no client_golang).
type Histogram struct {
	buckets []float64
	counts  []uint64
	count   uint64
	sum     float64
}

func NewHistogram(buckets []float64) *Histogram {
	b := append([]float64(nil), buckets...)
	sort.Float64s(b)
	return &Histogram{
		buckets: b,
		counts:  make([]uint64, len(b)),
	}
}

func (h *Histogram) Clone() *Histogram {
	if h == nil {
		return nil
	}

	return &Histogram{
		buckets: append([]float64(nil), h.buckets...),
		counts:  append([]uint64(nil), h.counts...),
		count:   h.count,
		sum:     h.sum,
	}
}

func (h *Histogram) Observe(v float64) {
	h.count++
	h.sum += v
	for i, upper := range h.buckets {
		if v <= upper {
			h.counts[i]++
			return
		}
	}
}

func (h *Histogram) RenderPrometheus(name string, labelSet string) string {
	// Prometheus exposition format for histograms:
	// <name>_bucket{le="...",...} <count>
	// <name>_bucket{le="+Inf",...} <count>
	// <name>_sum{...} <sum>
	// <name>_count{...} <count>
	var out string
	var cumulative uint64
	prefix := ""
	if labelSet != "" {
		prefix = labelSet + ","
	}
	for i, upper := range h.buckets {
		cumulative += h.counts[i]
		out += fmt.Sprintf("%s_bucket{%sle=%q} %d\n", name, prefix, fmt.Sprintf("%g", upper), cumulative)
	}
	out += fmt.Sprintf("%s_bucket{%sle=%q} %d\n", name, prefix, "+Inf", h.count)
	out += fmt.Sprintf("%s_sum{%s} %g\n", name, labelSet, h.sum)
	out += fmt.Sprintf("%s_count{%s} %d\n", name, labelSet, h.count)
	return out
}
