package metrics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/gin-gonic/gin"
)

type apiKey struct {
	Method string
	Path   string
	Status int
}

type apiDurKey struct {
	Method string
	Path   string
}

type backendKey struct {
	Operation string
	Status    string
}

type signKey struct {
	Status string
}

// ControllerMetrics collects controller metrics and renders Prometheus text format.
// This is intentionally dependency-free (no client_golang) to avoid adding modules.
type ControllerMetrics struct {
	mu sync.Mutex

	apiRequests map[apiKey]uint64
	apiLatency  map[apiDurKey]*Histogram

	backendOps map[backendKey]uint64
	signingDur map[signKey]*Histogram

	// DNSSEC scheduler metrics
	schedulerLastRun          time.Time
	schedulerEarliestExpire   time.Time
	schedulerSecondsRemaining float64
	schedulerResign           map[string]uint64

	requestLatencyBuckets []float64
	signingLatencyBuckets []float64
}

func NewControllerMetrics() *ControllerMetrics {
	return &ControllerMetrics{
		apiRequests:     make(map[apiKey]uint64),
		apiLatency:      make(map[apiDurKey]*Histogram),
		backendOps:      make(map[backendKey]uint64),
		signingDur:      make(map[signKey]*Histogram),
		schedulerResign: make(map[string]uint64),
		requestLatencyBuckets: []float64{
			0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
		},
		signingLatencyBuckets: []float64{
			0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
		},
	}
}

// Middleware records API request count and duration.
func (m *ControllerMetrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		path := c.FullPath()
		if path == "" {
			// Fallback for not-found routes.
			path = c.Request.URL.Path
		}

		method := c.Request.Method
		status := c.Writer.Status()
		seconds := time.Since(start).Seconds()

		m.mu.Lock()
		m.apiRequests[apiKey{Method: method, Path: path, Status: status}]++

		dk := apiDurKey{Method: method, Path: path}
		h, ok := m.apiLatency[dk]
		if !ok {
			h = NewHistogram(m.requestLatencyBuckets)
			m.apiLatency[dk] = h
		}
		h.Observe(seconds)
		m.mu.Unlock()
	}
}

func (m *ControllerMetrics) IncBackendOperation(operation string, status string) {
	if status == "" {
		status = "unknown"
	}
	m.mu.Lock()
	m.backendOps[backendKey{Operation: operation, Status: status}]++
	m.mu.Unlock()
}

func (m *ControllerMetrics) ObserveSigningDuration(status string, seconds float64) {
	if status == "" {
		status = "unknown"
	}
	m.mu.Lock()
	h, ok := m.signingDur[signKey{Status: status}]
	if !ok {
		h = NewHistogram(m.signingLatencyBuckets)
		m.signingDur[signKey{Status: status}] = h
	}
	h.Observe(seconds)
	m.mu.Unlock()
}

// SchedulerMetrics (implements pkg/dnssec.SchedulerMetrics)
func (m *ControllerMetrics) SetEarliestExpiration(t time.Time) {
	m.mu.Lock()
	m.schedulerEarliestExpire = t
	m.mu.Unlock()
}

func (m *ControllerMetrics) IncResign(result string) {
	if result == "" {
		result = "unknown"
	}
	m.mu.Lock()
	m.schedulerResign[result]++
	m.mu.Unlock()
}

func (m *ControllerMetrics) SetLastRun(t time.Time) {
	m.mu.Lock()
	m.schedulerLastRun = t
	m.mu.Unlock()
}

func (m *ControllerMetrics) SetSecondsRemaining(seconds float64) {
	m.mu.Lock()
	m.schedulerSecondsRemaining = seconds
	m.mu.Unlock()
}

// CountZones counts all zones using ListZones pagination.
func CountZones(ctx context.Context, store backend.ZoneStore) (int, error) {
	const pageSize = 1000
	offset := 0
	total := 0
	for {
		zones, err := store.ListZones(ctx, backend.ListOptions{Limit: pageSize, Offset: offset})
		if err != nil {
			return 0, err
		}
		total += len(zones)
		if len(zones) < pageSize {
			return total, nil
		}
		offset += pageSize
	}
}

func (m *ControllerMetrics) Render(zonesTotal int) string {
	// Snapshot under lock to keep exposition consistent.
	m.mu.Lock()
	apiRequests := make(map[apiKey]uint64, len(m.apiRequests))
	for k, v := range m.apiRequests {
		apiRequests[k] = v
	}
	apiLatency := make(map[apiDurKey]*Histogram, len(m.apiLatency))
	for k, v := range m.apiLatency {
		// Shallow copy is ok; Histogram is mutated only under lock.
		apiLatency[k] = v
	}
	backendOps := make(map[backendKey]uint64, len(m.backendOps))
	for k, v := range m.backendOps {
		backendOps[k] = v
	}
	signingDur := make(map[signKey]*Histogram, len(m.signingDur))
	for k, v := range m.signingDur {
		signingDur[k] = v
	}

	schedulerLastRun := m.schedulerLastRun
	schedulerEarliestExpire := m.schedulerEarliestExpire
	schedulerSecondsRemaining := m.schedulerSecondsRemaining
	schedulerResign := make(map[string]uint64, len(m.schedulerResign))
	for k, v := range m.schedulerResign {
		schedulerResign[k] = v
	}
	m.mu.Unlock()

	var b strings.Builder

	b.WriteString("# HELP api_requests_total Total number of API requests.\n")
	b.WriteString("# TYPE api_requests_total counter\n")
	for k, v := range apiRequests {
		b.WriteString(fmt.Sprintf("api_requests_total{method=%q,path=%q,status=%q} %d\n",
			k.Method, k.Path, fmt.Sprintf("%d", k.Status), v))
	}

	b.WriteString("# HELP api_request_duration_seconds API request latency histogram.\n")
	b.WriteString("# TYPE api_request_duration_seconds histogram\n")
	for k, h := range apiLatency {
		labelSet := fmt.Sprintf("method=%q,path=%q", k.Method, k.Path)
		b.WriteString(h.RenderPrometheus("api_request_duration_seconds", labelSet))
	}

	b.WriteString("# HELP zones_total Current number of zones.\n")
	b.WriteString("# TYPE zones_total gauge\n")
	b.WriteString(fmt.Sprintf("zones_total %d\n", zonesTotal))

	b.WriteString("# HELP dnssec_signing_duration_seconds DNSSEC signing duration histogram.\n")
	b.WriteString("# TYPE dnssec_signing_duration_seconds histogram\n")
	for k, h := range signingDur {
		labelSet := fmt.Sprintf("status=%q", k.Status)
		b.WriteString(h.RenderPrometheus("dnssec_signing_duration_seconds", labelSet))
	}

	b.WriteString("# HELP backend_operations_total Backend operations by operation and status.\n")
	b.WriteString("# TYPE backend_operations_total counter\n")
	for k, v := range backendOps {
		b.WriteString(fmt.Sprintf("backend_operations_total{operation=%q,status=%q} %d\n", k.Operation, k.Status, v))
	}

	b.WriteString("# HELP dnssec_scheduler_last_run_timestamp_seconds Last DNSSEC scheduler run time.\n")
	b.WriteString("# TYPE dnssec_scheduler_last_run_timestamp_seconds gauge\n")
	if !schedulerLastRun.IsZero() {
		b.WriteString(fmt.Sprintf("dnssec_scheduler_last_run_timestamp_seconds %d\n", schedulerLastRun.Unix()))
	} else {
		b.WriteString("dnssec_scheduler_last_run_timestamp_seconds 0\n")
	}

	b.WriteString("# HELP dnssec_scheduler_earliest_expiration_timestamp_seconds Earliest DNSSEC signature expiration across all zones.\n")
	b.WriteString("# TYPE dnssec_scheduler_earliest_expiration_timestamp_seconds gauge\n")
	if !schedulerEarliestExpire.IsZero() {
		b.WriteString(fmt.Sprintf("dnssec_scheduler_earliest_expiration_timestamp_seconds %d\n", schedulerEarliestExpire.Unix()))
	} else {
		b.WriteString("dnssec_scheduler_earliest_expiration_timestamp_seconds 0\n")
	}

	b.WriteString("# HELP dnssec_scheduler_seconds_remaining Seconds remaining until earliest expiration.\n")
	b.WriteString("# TYPE dnssec_scheduler_seconds_remaining gauge\n")
	b.WriteString(fmt.Sprintf("dnssec_scheduler_seconds_remaining %g\n", schedulerSecondsRemaining))

	b.WriteString("# HELP dnssec_scheduler_resign_total DNSSEC resign attempts.\n")
	b.WriteString("# TYPE dnssec_scheduler_resign_total counter\n")
	for k, v := range schedulerResign {
		b.WriteString(fmt.Sprintf("dnssec_scheduler_resign_total{result=%q} %d\n", k, v))
	}

	return b.String()
}
