package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/metrics/promtext"
	"github.com/akam1o/arca-dns/pkg/model"
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

type backendErrorKey struct {
	Operation  string
	ErrorClass string
}

type backendDurKey struct {
	Operation  string
	Status     string
	ErrorClass string
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

	backendOps     map[backendKey]uint64
	backendErrors  map[backendErrorKey]uint64
	backendLatency map[backendDurKey]*Histogram
	signingDur     map[signKey]*Histogram

	// DNSSEC scheduler metrics
	schedulerLastRun          time.Time
	schedulerEarliestExpire   time.Time
	schedulerSecondsRemaining float64
	schedulerResign           map[string]uint64

	requestLatencyBuckets []float64
	backendLatencyBuckets []float64
	signingLatencyBuckets []float64
}

func NewControllerMetrics() *ControllerMetrics {
	return &ControllerMetrics{
		apiRequests:     make(map[apiKey]uint64),
		apiLatency:      make(map[apiDurKey]*Histogram),
		backendOps:      make(map[backendKey]uint64),
		backendErrors:   make(map[backendErrorKey]uint64),
		backendLatency:  make(map[backendDurKey]*Histogram),
		signingDur:      make(map[signKey]*Histogram),
		schedulerResign: make(map[string]uint64),
		requestLatencyBuckets: []float64{
			0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
		},
		backendLatencyBuckets: []float64{
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

func (m *ControllerMetrics) ObserveBackendOperation(operation string, err error, seconds float64) {
	status := statusLabel(err)
	errorClass := errorClassLabel(err)

	m.mu.Lock()
	m.backendOps[backendKey{Operation: operation, Status: status}]++
	if err != nil {
		m.backendErrors[backendErrorKey{Operation: operation, ErrorClass: errorClass}]++
	}

	dk := backendDurKey{Operation: operation, Status: status, ErrorClass: errorClass}
	h, ok := m.backendLatency[dk]
	if !ok {
		h = NewHistogram(m.backendLatencyBuckets)
		m.backendLatency[dk] = h
	}
	h.Observe(seconds)
	m.mu.Unlock()
}

func statusLabel(err error) string {
	if err == nil {
		return "success"
	}
	return "error"
}

func errorClassLabel(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, model.ErrZoneNotFound):
		return "not_found"
	case errors.Is(err, model.ErrVersionNotFound):
		return "version_not_found"
	case errors.Is(err, model.ErrZoneAlreadyExists):
		return "already_exists"
	case errors.Is(err, model.ErrConflict):
		return "conflict"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "backend_error"
	}
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

// CountZones counts all zones using lightweight summaries when the backend
// supports them, avoiding full record loads during metrics scrapes.
func CountZones(ctx context.Context, store backend.ZoneStore) (int, error) {
	const pageSize = 1000
	offset := 0
	total := 0
	for {
		zones, err := backend.ListZoneSummaries(ctx, store, backend.ListOptions{Limit: pageSize, Offset: offset})
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
		apiLatency[k] = v.Clone()
	}
	backendOps := make(map[backendKey]uint64, len(m.backendOps))
	for k, v := range m.backendOps {
		backendOps[k] = v
	}
	backendErrors := make(map[backendErrorKey]uint64, len(m.backendErrors))
	for k, v := range m.backendErrors {
		backendErrors[k] = v
	}
	backendLatency := make(map[backendDurKey]*Histogram, len(m.backendLatency))
	for k, v := range m.backendLatency {
		backendLatency[k] = v.Clone()
	}
	signingDur := make(map[signKey]*Histogram, len(m.signingDur))
	for k, v := range m.signingDur {
		signingDur[k] = v.Clone()
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
		labelSet := promtext.FormatLabels(
			promtext.Label{Name: "method", Value: k.Method},
			promtext.Label{Name: "path", Value: k.Path},
			promtext.Label{Name: "status", Value: fmt.Sprintf("%d", k.Status)},
		)
		b.WriteString(fmt.Sprintf("api_requests_total{%s} %d\n", labelSet, v))
	}

	b.WriteString("# HELP api_request_duration_seconds API request latency histogram.\n")
	b.WriteString("# TYPE api_request_duration_seconds histogram\n")
	for k, h := range apiLatency {
		labelSet := promtext.FormatLabels(
			promtext.Label{Name: "method", Value: k.Method},
			promtext.Label{Name: "path", Value: k.Path},
		)
		b.WriteString(h.RenderPrometheus("api_request_duration_seconds", labelSet))
	}

	b.WriteString("# HELP zones_total Current number of zones.\n")
	b.WriteString("# TYPE zones_total gauge\n")
	b.WriteString(fmt.Sprintf("zones_total %d\n", zonesTotal))

	b.WriteString("# HELP dnssec_signing_duration_seconds DNSSEC signing duration histogram.\n")
	b.WriteString("# TYPE dnssec_signing_duration_seconds histogram\n")
	for k, h := range signingDur {
		labelSet := promtext.FormatLabels(promtext.Label{Name: "status", Value: k.Status})
		b.WriteString(h.RenderPrometheus("dnssec_signing_duration_seconds", labelSet))
	}

	b.WriteString("# HELP backend_operations_total Backend operations by operation and status.\n")
	b.WriteString("# TYPE backend_operations_total counter\n")
	for k, v := range backendOps {
		labelSet := promtext.FormatLabels(
			promtext.Label{Name: "operation", Value: k.Operation},
			promtext.Label{Name: "status", Value: k.Status},
		)
		b.WriteString(fmt.Sprintf("backend_operations_total{%s} %d\n", labelSet, v))
	}

	b.WriteString("# HELP backend_operation_errors_total Backend operation errors by bounded error class.\n")
	b.WriteString("# TYPE backend_operation_errors_total counter\n")
	for k, v := range backendErrors {
		labelSet := promtext.FormatLabels(
			promtext.Label{Name: "operation", Value: k.Operation},
			promtext.Label{Name: "error_class", Value: k.ErrorClass},
		)
		b.WriteString(fmt.Sprintf("backend_operation_errors_total{%s} %d\n", labelSet, v))
	}

	b.WriteString("# HELP backend_operation_duration_seconds Backend operation latency histogram.\n")
	b.WriteString("# TYPE backend_operation_duration_seconds histogram\n")
	for k, h := range backendLatency {
		labelSet := promtext.FormatLabels(
			promtext.Label{Name: "operation", Value: k.Operation},
			promtext.Label{Name: "status", Value: k.Status},
			promtext.Label{Name: "error_class", Value: k.ErrorClass},
		)
		b.WriteString(h.RenderPrometheus("backend_operation_duration_seconds", labelSet))
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
		labelSet := promtext.FormatLabels(promtext.Label{Name: "result", Value: k})
		b.WriteString(fmt.Sprintf("dnssec_scheduler_resign_total{%s} %d\n", labelSet, v))
	}

	return b.String()
}
