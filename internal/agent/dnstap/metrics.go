package dnstap

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// MetricsAggregator aggregates DNS query metrics from DNSTap frames.
type MetricsAggregator struct {
	logger *zap.Logger

	// Metrics
	mu              sync.RWMutex
	queriesTotal    map[string]map[string]int64 // [qtype][rcode]count
	tcpQueriesTotal int64
	udpQueriesTotal int64
	latencyBuckets  []float64 // Histogram buckets
	latencyCounts   map[float64]int64

	// DNSSEC validation stats
	dnssecValid   int64
	dnssecInvalid int64

	// Last reset time
	lastReset time.Time
}

// MetricsSnapshot represents a point-in-time metrics snapshot.
type MetricsSnapshot struct {
	QueriesTotal    map[string]map[string]int64 // [qtype][rcode]count
	TCPQueriesTotal int64
	UDPQueriesTotal int64
	LatencyCounts   map[float64]int64
	DNSSECValid     int64
	DNSSECInvalid   int64
	Timestamp       time.Time
}

// NewMetricsAggregator creates a new metrics aggregator.
func NewMetricsAggregator(logger *zap.Logger) *MetricsAggregator {
	return &MetricsAggregator{
		logger:         logger,
		queriesTotal:   make(map[string]map[string]int64),
		latencyBuckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0}, // P50, P95, P99 buckets
		latencyCounts:  make(map[float64]int64),
		lastReset:      time.Now(),
	}
}

// RecordQuery records a DNS query.
func (m *MetricsAggregator) RecordQuery(qtype, rcode string, isTCP bool, latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record query by type and rcode
	if m.queriesTotal[qtype] == nil {
		m.queriesTotal[qtype] = make(map[string]int64)
	}
	m.queriesTotal[qtype][rcode]++

	// Record transport
	if isTCP {
		m.tcpQueriesTotal++
	} else {
		m.udpQueriesTotal++
	}

	// Record latency histogram (non-cumulative counts per bucket)
	latencySec := latency.Seconds()
	recorded := false
	for _, bucket := range m.latencyBuckets {
		if !recorded && latencySec <= bucket {
			m.latencyCounts[bucket]++
			recorded = true
			break
		}
	}
	// If latency exceeds all buckets, count in the last bucket
	if !recorded && len(m.latencyBuckets) > 0 {
		lastBucket := m.latencyBuckets[len(m.latencyBuckets)-1]
		m.latencyCounts[lastBucket]++
	}
}

// RecordDNSSEC records DNSSEC validation status.
func (m *MetricsAggregator) RecordDNSSEC(valid bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if valid {
		m.dnssecValid++
	} else {
		m.dnssecInvalid++
	}
}

// GetSnapshot returns a snapshot of current metrics.
func (m *MetricsAggregator) GetSnapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Deep copy queries
	queries := make(map[string]map[string]int64)
	for qtype, rcodes := range m.queriesTotal {
		queries[qtype] = make(map[string]int64)
		for rcode, count := range rcodes {
			queries[qtype][rcode] = count
		}
	}

	// Deep copy latency counts
	latency := make(map[float64]int64)
	for bucket, count := range m.latencyCounts {
		latency[bucket] = count
	}

	return MetricsSnapshot{
		QueriesTotal:    queries,
		TCPQueriesTotal: m.tcpQueriesTotal,
		UDPQueriesTotal: m.udpQueriesTotal,
		LatencyCounts:   latency,
		DNSSECValid:     m.dnssecValid,
		DNSSECInvalid:   m.dnssecInvalid,
		Timestamp:       time.Now(),
	}
}

// Reset resets all metrics.
func (m *MetricsAggregator) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.queriesTotal = make(map[string]map[string]int64)
	m.tcpQueriesTotal = 0
	m.udpQueriesTotal = 0
	m.latencyCounts = make(map[float64]int64)
	m.dnssecValid = 0
	m.dnssecInvalid = 0
	m.lastReset = time.Now()

	m.logger.Debug("Metrics reset")
}

// GetQPS calculates queries per second since last reset.
func (m *MetricsAggregator) GetQPS() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	elapsed := time.Since(m.lastReset).Seconds()
	if elapsed == 0 {
		return 0
	}

	total := int64(0)
	for _, rcodes := range m.queriesTotal {
		for _, count := range rcodes {
			total += count
		}
	}

	return float64(total) / elapsed
}
