package dnstap

import (
	"fmt"
	"sort"
	"strings"
)

// PrometheusExporter exports metrics in Prometheus format.
type PrometheusExporter struct {
	aggregator *MetricsAggregator
}

// NewPrometheusExporter creates a new Prometheus exporter.
func NewPrometheusExporter(aggregator *MetricsAggregator) *PrometheusExporter {
	return &PrometheusExporter{
		aggregator: aggregator,
	}
}

// Export returns metrics in Prometheus text format.
func (e *PrometheusExporter) Export() string {
	snapshot := e.aggregator.GetSnapshot()
	var sb strings.Builder

	// Header
	sb.WriteString("# HELP dns_queries_total Total number of DNS queries by type and response code\n")
	sb.WriteString("# TYPE dns_queries_total counter\n")

	// Sort query types for deterministic output
	qtypes := make([]string, 0, len(snapshot.QueriesTotal))
	for qtype := range snapshot.QueriesTotal {
		qtypes = append(qtypes, qtype)
	}
	sort.Strings(qtypes)

	for _, qtype := range qtypes {
		rcodes := snapshot.QueriesTotal[qtype]

		// Sort rcodes
		rcodeKeys := make([]string, 0, len(rcodes))
		for rcode := range rcodes {
			rcodeKeys = append(rcodeKeys, rcode)
		}
		sort.Strings(rcodeKeys)

		for _, rcode := range rcodeKeys {
			count := rcodes[rcode]
			sb.WriteString(fmt.Sprintf(`dns_queries_total{type="%s",rcode="%s"} %d`+"\n",
				qtype, rcode, count))
		}
	}

	// TCP/UDP queries
	sb.WriteString("\n# HELP dns_tcp_queries_total Total number of TCP DNS queries\n")
	sb.WriteString("# TYPE dns_tcp_queries_total counter\n")
	sb.WriteString(fmt.Sprintf("dns_tcp_queries_total %d\n", snapshot.TCPQueriesTotal))

	sb.WriteString("\n# HELP dns_udp_queries_total Total number of UDP DNS queries\n")
	sb.WriteString("# TYPE dns_udp_queries_total counter\n")
	sb.WriteString(fmt.Sprintf("dns_udp_queries_total %d\n", snapshot.UDPQueriesTotal))

	// Latency histogram
	sb.WriteString("\n# HELP dns_query_duration_seconds DNS query duration in seconds\n")
	sb.WriteString("# TYPE dns_query_duration_seconds histogram\n")

	// Sort buckets
	buckets := make([]float64, 0, len(snapshot.LatencyCounts))
	for bucket := range snapshot.LatencyCounts {
		buckets = append(buckets, bucket)
	}
	sort.Float64s(buckets)

	cumulativeCount := int64(0)
	for _, bucket := range buckets {
		count := snapshot.LatencyCounts[bucket]
		cumulativeCount += count
		sb.WriteString(fmt.Sprintf(`dns_query_duration_seconds_bucket{le="%g"} %d`+"\n",
			bucket, cumulativeCount))
	}
	sb.WriteString(fmt.Sprintf(`dns_query_duration_seconds_bucket{le="+Inf"} %d`+"\n", cumulativeCount))
	sb.WriteString(fmt.Sprintf("dns_query_duration_seconds_sum %.6f\n", snapshot.LatencySumSec))
	sb.WriteString(fmt.Sprintf("dns_query_duration_seconds_count %d\n", cumulativeCount))

	// DNSSEC stats
	sb.WriteString("\n# HELP dns_dnssec_valid_total Total number of DNSSEC valid responses\n")
	sb.WriteString("# TYPE dns_dnssec_valid_total counter\n")
	sb.WriteString(fmt.Sprintf("dns_dnssec_valid_total %d\n", snapshot.DNSSECValid))

	sb.WriteString("\n# HELP dns_dnssec_invalid_total Total number of DNSSEC invalid responses\n")
	sb.WriteString("# TYPE dns_dnssec_invalid_total counter\n")
	sb.WriteString(fmt.Sprintf("dns_dnssec_invalid_total %d\n", snapshot.DNSSECInvalid))

	// QPS (gauge)
	qps := e.aggregator.GetQPS()
	sb.WriteString("\n# HELP dns_queries_per_second Current queries per second\n")
	sb.WriteString("# TYPE dns_queries_per_second gauge\n")
	sb.WriteString(fmt.Sprintf("dns_queries_per_second %.2f\n", qps))

	return sb.String()
}
