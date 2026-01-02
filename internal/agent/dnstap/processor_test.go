package dnstap

import (
	"net"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"google.golang.org/protobuf/proto"
)

// TestProcessor_ProcessFrame tests frame processing through decoder and metrics.
func TestProcessor_ProcessFrame(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := ProcessorConfig{
		ReceiverConfig: ReceiverConfig{
			SocketPath: "/tmp/test-dnstap.sock",
			BufferSize: 10,
		},
		SamplerConfig: SamplerConfig{
			SampleRate: 1.0, // Sample all queries
		},
		PrometheusEnabled: true,
	}

	processor := NewProcessor(config, logger)

	// Create a test DNSTap message
	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion("example.com.", dns.TypeA)
	queryData, err := dnsQuery.Pack()
	require.NoError(t, err)

	dnsResponse := new(dns.Msg)
	dnsResponse.SetReply(dnsQuery)
	dnsResponse.Rcode = dns.RcodeSuccess
	responseData, err := dnsResponse.Pack()
	require.NoError(t, err)

	queryTimeSec := uint64(time.Now().Unix())
	queryTimeNsec := uint32(0)
	responseTimeSec := queryTimeSec
	responseTimeNsec := uint32(10000000) // 10ms later
	socketProto := dnstap.SocketProtocol_UDP
	msgType := dnstap.Message_CLIENT_RESPONSE
	dnstapType := dnstap.Dnstap_MESSAGE

	clientIP := net.ParseIP("192.0.2.100")

	dt := &dnstap.Dnstap{
		Type: &dnstapType,
		Message: &dnstap.Message{
			Type:             &msgType,
			SocketProtocol:   &socketProto,
			QueryAddress:     clientIP,
			QueryMessage:     queryData,
			ResponseMessage:  responseData,
			QueryTimeSec:     &queryTimeSec,
			QueryTimeNsec:    &queryTimeNsec,
			ResponseTimeSec:  &responseTimeSec,
			ResponseTimeNsec: &responseTimeNsec,
		},
	}

	frameData, err := proto.Marshal(dt)
	require.NoError(t, err)

	// Process frame
	frame := Frame{
		Data:      frameData,
		Timestamp: time.Now(),
	}

	processor.processFrame(frame)

	// Verify metrics were updated
	metrics := processor.GetMetrics()

	// Calculate total queries
	totalQueries := int64(0)
	for _, rcodes := range metrics.QueriesTotal {
		for _, count := range rcodes {
			totalQueries += count
		}
	}

	assert.Equal(t, int64(1), totalQueries)
	assert.Equal(t, int64(1), metrics.UDPQueriesTotal)
	assert.Contains(t, metrics.QueriesTotal, "A")
	assert.Contains(t, metrics.QueriesTotal["A"], "NOERROR")
}

// TestProcessor_GetPrometheusMetrics tests Prometheus metrics export.
func TestProcessor_GetPrometheusMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := ProcessorConfig{
		ReceiverConfig: ReceiverConfig{
			SocketPath: "/tmp/test-dnstap-prom.sock",
			BufferSize: 10,
		},
		SamplerConfig: SamplerConfig{
			SampleRate: 1.0,
		},
		PrometheusEnabled: true,
	}

	processor := NewProcessor(config, logger)

	// Record some test queries
	processor.metrics.RecordQuery("A", "NOERROR", false, 5*time.Millisecond)
	processor.metrics.RecordQuery("AAAA", "NOERROR", true, 10*time.Millisecond)

	// Get Prometheus metrics
	metricsText, err := processor.GetPrometheusMetrics()
	require.NoError(t, err)
	assert.Contains(t, metricsText, "dns_queries_total")
	assert.Contains(t, metricsText, "udp_queries_total")
	assert.Contains(t, metricsText, "tcp_queries_total")
	assert.Contains(t, metricsText, "dns_query_duration_seconds")
	assert.Contains(t, metricsText, "dns_query_duration_seconds_sum 0.015000")
}

// TestProcessor_InvalidFrame tests handling of invalid frames.
func TestProcessor_InvalidFrame(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := ProcessorConfig{
		ReceiverConfig: ReceiverConfig{
			SocketPath: "/tmp/test-dnstap-invalid.sock",
			BufferSize: 10,
		},
		SamplerConfig: SamplerConfig{
			SampleRate: 1.0,
		},
		PrometheusEnabled: false,
	}

	processor := NewProcessor(config, logger)

	// Process invalid frame
	frame := Frame{
		Data:      []byte("invalid protobuf data"),
		Timestamp: time.Now(),
	}

	// Should not panic
	processor.processFrame(frame)

	// Metrics should be empty
	metrics := processor.GetMetrics()
	totalQueries := int64(0)
	for _, rcodes := range metrics.QueriesTotal {
		for _, count := range rcodes {
			totalQueries += count
		}
	}
	assert.Equal(t, int64(0), totalQueries)
}

// TestProcessor_NonClientMessage tests skipping non-client messages.
func TestProcessor_NonClientMessage(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := ProcessorConfig{
		ReceiverConfig: ReceiverConfig{
			SocketPath: "/tmp/test-dnstap-nonclient.sock",
			BufferSize: 10,
		},
		SamplerConfig: SamplerConfig{
			SampleRate: 1.0,
		},
		PrometheusEnabled: false,
	}

	processor := NewProcessor(config, logger)

	// Create a RESOLVER_QUERY message (not CLIENT_*)
	msgType := dnstap.Message_RESOLVER_QUERY
	dnstapType := dnstap.Dnstap_MESSAGE

	dt := &dnstap.Dnstap{
		Type: &dnstapType,
		Message: &dnstap.Message{
			Type: &msgType,
		},
	}

	frameData, err := proto.Marshal(dt)
	require.NoError(t, err)

	frame := Frame{
		Data:      frameData,
		Timestamp: time.Now(),
	}

	// Process frame
	processor.processFrame(frame)

	// Metrics should be empty (message skipped)
	metrics := processor.GetMetrics()
	totalQueries := int64(0)
	for _, rcodes := range metrics.QueriesTotal {
		for _, count := range rcodes {
			totalQueries += count
		}
	}
	assert.Equal(t, int64(0), totalQueries)
}
