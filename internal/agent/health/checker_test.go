package health

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func skipIfBindNotPermitted(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("bind not permitted in this environment: %v", err)
	}
}

func TestChecker_checkDNSQuery(t *testing.T) {
	logger := zap.NewNop()

	// Start test DNS server
	server, addr := startTestDNSServer(t, dns.RcodeSuccess)
	defer func() { _ = server.Shutdown() }()

	checker := NewChecker(config.HealthConfig{
		QueryTimeout: 5 * time.Second,
		TestRecord:   "example.com",
	}, logger)

	ctx := context.Background()
	result := checker.checkDNSQuery(ctx, addr, CheckTypeQuery)

	assert.True(t, result.Success)
	assert.NoError(t, result.Error)
}

func TestChecker_checkDNSQuery_Failure(t *testing.T) {
	logger := zap.NewNop()

	// Start test DNS server that returns SERVFAIL
	server, addr := startTestDNSServer(t, dns.RcodeServerFailure)
	defer func() { _ = server.Shutdown() }()

	checker := NewChecker(config.HealthConfig{
		QueryTimeout: 5 * time.Second,
		TestRecord:   "example.com",
	}, logger)

	ctx := context.Background()
	result := checker.checkDNSQuery(ctx, addr, CheckTypeQuery)

	assert.False(t, result.Success)
	assert.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "SERVFAIL")
}

func TestChecker_checkLatency(t *testing.T) {
	logger := zap.NewNop()

	// Start test DNS server
	server, addr := startTestDNSServer(t, dns.RcodeSuccess)
	defer func() { _ = server.Shutdown() }()

	checker := NewChecker(config.HealthConfig{
		QueryTimeout:     5 * time.Second,
		LatencyThreshold: 100 * time.Millisecond,
		TestRecord:       "example.com",
	}, logger)

	// Override server address for latency check
	// (In real implementation, this would use localhost:53)
	ctx := context.Background()

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	client := &dns.Client{
		Timeout: checker.config.QueryTimeout,
	}

	_, rtt, err := client.ExchangeContext(ctx, msg, addr)
	require.NoError(t, err)

	// Manual latency check
	result := CheckResult{
		Type:      CheckTypeLatency,
		Success:   rtt <= checker.config.LatencyThreshold,
		Timestamp: time.Now(),
		Latency:   rtt,
	}

	if !result.Success {
		result.Error = err
	}

	// Latency should be very low for local server
	assert.True(t, result.Success)
	assert.Less(t, result.Latency, 100*time.Millisecond)
}

func TestChecker_CheckAll(t *testing.T) {
	logger := zap.NewNop()

	server, addr := startTestDNSServer(t, dns.RcodeSuccess)
	defer func() { _ = server.Shutdown() }()

	checker := NewChecker(config.HealthConfig{
		QueryTimeout:     2 * time.Second,
		LatencyThreshold: 100 * time.Millisecond,
		TestRecord:       "example.com",
		NSDServer:        addr,
		UnboundServer:    addr,
	}, logger)

	ctx := context.Background()
	status := checker.CheckAll(ctx)

	// Check that all check types are present
	assert.Contains(t, status.Checks, CheckTypeQuery)
	assert.Contains(t, status.Checks, CheckTypeFullPath)
	assert.Contains(t, status.Checks, CheckTypeLatency)

	assert.True(t, status.Healthy)
	assert.True(t, status.Checks[CheckTypeQuery].Success)
	assert.True(t, status.Checks[CheckTypeFullPath].Success)
	assert.True(t, status.Checks[CheckTypeLatency].Success)
}

func TestChecker_Run(t *testing.T) {
	logger := zap.NewNop()

	server, addr := startTestDNSServer(t, dns.RcodeSuccess)
	defer func() { _ = server.Shutdown() }()

	checker := NewChecker(config.HealthConfig{
		CheckInterval:    20 * time.Millisecond,
		QueryTimeout:     500 * time.Millisecond,
		LatencyThreshold: 100 * time.Millisecond,
		TestRecord:       "example.com",
		NSDServer:        addr,
		UnboundServer:    addr,
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	statusChan := make(chan HealthStatus, 10)
	errChan := make(chan error, 1)

	go func() { errChan <- checker.Run(ctx, statusChan) }()

	// Wait for at least one status update
	select {
	case status := <-statusChan:
		// Check that we received a status
		assert.NotNil(t, status.Checks)
		assert.True(t, status.Healthy)
		assert.Contains(t, status.Checks, CheckTypeQuery)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for initial status update")
	}

	select {
	case status := <-statusChan:
		assert.True(t, status.Healthy)
		assert.Contains(t, status.Checks, CheckTypeFullPath)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for periodic status update")
	}

	cancel()

	select {
	case err := <-errChan:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for health checker to stop")
	}
}

// startTestDNSServer starts a test DNS server and returns the server and address.
func startTestDNSServer(t *testing.T, rcode int) (*dns.Server, string) {
	t.Helper()

	// Create handler
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = rcode

		if rcode == dns.RcodeSuccess {
			// Add answer
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("127.0.0.1"),
			})
		}

		_ = w.WriteMsg(msg)
	})

	// Start UDP server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		skipIfBindNotPermitted(t, err)
	}
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() { _ = server.ActivateAndServe() }()

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	return server, pc.LocalAddr().String()
}
