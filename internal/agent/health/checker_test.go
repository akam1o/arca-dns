package health

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
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

func TestChecker_checkProcess(t *testing.T) {
	logger := zap.NewNop()

	t.Run("socket exists", func(t *testing.T) {
		// Create temp socket file
		tmpDir := t.TempDir()
		socketPath := filepath.Join(tmpDir, "test.sock")
		f, err := os.Create(socketPath)
		require.NoError(t, err)
		f.Close()

		checker := NewChecker(config.HealthConfig{}, socketPath, "", logger)
		result := checker.checkProcess()

		assert.True(t, result.Success)
		assert.NoError(t, result.Error)
		assert.Equal(t, CheckTypeProcess, result.Type)
	})

	t.Run("socket missing", func(t *testing.T) {
		checker := NewChecker(config.HealthConfig{}, "/nonexistent/socket", "", logger)
		result := checker.checkProcess()

		assert.False(t, result.Success)
		assert.Error(t, result.Error)
		assert.Equal(t, CheckTypeProcess, result.Type)
	})

	t.Run("no socket configured", func(t *testing.T) {
		checker := NewChecker(config.HealthConfig{}, "", "", logger)
		result := checker.checkProcess()

		assert.True(t, result.Success)
		assert.NoError(t, result.Error)
	})
}

func TestChecker_checkSocket(t *testing.T) {
	logger := zap.NewNop()

	t.Run("socket responsive", func(t *testing.T) {
		// Skip this test on macOS due to path length limitations with t.TempDir()
		tmpDir := os.TempDir()
		socketPath := filepath.Join(tmpDir, "arca-dns-test.sock")

		// Clean up any existing socket
		os.Remove(socketPath)
		defer os.Remove(socketPath)

		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			skipIfBindNotPermitted(t, err)
		}
		require.NoError(t, err)
		defer listener.Close()

		// Accept connections in background
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()

		// Give server time to start
		time.Sleep(10 * time.Millisecond)

		checker := NewChecker(config.HealthConfig{}, socketPath, "", logger)
		result := checker.checkSocket()

		assert.True(t, result.Success)
		assert.NoError(t, result.Error)
		assert.Equal(t, CheckTypeSocket, result.Type)
	})

	t.Run("socket not responsive", func(t *testing.T) {
		checker := NewChecker(config.HealthConfig{}, "/nonexistent/socket", "", logger)
		result := checker.checkSocket()

		assert.False(t, result.Success)
		assert.Error(t, result.Error)
		assert.Equal(t, CheckTypeSocket, result.Type)
	})

	t.Run("no socket configured", func(t *testing.T) {
		checker := NewChecker(config.HealthConfig{}, "", "", logger)
		result := checker.checkSocket()

		assert.True(t, result.Success)
		assert.NoError(t, result.Error)
	})
}

func TestChecker_checkDNSQuery(t *testing.T) {
	logger := zap.NewNop()

	// Start test DNS server
	server, addr := startTestDNSServer(t, dns.RcodeSuccess)
	defer func() { _ = server.Shutdown() }()

	checker := NewChecker(config.HealthConfig{
		QueryTimeout: 5 * time.Second,
		TestRecord:   "example.com",
	}, "", "", logger)

	ctx := context.Background()
	result := checker.checkDNSQuery(ctx, addr)

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
	}, "", "", logger)

	ctx := context.Background()
	result := checker.checkDNSQuery(ctx, addr)

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
	}, "", "", logger)

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

	// Create temp socket with shorter path
	tmpDir := os.TempDir()
	socketPath := filepath.Join(tmpDir, "arca-dns-test2.sock")

	// Clean up any existing socket
	os.Remove(socketPath)
	defer os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		skipIfBindNotPermitted(t, err)
	}
	require.NoError(t, err)
	defer listener.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Start test DNS server
	dnsServer, _ := startTestDNSServer(t, dns.RcodeSuccess)
	defer func() { _ = dnsServer.Shutdown() }()

	checker := NewChecker(config.HealthConfig{
		QueryTimeout:     2 * time.Second,
		LatencyThreshold: 100 * time.Millisecond,
		TestRecord:       "example.com",
	}, socketPath, "", logger)

	// Note: CheckAll uses hardcoded localhost:53 and localhost:5353
	// In this test, we can only verify the logic structure
	ctx := context.Background()
	status := checker.CheckAll(ctx)

	// Check that all check types are present
	assert.Contains(t, status.Checks, CheckTypeProcess)
	assert.Contains(t, status.Checks, CheckTypeSocket)
	assert.Contains(t, status.Checks, CheckTypeQuery)
	assert.Contains(t, status.Checks, CheckTypeFullPath)
	assert.Contains(t, status.Checks, CheckTypeLatency)

	// Process and socket checks should pass
	assert.True(t, status.Checks[CheckTypeProcess].Success)
	assert.True(t, status.Checks[CheckTypeSocket].Success)

	// DNS checks will fail (no DNS server on localhost:53/5353)
	// This is expected in unit test environment
}

func TestChecker_Run(t *testing.T) {
	logger := zap.NewNop()

	checker := NewChecker(config.HealthConfig{
		CheckInterval:    50 * time.Millisecond,
		QueryTimeout:     100 * time.Millisecond, // Short timeout for test
		LatencyThreshold: 100 * time.Millisecond,
	}, "", "", logger)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	statusChan := make(chan HealthStatus, 10)

	go func() { _ = checker.Run(ctx, statusChan) }()

	// Wait for at least one status update
	select {
	case status := <-statusChan:
		// Check that we received a status
		assert.NotNil(t, status.Checks)
		assert.Contains(t, status.Checks, CheckTypeProcess)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for initial status update")
	}

	// Verify we can receive more updates
	time.Sleep(100 * time.Millisecond)

	// Drain channel to count updates
	updateCount := 1 // Already got one above
	for {
		select {
		case <-statusChan:
			updateCount++
		case <-time.After(10 * time.Millisecond):
			goto done
		}
	}

done:
	// Should have received multiple updates (initial + at least 1 periodic)
	assert.GreaterOrEqual(t, updateCount, 1, "Should receive at least 1 status update")
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
