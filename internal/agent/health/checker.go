package health

import (
	"context"
	"fmt"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// CheckType represents the type of health check.
type CheckType string

const (
	CheckTypeQuery    CheckType = "query"
	CheckTypeFullPath CheckType = "full_path"
	CheckTypeLatency  CheckType = "latency"
)

// CheckResult contains the result of a health check.
type CheckResult struct {
	Type      CheckType
	Success   bool
	Latency   time.Duration
	Error     error
	Timestamp time.Time
}

// HealthStatus represents the overall health status.
type HealthStatus struct {
	Healthy      bool
	Checks       map[CheckType]CheckResult
	LastCheck    time.Time
	FailureCount int
}

// Checker performs health checks on DNS services.
type Checker struct {
	config config.HealthConfig
	logger *zap.Logger

	testZone      string
	testRecord    string
	nsdServer     string
	unboundServer string

	checkAuthoritative bool
	checkResolver      bool
}

// CheckerOptions controls which DNS paths are considered active for health.
type CheckerOptions struct {
	CheckAuthoritative bool
	CheckResolver      bool
}

// NewChecker creates a new health checker.
func NewChecker(cfg config.HealthConfig, logger *zap.Logger) *Checker {
	return NewCheckerWithOptions(cfg, CheckerOptions{
		CheckAuthoritative: true,
		CheckResolver:      true,
	}, logger)
}

// NewCheckerWithOptions creates a health checker for the enabled DNS components.
func NewCheckerWithOptions(cfg config.HealthConfig, opts CheckerOptions, logger *zap.Logger) *Checker {
	nsdServer := cfg.NSDServer
	if nsdServer == "" {
		nsdServer = "127.0.0.1:5353"
	}

	unboundServer := cfg.UnboundServer
	if unboundServer == "" {
		unboundServer = "127.0.0.1:53"
	}

	testZone := cfg.TestZone
	if testZone == "" {
		testZone = "localhost."
	}

	testRecord := cfg.TestRecord
	if testRecord == "" {
		testRecord = "localhost."
	}

	return &Checker{
		config:             cfg,
		logger:             logger,
		testZone:           testZone,
		testRecord:         testRecord,
		nsdServer:          nsdServer,
		unboundServer:      unboundServer,
		checkAuthoritative: opts.CheckAuthoritative,
		checkResolver:      opts.CheckResolver,
	}
}

// Run starts the health check loop.
func (c *Checker) Run(ctx context.Context, statusChan chan<- HealthStatus) error {
	c.logger.Info("Starting health check loop",
		zap.Duration("interval", c.config.CheckInterval))

	ticker := time.NewTicker(c.config.CheckInterval)
	defer ticker.Stop()

	// Run initial check immediately
	status := c.CheckAll(ctx)
	select {
	case statusChan <- status:
	case <-ctx.Done():
		return ctx.Err()
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Health check loop stopped")
			return ctx.Err()

		case <-ticker.C:
			status := c.CheckAll(ctx)
			select {
			case statusChan <- status:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// CheckAll performs all health checks.
// Checks (all must pass):
// 1. Direct authoritative DNS (NSD) responds
// 2. Full-path DNS through Unbound responds
// 3. Latency under threshold (<100ms)
func (c *Checker) CheckAll(ctx context.Context) HealthStatus {
	checks := make(map[CheckType]CheckResult)
	healthy := true
	checksRun := 0

	// Check 1: DNS query to NSD (direct)
	if c.checkAuthoritative {
		checks[CheckTypeQuery] = c.checkDNSQuery(ctx, c.nsdServer, CheckTypeQuery)
		healthy = healthy && checks[CheckTypeQuery].Success
		checksRun++
	}

	// Check 2: Full path query through Unbound
	if c.checkResolver {
		checks[CheckTypeFullPath] = c.checkDNSQuery(ctx, c.unboundServer, CheckTypeFullPath)
		healthy = healthy && checks[CheckTypeFullPath].Success
		checksRun++

		// Check 3: Latency check
		checks[CheckTypeLatency] = c.checkLatency(ctx)
		healthy = healthy && checks[CheckTypeLatency].Success
		checksRun++
	}

	// Determine overall health:
	// DNS checks are the source of truth for routing decisions.
	if checksRun == 0 {
		healthy = false
	}

	return HealthStatus{
		Healthy:   healthy,
		Checks:    checks,
		LastCheck: time.Now(),
	}
}

// checkDNSQuery performs a DNS query and verifies the response.
func (c *Checker) checkDNSQuery(ctx context.Context, server string, checkType CheckType) CheckResult {
	start := time.Now()

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(c.testRecord), dns.TypeA)

	// Create DNS client
	client := &dns.Client{
		Timeout: c.config.QueryTimeout,
	}

	// Perform query
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return CheckResult{
			Type:      checkType,
			Success:   false,
			Error:     fmt.Errorf("DNS query failed: %w", err),
			Timestamp: time.Now(),
			Latency:   time.Since(start),
		}
	}

	// Verify response code
	if resp.Rcode != dns.RcodeSuccess {
		return CheckResult{
			Type:      checkType,
			Success:   false,
			Error:     fmt.Errorf("DNS query returned error: %s", dns.RcodeToString[resp.Rcode]),
			Timestamp: time.Now(),
			Latency:   time.Since(start),
		}
	}

	return CheckResult{
		Type:      checkType,
		Success:   true,
		Timestamp: time.Now(),
		Latency:   time.Since(start),
	}
}

// checkLatency verifies that DNS queries complete within the acceptable threshold.
func (c *Checker) checkLatency(ctx context.Context) CheckResult {
	start := time.Now()

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(c.testRecord), dns.TypeA)

	// Create DNS client
	client := &dns.Client{
		Timeout: c.config.QueryTimeout,
	}

	// Perform query
	_, rtt, err := client.ExchangeContext(ctx, msg, c.unboundServer)
	if err != nil {
		return CheckResult{
			Type:      CheckTypeLatency,
			Success:   false,
			Error:     fmt.Errorf("latency check query failed: %w", err),
			Timestamp: time.Now(),
			Latency:   time.Since(start),
		}
	}

	// Check if latency is within threshold
	if rtt > c.config.LatencyThreshold {
		return CheckResult{
			Type:      CheckTypeLatency,
			Success:   false,
			Error:     fmt.Errorf("latency %v exceeds threshold %v", rtt, c.config.LatencyThreshold),
			Timestamp: time.Now(),
			Latency:   rtt,
		}
	}

	return CheckResult{
		Type:      CheckTypeLatency,
		Success:   true,
		Timestamp: time.Now(),
		Latency:   rtt,
	}
}

// CheckHealth performs a single health check and returns the status.
// This is a convenience method for one-time checks.
func (c *Checker) CheckHealth(ctx context.Context) HealthStatus {
	return c.CheckAll(ctx)
}
