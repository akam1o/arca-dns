package dnssec

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
	"go.uber.org/zap"
)

// ErrSignatureExpirationUnavailable indicates that a zone has no stored
// signature expiration metadata or readable signed artifact.
var ErrSignatureExpirationUnavailable = errors.New("signature expiration unavailable")

// Clock provides the current time (injectable for testing).
type Clock interface {
	Now() time.Time
}

// Ticker provides periodic ticks (injectable for testing).
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// SchedulerMetrics tracks scheduler metrics.
type SchedulerMetrics interface {
	SetEarliestExpiration(t time.Time)
	IncResign(result string)
	SetLastRun(t time.Time)
	SetSecondsRemaining(seconds float64)
}

// ZoneLister lists zones from the backend.
type ZoneLister interface {
	ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error)
}

// Signer signs zones.
type Signer interface {
	GetEarliestExpiration(ctx context.Context, zoneName string) (uint32, error)
	ResignZone(ctx context.Context, zoneName string) error
}

// SchedulerConfig configures the signature freshness scheduler.
type SchedulerConfig struct {
	// CheckInterval is how often to check for expiring signatures (default: 1 hour)
	CheckInterval time.Duration

	// ResignThreshold is when to re-sign (default: 7 days before expiration)
	ResignThreshold time.Duration

	// InitialJitter is max random delay on first run (default: 5 minutes)
	InitialJitter time.Duration

	// FailureBackoffMin is minimum backoff on failure (default: 5 minutes)
	FailureBackoffMin time.Duration

	// FailureBackoffMax is maximum backoff on failure (default: 6 hours)
	FailureBackoffMax time.Duration
}

// DefaultSchedulerConfig returns default scheduler configuration.
func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		CheckInterval:     1 * time.Hour,
		ResignThreshold:   7 * 24 * time.Hour,
		InitialJitter:     5 * time.Minute,
		FailureBackoffMin: 5 * time.Minute,
		FailureBackoffMax: 6 * time.Hour,
	}
}

// Scheduler manages signature freshness checks and automatic re-signing.
type Scheduler struct {
	config  SchedulerConfig
	lister  ZoneLister
	signer  Signer
	clock   Clock
	ticker  Ticker
	metrics SchedulerMetrics
	logger  *zap.Logger

	// Per-zone backoff tracking
	backoffMu sync.Mutex
	backoff   map[string]*backoffState
}

// backoffState tracks per-zone failure backoff.
type backoffState struct {
	failures    int
	nextAllowed time.Time
}

// NewScheduler creates a new signature freshness scheduler.
func NewScheduler(
	config SchedulerConfig,
	lister ZoneLister,
	signer Signer,
	clock Clock,
	ticker Ticker,
	metrics SchedulerMetrics,
	logger *zap.Logger,
) *Scheduler {
	if clock == nil {
		clock = &realClock{}
	}
	if metrics == nil {
		metrics = &noopMetrics{}
	}

	return &Scheduler{
		config:  config,
		lister:  lister,
		signer:  signer,
		clock:   clock,
		ticker:  ticker,
		metrics: metrics,
		logger:  logger,
		backoff: make(map[string]*backoffState),
	}
}

// Start starts the scheduler background loop.
// It blocks until ctx is cancelled or an error occurs.
func (s *Scheduler) Start(ctx context.Context) error {
	// Apply initial jitter to avoid thundering herd on restart
	if s.config.InitialJitter > 0 {
		jitter := time.Duration(rand.Int63n(int64(s.config.InitialJitter)))
		s.logger.Info("Scheduler starting with initial jitter",
			zap.Duration("jitter", jitter))

		select {
		case <-time.After(jitter):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	s.logger.Info("Signature freshness scheduler started",
		zap.Duration("check_interval", s.config.CheckInterval),
		zap.Duration("resign_threshold", s.config.ResignThreshold))

	// Run immediately on start
	s.run(ctx)

	// Then run on each tick
	// Note: Ticker lifecycle is managed by the caller (not stopped here)
	for {
		select {
		case <-s.ticker.C():
			s.run(ctx)
		case <-ctx.Done():
			s.logger.Info("Signature freshness scheduler stopping")
			return ctx.Err()
		}
	}
}

// run performs one scheduler check cycle.
func (s *Scheduler) run(ctx context.Context) {
	now := s.clock.Now()
	s.metrics.SetLastRun(now)

	s.logger.Debug("Scheduler run starting")

	// List all zones
	zones, err := s.lister.ListZones(ctx, backend.ListOptions{})
	if err != nil {
		s.logger.Error("Failed to list zones", zap.Error(err))
		return
	}

	// Track earliest expiration across all zones
	var earliestExpiration time.Time
	zonesChecked := 0
	zonesResigned := 0
	zonesSkipped := 0

	for _, zone := range zones {
		// Skip zones without DNSSEC enabled
		if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
			continue
		}

		zonesChecked++

		// Get earliest RRSIG expiration for this zone
		expiration, err := s.signer.GetEarliestExpiration(ctx, zone.Name)
		if err != nil {
			if errors.Is(err, ErrSignatureExpirationUnavailable) {
				resigned, skipped := s.attemptResign(ctx, zone.Name, now,
					"Re-signing zone because signature expiration is unavailable",
					zap.Error(err))
				if skipped {
					zonesSkipped++
				}
				if resigned {
					zonesResigned++
				}
				continue
			}

			s.logger.Warn("Failed to get expiration for zone",
				zap.String("zone", zone.Name),
				zap.Error(err))
			continue
		}

		// Convert UNIX timestamp to time.Time
		expirationTime := time.Unix(int64(expiration), 0)
		remaining := expirationTime.Sub(now)

		// Track global earliest expiration
		if earliestExpiration.IsZero() || expirationTime.Before(earliestExpiration) {
			earliestExpiration = expirationTime
		}

		// Check if re-sign is needed
		if remaining < s.config.ResignThreshold {
			resigned, skipped := s.attemptResign(ctx, zone.Name, now,
				"Re-signing zone due to expiring signatures",
				zap.Duration("remaining", remaining),
				zap.Time("expiration", expirationTime))
			if skipped {
				zonesSkipped++
			}
			if resigned {
				zonesResigned++
			}
		}
	}

	// Update metrics
	if !earliestExpiration.IsZero() {
		s.metrics.SetEarliestExpiration(earliestExpiration)
		secondsRemaining := earliestExpiration.Sub(now).Seconds()
		s.metrics.SetSecondsRemaining(secondsRemaining)
	}

	s.logger.Info("Scheduler run completed",
		zap.Int("zones_checked", zonesChecked),
		zap.Int("zones_resigned", zonesResigned),
		zap.Int("zones_skipped", zonesSkipped),
		zap.Time("earliest_expiration", earliestExpiration))
}

func (s *Scheduler) attemptResign(ctx context.Context, zoneName string, now time.Time, message string, fields ...zap.Field) (resigned bool, skipped bool) {
	if s.isBackedOff(zoneName, now) {
		s.logger.Debug("Zone skipped due to backoff",
			zap.String("zone", zoneName))
		return false, true
	}

	logFields := append([]zap.Field{zap.String("zone", zoneName)}, fields...)
	s.logger.Info(message, logFields...)

	if err := s.signer.ResignZone(ctx, zoneName); err != nil {
		s.logger.Error("Failed to re-sign zone",
			zap.String("zone", zoneName),
			zap.Error(err))
		s.metrics.IncResign("error")
		s.recordFailure(zoneName, now)
		return false, false
	}

	s.logger.Info("Successfully re-signed zone",
		zap.String("zone", zoneName))
	s.metrics.IncResign("success")
	s.clearBackoff(zoneName)
	return true, false
}

// isBackedOff checks if a zone is currently backed off due to previous failures.
func (s *Scheduler) isBackedOff(zoneName string, now time.Time) bool {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()

	state, exists := s.backoff[zoneName]
	if !exists {
		return false
	}

	return now.Before(state.nextAllowed)
}

// recordFailure records a failure and calculates exponential backoff.
func (s *Scheduler) recordFailure(zoneName string, now time.Time) {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()

	state, exists := s.backoff[zoneName]
	if !exists {
		state = &backoffState{failures: 0}
		s.backoff[zoneName] = state
	}

	state.failures++

	// Exponential backoff: min * 2^failures (capped at max)
	delay := s.config.FailureBackoffMin * time.Duration(1<<uint(state.failures))
	if delay > s.config.FailureBackoffMax {
		delay = s.config.FailureBackoffMax
	}

	// Add small jitter (0-10% of delay)
	jitter := time.Duration(rand.Int63n(int64(delay / 10)))
	delay += jitter

	state.nextAllowed = now.Add(delay)

	s.logger.Debug("Zone backoff updated",
		zap.String("zone", zoneName),
		zap.Int("failures", state.failures),
		zap.Duration("backoff", delay),
		zap.Time("next_allowed", state.nextAllowed))
}

// clearBackoff clears the backoff state for a zone after successful re-sign.
func (s *Scheduler) clearBackoff(zoneName string) {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()

	delete(s.backoff, zoneName)
}

// realClock implements Clock using time.Now.
type realClock struct{}

func (c *realClock) Now() time.Time {
	return time.Now()
}

// noopMetrics implements SchedulerMetrics with no-ops.
type noopMetrics struct{}

func (m *noopMetrics) SetEarliestExpiration(t time.Time)   {}
func (m *noopMetrics) IncResign(result string)             {}
func (m *noopMetrics) SetLastRun(t time.Time)              {}
func (m *noopMetrics) SetSecondsRemaining(seconds float64) {}
