package dnssec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
	"go.uber.org/zap"
)

// fakeClock implements Clock for testing.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// manualTicker implements Ticker for testing.
type manualTicker struct {
	c chan time.Time
}

func newManualTicker() *manualTicker {
	return &manualTicker{c: make(chan time.Time, 1)}
}

func (t *manualTicker) C() <-chan time.Time {
	return t.c
}

func (t *manualTicker) Stop() {
	close(t.c)
}

func (t *manualTicker) Tick() {
	t.c <- time.Now()
}

// fakeZoneLister implements ZoneLister for testing.
type fakeZoneLister struct {
	zones []*model.Zone
	err   error
}

func (l *fakeZoneLister) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	if l.err != nil {
		return nil, l.err
	}
	return l.zones, nil
}

// fakeSigner implements Signer for testing.
type fakeSigner struct {
	mu          sync.Mutex
	expirations map[string]uint32 // zoneName -> expiration timestamp
	resignCalls []string          // track resign calls
	resignErr   error
}

func newFakeSigner() *fakeSigner {
	return &fakeSigner{
		expirations: make(map[string]uint32),
		resignCalls: make([]string, 0),
	}
}

func (s *fakeSigner) GetEarliestExpiration(ctx context.Context, zoneName string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	exp, ok := s.expirations[zoneName]
	if !ok {
		return 0, errors.New("no expiration data")
	}
	return exp, nil
}

func (s *fakeSigner) ResignZone(ctx context.Context, zoneName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resignCalls = append(s.resignCalls, zoneName)
	return s.resignErr
}

func (s *fakeSigner) GetResignCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.resignCalls...) // copy
}

// fakeMetrics implements SchedulerMetrics for testing.
type fakeMetrics struct {
	mu                 sync.Mutex
	earliestExpiration time.Time
	resignCounts       map[string]int
	lastRun            time.Time
	secondsRemaining   float64
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{
		resignCounts: make(map[string]int),
	}
}

func (m *fakeMetrics) SetEarliestExpiration(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.earliestExpiration = t
}

func (m *fakeMetrics) IncResign(result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resignCounts[result]++
}

func (m *fakeMetrics) SetLastRun(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRun = t
}

func (m *fakeMetrics) GetLastRun() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRun
}

func (m *fakeMetrics) SetSecondsRemaining(seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secondsRemaining = seconds
}

func (m *fakeMetrics) GetResignCount(result string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resignCounts[result]
}

func TestScheduler_NoZones(t *testing.T) {
	clock := &fakeClock{now: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	ticker := newManualTicker()
	lister := &fakeZoneLister{zones: []*model.Zone{}}
	signer := newFakeSigner()
	metrics := newFakeMetrics()
	logger := zap.NewNop()

	config := DefaultSchedulerConfig()
	config.InitialJitter = 0 // disable jitter for test

	scheduler := NewScheduler(config, lister, signer, clock, ticker, metrics, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start scheduler in background
	go func() {
		_ = scheduler.Start(ctx)
	}()

	// Wait for initial run
	time.Sleep(10 * time.Millisecond)

	// Check that last run was updated
	if metrics.GetLastRun().IsZero() {
		t.Error("lastRun not updated")
	}

	// No zones, so no resign calls
	if len(signer.GetResignCalls()) != 0 {
		t.Errorf("Expected 0 resign calls, got %d", len(signer.GetResignCalls()))
	}

	cancel()
}

func TestScheduler_ZoneExpiresIn6Days(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	ticker := newManualTicker()

	// Zone expires in 6 days (< 7 day threshold)
	expirationTime := now.Add(6 * 24 * time.Hour)

	zone := &model.Zone{
		Name: "example.com.",
		DNSSEC: &model.DNSSECConfig{
			Enabled: true,
		},
	}

	lister := &fakeZoneLister{zones: []*model.Zone{zone}}
	signer := newFakeSigner()
	signer.expirations["example.com."] = uint32(expirationTime.Unix())

	metrics := newFakeMetrics()
	logger := zap.NewNop()

	config := DefaultSchedulerConfig()
	config.InitialJitter = 0
	config.ResignThreshold = 7 * 24 * time.Hour

	scheduler := NewScheduler(config, lister, signer, clock, ticker, metrics, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = scheduler.Start(ctx)
	}()

	time.Sleep(10 * time.Millisecond)

	// Should have attempted resign
	resignCalls := signer.GetResignCalls()
	if len(resignCalls) != 1 {
		t.Fatalf("Expected 1 resign call, got %d", len(resignCalls))
	}
	if resignCalls[0] != "example.com." {
		t.Errorf("Expected resign call for example.com., got %s", resignCalls[0])
	}

	// Check metrics
	if metrics.GetResignCount("success") != 1 {
		t.Errorf("Expected 1 success metric, got %d", metrics.GetResignCount("success"))
	}

	cancel()
}

func TestScheduler_ZoneExpiresIn8Days(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	ticker := newManualTicker()

	// Zone expires in 8 days (> 7 day threshold)
	expirationTime := now.Add(8 * 24 * time.Hour)

	zone := &model.Zone{
		Name: "example.com.",
		DNSSEC: &model.DNSSECConfig{
			Enabled: true,
		},
	}

	lister := &fakeZoneLister{zones: []*model.Zone{zone}}
	signer := newFakeSigner()
	signer.expirations["example.com."] = uint32(expirationTime.Unix())

	metrics := newFakeMetrics()
	logger := zap.NewNop()

	config := DefaultSchedulerConfig()
	config.InitialJitter = 0
	config.ResignThreshold = 7 * 24 * time.Hour

	scheduler := NewScheduler(config, lister, signer, clock, ticker, metrics, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = scheduler.Start(ctx)
	}()

	time.Sleep(10 * time.Millisecond)

	// Should NOT have attempted resign
	resignCalls := signer.GetResignCalls()
	if len(resignCalls) != 0 {
		t.Errorf("Expected 0 resign calls, got %d", len(resignCalls))
	}

	cancel()
}

func TestScheduler_ResignFails(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	ticker := newManualTicker()

	expirationTime := now.Add(6 * 24 * time.Hour)

	zone := &model.Zone{
		Name: "example.com.",
		DNSSEC: &model.DNSSECConfig{
			Enabled: true,
		},
	}

	lister := &fakeZoneLister{zones: []*model.Zone{zone}}
	signer := newFakeSigner()
	signer.expirations["example.com."] = uint32(expirationTime.Unix())
	signer.resignErr = errors.New("signing failed")

	metrics := newFakeMetrics()
	logger := zap.NewNop()

	config := DefaultSchedulerConfig()
	config.InitialJitter = 0
	config.ResignThreshold = 7 * 24 * time.Hour

	scheduler := NewScheduler(config, lister, signer, clock, ticker, metrics, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = scheduler.Start(ctx)
	}()

	time.Sleep(10 * time.Millisecond)

	// Should have attempted resign (and failed)
	resignCalls := signer.GetResignCalls()
	if len(resignCalls) != 1 {
		t.Fatalf("Expected 1 resign call, got %d", len(resignCalls))
	}

	// Check error metric
	if metrics.GetResignCount("error") != 1 {
		t.Errorf("Expected 1 error metric, got %d", metrics.GetResignCount("error"))
	}

	cancel()
}

func TestScheduler_BackoffAfterFailure(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	ticker := newManualTicker()

	expirationTime := now.Add(6 * 24 * time.Hour)

	zone := &model.Zone{
		Name: "example.com.",
		DNSSEC: &model.DNSSECConfig{
			Enabled: true,
		},
	}

	lister := &fakeZoneLister{zones: []*model.Zone{zone}}
	signer := newFakeSigner()
	signer.expirations["example.com."] = uint32(expirationTime.Unix())
	signer.resignErr = errors.New("signing failed")

	metrics := newFakeMetrics()
	logger := zap.NewNop()

	config := DefaultSchedulerConfig()
	config.InitialJitter = 0
	config.ResignThreshold = 7 * 24 * time.Hour
	config.FailureBackoffMin = 5 * time.Minute

	scheduler := NewScheduler(config, lister, signer, clock, ticker, metrics, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = scheduler.Start(ctx)
	}()

	time.Sleep(10 * time.Millisecond)

	// First attempt (fails)
	if len(signer.GetResignCalls()) != 1 {
		t.Fatalf("Expected 1 resign call after first run, got %d", len(signer.GetResignCalls()))
	}

	// Check that error metric was incremented
	if metrics.GetResignCount("error") != 1 {
		t.Errorf("Expected 1 error metric, got %d", metrics.GetResignCount("error"))
	}

	// Trigger another tick immediately (should be backed off)
	ticker.Tick()
	time.Sleep(10 * time.Millisecond)

	// Should still be 1 call (backed off)
	resignCalls := signer.GetResignCalls()
	if len(resignCalls) != 1 {
		t.Errorf("Expected still 1 resign call (backed off), got %d", len(resignCalls))
	}

	// Verify backoff state exists
	scheduler.backoffMu.Lock()
	state, exists := scheduler.backoff["example.com."]
	scheduler.backoffMu.Unlock()

	if !exists {
		t.Fatal("Expected backoff state to exist")
	}
	if state.failures != 1 {
		t.Errorf("Expected 1 failure, got %d", state.failures)
	}
	if state.nextAllowed.Before(now) {
		t.Errorf("Expected nextAllowed to be in the future")
	}

	cancel()
}

func TestScheduler_SkipsDNSSECDisabledZones(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	ticker := newManualTicker()

	zones := []*model.Zone{
		{
			Name:   "enabled.com.",
			DNSSEC: &model.DNSSECConfig{Enabled: true},
		},
		{
			Name:   "disabled.com.",
			DNSSEC: &model.DNSSECConfig{Enabled: false},
		},
		{
			Name:   "nil.com.",
			DNSSEC: nil,
		},
	}

	expirationTime := now.Add(6 * 24 * time.Hour)

	lister := &fakeZoneLister{zones: zones}
	signer := newFakeSigner()
	signer.expirations["enabled.com."] = uint32(expirationTime.Unix())

	metrics := newFakeMetrics()
	logger := zap.NewNop()

	config := DefaultSchedulerConfig()
	config.InitialJitter = 0

	scheduler := NewScheduler(config, lister, signer, clock, ticker, metrics, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = scheduler.Start(ctx)
	}()

	time.Sleep(10 * time.Millisecond)

	// Should only resign enabled.com.
	resignCalls := signer.GetResignCalls()
	if len(resignCalls) != 1 {
		t.Fatalf("Expected 1 resign call, got %d", len(resignCalls))
	}
	if resignCalls[0] != "enabled.com." {
		t.Errorf("Expected resign for enabled.com., got %s", resignCalls[0])
	}

	cancel()
}
