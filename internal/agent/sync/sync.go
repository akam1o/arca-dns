package sync

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"go.uber.org/zap"
)

// ZoneSyncState tracks the current state of a zone on the agent.
type ZoneSyncState struct {
	ZoneName    string
	Version     string    // ETag from controller
	LastSync    time.Time // Last successful sync time
	LastAttempt time.Time // Last sync attempt time
	FailCount   int       // Consecutive failure count
}

// Syncer manages zone synchronization from controller to agent.
type Syncer struct {
	client      *Client
	fileMgr     *FileManager
	config      config.SyncConfig
	logger      *zap.Logger
	zoneStates  map[string]*ZoneSyncState // Track state per zone
	lastSuccess time.Time                 // Last successful sync (any zone)
	mu          sync.RWMutex              // Protects zoneStates and lastSuccess

	onZoneApplied func(ctx context.Context, zoneName string) error
}

// NewSyncer creates a new zone syncer.
func NewSyncer(client *Client, fileMgr *FileManager, cfg config.SyncConfig, logger *zap.Logger) *Syncer {
	return &Syncer{
		client:     client,
		fileMgr:    fileMgr,
		config:     cfg,
		logger:     logger,
		zoneStates: make(map[string]*ZoneSyncState),
		// lastSuccess is zero value (time.Time{}) to indicate no successful sync yet
	}
}

// SetOnZoneApplied sets a hook to be called after a zone file is written successfully.
// Returning an error will mark the sync for that zone as failed.
func (s *Syncer) SetOnZoneApplied(fn func(ctx context.Context, zoneName string) error) {
	s.onZoneApplied = fn
}

// Run starts the sync loop with configurable interval and jitter.
// This is the main entry point for the sync process.
func (s *Syncer) Run(ctx context.Context) error {
	s.logger.Info("Starting zone sync loop",
		zap.Duration("interval", s.config.SyncInterval),
		zap.Duration("jitter", s.config.Jitter))

	// Create ticker with jitter to prevent thundering herd
	ticker := time.NewTicker(s.addJitter(s.config.SyncInterval))
	defer ticker.Stop()

	// Run initial sync immediately
	if err := s.SyncAll(ctx); err != nil {
		s.logger.Error("Initial sync failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Sync loop stopped")
			return ctx.Err()

		case <-ticker.C:
			// Check for max staleness SLO violation
			s.mu.RLock()
			lastSuccess := s.lastSuccess
			s.mu.RUnlock()

			if time.Since(lastSuccess) > s.config.MaxStaleness {
				s.logger.Error("Max staleness SLO violated",
					zap.Duration("since_last_success", time.Since(lastSuccess)),
					zap.Duration("max_staleness", s.config.MaxStaleness))
			}

			// Perform sync
			if err := s.SyncAll(ctx); err != nil {
				s.logger.Error("Sync failed", zap.Error(err))
			}

			// Reset ticker with new jitter
			ticker.Reset(s.addJitter(s.config.SyncInterval))
		}
	}
}

// SyncAll synchronizes all zones from the controller.
// Algorithm:
// 1. Fetch zone list with current ETags
// 2. Compare with local state
// 3. Download changed zones (conditional fetch)
// 4. Verify integrity (checksum)
// 5. Atomic file write (write to .tmp, fsync, rename)
// 6. Backup old version (keep last N)
// 7. Trigger NSD/Unbound reload (delegated to caller)
func (s *Syncer) SyncAll(ctx context.Context) error {
	s.logger.Debug("Starting sync cycle")

	// Step 1: Fetch zone list from controller
	zones, err := s.client.ListZones()
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}

	s.logger.Debug("Fetched zone list",
		zap.Int("count", len(zones)))

	// Step 2-7: Process each zone
	successCount := 0
	errorCount := 0

	for _, zone := range zones {
		if err := s.syncZone(ctx, zone); err != nil {
			s.logger.Error("Failed to sync zone",
				zap.String("zone", zone.Name),
				zap.Error(err))
			errorCount++

			// Update failure count
			s.mu.Lock()
			state := s.getOrCreateStateLocked(zone.Name)
			state.FailCount++
			state.LastAttempt = time.Now()
			s.mu.Unlock()
		} else {
			successCount++

			// Reset failure count and update state
			s.mu.Lock()
			state := s.getOrCreateStateLocked(zone.Name)
			state.Version = zone.Version
			state.LastSync = time.Now()
			state.LastAttempt = time.Now()
			state.FailCount = 0
			s.mu.Unlock()
		}
	}

	// Update last success time if any zone succeeded
	if successCount > 0 {
		s.mu.Lock()
		s.lastSuccess = time.Now()
		s.mu.Unlock()
	}

	s.logger.Info("Sync cycle completed",
		zap.Int("success", successCount),
		zap.Int("errors", errorCount),
		zap.Int("total", len(zones)))

	// Return error only if all zones failed
	if errorCount > 0 && successCount == 0 {
		return fmt.Errorf("all zones failed to sync (%d errors)", errorCount)
	}

	return nil
}

// syncZone synchronizes a single zone.
func (s *Syncer) syncZone(ctx context.Context, zone ZoneInfo) error {
	// Get current state
	s.mu.RLock()
	currentETag := ""
	if state, exists := s.zoneStates[zone.Name]; exists {
		currentETag = state.Version
	}
	s.mu.RUnlock()

	// Step 3: Conditional fetch using ETag
	zoneContent, newETag, notModified, err := s.client.FetchSignedZone(zone.Name, currentETag)
	if err != nil {
		return fmt.Errorf("failed to fetch zone: %w", err)
	}

	// If zone hasn't changed, skip the rest
	if notModified {
		s.logger.Debug("Zone not modified (304)",
			zap.String("zone", zone.Name),
			zap.String("etag", currentETag))
		return nil
	}

	s.logger.Info("Zone updated, applying changes",
		zap.String("zone", zone.Name),
		zap.String("old_version", currentETag),
		zap.String("new_version", newETag))

	// Step 4: Checksum verification is done in client.FetchSignedZone

	// Step 5: Atomic file write
	// Step 6: Backup old version (handled by FileManager)
	if err := s.fileMgr.WriteZoneFile(zone.Name, zoneContent); err != nil {
		return fmt.Errorf("failed to write zone file: %w", err)
	}

	// Step 7: NSD/Unbound reload is handled by the caller (main agent loop) via hook.
	if s.onZoneApplied != nil {
		if err := s.onZoneApplied(ctx, zone.Name); err != nil {
			return fmt.Errorf("post-apply hook failed: %w", err)
		}
	}

	s.logger.Info("Zone synchronized successfully",
		zap.String("zone", zone.Name),
		zap.String("version", newETag))

	return nil
}

// SyncZone synchronizes a specific zone by name.
// Useful for on-demand sync or testing.
func (s *Syncer) SyncZone(ctx context.Context, zoneName string) error {
	// Fetch zone info from controller
	zones, err := s.client.ListZones()
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}

	// Find the target zone
	var targetZone *ZoneInfo
	for _, z := range zones {
		if z.Name == zoneName {
			targetZone = &z
			break
		}
	}

	if targetZone == nil {
		return fmt.Errorf("zone not found: %s", zoneName)
	}

	return s.syncZone(ctx, *targetZone)
}

// GetZoneState returns the current sync state for a zone.
func (s *Syncer) GetZoneState(zoneName string) *ZoneSyncState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, exists := s.zoneStates[zoneName]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modification
	stateCopy := *state
	return &stateCopy
}

// GetAllZoneStates returns all zone states.
func (s *Syncer) GetAllZoneStates() map[string]*ZoneSyncState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy to prevent external modification
	states := make(map[string]*ZoneSyncState)
	for k, v := range s.zoneStates {
		// Copy struct
		stateCopy := *v
		states[k] = &stateCopy
	}
	return states
}

// GetLastSuccessTime returns the last successful sync time.
func (s *Syncer) GetLastSuccessTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSuccess
}

// IsStale returns true if sync is stale (exceeds MaxStaleness).
func (s *Syncer) IsStale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.lastSuccess) > s.config.MaxStaleness
}

// getOrCreateStateLocked gets or creates a zone state.
// Caller must hold mu.Lock().
func (s *Syncer) getOrCreateStateLocked(zoneName string) *ZoneSyncState {
	state, exists := s.zoneStates[zoneName]
	if !exists {
		state = &ZoneSyncState{
			ZoneName: zoneName,
		}
		s.zoneStates[zoneName] = state
	}
	return state
}

// addJitter adds random jitter to prevent thundering herd.
func (s *Syncer) addJitter(duration time.Duration) time.Duration {
	if s.config.Jitter <= 0 {
		return duration
	}

	// Add random jitter: duration ± jitter/2
	jitterNanos := s.config.Jitter.Nanoseconds()
	randomJitter := rand.Int63n(jitterNanos) - (jitterNanos / 2)

	return duration + time.Duration(randomJitter)
}
