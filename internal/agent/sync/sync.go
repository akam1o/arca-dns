package sync

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
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
	onZoneDeleted func(ctx context.Context, zoneName string) error
}

// NewSyncer creates a new zone syncer.
func NewSyncer(client *Client, fileMgr *FileManager, cfg config.SyncConfig, logger *zap.Logger) *Syncer {
	if client != nil {
		client.SetVerifyChecksums(cfg.VerifyChecksums)
	}

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

// SetOnZoneDeleted sets a hook to be called after a zone file is deleted successfully.
// Returning an error will keep the zone state so the deletion reload can be retried.
func (s *Syncer) SetOnZoneDeleted(fn func(ctx context.Context, zoneName string) error) {
	s.onZoneDeleted = fn
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

			if !lastSuccess.IsZero() && time.Since(lastSuccess) > s.config.MaxStaleness {
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
// 8. Delete local zones no longer present on the controller
func (s *Syncer) SyncAll(ctx context.Context) error {
	s.logger.Debug("Starting sync cycle")

	// Step 1: Fetch zone list from controller
	zones, err := s.client.ListZones()
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}

	s.logger.Debug("Fetched zone list",
		zap.Int("count", len(zones)))

	controllerZones := make(map[string]struct{}, len(zones))
	controllerZoneFiles := make(map[string]struct{}, len(zones))
	for _, zone := range zones {
		controllerZones[zone.Name] = struct{}{}
		controllerZoneFiles[SafeZoneFilename(zone.Name)] = struct{}{}
	}

	// Step 2-7: Process each zone
	successCount := 0
	errorCount := 0
	zoneErrorCount := 0

	for _, zone := range zones {
		if err := s.syncZone(ctx, zone); err != nil {
			s.logger.Error("Failed to sync zone",
				zap.String("zone", zone.Name),
				zap.Error(err))
			errorCount++
			zoneErrorCount++

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
			state.LastSync = time.Now()
			state.LastAttempt = time.Now()
			state.FailCount = 0
			s.mu.Unlock()
		}
	}

	deleteCount, deleteErrorCount := s.deleteRemovedZones(ctx, controllerZones, controllerZoneFiles)
	successCount += deleteCount
	errorCount += deleteErrorCount

	// Update last success time if the cycle made progress, or if an empty controller list was reconciled.
	if successCount > 0 || (len(zones) == 0 && errorCount == 0) {
		s.mu.Lock()
		s.lastSuccess = time.Now()
		s.mu.Unlock()
	}

	s.logger.Info("Sync cycle completed",
		zap.Int("success", successCount),
		zap.Int("deleted", deleteCount),
		zap.Int("errors", errorCount),
		zap.Int("total", len(zones)))

	// Return error if all active controller zones failed, or if reconciliation had no success.
	if zoneErrorCount > 0 && zoneErrorCount == len(zones) {
		if deleteErrorCount > 0 {
			return fmt.Errorf("all zones failed to sync (%d errors); failed to delete removed zones (%d errors)", zoneErrorCount, deleteErrorCount)
		}
		return fmt.Errorf("all zones failed to sync (%d errors)", zoneErrorCount)
	}
	if deleteErrorCount > 0 {
		return fmt.Errorf("failed to delete removed zones (%d errors)", deleteErrorCount)
	}
	if errorCount > 0 && successCount == 0 {
		return fmt.Errorf("sync failed (%d errors)", errorCount)
	}

	return nil
}

// deleteRemovedZones deletes local zone files that disappeared from the controller list.
func (s *Syncer) deleteRemovedZones(ctx context.Context, controllerZones map[string]struct{}, controllerZoneFiles map[string]struct{}) (int, int) {
	s.mu.RLock()
	staleStateZones := make([]string, 0)
	staleAliases := make([]string, 0)
	for zoneName := range s.zoneStates {
		if _, exists := controllerZones[zoneName]; exists {
			continue
		}
		if _, fileStillDesired := controllerZoneFiles[SafeZoneFilename(zoneName)]; fileStillDesired {
			staleAliases = append(staleAliases, zoneName)
			continue
		}
		staleStateZones = append(staleStateZones, zoneName)
	}
	s.mu.RUnlock()

	sort.Strings(staleAliases)
	for _, zoneName := range staleAliases {
		s.mu.Lock()
		delete(s.zoneStates, zoneName)
		s.mu.Unlock()

		s.logger.Debug("Removed stale zone state with desired zone file still present",
			zap.String("zone", zoneName),
			zap.String("zone_file", SafeZoneFilename(zoneName)))
	}

	deletedCount := 0
	errorCount := 0
	attemptedFiles := make(map[string]struct{}, len(staleStateZones))

	sort.Strings(staleStateZones)
	for _, zoneName := range staleStateZones {
		attemptedFiles[SafeZoneFilename(zoneName)] = struct{}{}
		if err := s.deleteRemovedZone(ctx, zoneName); err != nil {
			s.logger.Error("Failed to delete removed zone",
				zap.String("zone", zoneName),
				zap.Error(err))
			s.recordDeleteFailure(zoneName)
			errorCount++
			continue
		}
		deletedCount++
	}

	localZoneFiles, err := s.fileMgr.listZoneFiles()
	if err != nil {
		s.logger.Error("Failed to list local zone files", zap.Error(err))
		return deletedCount, errorCount + 1
	}

	for _, zoneFile := range localZoneFiles {
		if _, exists := controllerZoneFiles[zoneFile]; exists {
			continue
		}
		if _, attempted := attemptedFiles[zoneFile]; attempted {
			continue
		}

		if err := s.deleteRemovedZone(ctx, zoneFile); err != nil {
			s.logger.Error("Failed to delete orphaned zone file",
				zap.String("zone_file", zoneFile),
				zap.Error(err))
			s.recordDeleteFailure(zoneFile)
			errorCount++
			continue
		}
		deletedCount++
	}

	return deletedCount, errorCount
}

func (s *Syncer) deleteRemovedZone(ctx context.Context, zoneName string) error {
	if err := s.fileMgr.DeleteZoneFile(zoneName); err != nil {
		return fmt.Errorf("failed to delete zone file: %w", err)
	}

	if s.onZoneDeleted != nil {
		if err := s.onZoneDeleted(ctx, zoneName); err != nil {
			return fmt.Errorf("post-delete hook failed: %w", err)
		}
	}

	s.mu.Lock()
	delete(s.zoneStates, zoneName)
	s.mu.Unlock()

	s.logger.Info("Deleted removed zone",
		zap.String("zone", zoneName))

	return nil
}

func (s *Syncer) recordDeleteFailure(zoneName string) {
	s.mu.Lock()
	state := s.getOrCreateStateLocked(zoneName)
	state.FailCount++
	state.LastAttempt = time.Now()
	s.mu.Unlock()
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

		// Prefer the response ETag (may be quoted); keep our local state aligned.
		if newETag != "" {
			s.mu.Lock()
			state := s.getOrCreateStateLocked(zone.Name)
			state.Version = newETag
			s.mu.Unlock()
		}
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

	// Record the effective ETag/version returned by the controller.
	s.mu.Lock()
	state := s.getOrCreateStateLocked(zone.Name)
	state.Version = newETag
	s.mu.Unlock()

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
