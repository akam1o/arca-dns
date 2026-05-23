package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/model"
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

	onZoneApplied        func(ctx context.Context, zoneName string) error
	onZoneApplyRollback  func(ctx context.Context, zoneName string, hadPrevious bool) error
	onZoneDeleted        func(ctx context.Context, zoneName string) error
	onZoneDeleteRollback func(ctx context.Context, zoneName string) error
	validateZoneFile     func(ctx context.Context, zoneName string, zonePath string) error
}

// NewSyncer creates a new zone syncer.
func NewSyncer(client *Client, fileMgr *FileManager, cfg config.SyncConfig, logger *zap.Logger) *Syncer {
	if client != nil {
		client.SetVerifyChecksums(cfg.VerifyChecksums)
		client.SetSignatureVerification(cfg.VerifySignatures, cfg.ControllerSignatureKey)
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

// SetOnZoneApplyRollback sets a hook to restore service references after a
// zone apply hook fails and the active zone file has been rolled back.
func (s *Syncer) SetOnZoneApplyRollback(fn func(ctx context.Context, zoneName string, hadPrevious bool) error) {
	s.onZoneApplyRollback = fn
}

// SetOnZoneDeleted sets a hook to be called before removing the local zone file.
// Returning an error keeps the zone file and state so the deletion can be retried.
func (s *Syncer) SetOnZoneDeleted(fn func(ctx context.Context, zoneName string) error) {
	s.onZoneDeleted = fn
}

// SetOnZoneDeleteRollback sets a hook that restores service references when
// local zone file removal fails after SetOnZoneDeleted has already succeeded.
func (s *Syncer) SetOnZoneDeleteRollback(fn func(ctx context.Context, zoneName string) error) {
	s.onZoneDeleteRollback = fn
}

// SetValidateZoneFile sets a hook used to validate the temporary zone file
// before it replaces the active file.
func (s *Syncer) SetValidateZoneFile(fn func(ctx context.Context, zoneName string, zonePath string) error) {
	s.validateZoneFile = fn
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
	zones, err := s.client.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}
	if err := validateControllerZoneList(zones); err != nil {
		return err
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
			s.recordZoneSyncFailure(zone.Name, time.Now())
		} else {
			successCount++
			s.recordZoneSyncSuccess(zone.Name, time.Now())
		}
	}

	deleteCount, deleteErrorCount := s.deleteRemovedZones(ctx, controllerZones, controllerZoneFiles)
	successCount += deleteCount
	errorCount += deleteErrorCount

	// Update last success time only after a fully clean reconciliation.
	if errorCount == 0 && (successCount > 0 || len(zones) == 0) {
		s.recordSyncSuccess(time.Now())
	}

	s.logger.Info("Sync cycle completed",
		zap.Int("success", successCount),
		zap.Int("deleted", deleteCount),
		zap.Int("errors", errorCount),
		zap.Int("total", len(zones)))

	// Return error for any failed active zone so callers do not treat a
	// partially-applied reconciliation as healthy.
	if zoneErrorCount > 0 {
		if deleteErrorCount > 0 {
			return fmt.Errorf("zones failed to sync (%d errors); failed to delete removed zones (%d errors)", zoneErrorCount, deleteErrorCount)
		}
		return fmt.Errorf("zones failed to sync (%d errors)", zoneErrorCount)
	}
	if deleteErrorCount > 0 {
		return fmt.Errorf("failed to delete removed zones (%d errors)", deleteErrorCount)
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

	managedZones, err := s.fileMgr.listManagedZones()
	if err != nil {
		s.logger.Error("Failed to list managed zone files", zap.Error(err))
		return deletedCount, errorCount + 1
	}

	for _, managedZone := range managedZones {
		if _, exists := controllerZoneFiles[managedZone.SafeName]; exists {
			continue
		}
		if _, attempted := attemptedFiles[managedZone.SafeName]; attempted {
			continue
		}

		if err := s.deleteRemovedZone(ctx, managedZone.ZoneName); err != nil {
			s.logger.Error("Failed to delete orphaned zone file",
				zap.String("zone", managedZone.ZoneName),
				zap.String("zone_file", managedZone.SafeName),
				zap.Error(err))
			s.recordDeleteFailure(managedZone.ZoneName)
			errorCount++
			continue
		}
		deletedCount++
	}

	return deletedCount, errorCount
}

func (s *Syncer) deleteRemovedZone(ctx context.Context, zoneName string) error {
	if s.onZoneDeleted != nil {
		if err := s.onZoneDeleted(ctx, zoneName); err != nil {
			return fmt.Errorf("delete hook failed: %w", err)
		}
	}

	if err := s.fileMgr.deleteZoneFiles(zoneName); err != nil {
		deleteErr := fmt.Errorf("failed to delete zone file: %w", err)
		if rollbackErr := s.rollbackDeletedZone(ctx, zoneName); rollbackErr != nil {
			return errors.Join(deleteErr, fmt.Errorf("rollback deleted zone: %w", rollbackErr))
		}
		return deleteErr
	}

	if err := s.fileMgr.removeManagedZone(zoneName); err != nil {
		return fmt.Errorf("failed to update managed zone index: %w", err)
	}

	s.mu.Lock()
	delete(s.zoneStates, zoneName)
	s.mu.Unlock()

	s.logger.Info("Deleted removed zone",
		zap.String("zone", zoneName))

	return nil
}

func (s *Syncer) rollbackDeletedZone(ctx context.Context, zoneName string) error {
	if s.onZoneDeleteRollback == nil {
		return nil
	}
	if err := s.onZoneDeleteRollback(ctx, zoneName); err != nil {
		s.logger.Error("Failed to roll back deleted zone service references",
			zap.String("zone", zoneName),
			zap.Error(err))
		return err
	}
	s.logger.Info("Rolled back deleted zone service references",
		zap.String("zone", zoneName))
	return nil
}

func (s *Syncer) recordDeleteFailure(zoneName string) {
	s.recordZoneSyncFailure(zoneName, time.Now())
}

func (s *Syncer) recordZoneSyncFailure(zoneName string, now time.Time) {
	s.mu.Lock()
	state := s.getOrCreateStateLocked(zoneName)
	state.FailCount++
	state.LastAttempt = now
	s.mu.Unlock()
}

func (s *Syncer) recordZoneSyncSuccess(zoneName string, now time.Time) {
	s.mu.Lock()
	state := s.getOrCreateStateLocked(zoneName)
	state.LastSync = now
	state.LastAttempt = now
	state.FailCount = 0
	s.mu.Unlock()
}

func (s *Syncer) recordSyncSuccess(now time.Time) {
	s.mu.Lock()
	s.lastSuccess = now
	s.mu.Unlock()
}

// syncZone synchronizes a single zone.
func (s *Syncer) syncZone(ctx context.Context, zone ZoneInfo) error {
	if _, err := validateControllerZoneName(zone.Name); err != nil {
		return fmt.Errorf("invalid zone name from controller: %w", err)
	}

	// Get current state
	s.mu.RLock()
	currentETag := ""
	currentBody := ""
	if state, exists := s.zoneStates[zone.Name]; exists {
		currentETag = state.Version
	}
	s.mu.RUnlock()

	if currentETag != "" {
		var matches bool
		currentBody, matches = s.localZoneFileForState(zone.Name, currentETag)
		if !matches {
			s.logger.Warn("Local zone file missing or mismatched, forcing full fetch",
				zap.String("zone", zone.Name),
				zap.String("etag", currentETag))
			currentETag = ""
			currentBody = ""
		}
	}

	currentSerial, hasCurrentSerial := s.localZoneSerial(zone.Name)

	// Step 3: Conditional fetch using ETag
	artifact, err := s.client.FetchSignedZoneArtifactWithCurrent(ctx, zone.Name, currentETag, currentBody)
	if err != nil {
		return fmt.Errorf("failed to fetch zone: %w", err)
	}

	// If zone hasn't changed, skip the rest
	if artifact.NotModified {
		s.logger.Debug("Zone not modified (304)",
			zap.String("zone", zone.Name),
			zap.String("etag", currentETag))
		return nil
	}

	if hasCurrentSerial && zoneSerialBefore(artifact.Serial, currentSerial) {
		return fmt.Errorf("rejected stale signed zone: serial %d is older than local serial %d", artifact.Serial, currentSerial)
	}

	s.logger.Info("Zone updated, applying changes",
		zap.String("zone", zone.Name),
		zap.String("old_version", currentETag),
		zap.String("new_version", artifact.ETag),
		zap.Uint32("serial", artifact.Serial))

	// Step 4: Checksum verification is done in client.FetchSignedZone

	// Step 5: Atomic file write
	// Step 6: Backup old version (handled by FileManager)
	var validate func(zonePath string) error
	if s.validateZoneFile != nil {
		validate = func(zonePath string) error {
			return s.validateZoneFile(ctx, zone.Name, zonePath)
		}
	}
	hadPreviousZoneFile := s.fileMgr.ZoneExists(zone.Name)
	rollbackZoneFile, err := s.fileMgr.WriteZoneFileValidatedWithRollback(zone.Name, artifact.Content, validate)
	if err != nil {
		return fmt.Errorf("failed to write zone file: %w", err)
	}

	// Step 7: NSD/Unbound reload is handled by the caller (main agent loop) via hook.
	if s.onZoneApplied != nil {
		if err := s.onZoneApplied(ctx, zone.Name); err != nil {
			rollbackErr := s.rollbackFailedApply(ctx, zone.Name, hadPreviousZoneFile, rollbackZoneFile)
			if rollbackErr != nil {
				return errors.Join(
					fmt.Errorf("post-apply hook failed: %w", err),
					rollbackErr,
				)
			}
			return fmt.Errorf("post-apply hook failed: %w", err)
		}
	}

	s.logger.Info("Zone synchronized successfully",
		zap.String("zone", zone.Name),
		zap.String("version", artifact.ETag),
		zap.Uint32("serial", artifact.Serial))

	// Record the effective ETag/version returned by the controller.
	s.mu.Lock()
	state := s.getOrCreateStateLocked(zone.Name)
	state.Version = artifact.ETag
	s.mu.Unlock()

	return nil
}

func (s *Syncer) rollbackFailedApply(ctx context.Context, zoneName string, hadPrevious bool, rollbackZoneFile func() error) error {
	if hadPrevious {
		return errors.Join(
			rollbackZoneFile(),
			s.rollbackAppliedZone(ctx, zoneName, hadPrevious),
		)
	}

	if err := s.rollbackAppliedZone(ctx, zoneName, hadPrevious); err != nil {
		s.logger.Warn("Keeping newly applied zone file because service reference rollback failed",
			zap.String("zone", zoneName),
			zap.Error(err))
		return err
	}
	return rollbackZoneFile()
}

func (s *Syncer) rollbackAppliedZone(ctx context.Context, zoneName string, hadPrevious bool) error {
	if s.onZoneApplyRollback == nil {
		return nil
	}
	if err := s.onZoneApplyRollback(ctx, zoneName, hadPrevious); err != nil {
		s.logger.Error("Failed to roll back applied zone service references",
			zap.String("zone", zoneName),
			zap.Bool("had_previous", hadPrevious),
			zap.Error(err))
		return fmt.Errorf("rollback applied zone service references: %w", err)
	}
	s.logger.Info("Rolled back applied zone service references",
		zap.String("zone", zoneName),
		zap.Bool("had_previous", hadPrevious))
	return nil
}

func (s *Syncer) localZoneFileForState(zoneName, currentETag string) (string, bool) {
	if !s.fileMgr.ZoneExists(zoneName) {
		return "", false
	}

	expectedHash := etagValue(currentETag)
	if len(expectedHash) != 64 || !isHex(expectedHash) {
		return "", true
	}

	content, err := s.fileMgr.ReadZoneFile(zoneName)
	if err != nil {
		return "", false
	}

	sum := sha256.Sum256([]byte(content))
	if hex.EncodeToString(sum[:]) != expectedHash {
		return "", false
	}

	return content, true
}

func (s *Syncer) localZoneSerial(zoneName string) (uint32, bool) {
	if !s.fileMgr.ZoneExists(zoneName) {
		return 0, false
	}

	content, err := s.fileMgr.ReadZoneFile(zoneName)
	if err != nil {
		s.logger.Warn("Failed to read local zone file for serial check",
			zap.String("zone", zoneName),
			zap.Error(err))
		return 0, false
	}

	serial, err := parseZoneSOASerial(zoneName, content)
	if err != nil {
		s.logger.Warn("Failed to parse local SOA serial for rollback check",
			zap.String("zone", zoneName),
			zap.Error(err))
		return 0, false
	}

	return serial, true
}

func etagValue(etag string) string {
	etag = strings.TrimSpace(etag)
	etag = strings.TrimPrefix(etag, "W/")
	etag = strings.TrimSpace(etag)
	return strings.Trim(etag, "\"")
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// SyncZone synchronizes a specific zone by name.
// Useful for on-demand sync or testing.
func (s *Syncer) SyncZone(ctx context.Context, zoneName string) error {
	if _, err := validateControllerZoneName(zoneName); err != nil {
		return fmt.Errorf("invalid requested zone name: %w", err)
	}

	// Fetch zone info from controller
	zones, err := s.client.ListZones(ctx)
	if err != nil {
		s.recordZoneSyncFailure(zoneName, time.Now())
		return fmt.Errorf("failed to list zones: %w", err)
	}
	if err := validateControllerZoneList(zones); err != nil {
		s.recordZoneSyncFailure(zoneName, time.Now())
		return err
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
		s.recordZoneSyncFailure(zoneName, time.Now())
		return fmt.Errorf("zone not found: %s", zoneName)
	}

	if err := s.syncZone(ctx, *targetZone); err != nil {
		s.recordZoneSyncFailure(targetZone.Name, time.Now())
		return err
	}

	now := time.Now()
	s.recordZoneSyncSuccess(targetZone.Name, now)
	s.recordSyncSuccess(now)
	return nil
}

func validateControllerZoneList(zones []ZoneInfo) error {
	seen := make(map[string]int, len(zones))
	for i, zone := range zones {
		normalized, err := validateControllerZoneName(zone.Name)
		if err != nil {
			return fmt.Errorf("invalid zone name from controller at index %d: %w", i, err)
		}
		if previous, exists := seen[normalized]; exists {
			return fmt.Errorf("duplicate zone name from controller at index %d: %q duplicates index %d", i, zone.Name, previous)
		}
		seen[normalized] = i
	}
	return nil
}

func validateControllerZoneName(zoneName string) (string, error) {
	normalized := model.NormalizeZoneName(zoneName)
	if err := model.ValidateZoneName(normalized); err != nil {
		return "", fmt.Errorf("%q: %w", zoneName, err)
	}
	return normalized, nil
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

// FailedZoneCount returns the number of zones with outstanding sync failures.
func (s *Syncer) FailedZoneCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, state := range s.zoneStates {
		if state.FailCount > 0 {
			count++
		}
	}
	return count
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
	if duration <= 0 {
		return time.Nanosecond
	}
	if s.config.Jitter <= 0 {
		return duration
	}

	// Add random jitter: duration ± jitter/2
	jitterNanos := s.config.Jitter.Nanoseconds()
	randomJitter := rand.Int63n(jitterNanos) - (jitterNanos / 2)

	next := duration + time.Duration(randomJitter)
	minDuration := duration / 2
	if minDuration <= 0 {
		minDuration = time.Nanosecond
	}
	if next < minDuration {
		return minDuration
	}
	return next
}
