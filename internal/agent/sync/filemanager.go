package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"go.uber.org/zap"
)

// FileManager handles atomic file writes, backups, and version management.
type FileManager struct {
	zoneDir        string
	backupVersions int
	logger         *zap.Logger
}

const managedZonesIndexFile = ".arca-dns-managed-zones.json"

type managedZonesIndex struct {
	Zones   []string           `json:"zones,omitempty"`
	Entries []managedZoneEntry `json:"entries,omitempty"`
}

type managedZoneEntry struct {
	Name string `json:"name"`
	File string `json:"file"`
}

type managedZoneRef struct {
	ZoneName string
	SafeName string
}

// NewFileManager creates a new file manager.
func NewFileManager(zoneDir string, backupVersions int, logger *zap.Logger) *FileManager {
	if backupVersions < 0 {
		backupVersions = 0
	}
	return &FileManager{
		zoneDir:        zoneDir,
		backupVersions: backupVersions,
		logger:         logger,
	}
}

// WriteZoneFile writes a zone file atomically with backup.
// Algorithm:
// 1. Check disk space before write
// 2. Write to temporary file
// 3. Fsync the temporary file
// 4. Backup old version (if exists)
// 5. Record the file as agent-managed
// 6. Rename temporary file to target (atomic operation)
// 7. Clean up old backups
func (fm *FileManager) WriteZoneFile(zoneName string, content string) error {
	return fm.WriteZoneFileValidated(zoneName, content, nil)
}

// WriteZoneFileValidated writes a zone file atomically after validating the
// temporary file, if a validator is provided.
func (fm *FileManager) WriteZoneFileValidated(zoneName string, content string, validate func(zonePath string) error) error {
	_, err := fm.WriteZoneFileValidatedWithRollback(zoneName, content, validate)
	return err
}

// WriteZoneFileValidatedWithRollback writes a zone file atomically and returns
// a rollback function that restores the previous active file and managed-zone
// index entry. The rollback function is intended for service hook failures
// after the filesystem commit has already succeeded.
func (fm *FileManager) WriteZoneFileValidatedWithRollback(zoneName string, content string, validate func(zonePath string) error) (func() error, error) {
	targetPath := fm.GetZonePath(zoneName) // Use safe path with GetZonePath
	tmpPath := targetPath + ".tmp"

	// Check disk space (require at least 100MB free)
	if err := fm.checkDiskSpace(100 * 1024 * 1024); err != nil {
		return nil, fmt.Errorf("insufficient disk space: %w", err)
	}

	snapshot, err := snapshotZoneFile(targetPath)
	if err != nil {
		return nil, err
	}

	// Write to temporary file
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Fsync the temporary file to ensure it's written to disk
	if err := fm.fsyncFile(tmpPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to fsync temporary file: %w", err)
	}

	if validate != nil {
		if err := validate(tmpPath); err != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("zone validation failed: %w", err)
		}
	}

	backupPath := ""
	// Backup old version if it exists
	if _, err := os.Stat(targetPath); err == nil {
		backupPath, err = fm.backupFile(targetPath)
		if err != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("failed to backup old version: %w", err)
		}
	}

	rollbackManagedZone, err := fm.recordManagedZoneWithRollback(zoneName)
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to record managed zone: %w", err)
	}

	// Atomic rename (this is the commit point)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		if rollbackErr := rollbackManagedZone(); rollbackErr != nil {
			fm.logger.Warn("Failed to roll back managed zone index",
				zap.String("zone", zoneName),
				zap.Error(rollbackErr))
		}
		return nil, fmt.Errorf("failed to rename temporary file: %w", err)
	}

	// Clean up old backups
	if err := fm.cleanupBackups(zoneName); err != nil {
		// Log but don't fail - the zone file was written successfully
		fm.logger.Warn("Failed to clean up old backups",
			zap.String("zone", zoneName),
			zap.Error(err))
	}

	fm.logger.Info("Zone file written successfully",
		zap.String("zone", zoneName),
		zap.String("path", targetPath))

	return func() error {
		var errs []error
		if err := restoreZoneFileSnapshot(targetPath, snapshot); err != nil {
			errs = append(errs, err)
		}
		if rollbackManagedZone != nil {
			if err := rollbackManagedZone(); err != nil {
				errs = append(errs, fmt.Errorf("roll back managed zone index: %w", err))
			}
		}
		if backupPath != "" {
			if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove rollback backup: %w", err))
			}
		}
		return errors.Join(errs...)
	}, nil
}

// GetZonePath returns the path to a zone file with safe filename.
func (fm *FileManager) GetZonePath(zoneName string) string {
	return ZoneFilePath(fm.zoneDir, zoneName)
}

// ZoneExists checks if a zone file exists.
func (fm *FileManager) ZoneExists(zoneName string) bool {
	path := fm.GetZonePath(zoneName)
	_, err := os.Stat(path)
	return err == nil
}

// ReadZoneFile reads a zone file.
func (fm *FileManager) ReadZoneFile(zoneName string) (string, error) {
	path := fm.GetZonePath(zoneName)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read zone file: %w", err)
	}
	return string(content), nil
}

// DeleteZoneFile deletes a zone file and its backups.
func (fm *FileManager) DeleteZoneFile(zoneName string) error {
	targetPath := fm.GetZonePath(zoneName)

	if err := fm.deleteZoneFiles(zoneName); err != nil {
		return err
	}

	if err := fm.removeManagedZone(zoneName); err != nil {
		return fmt.Errorf("failed to update managed zone index: %w", err)
	}

	fm.logger.Info("Zone file deleted",
		zap.String("zone", zoneName),
		zap.String("path", targetPath))

	return nil
}

func (fm *FileManager) deleteZoneFiles(zoneName string) error {
	targetPath := fm.GetZonePath(zoneName)

	// Delete main file
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete zone file: %w", err)
	}

	// Delete backups
	backups, err := fm.listBackups(zoneName)
	if err != nil {
		fm.logger.Warn("Failed to list backups after deleting zone file",
			zap.String("zone", zoneName),
			zap.Error(err))
		return nil
	}

	for _, backup := range backups {
		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			fm.logger.Warn("Failed to delete backup",
				zap.String("path", backup),
				zap.Error(err))
		}
	}

	return nil
}

// backupFile creates a backup of the given file.
// Backups are named: {filename}.backup.{nanoseconds}
func (fm *FileManager) backupFile(path string) (string, error) {
	// Use nanoseconds for unique timestamp
	backupPath := fmt.Sprintf("%s.backup.%d", path, time.Now().UnixNano())

	// Copy file
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file for backup: %w", err)
	}

	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to write backup file: %w", err)
	}

	return backupPath, nil
}

type zoneFileSnapshot struct {
	exists bool
	mode   os.FileMode
	data   []byte
}

func snapshotZoneFile(path string) (zoneFileSnapshot, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zoneFileSnapshot{}, nil
		}
		return zoneFileSnapshot{}, fmt.Errorf("stat active zone file: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return zoneFileSnapshot{}, fmt.Errorf("read active zone file: %w", err)
	}
	return zoneFileSnapshot{
		exists: true,
		mode:   info.Mode().Perm(),
		data:   data,
	}, nil
}

func restoreZoneFileSnapshot(path string, snapshot zoneFileSnapshot) error {
	if !snapshot.exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove rolled back zone file: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create zone directory for rollback: %w", err)
	}

	tmpPath := path + ".rollback"
	if err := os.WriteFile(tmpPath, snapshot.data, snapshot.mode); err != nil {
		return fmt.Errorf("write rollback zone file: %w", err)
	}
	file, err := os.OpenFile(tmpPath, os.O_RDWR, 0)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("open rollback zone file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync rollback zone file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close rollback zone file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename rollback zone file: %w", err)
	}
	return nil
}

// cleanupBackups removes old backup files, keeping only the most recent N versions.
func (fm *FileManager) cleanupBackups(zoneName string) error {
	backups, err := fm.listBackups(zoneName)
	if err != nil {
		return err
	}

	// If we have more backups than the limit, delete the oldest ones
	if len(backups) > fm.backupVersions {
		// Sort by modification time (oldest first)
		sort.Slice(backups, func(i, j int) bool {
			infoI, errI := os.Stat(backups[i])
			infoJ, errJ := os.Stat(backups[j])
			// If either file disappeared or can't be stat'd, put it first (will be deleted)
			if errI != nil {
				return true
			}
			if errJ != nil {
				return false
			}
			return infoI.ModTime().Before(infoJ.ModTime())
		})

		// Delete oldest backups
		toDelete := len(backups) - fm.backupVersions
		for i := 0; i < toDelete; i++ {
			if err := os.Remove(backups[i]); err != nil {
				fm.logger.Warn("Failed to delete old backup",
					zap.String("path", backups[i]),
					zap.Error(err))
			}
		}
	}

	return nil
}

// listBackups returns a list of backup files for a zone.
func (fm *FileManager) listBackups(zoneName string) ([]string, error) {
	pattern := ZoneBackupPattern(fm.zoneDir, zoneName)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}
	return matches, nil
}

func (fm *FileManager) managedZonesIndexPath() string {
	return filepath.Join(fm.zoneDir, managedZonesIndexFile)
}

func (fm *FileManager) readManagedZones() (map[string]string, error) {
	path := fm.managedZonesIndexPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read managed zone index: %w", err)
	}

	var index managedZonesIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse managed zone index: %w", err)
	}

	zones := make(map[string]string, len(index.Zones)+len(index.Entries))
	for _, entry := range index.Entries {
		fileName := entry.File
		if strings.TrimSpace(fileName) == "" {
			fileName = entry.Name
		}
		safeName := SafeZoneFilename(fileName)
		if safeName == "" {
			continue
		}
		zoneName := strings.TrimSpace(entry.Name)
		if zoneName == "" {
			zoneName = safeName
		} else {
			zoneName = model.NormalizeZoneName(zoneName)
		}
		zones[safeName] = zoneName
	}
	for _, zone := range index.Zones {
		safeName := SafeZoneFilename(zone)
		if safeName == "" {
			continue
		}
		// Backward compatibility for the previous index format, which only
		// stored the safe filename and cannot recover truncated long FQDNs.
		if _, exists := zones[safeName]; !exists {
			zones[safeName] = safeName
		}
	}
	return zones, nil
}

func (fm *FileManager) writeManagedZones(zones map[string]string) error {
	entries := make([]managedZoneEntry, 0, len(zones))
	for safeName, zoneName := range zones {
		entries = append(entries, managedZoneEntry{
			Name: zoneName,
			File: safeName,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].File < entries[j].File
	})

	data, err := json.MarshalIndent(managedZonesIndex{Entries: entries}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal managed zone index: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(fm.zoneDir, 0755); err != nil {
		return fmt.Errorf("create zone directory: %w", err)
	}

	path := fm.managedZonesIndexPath()
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write managed zone index tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename managed zone index: %w", err)
	}
	return nil
}

func (fm *FileManager) recordManagedZone(zoneName string) error {
	_, err := fm.recordManagedZoneWithRollback(zoneName)
	return err
}

func (fm *FileManager) recordManagedZoneWithRollback(zoneName string) (func() error, error) {
	zones, err := fm.readManagedZones()
	if err != nil {
		return nil, err
	}

	safeName := SafeZoneFilename(zoneName)
	previousZoneName, hadPrevious := zones[safeName]
	zones[safeName] = model.NormalizeZoneName(zoneName)
	if err := fm.writeManagedZones(zones); err != nil {
		return nil, err
	}

	return func() error {
		zones, err := fm.readManagedZones()
		if err != nil {
			return err
		}
		if hadPrevious {
			zones[safeName] = previousZoneName
		} else {
			delete(zones, safeName)
		}
		return fm.writeManagedZones(zones)
	}, nil
}

func (fm *FileManager) removeManagedZone(zoneName string) error {
	zones, err := fm.readManagedZones()
	if err != nil {
		return err
	}
	delete(zones, SafeZoneFilename(zoneName))
	return fm.writeManagedZones(zones)
}

func (fm *FileManager) listManagedZones() ([]managedZoneRef, error) {
	zones, err := fm.readManagedZones()
	if err != nil {
		return nil, err
	}

	refs := make([]managedZoneRef, 0, len(zones))
	for safeName, zoneName := range zones {
		refs = append(refs, managedZoneRef{
			ZoneName: zoneName,
			SafeName: safeName,
		})
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].SafeName < refs[j].SafeName
	})
	return refs, nil
}

func (fm *FileManager) listManagedZoneFiles() ([]string, error) {
	zones, err := fm.listManagedZones()
	if err != nil {
		return nil, err
	}

	zoneNames := make([]string, 0, len(zones))
	for _, zone := range zones {
		zoneNames = append(zoneNames, zone.SafeName)
	}
	sort.Strings(zoneNames)
	return zoneNames, nil
}

// fsyncFile performs fsync on a file to ensure it's written to disk.
func (fm *FileManager) fsyncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := file.Sync(); err != nil {
		return err
	}

	return nil
}

// checkDiskSpace checks if there is enough free disk space.
func (fm *FileManager) checkDiskSpace(requiredBytes uint64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(fm.zoneDir, &stat); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	// Available blocks * block size
	availableBytes := stat.Bavail * uint64(stat.Bsize)

	if availableBytes < requiredBytes {
		return fmt.Errorf("insufficient disk space: available=%d, required=%d", availableBytes, requiredBytes)
	}

	return nil
}

// EnsureDirectory ensures that the zone directory exists and has correct permissions.
func (fm *FileManager) EnsureDirectory() error {
	if err := os.MkdirAll(fm.zoneDir, 0755); err != nil {
		return fmt.Errorf("failed to create zone directory: %w", err)
	}

	// Check write permissions
	testFile := filepath.Join(fm.zoneDir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("zone directory is not writable: %w", err)
	}
	os.Remove(testFile)

	return nil
}
