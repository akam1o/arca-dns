package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

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
	if err := fm.ensureZoneDirectory(); err != nil {
		return nil, err
	}

	targetPath := fm.GetZonePath(zoneName) // Use safe path with GetZonePath

	// Check disk space (require at least 100MB free)
	if err := fm.checkDiskSpace(100 * 1024 * 1024); err != nil {
		return nil, fmt.Errorf("insufficient disk space: %w", err)
	}

	snapshot, err := snapshotZoneFile(targetPath)
	if err != nil {
		return nil, err
	}

	// Write to temporary file and sync it before publishing.
	tmpPath, err := writeTempFileSync(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".*.tmp", []byte(content), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write temporary file: %w", err)
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if validate != nil {
		if err := validate(tmpPath); err != nil {
			return nil, fmt.Errorf("zone validation failed: %w", err)
		}
	}

	backupPath := ""
	// Backup old version if it exists
	if _, err := os.Stat(targetPath); err == nil {
		backupPath, err = fm.backupFile(targetPath)
		if err != nil {
			return nil, fmt.Errorf("failed to backup old version: %w", err)
		}
	}

	// Atomic rename (this is the commit point)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return nil, fmt.Errorf("failed to rename temporary file: %w", err)
	}
	cleanupTmp = false
	if err := fm.fsyncDir(filepath.Dir(targetPath)); err != nil {
		return nil, errors.Join(
			fmt.Errorf("fsync zone directory: %w", err),
			rollbackZoneFileCommit(targetPath, snapshot, backupPath),
		)
	}

	rollbackManagedZone, err := fm.recordManagedZoneWithRollback(zoneName)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("failed to record managed zone: %w", err),
			rollbackZoneFileCommit(targetPath, snapshot, backupPath),
		)
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
			if err := removeRollbackBackup(backupPath); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}, nil
}

func rollbackZoneFileCommit(targetPath string, snapshot zoneFileSnapshot, backupPath string) error {
	var errs []error
	if err := restoreZoneFileSnapshot(targetPath, snapshot); err != nil {
		errs = append(errs, err)
	}
	if backupPath != "" {
		if err := removeRollbackBackup(backupPath); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeRollbackBackup(backupPath string) error {
	if err := os.Remove(backupPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove rollback backup: %w", err)
	}
	if err := syncDir(filepath.Dir(backupPath)); err != nil {
		return fmt.Errorf("fsync rollback backup directory: %w", err)
	}
	return nil
}

// GetZonePath returns the path to a zone file with safe filename.
func (fm *FileManager) GetZonePath(zoneName string) string {
	return ZoneFilePath(fm.zoneDir, zoneName)
}

// ZoneExists checks if a zone file exists.
func (fm *FileManager) ZoneExists(zoneName string) bool {
	if err := fm.validateZoneDirectoryIfExists(); err != nil {
		return false
	}
	path := fm.GetZonePath(zoneName)
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// ReadZoneFile reads a zone file.
func (fm *FileManager) ReadZoneFile(zoneName string) (string, error) {
	if err := fm.validateZoneDirectoryIfExists(); err != nil {
		return "", err
	}
	path := fm.GetZonePath(zoneName)
	content, _, err := readRegularSyncFile(path, "zone file")
	if err != nil {
		return "", fmt.Errorf("failed to read zone file: %w", err)
	}
	return string(content), nil
}

// DeleteZoneFile deletes a zone file and its backups.
func (fm *FileManager) DeleteZoneFile(zoneName string) error {
	if err := fm.validateZoneDirectoryIfExists(); err != nil {
		return err
	}
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
	changed := false

	// Delete main file
	if err := os.Remove(targetPath); err == nil {
		changed = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete zone file: %w", err)
	}

	// Delete backups
	backups, err := fm.listBackups(zoneName)
	if err != nil {
		fm.logger.Warn("Failed to list backups after deleting zone file",
			zap.String("zone", zoneName),
			zap.Error(err))
		if changed {
			if syncErr := fm.fsyncDir(fm.zoneDir); syncErr != nil {
				return fmt.Errorf("fsync zone directory after delete: %w", syncErr)
			}
		}
		return nil
	}

	for _, backup := range backups {
		if err := os.Remove(backup); err == nil {
			changed = true
		} else if !os.IsNotExist(err) {
			fm.logger.Warn("Failed to delete backup",
				zap.String("path", backup),
				zap.Error(err))
		}
	}

	if changed {
		if err := fm.fsyncDir(fm.zoneDir); err != nil {
			return fmt.Errorf("fsync zone directory after delete: %w", err)
		}
	}

	return nil
}

// backupFile creates a backup of the given file.
// Backups are named: {filename}.backup.{random}
func (fm *FileManager) backupFile(path string) (string, error) {
	// Copy file
	content, _, err := readRegularSyncFile(path, "zone file")
	if err != nil {
		return "", fmt.Errorf("failed to read file for backup: %w", err)
	}

	backupPath, err := writeTempFileSync(filepath.Dir(path), filepath.Base(path)+".backup.*", content, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write backup file: %w", err)
	}
	if err := fm.fsyncDir(filepath.Dir(backupPath)); err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("failed to fsync backup directory: %w", err)
	}

	return backupPath, nil
}

type zoneFileSnapshot struct {
	exists bool
	mode   os.FileMode
	data   []byte
}

func snapshotZoneFile(path string) (zoneFileSnapshot, error) {
	data, mode, err := readRegularSyncFile(path, "active zone file")
	if err != nil {
		if os.IsNotExist(err) {
			return zoneFileSnapshot{}, nil
		}
		return zoneFileSnapshot{}, fmt.Errorf("read active zone file: %w", err)
	}
	return zoneFileSnapshot{
		exists: true,
		mode:   mode,
		data:   data,
	}, nil
}

func restoreZoneFileSnapshot(path string, snapshot zoneFileSnapshot) error {
	if !snapshot.exists {
		if err := os.Remove(path); err == nil {
			if err := syncDir(filepath.Dir(path)); err != nil {
				return fmt.Errorf("fsync rolled back zone directory: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("remove rolled back zone file: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create zone directory for rollback: %w", err)
	}

	tmpPath, err := writeTempFileSync(filepath.Dir(path), "."+filepath.Base(path)+".*.rollback", snapshot.data, snapshot.mode)
	if err != nil {
		return fmt.Errorf("write rollback zone file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename rollback zone file: %w", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("fsync rollback zone directory: %w", err)
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
		deleted := false
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
			} else {
				deleted = true
			}
		}
		if deleted {
			if err := fm.fsyncDir(fm.zoneDir); err != nil {
				return fmt.Errorf("fsync zone directory after backup cleanup: %w", err)
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
	if err := fm.validateZoneDirectoryIfExists(); err != nil {
		return nil, err
	}

	path := fm.managedZonesIndexPath()
	data, _, err := readRegularSyncFile(path, "managed zone index")
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

func readRegularSyncFile(path string, label string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, fmt.Errorf("%s must not be a symlink: %s", label, path)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s must be a regular file: %s", label, path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, 0, fmt.Errorf("%s changed while opening: %s", label, path)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s must be a regular file: %s", label, path)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, err
	}
	return data, openedInfo.Mode().Perm(), nil
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

	if err := fm.ensureZoneDirectory(); err != nil {
		return err
	}

	path := fm.managedZonesIndexPath()
	tmpPath, err := writeTempFileSync(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp", data, 0644)
	if err != nil {
		return fmt.Errorf("write managed zone index tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename managed zone index: %w", err)
	}
	if err := fm.fsyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("fsync managed zone index directory: %w", err)
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

func writeTempFileSync(dir string, pattern string, data []byte, perm os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}

	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if n, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	} else if n != len(data) {
		_ = tmp.Close()
		return "", io.ErrShortWrite
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	cleanupTmp = false
	return tmpPath, nil
}

func (fm *FileManager) fsyncDir(path string) error {
	return syncDir(path)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	if err := dir.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
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
	if err := fm.ensureZoneDirectory(); err != nil {
		return err
	}

	// Check write permissions with an unpredictable temp file to avoid following symlinks.
	testFile, err := writeTempFileSync(fm.zoneDir, ".write_test-*", []byte("test"), 0644)
	if err != nil {
		return fmt.Errorf("zone directory is not writable: %w", err)
	}
	if err := os.Remove(testFile); err != nil {
		return fmt.Errorf("failed to remove zone directory write test file: %w", err)
	}
	if err := fm.fsyncDir(fm.zoneDir); err != nil {
		return fmt.Errorf("fsync zone directory after write test cleanup: %w", err)
	}

	return nil
}

func (fm *FileManager) ensureZoneDirectory() error {
	existed := true
	if err := validateExistingZoneDirectory(fm.zoneDir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat zone directory: %w", err)
		}
		existed = false
	}

	if err := os.MkdirAll(fm.zoneDir, 0755); err != nil {
		return fmt.Errorf("failed to create zone directory: %w", err)
	}
	if err := validateExistingZoneDirectory(fm.zoneDir); err != nil {
		return fmt.Errorf("stat zone directory: %w", err)
	}
	if !existed {
		if err := syncDir(filepath.Dir(fm.zoneDir)); err != nil {
			return fmt.Errorf("fsync zone directory parent: %w", err)
		}
	}

	return nil
}

func (fm *FileManager) validateZoneDirectoryIfExists() error {
	if err := validateExistingZoneDirectory(fm.zoneDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat zone directory: %w", err)
	}
	return nil
}

func validateExistingZoneDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("zone directory must not be a symlink: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("zone path must be a directory: %s", path)
	}
	return nil
}
