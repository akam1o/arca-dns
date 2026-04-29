package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// FileManager handles atomic file writes, backups, and version management.
type FileManager struct {
	zoneDir        string
	backupVersions int
	logger         *zap.Logger
}

// NewFileManager creates a new file manager.
func NewFileManager(zoneDir string, backupVersions int, logger *zap.Logger) *FileManager {
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
// 5. Rename temporary file to target (atomic operation)
// 6. Clean up old backups
func (fm *FileManager) WriteZoneFile(zoneName string, content string) error {
	targetPath := fm.GetZonePath(zoneName) // Use safe path with GetZonePath
	tmpPath := targetPath + ".tmp"

	// Check disk space (require at least 100MB free)
	if err := fm.checkDiskSpace(100 * 1024 * 1024); err != nil {
		return fmt.Errorf("insufficient disk space: %w", err)
	}

	// Write to temporary file
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Fsync the temporary file to ensure it's written to disk
	if err := fm.fsyncFile(tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to fsync temporary file: %w", err)
	}

	// Backup old version if it exists
	if _, err := os.Stat(targetPath); err == nil {
		if err := fm.backupFile(targetPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to backup old version: %w", err)
		}
	}

	// Atomic rename (this is the commit point)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
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

	return nil
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

	// Delete main file
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete zone file: %w", err)
	}

	// Delete backups
	backups, err := fm.listBackups(zoneName)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	for _, backup := range backups {
		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			fm.logger.Warn("Failed to delete backup",
				zap.String("path", backup),
				zap.Error(err))
		}
	}

	fm.logger.Info("Zone file deleted",
		zap.String("zone", zoneName),
		zap.String("path", targetPath))

	return nil
}

// backupFile creates a backup of the given file.
// Backups are named: {filename}.backup.{nanoseconds}
func (fm *FileManager) backupFile(path string) error {
	// Use nanoseconds for unique timestamp
	backupPath := fmt.Sprintf("%s.backup.%d", path, time.Now().UnixNano())

	// Copy file
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file for backup: %w", err)
	}

	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
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

// listZoneFiles returns the safe zone names for managed zone files in the zone directory.
func (fm *FileManager) listZoneFiles() ([]string, error) {
	pattern := filepath.Join(fm.zoneDir, "*.zone")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list zone files: %w", err)
	}

	zoneNames := make([]string, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			return nil, fmt.Errorf("failed to stat zone file: %w", err)
		}
		if info.IsDir() {
			continue
		}

		fileName := filepath.Base(match)
		zoneNames = append(zoneNames, fileName[:len(fileName)-len(".zone")])
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
