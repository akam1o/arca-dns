package sync

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestFileManager_WriteZoneFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)

	// Ensure directory exists
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	// Write zone file
	zoneName := "example.com."
	content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`

	if err := fm.WriteZoneFile(zoneName, content); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	managedZones, err := fm.listManagedZoneFiles()
	if err != nil {
		t.Fatalf("listManagedZoneFiles failed: %v", err)
	}
	if len(managedZones) != 1 || managedZones[0] != "example.com" {
		t.Fatalf("managed zones mismatch: got %v", managedZones)
	}

	// Verify file exists
	if !fm.ZoneExists(zoneName) {
		t.Error("Zone file should exist")
	}

	// Read and verify content
	readContent, err := fm.ReadZoneFile(zoneName)
	if err != nil {
		t.Fatalf("ReadZoneFile failed: %v", err)
	}

	if readContent != content {
		t.Errorf("Content mismatch: expected %q, got %q", content, readContent)
	}
}

func TestFileManager_WriteZoneFileDoesNotFollowPredictableTempSymlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."
	targetPath := fm.GetZonePath(zoneName)
	sentinelPath := filepath.Join(tmpDir, "sentinel")
	sentinel := []byte("keep")
	if err := os.WriteFile(sentinelPath, sentinel, 0600); err != nil {
		t.Fatalf("failed to write sentinel: %v", err)
	}
	if err := os.Symlink(sentinelPath, targetPath+".tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, content); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("failed to read sentinel: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("sentinel = %q, want %q", got, sentinel)
	}

	linkInfo, err := os.Lstat(targetPath + ".tmp")
	if err != nil {
		t.Fatalf("predictable temp symlink should remain untouched: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected predictable temp path to remain a symlink, mode=%v", linkInfo.Mode())
	}
}

func TestFileManager_WriteZoneFileManagedIndexFailureDoesNotPublish(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)

	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}
	if err := os.Mkdir(fm.managedZonesIndexPath(), 0755); err != nil {
		t.Fatalf("Failed to block managed index path: %v", err)
	}

	zoneName := "example.com."
	content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, content); err == nil {
		t.Fatal("WriteZoneFile should fail when the managed zone index cannot be written")
	}

	if fm.ZoneExists(zoneName) {
		t.Fatal("zone file should not be published when managed index recording fails")
	}
	if _, err := os.Stat(fm.GetZonePath(zoneName) + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary zone file should be removed, stat err=%v", err)
	}
	tempPattern := filepath.Join(tmpDir, "."+filepath.Base(fm.GetZonePath(zoneName))+".*.tmp")
	matches, globErr := filepath.Glob(tempPattern)
	if globErr != nil {
		t.Fatalf("temporary zone glob failed: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary zone files should be removed, got %v", matches)
	}
}

func TestFileManager_WriteZoneFileDoesNotFollowManagedIndexTempSymlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	indexPath := fm.managedZonesIndexPath()
	sentinelPath := filepath.Join(tmpDir, "sentinel")
	sentinel := []byte("keep")
	if err := os.WriteFile(sentinelPath, sentinel, 0600); err != nil {
		t.Fatalf("failed to write sentinel: %v", err)
	}
	if err := os.Symlink(sentinelPath, indexPath+".tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	zoneName := "example.com."
	content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, content); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("failed to read sentinel: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("sentinel = %q, want %q", got, sentinel)
	}

	linkInfo, err := os.Lstat(indexPath + ".tmp")
	if err != nil {
		t.Fatalf("predictable managed index temp symlink should remain untouched: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected predictable managed index temp path to remain a symlink, mode=%v", linkInfo.Mode())
	}
}

func TestFileManager_WriteZoneFileRollbackDoesNotFollowPredictableSymlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."
	original := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	replacement := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122802 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, original); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	targetPath := fm.GetZonePath(zoneName)
	sentinelPath := filepath.Join(tmpDir, "rollback-sentinel")
	sentinel := []byte("keep")
	if err := os.WriteFile(sentinelPath, sentinel, 0600); err != nil {
		t.Fatalf("failed to write sentinel: %v", err)
	}
	if err := os.Symlink(sentinelPath, targetPath+".rollback"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if err := os.Remove(fm.managedZonesIndexPath()); err != nil {
		t.Fatalf("failed to remove managed index: %v", err)
	}
	if err := os.Mkdir(fm.managedZonesIndexPath(), 0755); err != nil {
		t.Fatalf("failed to block managed index path: %v", err)
	}

	if err := fm.WriteZoneFile(zoneName, replacement); err == nil {
		t.Fatal("WriteZoneFile should fail when managed index read is blocked")
	}

	current, err := fm.ReadZoneFile(zoneName)
	if err != nil {
		t.Fatalf("ReadZoneFile failed: %v", err)
	}
	if current != original {
		t.Fatalf("current zone file changed after rollback failure path")
	}

	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("failed to read sentinel: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("sentinel = %q, want %q", got, sentinel)
	}

	linkInfo, err := os.Lstat(targetPath + ".rollback")
	if err != nil {
		t.Fatalf("predictable rollback symlink should remain untouched: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected predictable rollback path to remain a symlink, mode=%v", linkInfo.Mode())
	}
}

func TestFileManager_Backup(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)

	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."

	// Write initial version
	content1 := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, content1); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	// Write second version (should create backup)
	content2 := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122802 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, content2); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	// Check that backup was created
	backups, err := fm.listBackups(zoneName)
	if err != nil {
		t.Fatalf("listBackups failed: %v", err)
	}

	if len(backups) != 1 {
		t.Errorf("Expected 1 backup, got %d", len(backups))
	}

	// Current file should have new content
	currentContent, err := fm.ReadZoneFile(zoneName)
	if err != nil {
		t.Fatalf("ReadZoneFile failed: %v", err)
	}

	if currentContent != content2 {
		t.Errorf("Current content should be content2")
	}
}

func TestFileManager_BackupDoesNotFollowPredictableSymlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."
	content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, content); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	zonePath := fm.GetZonePath(zoneName)
	sentinelPath := filepath.Join(tmpDir, "backup-sentinel")
	sentinel := []byte("keep")
	if err := os.WriteFile(sentinelPath, sentinel, 0600); err != nil {
		t.Fatalf("failed to write sentinel: %v", err)
	}
	predictableBackupPath := zonePath + ".backup.123456789"
	if err := os.Symlink(sentinelPath, predictableBackupPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	backupPath, err := fm.backupFile(zonePath)
	if err != nil {
		t.Fatalf("backupFile failed: %v", err)
	}
	if backupPath == predictableBackupPath {
		t.Fatalf("backup path used predictable symlink path")
	}

	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("failed to read sentinel: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("sentinel = %q, want %q", got, sentinel)
	}

	linkInfo, err := os.Lstat(predictableBackupPath)
	if err != nil {
		t.Fatalf("predictable backup symlink should remain untouched: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected predictable backup path to remain a symlink, mode=%v", linkInfo.Mode())
	}

	backupContent, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed to read backup: %v", err)
	}
	if string(backupContent) != content {
		t.Fatalf("backup content changed")
	}
}

func TestFileManager_BackupCleanup(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 2, logger) // Keep only 2 backups

	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."

	// Write 5 versions
	// First write creates no backup (no existing file)
	// Second write creates 1 backup
	// Third write creates 2 backups, then cleanup keeps 2
	// Fourth write creates 3 backups, cleanup removes oldest, keeps 2
	// Fifth write creates 3 backups, cleanup removes oldest, keeps 2
	for i := 1; i <= 5; i++ {
		content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 202412280` + string(rune('0'+i)) + ` 3600 1800 604800 86400`
		if err := fm.WriteZoneFile(zoneName, content); err != nil {
			t.Fatalf("WriteZoneFile failed on version %d: %v", i, err)
		}
	}

	// Should have only 2 backups (most recent)
	// Note: First write doesn't create a backup (no existing file)
	// So we have 4 writes that create backups, cleanup keeps 2
	backups, err := fm.listBackups(zoneName)
	if err != nil {
		t.Fatalf("listBackups failed: %v", err)
	}

	if len(backups) != 2 {
		t.Errorf("Expected 2 backups, got %d", len(backups))
	}
}

func TestFileManager_NegativeBackupVersionsKeepsNoBackups(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, -1, logger)

	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."
	content1 := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	content2 := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122802 3600 1800 604800 86400`

	if err := fm.WriteZoneFile(zoneName, content1); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}
	if err := fm.WriteZoneFile(zoneName, content2); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	backups, err := fm.listBackups(zoneName)
	if err != nil {
		t.Fatalf("listBackups failed: %v", err)
	}
	if len(backups) != 0 {
		t.Fatalf("Expected 0 backups, got %d", len(backups))
	}
}

func TestFileManager_WriteZoneFileValidatedFailurePreservesCurrent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."
	original := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	replacement := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122802 3600 1800 604800 86400`

	if err := fm.WriteZoneFile(zoneName, original); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	err = fm.WriteZoneFileValidated(zoneName, replacement, func(zonePath string) error {
		if _, statErr := os.Stat(zonePath); statErr != nil {
			t.Fatalf("temporary zone path should exist during validation: %v", statErr)
		}
		return errors.New("invalid zone")
	})
	if err == nil {
		t.Fatal("expected validation failure")
	}

	current, err := fm.ReadZoneFile(zoneName)
	if err != nil {
		t.Fatalf("ReadZoneFile failed: %v", err)
	}
	if current != original {
		t.Fatalf("current zone file changed after validation failure")
	}
	if _, err := os.Stat(fm.GetZonePath(zoneName) + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file should be removed, got err=%v", err)
	}

	backups, err := fm.listBackups(zoneName)
	if err != nil {
		t.Fatalf("listBackups failed: %v", err)
	}
	if len(backups) != 0 {
		t.Fatalf("expected no backup when validation fails, got %d", len(backups))
	}
}

func TestFileManager_DeleteZoneFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)

	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	zoneName := "example.com."

	// Write zone file
	content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	if err := fm.WriteZoneFile(zoneName, content); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	// Write again to create backup
	if err := fm.WriteZoneFile(zoneName, content+"updated"); err != nil {
		t.Fatalf("WriteZoneFile failed: %v", err)
	}

	// Delete zone file
	if err := fm.DeleteZoneFile(zoneName); err != nil {
		t.Fatalf("DeleteZoneFile failed: %v", err)
	}

	// Verify file and backups are gone
	if fm.ZoneExists(zoneName) {
		t.Error("Zone file should not exist")
	}

	backups, err := fm.listBackups(zoneName)
	if err != nil {
		t.Fatalf("listBackups failed: %v", err)
	}

	if len(backups) != 0 {
		t.Errorf("Expected 0 backups, got %d", len(backups))
	}

	managedZones, err := fm.listManagedZoneFiles()
	if err != nil {
		t.Fatalf("listManagedZoneFiles failed: %v", err)
	}
	if len(managedZones) != 0 {
		t.Fatalf("managed zones should be empty after delete, got %v", managedZones)
	}
}

func TestFileManager_GetZonePath(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	fm := NewFileManager("/var/lib/nsd/zones", 3, logger)

	path := fm.GetZonePath("example.com.")
	// SafeZoneFilename removes trailing dots, so "example.com." becomes "example.com"
	expected := filepath.Join("/var/lib/nsd/zones", "example.com.zone")

	if path != expected {
		t.Errorf("Expected path %s, got %s", expected, path)
	}
}

func TestFileManager_EnsureDirectory(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "nested", "zones")

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(subDir, 3, logger)

	// Ensure directory (should create nested directories)
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(subDir)
	if err != nil {
		t.Fatalf("Directory should exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("Should be a directory")
	}

	// Verify write permissions
	testFile := filepath.Join(subDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Errorf("Directory should be writable: %v", err)
	}
}
