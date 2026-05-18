package sync

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestFileManager_ReadZoneFileRejectsSymlinkedZoneFile(t *testing.T) {
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
	if err := os.WriteFile(sentinelPath, []byte("secret"), 0600); err != nil {
		t.Fatalf("failed to write sentinel: %v", err)
	}
	if err := os.Symlink(sentinelPath, targetPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err = fm.ReadZoneFile(zoneName)
	if err == nil {
		t.Fatal("ReadZoneFile should reject symlinked zone file")
	}
	if !strings.Contains(err.Error(), "zone file") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink zone file error, got %v", err)
	}
	if fm.ZoneExists(zoneName) {
		t.Fatal("ZoneExists should not treat symlinked zone file as an active zone")
	}
}

func TestFileManager_WriteZoneFileRejectsSymlinkedExistingZoneFile(t *testing.T) {
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
	sentinel := []byte("secret")
	if err := os.WriteFile(sentinelPath, sentinel, 0600); err != nil {
		t.Fatalf("failed to write sentinel: %v", err)
	}
	if err := os.Symlink(sentinelPath, targetPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	content := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	err = fm.WriteZoneFile(zoneName, content)
	if err == nil {
		t.Fatal("WriteZoneFile should reject symlinked existing zone file")
	}
	if !strings.Contains(err.Error(), "active zone file") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink active zone file error, got %v", err)
	}

	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("failed to read sentinel: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("sentinel = %q, want %q", got, sentinel)
	}

	linkInfo, err := os.Lstat(targetPath)
	if err != nil {
		t.Fatalf("symlinked target should remain untouched: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected target path to remain a symlink, mode=%v", linkInfo.Mode())
	}

	backups, err := filepath.Glob(ZoneBackupPattern(tmpDir, zoneName))
	if err != nil {
		t.Fatalf("backup glob failed: %v", err)
	}
	if len(backups) != 0 {
		t.Fatalf("symlinked zone file should not be backed up, got %v", backups)
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

func TestFileManager_ReadManagedZonesRejectsSymlinkedIndex(t *testing.T) {
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

	realIndexPath := filepath.Join(tmpDir, "managed-zones.real.json")
	if err := os.WriteFile(realIndexPath, []byte(`{"entries":[{"name":"example.com.","file":"example.com"}]}`), 0600); err != nil {
		t.Fatalf("failed to write real managed index: %v", err)
	}
	if err := os.Symlink(realIndexPath, fm.managedZonesIndexPath()); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err = fm.readManagedZones()
	if err == nil {
		t.Fatal("readManagedZones should reject symlinked managed zone index")
	}
	if !strings.Contains(err.Error(), "managed zone index") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink managed zone index error, got %v", err)
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

func TestFileManager_EnsureDirectoryRejectsSymlinkedZoneDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	targetDir := filepath.Join(tmpDir, "target")
	zoneDir := filepath.Join(tmpDir, "zones")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}
	if err := os.Symlink(targetDir, zoneDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(zoneDir, 3, logger)
	err = fm.EnsureDirectory()
	if err == nil {
		t.Fatal("EnsureDirectory should reject symlinked zone directory")
	}
	if !strings.Contains(err.Error(), "zone directory") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("EnsureDirectory error = %v, want symlinked zone directory error", err)
	}

	matches, globErr := filepath.Glob(filepath.Join(targetDir, ".write_test-*"))
	if globErr != nil {
		t.Fatalf("Failed to inspect target dir: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("write test should not run inside symlink target, got %v", matches)
	}
}

func TestFileManager_WriteZoneFileRejectsSymlinkedZoneDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	targetDir := filepath.Join(tmpDir, "target")
	zoneDir := filepath.Join(tmpDir, "zones")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}
	if err := os.Symlink(targetDir, zoneDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(zoneDir, 3, logger)
	err = fm.WriteZoneFile("example.com.", "$ORIGIN example.com.\n")
	if err == nil {
		t.Fatal("WriteZoneFile should reject symlinked zone directory")
	}
	if !strings.Contains(err.Error(), "zone directory") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("WriteZoneFile error = %v, want symlinked zone directory error", err)
	}
	if _, statErr := os.Stat(filepath.Join(targetDir, "example.com.zone")); !os.IsNotExist(statErr) {
		t.Fatalf("zone file should not be written inside symlink target, stat err=%v", statErr)
	}
}

func TestFileManager_DeleteZoneFileRejectsSymlinkedZoneDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	targetDir := filepath.Join(tmpDir, "target")
	zoneDir := filepath.Join(tmpDir, "zones")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}
	targetZonePath := filepath.Join(targetDir, "example.com.zone")
	if err := os.WriteFile(targetZonePath, []byte("keep"), 0644); err != nil {
		t.Fatalf("Failed to write target zone file: %v", err)
	}
	if err := os.Symlink(targetDir, zoneDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(zoneDir, 3, logger)
	err = fm.DeleteZoneFile("example.com.")
	if err == nil {
		t.Fatal("DeleteZoneFile should reject symlinked zone directory")
	}
	if !strings.Contains(err.Error(), "zone directory") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("DeleteZoneFile error = %v, want symlinked zone directory error", err)
	}
	if _, statErr := os.Stat(targetZonePath); statErr != nil {
		t.Fatalf("zone file in symlink target should remain, stat err=%v", statErr)
	}
}

func TestFileManager_EnsureDirectoryDoesNotFollowWriteTestSymlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "arca-dns-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sentinelPath := filepath.Join(tmpDir, "sentinel")
	if err := os.WriteFile(sentinelPath, []byte("unchanged"), 0600); err != nil {
		t.Fatalf("Failed to write sentinel: %v", err)
	}

	writeTestPath := filepath.Join(tmpDir, ".write_test")
	if err := os.Symlink(sentinelPath, writeTestPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	logger, _ := zap.NewDevelopment()
	fm := NewFileManager(tmpDir, 3, logger)
	if err := fm.EnsureDirectory(); err != nil {
		t.Fatalf("EnsureDirectory failed: %v", err)
	}

	sentinelData, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("Failed to read sentinel: %v", err)
	}
	if string(sentinelData) != "unchanged" {
		t.Fatalf("sentinel was modified: %q", string(sentinelData))
	}

	info, err := os.Lstat(writeTestPath)
	if err != nil {
		t.Fatalf("write test symlink should remain: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("write test path should remain a symlink")
	}
}
