package nsd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"go.uber.org/zap"
)

func TestNewController(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := config.NSDConfig{
		Enabled:       true,
		ControlPath:   "/usr/sbin/nsd-control",
		CheckzonePath: "/usr/sbin/nsd-checkzone",
		ReloadTimeout: 10 * time.Second,
	}

	ctrl := NewController(cfg, logger)

	if ctrl == nil {
		t.Fatal("Expected non-nil controller")
	}

	if ctrl.config.ControlPath != cfg.ControlPath {
		t.Errorf("Expected ControlPath %s, got %s", cfg.ControlPath, ctrl.config.ControlPath)
	}
}

func TestController_Disabled(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := config.NSDConfig{
		Enabled:       false, // Disabled
		ReloadTimeout: 10 * time.Second,
	}

	ctrl := NewController(cfg, logger)

	// All operations should succeed but do nothing when disabled
	if err := ctrl.ReloadZone("example.com."); err != nil {
		t.Errorf("ReloadZone should succeed when disabled: %v", err)
	}

	if err := ctrl.EnsureZone("example.com."); err != nil {
		t.Errorf("EnsureZone should succeed when disabled: %v", err)
	}

	if err := ctrl.DeleteZone("example.com."); err != nil {
		t.Errorf("DeleteZone should succeed when disabled: %v", err)
	}

	if err := ctrl.NotifyZone("example.com."); err != nil {
		t.Errorf("NotifyZone should succeed when disabled: %v", err)
	}

	if err := ctrl.Reload(); err != nil {
		t.Errorf("Reload should succeed when disabled: %v", err)
	}

	if err := ctrl.CheckZone("example.com.", "/tmp/test.zone"); err != nil {
		t.Errorf("CheckZone should succeed when disabled: %v", err)
	}

	status, err := ctrl.Status()
	if err != nil {
		t.Errorf("Status should succeed when disabled: %v", err)
	}
	if status != "disabled" {
		t.Errorf("Expected status 'disabled', got '%s'", status)
	}

	if ctrl.IsRunning() {
		t.Error("IsRunning should return false when disabled")
	}
}

func TestController_EnsureZoneConfig(t *testing.T) {
	tmpDir := t.TempDir()
	commandLog := filepath.Join(tmpDir, "commands.log")
	controlPath := filepath.Join(tmpDir, "nsd-control")
	controlScript := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + commandLog + "\"\n"
	if err := os.WriteFile(controlPath, []byte(controlScript), 0755); err != nil {
		t.Fatalf("Failed to write fake nsd-control: %v", err)
	}

	zoneDir := filepath.Join(tmpDir, "zones")
	zoneConfigPath := filepath.Join(tmpDir, "arca-dns-zones.conf")

	logger, _ := zap.NewDevelopment()
	ctrl := NewController(config.NSDConfig{
		Enabled:        true,
		ConfigPath:     filepath.Join(tmpDir, "nsd.conf"),
		ZoneConfigPath: zoneConfigPath,
		ControlPath:    controlPath,
		ZoneDirectory:  zoneDir,
		ReloadTimeout:  2 * time.Second,
	}, logger)

	if err := ctrl.EnsureZone("Example.COM."); err != nil {
		t.Fatalf("EnsureZone failed: %v", err)
	}
	if err := ctrl.EnsureZone("example.com."); err != nil {
		t.Fatalf("EnsureZone should be idempotent: %v", err)
	}

	configData, err := os.ReadFile(zoneConfigPath)
	if err != nil {
		t.Fatalf("Failed to read generated config: %v", err)
	}
	configText := string(configData)
	if !strings.Contains(configText, "# arca-dns-zone: example.com.") {
		t.Fatalf("Generated config missing zone marker:\n%s", configText)
	}
	if !strings.Contains(configText, `name: "example.com."`) {
		t.Fatalf("Generated config missing zone name:\n%s", configText)
	}
	if !strings.Contains(configText, filepath.Join(zoneDir, "example.com.zone")) {
		t.Fatalf("Generated config missing zonefile path:\n%s", configText)
	}

	logData, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("Failed to read command log: %v", err)
	}
	if got := strings.Count(string(logData), "reconfig"); got != 1 {
		t.Fatalf("Expected one reconfig for idempotent ensure, got %d log=%q", got, string(logData))
	}

	if err := ctrl.DeleteZone("example.com."); err != nil {
		t.Fatalf("DeleteZone failed: %v", err)
	}

	configData, err = os.ReadFile(zoneConfigPath)
	if err != nil {
		t.Fatalf("Failed to read generated config after delete: %v", err)
	}
	if strings.Contains(string(configData), "# arca-dns-zone: example.com.") {
		t.Fatalf("Generated config still contains deleted zone:\n%s", string(configData))
	}
}

func TestController_RejectsInvalidManagedZoneName(t *testing.T) {
	tmpDir := t.TempDir()
	zoneConfigPath := filepath.Join(tmpDir, "arca-dns-zones.conf")

	ctrl := NewController(config.NSDConfig{
		Enabled:        true,
		ConfigPath:     filepath.Join(tmpDir, "nsd.conf"),
		ZoneConfigPath: zoneConfigPath,
		ControlPath:    filepath.Join(tmpDir, "nsd-control"),
		ZoneDirectory:  filepath.Join(tmpDir, "zones"),
		ReloadTimeout:  2 * time.Second,
	}, zap.NewNop())

	err := ctrl.EnsureZone("bad.com\"\ninclude: \"/tmp/pwn\"")
	if err == nil {
		t.Fatal("EnsureZone should reject invalid zone names")
	}
	if !strings.Contains(err.Error(), "invalid zone name") {
		t.Fatalf("Unexpected error: %v", err)
	}
	if _, statErr := os.Stat(zoneConfigPath); !os.IsNotExist(statErr) {
		t.Fatalf("invalid zone name should not create config file, got err=%v", statErr)
	}
}

func TestWriteFileAtomicCleansTempFileWhenRenameFails(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "managed.conf")
	if err := os.Mkdir(targetPath, 0755); err != nil {
		t.Fatalf("Failed to create rename-blocking directory: %v", err)
	}

	err := writeFileAtomic(targetPath, []byte("zone config"), 0644)
	if err == nil {
		t.Fatal("writeFileAtomic should fail when target path is a directory")
	}

	if _, statErr := os.Stat(targetPath + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("expected temp config file to be removed, got err=%v", statErr)
	}
	tempPattern := filepath.Join(tmpDir, "."+filepath.Base(targetPath)+".*.tmp")
	matches, globErr := filepath.Glob(tempPattern)
	if globErr != nil {
		t.Fatalf("temp config glob failed: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("expected temp config files to be removed, got %v", matches)
	}
}

func TestWriteFileAtomicDoesNotFollowPredictableTempSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "managed.conf")
	sentinelPath := filepath.Join(tmpDir, "sentinel")
	sentinel := []byte("keep")
	if err := os.WriteFile(sentinelPath, sentinel, 0600); err != nil {
		t.Fatalf("failed to write sentinel: %v", err)
	}
	if err := os.Symlink(sentinelPath, targetPath+".tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if err := writeFileAtomic(targetPath, []byte("zone config"), 0644); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
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
		t.Fatalf("expected predictable temp symlink to remain untouched: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected predictable temp path to remain a symlink, mode=%v", linkInfo.Mode())
	}

	written, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed to read target config: %v", err)
	}
	if string(written) != "zone config" {
		t.Fatalf("target config = %q, want zone config", written)
	}
}

func TestController_CheckZone_ValidZone(t *testing.T) {
	// Skip if nsd-checkzone is not available
	if _, err := os.Stat("/usr/sbin/nsd-checkzone"); os.IsNotExist(err) {
		t.Skip("nsd-checkzone not available")
	}

	// Create a valid zone file
	tmpDir, err := os.MkdirTemp("", "nsd-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. (
		2024122801	; serial
		3600		; refresh
		1800		; retry
		604800		; expire
		86400 )		; minimum

@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
www	IN	A	192.0.2.2
`

	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	logger, _ := zap.NewDevelopment()
	cfg := config.NSDConfig{
		Enabled:       true,
		CheckzonePath: "/usr/sbin/nsd-checkzone",
		ReloadTimeout: 10 * time.Second,
	}

	ctrl := NewController(cfg, logger)

	if err := ctrl.CheckZone("example.com.", zoneFile); err != nil {
		t.Errorf("CheckZone failed for valid zone: %v", err)
	}
}

func TestController_CheckZone_InvalidZone(t *testing.T) {
	// Skip if nsd-checkzone is not available
	if _, err := os.Stat("/usr/sbin/nsd-checkzone"); os.IsNotExist(err) {
		t.Skip("nsd-checkzone not available")
	}

	// Create an invalid zone file
	tmpDir, err := os.MkdirTemp("", "nsd-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	zoneFile := filepath.Join(tmpDir, "invalid.zone")
	zoneContent := `This is not a valid zone file
Random content
Invalid syntax
`

	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	logger, _ := zap.NewDevelopment()
	cfg := config.NSDConfig{
		Enabled:       true,
		CheckzonePath: "/usr/sbin/nsd-checkzone",
		ReloadTimeout: 10 * time.Second,
	}

	ctrl := NewController(cfg, logger)

	if err := ctrl.CheckZone("example.com.", zoneFile); err == nil {
		t.Error("CheckZone should fail for invalid zone")
	}
}

func TestController_Timeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := config.NSDConfig{
		Enabled:       true,
		ControlPath:   "/bin/sleep", // Use sleep to simulate timeout
		ReloadTimeout: 100 * time.Millisecond,
	}

	ctrl := NewController(cfg, logger)

	// This should timeout
	err := ctrl.ReloadZone("10") // Sleep for 10 seconds
	if err == nil {
		t.Error("Expected timeout error")
	}

	if err != nil && !isTimeoutError(err) {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

// isTimeoutError checks if the error is a context deadline exceeded error
func isTimeoutError(err error) bool {
	errStr := err.Error()
	return errStr == "signal: killed" ||
		errStr == "context deadline exceeded" ||
		(len(errStr) > 20 && errStr[:20] == "nsd-control reload f")
}
