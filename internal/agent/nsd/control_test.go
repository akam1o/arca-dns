package nsd

import (
	"os"
	"path/filepath"
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
