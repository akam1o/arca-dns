package unbound

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
	cfg := config.UnboundConfig{
		Enabled:        true,
		ControlPath:    "/usr/sbin/unbound-control",
		CheckconfPath:  "/usr/sbin/unbound-checkconf",
		EDNSBufferSize: 1232,
		ReloadTimeout:  10 * time.Second,
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
	cfg := config.UnboundConfig{
		Enabled:       false, // Disabled
		ReloadTimeout: 10 * time.Second,
	}

	ctrl := NewController(cfg, logger)

	// All operations should succeed but do nothing when disabled
	if err := ctrl.Reload(); err != nil {
		t.Errorf("Reload should succeed when disabled: %v", err)
	}

	if err := ctrl.CheckConfig(); err != nil {
		t.Errorf("CheckConfig should succeed when disabled: %v", err)
	}

	if err := ctrl.UpdateStubZoneConfig("example.com."); err != nil {
		t.Errorf("UpdateStubZoneConfig should succeed when disabled: %v", err)
	}

	if err := ctrl.DeleteStubZoneConfig("example.com."); err != nil {
		t.Errorf("DeleteStubZoneConfig should succeed when disabled: %v", err)
	}

	if err := ctrl.FlushZone("example.com."); err != nil {
		t.Errorf("FlushZone should succeed when disabled: %v", err)
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

func TestController_GenerateStubZoneConfig(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := config.UnboundConfig{
		Enabled:        true,
		EDNSBufferSize: 1232,
		StubZoneConfig: config.StubZoneConfig{
			NSDAddress: "127.0.0.1",
			NSDPort:    5353,
		},
	}

	ctrl := NewController(cfg, logger)

	stubConfig, err := ctrl.GenerateStubZoneConfig("example.com.")
	if err != nil {
		t.Fatalf("GenerateStubZoneConfig failed: %v", err)
	}

	if stubConfig == "" {
		t.Error("Expected non-empty stub config")
	}

	// Check that config contains expected values
	expectedStrings := []string{
		"example.com.",
		"127.0.0.1",
		"5353",
		"stub-zone:",
		"name:",
		"stub-addr:",
	}

	for _, expected := range expectedStrings {
		if !contains(stubConfig, expected) {
			t.Errorf("Expected stub config to contain '%s', got: %s", expected, stubConfig)
		}
	}
}

func TestController_RejectsInvalidStubZoneName(t *testing.T) {
	tmpDir := t.TempDir()
	ctrl := NewController(config.UnboundConfig{
		Enabled:    true,
		ConfigPath: filepath.Join(tmpDir, "unbound.conf"),
		StubZoneConfig: config.StubZoneConfig{
			NSDAddress: "127.0.0.1",
			NSDPort:    5353,
		},
	}, zap.NewNop())

	invalidZoneName := "bad.com\"\ninclude: \"/tmp/pwn\""
	if _, err := ctrl.GenerateStubZoneConfig(invalidZoneName); err == nil {
		t.Fatal("GenerateStubZoneConfig should reject invalid zone names")
	} else if !strings.Contains(err.Error(), "invalid zone name") {
		t.Fatalf("Unexpected error: %v", err)
	}

	if err := ctrl.UpdateStubZoneConfig(invalidZoneName); err == nil {
		t.Fatal("UpdateStubZoneConfig should reject invalid zone names")
	} else if !strings.Contains(err.Error(), "invalid zone name") {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestController_DeleteStubZoneConfig(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := zap.NewDevelopment()
	cfg := config.UnboundConfig{
		Enabled:    true,
		ConfigPath: filepath.Join(tmpDir, "unbound.conf"),
		StubZoneConfig: config.StubZoneConfig{
			NSDAddress: "127.0.0.1",
			NSDPort:    5353,
		},
	}

	ctrl := NewController(cfg, logger)
	stubPath := filepath.Join(tmpDir, "stub-zone-example.com.conf")

	if err := ctrl.UpdateStubZoneConfig("example.com."); err != nil {
		t.Fatalf("UpdateStubZoneConfig failed: %v", err)
	}
	if _, err := os.Stat(stubPath); err != nil {
		t.Fatalf("expected stub-zone file to exist: %v", err)
	}

	if err := ctrl.DeleteStubZoneConfig("example.com."); err != nil {
		t.Fatalf("DeleteStubZoneConfig failed: %v", err)
	}
	if _, err := os.Stat(stubPath); !os.IsNotExist(err) {
		t.Fatalf("expected stub-zone file to be removed, got err=%v", err)
	}

	if err := ctrl.DeleteStubZoneConfig("example.com."); err != nil {
		t.Fatalf("DeleteStubZoneConfig should be idempotent: %v", err)
	}
}

func TestController_EnsureEDNSBufferSize_Correct(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := config.UnboundConfig{
		Enabled:        true,
		EDNSBufferSize: 1232, // Correct value
	}

	ctrl := NewController(cfg, logger)

	if err := ctrl.EnsureEDNSBufferSize(); err != nil {
		t.Errorf("EnsureEDNSBufferSize should succeed with correct value: %v", err)
	}
}

func TestController_EnsureEDNSBufferSize_Incorrect(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := config.UnboundConfig{
		Enabled:        true,
		EDNSBufferSize: 4096, // Incorrect value (not ECMP-safe)
	}

	ctrl := NewController(cfg, logger)

	err := ctrl.EnsureEDNSBufferSize()
	if err == nil {
		t.Error("EnsureEDNSBufferSize should fail with incorrect value")
	}

	expectedError := "EDNS buffer size mismatch: expected 1232, got 4096"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestController_Timeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := config.UnboundConfig{
		Enabled:       true,
		ControlPath:   "/bin/sleep", // Use sleep to simulate timeout
		ReloadTimeout: 100 * time.Millisecond,
	}

	ctrl := NewController(cfg, logger)

	// This should timeout
	err := ctrl.Reload()
	if err == nil {
		t.Error("Expected timeout error")
	}

	if err != nil && !isTimeoutError(err) {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && indexString(s, substr) >= 0)
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func isTimeoutError(err error) bool {
	errStr := err.Error()
	return errStr == "signal: killed" ||
		errStr == "context deadline exceeded" ||
		(len(errStr) > 25 && errStr[:25] == "unbound-control reload fa")
}
