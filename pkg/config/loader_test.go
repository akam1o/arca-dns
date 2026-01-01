package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadControllerConfig_Defaults(t *testing.T) {
	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)
	
	assert.Equal(t, "0.0.0.0:8080", cfg.API.Listen)
	assert.Equal(t, "memory", cfg.Backend.Type)
	assert.True(t, cfg.DNSSEC.Enabled)
	assert.Equal(t, uint8(13), cfg.DNSSEC.Algorithm)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestLoadControllerConfig_FromYAML(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")
	
	configContent := `
api:
  listen: "127.0.0.1:9090"
backend:
  type: "mysql"
dnssec:
  enabled: true
  algorithm: 13
  key_directory: "/tmp/keys"
storage:
  artifact_directory: "/tmp/artifacts"
  key_directory: "/tmp/storage-keys"
logging:
  level: "debug"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)
	
	cfg, err := LoadControllerConfig(configPath)
	require.NoError(t, err)
	
	assert.Equal(t, "127.0.0.1:9090", cfg.API.Listen)
	assert.Equal(t, "mysql", cfg.Backend.Type)
	assert.Equal(t, uint8(13), cfg.DNSSEC.Algorithm)
	assert.Equal(t, "/tmp/keys", cfg.DNSSEC.KeyDirectory)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoadControllerConfig_EnvOverride(t *testing.T) {
	// Set environment variables
	os.Setenv("ARCA_DNS_API_LISTEN", "0.0.0.0:7070")
	os.Setenv("ARCA_DNS_BACKEND_TYPE", "git")
	os.Setenv("ARCA_DNS_LOGGING_LEVEL", "warn")
	defer func() {
		os.Unsetenv("ARCA_DNS_API_LISTEN")
		os.Unsetenv("ARCA_DNS_BACKEND_TYPE")
		os.Unsetenv("ARCA_DNS_LOGGING_LEVEL")
	}()
	
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")
	
	configContent := `
api:
  listen: "127.0.0.1:8080"
backend:
  type: "memory"
logging:
  level: "info"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)
	
	cfg, err := LoadControllerConfig(configPath)
	require.NoError(t, err)
	
	// Environment variables should override YAML
	assert.Equal(t, "0.0.0.0:7070", cfg.API.Listen)
	assert.Equal(t, "git", cfg.Backend.Type)
	assert.Equal(t, "warn", cfg.Logging.Level)
}

func TestLoadControllerConfig_InvalidFile(t *testing.T) {
	cfg, err := LoadControllerConfig("/nonexistent/config.yaml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoadControllerConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")
	
	// Invalid YAML
	configContent := `
api:
  listen: "127.0.0.1:8080"
  invalid yaml here
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)
	
	cfg, err := LoadControllerConfig(configPath)
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestValidateControllerConfig_Valid(t *testing.T) {
	cfg := DefaultControllerConfig()
	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateControllerConfig_EmptyAPIListen(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.API.Listen = ""
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.listen")
}

func TestValidateControllerConfig_InvalidBackendType(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.Backend.Type = "invalid"
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend.type")
}

func TestValidateControllerConfig_EmptyKeyDirectory(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.DNSSEC.Enabled = true
	cfg.DNSSEC.KeyDirectory = ""
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_directory")
}

func TestValidateControllerConfig_InvalidAlgorithm(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.DNSSEC.Algorithm = 99
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")
}

func TestValidateControllerConfig_InvalidSignatureValidity(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.DNSSEC.SignatureValidity = -1 * time.Hour
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature_validity")
}

func TestValidateControllerConfig_ResignThresholdTooLarge(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.DNSSEC.SignatureValidity = 10 * 24 * time.Hour
	cfg.DNSSEC.ResignThreshold = 15 * 24 * time.Hour
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resign_threshold")
}

func TestLoadAgentConfig_Defaults(t *testing.T) {
	cfg, err := LoadAgentConfig("")
	require.NoError(t, err)
	
	assert.Equal(t, "http://localhost:8080", cfg.Controller.URL)
	assert.True(t, cfg.NSD.Enabled)
	assert.True(t, cfg.Unbound.Enabled)
	assert.Equal(t, 1232, cfg.Unbound.EDNSBufferSize)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestLoadAgentConfig_FromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")
	
	configContent := `
controller:
  url: "https://controller.example.com"
  api_key: "test-key"
nsd:
  enabled: true
  zone_directory: "/tmp/nsd-zones"
unbound:
  enabled: false
logging:
  level: "debug"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)
	
	cfg, err := LoadAgentConfig(configPath)
	require.NoError(t, err)
	
	assert.Equal(t, "https://controller.example.com", cfg.Controller.URL)
	assert.Equal(t, "test-key", cfg.Controller.APIKey)
	assert.Equal(t, "/tmp/nsd-zones", cfg.NSD.ZoneDirectory)
	assert.False(t, cfg.Unbound.Enabled)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestValidateAgentConfig_Valid(t *testing.T) {
	cfg := DefaultAgentConfig()
	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_EmptyControllerURL(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Controller.URL = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "controller.url")
}

func TestValidateAgentConfig_NSDMissingConfig(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.NSD.Enabled = true
	cfg.NSD.ConfigPath = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nsd.config_path")
}

func TestValidateAgentConfig_UnboundMissingConfig(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Unbound.Enabled = true
	cfg.Unbound.ConfigPath = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unbound.config_path")
}

func TestValidateAgentConfig_BIRDMissingPrefixes(t *testing.T) {
	// Note: anycast_prefixes is now optional (M5 uses protocol enable/disable)
	// This test now verifies that protocol_name is required
	cfg := DefaultAgentConfig()
	cfg.BIRD.Enabled = true
	cfg.BIRD.ProtocolName = "" // Missing required field
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "protocol_name")
}

func TestValidateAgentConfig_InvalidSyncInterval(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Sync.SyncInterval = 0
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync_interval")
}

func TestValidateAgentConfig_InvalidLogLevel(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Logging.Level = "invalid"
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logging.level")
}
