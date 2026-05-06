package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validTestAPIKeyHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
const alternateValidTestAPIKeyHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func validControllerConfigForTest() *ControllerConfig {
	cfg := DefaultControllerConfig()
	cfg.API.Auth.APIKeys = map[string]string{
		"admin": validTestAPIKeyHash,
	}
	return cfg
}

func TestLoadControllerConfig_DefaultsRequireAPIKeys(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_ENABLED", "true")

	cfg, err := LoadControllerConfig("")
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "api.auth.api_keys")
	assert.Contains(t, err.Error(), "echo -n '<api-key>' | sha256sum")
	assert.Contains(t, err.Error(), "api.auth.enabled: false")
}

func TestLoadControllerConfig_AuthDisabledFromEnvAllowsDefaults(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_ENABLED", "false")

	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)
	assert.False(t, cfg.API.Auth.Enabled)
	assert.Empty(t, cfg.API.Auth.APIKeys)
}

func TestLoadControllerConfig_APIKeysFromEnvAllowsDefaults(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_ADMIN", validTestAPIKeyHash)

	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)

	assert.True(t, cfg.API.Auth.Enabled)
	assert.Equal(t, map[string]string{
		"admin": validTestAPIKeyHash,
	}, cfg.API.Auth.APIKeys)
}

func TestDefaultControllerConfig_Defaults(t *testing.T) {
	cfg := DefaultControllerConfig()

	assert.Equal(t, "0.0.0.0:8080", cfg.API.Listen)
	assert.True(t, cfg.API.Auth.Enabled)
	assert.Equal(t, "sqlite", cfg.Backend.Type)
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
  auth:
    enabled: true
    api_keys:
      admin: "` + validTestAPIKeyHash + `"
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
	os.Setenv("ARCA_DNS_API_AUTH_ENABLED", "false")
	os.Setenv("ARCA_DNS_BACKEND_TYPE", "git")
	os.Setenv("ARCA_DNS_LOGGING_LEVEL", "warn")
	defer func() {
		os.Unsetenv("ARCA_DNS_API_LISTEN")
		os.Unsetenv("ARCA_DNS_API_AUTH_ENABLED")
		os.Unsetenv("ARCA_DNS_BACKEND_TYPE")
		os.Unsetenv("ARCA_DNS_LOGGING_LEVEL")
	}()

	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")

	configContent := `
api:
  listen: "127.0.0.1:8080"
  auth:
    enabled: true
    api_keys:
      admin: "` + validTestAPIKeyHash + `"
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
	assert.False(t, cfg.API.Auth.Enabled)
	assert.Equal(t, "git", cfg.Backend.Type)
	assert.Equal(t, "warn", cfg.Logging.Level)
}

func TestLoadControllerConfig_APIKeyEnvMergesAndOverridesYAML(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_ADMIN", alternateValidTestAPIKeyHash)
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_EDGE_AGENT", validTestAPIKeyHash)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")

	configContent := `
api:
  auth:
    enabled: true
    api_keys:
      admin: "` + validTestAPIKeyHash + `"
      readonly: "` + validTestAPIKeyHash + `"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadControllerConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, alternateValidTestAPIKeyHash, cfg.API.Auth.APIKeys["admin"])
	assert.Equal(t, validTestAPIKeyHash, cfg.API.Auth.APIKeys["edge_agent"])
	assert.Equal(t, validTestAPIKeyHash, cfg.API.Auth.APIKeys["readonly"])
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
	cfg := validControllerConfigForTest()
	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateControllerConfig_AuthEnabledRequiresAPIKeys(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.API.Auth.Enabled = true
	cfg.API.Auth.APIKeys = nil
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.auth.api_keys")
	assert.Contains(t, err.Error(), "echo -n '<api-key>' | sha256sum")
	assert.Contains(t, err.Error(), "api.auth.enabled: false")
}

func TestValidateControllerConfig_AuthEnabledRejectsInvalidAPIKeyHash(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.API.Auth.Enabled = true
	cfg.API.Auth.APIKeys = map[string]string{
		"admin": "sha256:REPLACE_WITH_SHA256_HEX",
	}
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.auth.api_keys.admin")
	assert.Contains(t, err.Error(), "sha256:<64 hex characters>")
}

func TestValidateControllerConfig_AuthDisabledAllowsEmptyAPIKeys(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.API.Auth.Enabled = false
	cfg.API.Auth.APIKeys = nil
	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateControllerConfig_EmptyAPIListen(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.Listen = ""
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.listen")
}

func TestValidateControllerConfig_InvalidBackendType(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Backend.Type = "invalid"
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend.type")
}

func TestValidateControllerConfig_EmptyKeyDirectory(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.Enabled = true
	cfg.DNSSEC.KeyDirectory = ""
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_directory")
}

func TestValidateControllerConfig_InvalidAlgorithm(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.Algorithm = 99
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")
}

func TestValidateControllerConfig_InvalidSignatureValidity(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.SignatureValidity = -1 * time.Hour
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature_validity")
}

func TestValidateControllerConfig_ResignThresholdTooLarge(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.SignatureValidity = 10 * 24 * time.Hour
	cfg.DNSSEC.ResignThreshold = 15 * 24 * time.Hour
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resign_threshold")
}

func TestValidateControllerConfig_InvalidNSEC3SaltLength(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.NSEC3SaltLength = -1
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nsec3_salt_length")
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

func TestLoadAgentConfig_EnvOverrideWithYAML(t *testing.T) {
	t.Setenv("ARCA_DNS_CONTROLLER_URL", "https://env-controller.example.com")
	t.Setenv("ARCA_DNS_CONTROLLER_API_KEY", "env-api-key")
	t.Setenv("ARCA_DNS_CONTROLLER_TLS_CERT_FILE", "/env/client.crt")
	t.Setenv("ARCA_DNS_NSD_ENABLED", "false")
	t.Setenv("ARCA_DNS_UNBOUND_STUB_ZONE_NSD_PORT", "5533")
	t.Setenv("ARCA_DNS_SYNC_VERIFY_CHECKSUMS", "false")
	t.Setenv("ARCA_DNS_HEALTH_QUERY_TIMEOUT", "2s")
	t.Setenv("ARCA_DNS_METRICS_PATH", "/env-metrics")
	t.Setenv("ARCA_DNS_LOGGING_ENABLE_CALLER", "true")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	configContent := `
controller:
  url: "https://yaml-controller.example.com"
  api_key: "yaml-api-key"
  tls:
    cert_file: "/yaml/client.crt"
nsd:
  enabled: true
  zone_directory: "/tmp/nsd-zones"
unbound:
  enabled: false
  stub_zone:
    nsd_port: 5353
sync:
  verify_checksums: true
health:
  query_timeout: 5s
metrics:
  path: "/yaml-metrics"
logging:
  level: "info"
  enable_caller: false
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadAgentConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, "https://env-controller.example.com", cfg.Controller.URL)
	assert.Equal(t, "env-api-key", cfg.Controller.APIKey)
	assert.Equal(t, "/env/client.crt", cfg.Controller.TLS.CertFile)
	assert.False(t, cfg.NSD.Enabled)
	assert.Equal(t, 5533, cfg.Unbound.StubZoneConfig.NSDPort)
	assert.False(t, cfg.Sync.VerifyChecksums)
	assert.Equal(t, 2*time.Second, cfg.Health.QueryTimeout)
	assert.Equal(t, "/env-metrics", cfg.Metrics.Path)
	assert.True(t, cfg.Logging.EnableCaller)
}

func TestLoadAgentConfig_EnvOverrideWithoutFile(t *testing.T) {
	t.Setenv("ARCA_DNS_CONTROLLER_URL", "https://env-only-controller.example.com")
	t.Setenv("ARCA_DNS_CONTROLLER_API_KEY", "env-only-api-key")

	cfg, err := LoadAgentConfig("")
	require.NoError(t, err)

	assert.Equal(t, "https://env-only-controller.example.com", cfg.Controller.URL)
	assert.Equal(t, "env-only-api-key", cfg.Controller.APIKey)
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
