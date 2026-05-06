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

func validAgentConfigForTest() *AgentConfig {
	cfg := DefaultAgentConfig()
	cfg.Sync.ControllerPublicKey = "test-signature-key"
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
	assert.Empty(t, cfg.API.ArtifactSignatureKey)
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
  artifact_signature_key: "yaml-signature-key"
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
	assert.Equal(t, "yaml-signature-key", cfg.API.ArtifactSignatureKey)
	assert.Equal(t, "mysql", cfg.Backend.Type)
	assert.Equal(t, uint8(13), cfg.DNSSEC.Algorithm)
	assert.Equal(t, "/tmp/keys", cfg.DNSSEC.KeyDirectory)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoadControllerConfig_GitAutoPullOptional(t *testing.T) {
	testCases := []struct {
		name         string
		gitYAML      string
		expectNil    bool
		expectedPull bool
	}{
		{
			name: "omitted",
			gitYAML: `
    repository_path: "/tmp/git"
    auto_push: true
`,
			expectNil: true,
		},
		{
			name: "explicit false",
			gitYAML: `
    repository_path: "/tmp/git"
    auto_push: true
    auto_pull: false
`,
		},
		{
			name: "explicit true",
			gitYAML: `
    repository_path: "/tmp/git"
    auto_push: false
    auto_pull: true
`,
			expectedPull: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "controller.yaml")

			configContent := `
api:
  auth:
    enabled: false
backend:
  type: "git"
  git:` + tc.gitYAML + `
`
			err := os.WriteFile(configPath, []byte(configContent), 0644)
			require.NoError(t, err)

			cfg, err := LoadControllerConfig(configPath)
			require.NoError(t, err)

			if tc.expectNil {
				assert.Nil(t, cfg.Backend.Git.AutoPull)
				return
			}
			require.NotNil(t, cfg.Backend.Git.AutoPull)
			assert.Equal(t, tc.expectedPull, *cfg.Backend.Git.AutoPull)
		})
	}
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

func TestLoadControllerConfig_NestedEnvOverrides(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_ADMIN", validTestAPIKeyHash)
	t.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", "env-signature-key")
	t.Setenv("ARCA_DNS_API_RATE_LIMIT_REQUESTS_PER_SECOND", "42")
	t.Setenv("ARCA_DNS_API_RATE_LIMIT_BURST", "84")
	t.Setenv("ARCA_DNS_BACKEND_TYPE", "postgres")
	t.Setenv("ARCA_DNS_BACKEND_POSTGRES_DSN", "postgres://env:pass@db:5432/arca_dns?sslmode=disable")
	t.Setenv("ARCA_DNS_BACKEND_POSTGRES_MAX_OPEN_CONNS", "17")
	t.Setenv("ARCA_DNS_BACKEND_ETCD_ENDPOINTS", "http://etcd-a:2379,http://etcd-b:2379")
	t.Setenv("ARCA_DNS_DNSSEC_SIGNATURE_VALIDITY", "240h")
	t.Setenv("ARCA_DNS_DNSSEC_RESIGN_THRESHOLD", "24h")
	t.Setenv("ARCA_DNS_DNSSEC_SCHEDULER_CHECK_INTERVAL", "15m")
	t.Setenv("ARCA_DNS_STORAGE_MAX_VERSIONS_PER_ZONE", "42")

	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)

	assert.Equal(t, 42, cfg.API.RateLimit.RequestsPerSecond)
	assert.Equal(t, "env-signature-key", cfg.API.ArtifactSignatureKey)
	assert.Equal(t, 84, cfg.API.RateLimit.Burst)
	assert.Equal(t, "postgres", cfg.Backend.Type)
	assert.Equal(t, "postgres://env:pass@db:5432/arca_dns?sslmode=disable", cfg.Backend.Postgres.DSN)
	assert.Equal(t, 17, cfg.Backend.Postgres.MaxOpenConns)
	assert.Equal(t, []string{"http://etcd-a:2379", "http://etcd-b:2379"}, cfg.Backend.Etcd.Endpoints)
	assert.Equal(t, 240*time.Hour, cfg.DNSSEC.SignatureValidity)
	assert.Equal(t, 24*time.Hour, cfg.DNSSEC.ResignThreshold)
	assert.Equal(t, 15*time.Minute, cfg.DNSSEC.SchedulerCheckInterval)
	assert.Equal(t, 42, cfg.Storage.MaxVersionsPerZone)
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

func TestValidateControllerConfig_InvalidRateLimit(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.RateLimit.Enabled = true
	cfg.API.RateLimit.RequestsPerSecond = 0
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.rate_limit.requests_per_second")

	cfg = validControllerConfigForTest()
	cfg.API.RateLimit.Enabled = true
	cfg.API.RateLimit.Burst = 0
	err = ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.rate_limit.burst")
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
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_PUBLIC_KEY", "test-signature-key")

	cfg, err := LoadAgentConfig("")
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080", cfg.Controller.URL)
	assert.True(t, cfg.NSD.Enabled)
	assert.True(t, cfg.Unbound.Enabled)
	assert.Equal(t, 1232, cfg.Unbound.EDNSBufferSize)
	assert.True(t, cfg.Sync.VerifySignatures)
	assert.Equal(t, "test-signature-key", cfg.Sync.ControllerPublicKey)
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
sync:
  controller_public_key: "yaml-signature-key"
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
	assert.True(t, cfg.Sync.VerifySignatures)
	assert.Equal(t, "yaml-signature-key", cfg.Sync.ControllerPublicKey)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoadAgentConfig_EnvOverrideWithYAML(t *testing.T) {
	t.Setenv("ARCA_DNS_CONTROLLER_URL", "https://env-controller.example.com")
	t.Setenv("ARCA_DNS_CONTROLLER_API_KEY", "env-api-key")
	t.Setenv("ARCA_DNS_CONTROLLER_TLS_CERT_FILE", "/env/client.crt")
	t.Setenv("ARCA_DNS_NSD_ENABLED", "false")
	t.Setenv("ARCA_DNS_UNBOUND_STUB_ZONE_NSD_PORT", "5533")
	t.Setenv("ARCA_DNS_SYNC_VERIFY_CHECKSUMS", "false")
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_PUBLIC_KEY", "env-signature-key")
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
  controller_public_key: "yaml-signature-key"
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
	assert.Equal(t, "env-signature-key", cfg.Sync.ControllerPublicKey)
	assert.Equal(t, 2*time.Second, cfg.Health.QueryTimeout)
	assert.Equal(t, "/env-metrics", cfg.Metrics.Path)
	assert.True(t, cfg.Logging.EnableCaller)
}

func TestLoadAgentConfig_EnvOverrideWithoutFile(t *testing.T) {
	t.Setenv("ARCA_DNS_CONTROLLER_URL", "https://env-only-controller.example.com")
	t.Setenv("ARCA_DNS_CONTROLLER_API_KEY", "env-only-api-key")
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_PUBLIC_KEY", "env-signature-key")

	cfg, err := LoadAgentConfig("")
	require.NoError(t, err)

	assert.Equal(t, "https://env-only-controller.example.com", cfg.Controller.URL)
	assert.Equal(t, "env-only-api-key", cfg.Controller.APIKey)
	assert.Equal(t, "env-signature-key", cfg.Sync.ControllerPublicKey)
}

func TestValidateAgentConfig_Valid(t *testing.T) {
	cfg := validAgentConfigForTest()
	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_EmptyControllerURL(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Controller.URL = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "controller.url")
}

func TestValidateAgentConfig_NSDMissingConfig(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.NSD.Enabled = true
	cfg.NSD.ConfigPath = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nsd.config_path")
}

func TestValidateAgentConfig_UnboundMissingConfig(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Unbound.Enabled = true
	cfg.Unbound.ConfigPath = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unbound.config_path")
}

func TestValidateAgentConfig_BIRDMissingPrefixes(t *testing.T) {
	// Note: anycast_prefixes is now optional (M5 uses protocol enable/disable)
	// This test now verifies that protocol_name is required
	cfg := validAgentConfigForTest()
	cfg.BIRD.Enabled = true
	cfg.BIRD.ProtocolName = "" // Missing required field
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "protocol_name")
}

func TestValidateAgentConfig_InvalidSyncInterval(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.SyncInterval = 0
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync_interval")
}

func TestValidateAgentConfig_InvalidBackupVersions(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.BackupVersions = -1
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync.backup_versions")
}

func TestValidateAgentConfig_VerifySignaturesRequiresKey(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Sync.VerifySignatures = true
	cfg.Sync.ControllerPublicKey = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync.controller_public_key")
}

func TestValidateAgentConfig_InvalidDNSTapSampleRate(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.DNSTap.Enabled = true
	cfg.DNSTap.SampleRate = 0
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dnstap.sample_rate")
}

func TestValidateAgentConfig_StatusServerRequiresListen(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Metrics.Enabled = false
	cfg.Metrics.Listen = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metrics.listen")
}

func TestValidateAgentConfig_MetricsPathCannotConflictWithStatusEndpoints(t *testing.T) {
	tests := []string{
		"/health",
		"ready",
		"  /status  ",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Metrics.Enabled = true
			cfg.Metrics.Path = path
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "metrics.path")
		})
	}
}

func TestValidateAgentConfig_MetricsPathMustBeStatic(t *testing.T) {
	tests := []string{
		"/*metrics",
		"/*metrics/rest",
		"/:metrics",
		"/metrics/:name",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Metrics.Enabled = true
			cfg.Metrics.Path = path
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "metrics.path")
		})
	}
}

func TestValidateAgentConfig_MetricsPathIgnoredWhenMetricsDisabled(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Metrics.Enabled = false
	cfg.Metrics.Path = "/health"
	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_InvalidLogLevel(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Logging.Level = "invalid"
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logging.level")
}
