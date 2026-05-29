package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validTestAPIKeyHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
const alternateValidTestAPIKeyHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const validTestArtifactSignatureKey = "test-artifact-signature-key-32-bytes"
const validYAMLArtifactSignatureKey = "yaml-artifact-signature-key-32-bytes"
const validEnvArtifactSignatureKey = "env-artifact-signature-key-32-bytes"
const validStatusAuthToken = "status-auth-token-32-byte-secret"

func validControllerConfigForTest() *ControllerConfig {
	cfg := DefaultControllerConfig()
	cfg.API.ArtifactSignatureKey = validTestArtifactSignatureKey
	cfg.API.Auth.APIKeys = map[string]string{
		"admin": validTestAPIKeyHash,
	}
	cfg.API.Auth.APIKeyRoles = map[string]string{
		"admin": "admin",
	}
	return cfg
}

func validAgentConfigForTest() *AgentConfig {
	cfg := DefaultAgentConfig()
	cfg.Sync.ControllerSignatureKey = validTestArtifactSignatureKey
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
	t.Setenv("ARCA_DNS_API_LISTEN", "127.0.0.1:8080")
	t.Setenv("ARCA_DNS_API_AUTH_ENABLED", "false")
	t.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", validEnvArtifactSignatureKey)

	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8080", cfg.API.Listen)
	assert.False(t, cfg.API.Auth.Enabled)
	assert.Empty(t, cfg.API.Auth.APIKeys)
	assert.Equal(t, validEnvArtifactSignatureKey, cfg.API.ArtifactSignatureKey)
}

func TestLoadControllerConfig_AuthDisabledStillRequiresArtifactSignatureKey(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_ENABLED", "false")

	cfg, err := LoadControllerConfig("")
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "api.artifact_signature_key")
	assert.Contains(t, err.Error(), "required")
}

func TestLoadControllerConfig_APIKeysFromEnvAllowsDefaults(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_ADMIN", validTestAPIKeyHash)
	t.Setenv("ARCA_DNS_API_AUTH_API_KEY_ROLES_ADMIN", "admin")
	t.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", validEnvArtifactSignatureKey)

	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)

	assert.True(t, cfg.API.Auth.Enabled)
	assert.Equal(t, validEnvArtifactSignatureKey, cfg.API.ArtifactSignatureKey)
	assert.Equal(t, map[string]string{
		"admin": validTestAPIKeyHash,
	}, cfg.API.Auth.APIKeys)
	assert.Equal(t, map[string]string{
		"admin": "admin",
	}, cfg.API.Auth.APIKeyRoles)
}

func TestLoadControllerConfig_APIKeysFromEnvRequireArtifactSignatureKey(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_ADMIN", validTestAPIKeyHash)
	t.Setenv("ARCA_DNS_API_AUTH_API_KEY_ROLES_ADMIN", "admin")

	cfg, err := LoadControllerConfig("")
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "api.artifact_signature_key")
	assert.Contains(t, err.Error(), "generate a shared secret")
}

func TestDefaultControllerConfig_Defaults(t *testing.T) {
	cfg := DefaultControllerConfig()

	assert.Equal(t, "0.0.0.0:8080", cfg.API.Listen)
	assert.Equal(t, "127.0.0.1:9053", cfg.Observability.Listen)
	assert.Empty(t, cfg.API.ArtifactSignatureKey)
	assert.True(t, cfg.API.Auth.Enabled)
	assert.False(t, cfg.API.Auth.AllowImplicitAdminRoles)
	assert.Equal(t, "sqlite", cfg.Backend.Type)
	assert.True(t, cfg.DNSSEC.Enabled)
	assert.Equal(t, uint8(13), cfg.DNSSEC.Algorithm)
	assert.Equal(t, "/var/lib/arca-dns/keys", cfg.DNSSEC.KeyDirectory)
	assert.Empty(t, cfg.Storage.KeyDirectory)
	assert.Equal(t, "/var/lib/arca-dns/keys", cfg.DNSSECKeyDirectory())
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestDefaultAgentConfig_MetricsListenIsLoopback(t *testing.T) {
	cfg := DefaultAgentConfig()

	assert.Equal(t, "127.0.0.1:9090", cfg.Metrics.Listen)
	assert.True(t, cfg.Metrics.Enabled)
}

func TestLoadControllerConfig_FromYAML(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")

	configContent := `
api:
  listen: "127.0.0.1:9090"
  artifact_signature_key: "` + validYAMLArtifactSignatureKey + `"
  artifact_signature_key_id: "Primary"
  auth:
    enabled: true
    api_keys:
      admin: "` + validTestAPIKeyHash + `"
    api_key_roles:
      admin: "admin"
observability:
  listen: "127.0.0.1:9053"
backend:
  type: "mysql"
  mysql:
    dsn: "user:pass@tcp(mysql:3306)/arca_dns?parseTime=true"
dnssec:
  enabled: true
  algorithm: 13
  key_directory: "/tmp/keys"
storage:
  artifact_directory: "/tmp/artifacts"
logging:
  level: "debug"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadControllerConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:9090", cfg.API.Listen)
	assert.Equal(t, "127.0.0.1:9053", cfg.Observability.Listen)
	assert.Equal(t, validYAMLArtifactSignatureKey, cfg.API.ArtifactSignatureKey)
	assert.Equal(t, "primary", cfg.API.ArtifactSignatureKeyID)
	assert.Equal(t, "admin", cfg.API.Auth.APIKeyRoles["admin"])
	assert.Equal(t, "mysql", cfg.Backend.Type)
	assert.Equal(t, uint8(13), cfg.DNSSEC.Algorithm)
	assert.Equal(t, "/tmp/keys", cfg.DNSSEC.KeyDirectory)
	assert.Equal(t, "/tmp/keys", cfg.DNSSECKeyDirectory())
	assert.Empty(t, cfg.Storage.KeyDirectory)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoadControllerBackendConfig_AllowsMissingRuntimeDSNForMigrationFlags(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")

	configContent := `
backend:
  type: "postgres"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadControllerBackendConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "postgres", cfg.Backend.Type)
	assert.Empty(t, cfg.Backend.Postgres.DSN)
}

func TestLoadControllerConfig_StorageKeyDirectoryAliasesDNSSECKeyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")

	configContent := `
api:
  listen: "127.0.0.1:8080"
  artifact_signature_key: "` + validYAMLArtifactSignatureKey + `"
  auth:
    enabled: false
storage:
  key_directory: "/tmp/storage-keys"
dnssec:
  enabled: true
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadControllerConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, "/tmp/storage-keys", cfg.Storage.KeyDirectory)
	assert.Equal(t, "/tmp/storage-keys", cfg.DNSSEC.KeyDirectory)
	assert.Equal(t, "/tmp/storage-keys", cfg.DNSSECKeyDirectory())
}

func TestLoadControllerConfig_StorageKeyDirectoryEnvAliasesDNSSECKeyDirectory(t *testing.T) {
	t.Setenv("ARCA_DNS_API_LISTEN", "127.0.0.1:8080")
	t.Setenv("ARCA_DNS_API_AUTH_ENABLED", "false")
	t.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", validEnvArtifactSignatureKey)
	t.Setenv("ARCA_DNS_STORAGE_KEY_DIRECTORY", "/tmp/env-storage-keys")

	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)

	assert.Equal(t, "/tmp/env-storage-keys", cfg.Storage.KeyDirectory)
	assert.Equal(t, "/tmp/env-storage-keys", cfg.DNSSEC.KeyDirectory)
	assert.Equal(t, "/tmp/env-storage-keys", cfg.DNSSECKeyDirectory())
}

func TestLoadControllerConfig_MismatchedKeyDirectoriesFail(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")

	configContent := `
api:
  listen: "127.0.0.1:8080"
  artifact_signature_key: "` + validYAMLArtifactSignatureKey + `"
  auth:
    enabled: false
storage:
  key_directory: "/tmp/storage-keys"
dnssec:
  key_directory: "/tmp/dnssec-keys"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadControllerConfig(configPath)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "storage.key_directory")
	assert.Contains(t, err.Error(), "dnssec.key_directory")
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
  listen: "127.0.0.1:8080"
  artifact_signature_key: "` + validYAMLArtifactSignatureKey + `"
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
	os.Setenv("ARCA_DNS_API_LISTEN", "127.0.0.1:7070")
	os.Setenv("ARCA_DNS_OBSERVABILITY_LISTEN", "0.0.0.0:7053")
	os.Setenv("ARCA_DNS_OBSERVABILITY_AUTH_TOKEN", validStatusAuthToken)
	os.Setenv("ARCA_DNS_API_AUTH_ENABLED", "false")
	os.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", validEnvArtifactSignatureKey)
	os.Setenv("ARCA_DNS_BACKEND_TYPE", "git")
	os.Setenv("ARCA_DNS_BACKEND_GIT_REPOSITORY_PATH", "/var/lib/arca-dns/git")
	os.Setenv("ARCA_DNS_LOGGING_LEVEL", "warn")
	defer func() {
		os.Unsetenv("ARCA_DNS_API_LISTEN")
		os.Unsetenv("ARCA_DNS_OBSERVABILITY_LISTEN")
		os.Unsetenv("ARCA_DNS_OBSERVABILITY_AUTH_TOKEN")
		os.Unsetenv("ARCA_DNS_API_AUTH_ENABLED")
		os.Unsetenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY")
		os.Unsetenv("ARCA_DNS_BACKEND_TYPE")
		os.Unsetenv("ARCA_DNS_BACKEND_GIT_REPOSITORY_PATH")
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
  type: "sqlite"
logging:
  level: "info"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadControllerConfig(configPath)
	require.NoError(t, err)

	// Environment variables should override YAML
	assert.Equal(t, "127.0.0.1:7070", cfg.API.Listen)
	assert.Equal(t, "0.0.0.0:7053", cfg.Observability.Listen)
	assert.Equal(t, validStatusAuthToken, cfg.Observability.AuthToken)
	assert.False(t, cfg.API.Auth.Enabled)
	assert.Equal(t, "git", cfg.Backend.Type)
	assert.Equal(t, "/var/lib/arca-dns/git", cfg.Backend.Git.RepositoryPath)
	assert.Equal(t, "warn", cfg.Logging.Level)
}

func TestLoadControllerConfig_NestedEnvOverrides(t *testing.T) {
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_ADMIN", validTestAPIKeyHash)
	t.Setenv("ARCA_DNS_API_AUTH_API_KEY_ROLES_ADMIN", "admin")
	t.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", validEnvArtifactSignatureKey)
	t.Setenv("ARCA_DNS_OBSERVABILITY_LISTEN", "127.0.0.1:9053")
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
	assert.Equal(t, "127.0.0.1:9053", cfg.Observability.Listen)
	assert.Equal(t, validEnvArtifactSignatureKey, cfg.API.ArtifactSignatureKey)
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
	t.Setenv("ARCA_DNS_API_AUTH_API_KEY_ROLES_ADMIN", "admin")
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_EDGE_AGENT", validTestAPIKeyHash)
	t.Setenv("ARCA_DNS_API_AUTH_API_KEY_ROLES_EDGE_AGENT", "agent")
	t.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", validEnvArtifactSignatureKey)
	readonlyHash := "sha256:" + strings.Repeat("2", 64)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "controller.yaml")

	configContent := `
api:
  auth:
    enabled: true
    api_keys:
      admin: "` + validTestAPIKeyHash + `"
      readonly: "` + readonlyHash + `"
    api_key_roles:
      readonly: "agent"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadControllerConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, alternateValidTestAPIKeyHash, cfg.API.Auth.APIKeys["admin"])
	assert.Equal(t, validTestAPIKeyHash, cfg.API.Auth.APIKeys["edge_agent"])
	assert.Equal(t, readonlyHash, cfg.API.Auth.APIKeys["readonly"])
	assert.Equal(t, "admin", cfg.API.Auth.APIKeyRoles["admin"])
	assert.Equal(t, "agent", cfg.API.Auth.APIKeyRoles["edge_agent"])
	assert.Equal(t, "agent", cfg.API.Auth.APIKeyRoles["readonly"])
}

func TestLoadControllerConfig_NormalizesAPIKeyHashes(t *testing.T) {
	upperHash := "sha256:" + strings.Repeat("A", 64)
	expectedHash := "sha256:" + strings.Repeat("a", 64)
	t.Setenv("ARCA_DNS_API_AUTH_API_KEYS_ADMIN", "  "+upperHash+"  ")
	t.Setenv("ARCA_DNS_API_AUTH_API_KEY_ROLES_ADMIN", "admin")
	t.Setenv("ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY", validEnvArtifactSignatureKey)

	cfg, err := LoadControllerConfig("")
	require.NoError(t, err)

	assert.Equal(t, expectedHash, cfg.API.Auth.APIKeys["admin"])
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

func TestValidateControllerAPIConfigSectionNormalizesFields(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.Listen = " 127.0.0.1:8080 "
	cfg.API.TrustedProxies = []string{" 10.0.0.1 ", "\t2001:db8::/32\n"}
	cfg.API.ArtifactSignatureKeyID = "Primary-Key"
	cfg.Observability.Listen = " 127.0.0.1:9053 "

	err := validateControllerAPIConfig(&cfg.API, &cfg.Observability)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:8080", cfg.API.Listen)
	assert.Equal(t, "127.0.0.1:9053", cfg.Observability.Listen)
	assert.Equal(t, []string{"10.0.0.1", "2001:db8::/32"}, cfg.API.TrustedProxies)
	assert.Equal(t, "primary-key", cfg.API.ArtifactSignatureKeyID)
}

func TestValidateControllerDNSSECConfigSectionRejectsInvalidScheduler(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.SchedulerEnabled = true
	cfg.DNSSEC.SchedulerCheckInterval = 0

	err := validateControllerDNSSECConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dnssec.scheduler_check_interval")
}

func TestValidateControllerConfig_TrustedProxies(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.TrustedProxies = []string{" 127.0.0.1 ", "10.0.0.0/8", "\t2001:db8::/32\n"}
	require.NoError(t, ValidateControllerConfig(cfg))
	assert.Equal(t, []string{"127.0.0.1", "10.0.0.0/8", "2001:db8::/32"}, cfg.API.TrustedProxies)

	cfg.API.TrustedProxies = []string{"not-an-ip"}
	err := ValidateControllerConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api.trusted_proxies[0]")
}

func TestValidateControllerConfig_TrustedProxiesRejectUnsafeValues(t *testing.T) {
	tests := []struct {
		name  string
		proxy string
		want  string
	}{
		{
			name:  "all IPv4",
			proxy: "0.0.0.0/0",
			want:  "must not trust all addresses",
		},
		{
			name:  "all IPv6",
			proxy: "::/0",
			want:  "must not trust all addresses",
		},
		{
			name:  "unspecified IPv4",
			proxy: "0.0.0.0",
			want:  "must not be an unspecified address",
		},
		{
			name:  "unspecified IPv6",
			proxy: "::",
			want:  "must not be an unspecified address",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			cfg.API.TrustedProxies = []string{tc.proxy}

			err := ValidateControllerConfig(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "api.trusted_proxies[0]")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
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

func TestValidateControllerConfig_AuthEnabledRejectsDuplicateAPIKeyHashes(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.Auth.APIKeys["agent"] = " sha256:" + strings.ToUpper(strings.TrimPrefix(validTestAPIKeyHash, "sha256:")) + " "

	err := ValidateControllerConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate hash")
	assert.Contains(t, err.Error(), "api.auth.api_keys")
}

func TestValidateControllerConfig_AuthEnabledNormalizesAPIKeyHashes(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.API.ArtifactSignatureKey = validTestArtifactSignatureKey
	cfg.API.Auth.Enabled = true
	cfg.API.Auth.APIKeys = map[string]string{
		"admin": "  sha256:" + strings.Repeat("B", 64) + "  ",
	}
	cfg.API.Auth.APIKeyRoles = map[string]string{
		"admin": "admin",
	}

	err := ValidateControllerConfig(cfg)
	require.NoError(t, err)

	assert.Equal(t, "sha256:"+strings.Repeat("b", 64), cfg.API.Auth.APIKeys["admin"])
	assert.Equal(t, "admin", cfg.API.Auth.APIKeyRoles["admin"])
}

func TestValidateControllerConfig_AuthRoles(t *testing.T) {
	t.Run("allows admin and agent roles", func(t *testing.T) {
		cfg := validControllerConfigForTest()
		cfg.API.Auth.APIKeys["agent"] = alternateValidTestAPIKeyHash
		cfg.API.Auth.APIKeyRoles = map[string]string{
			"admin": " admin ",
			"agent": " agent ",
		}

		err := ValidateControllerConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, "admin", cfg.API.Auth.APIKeyRoles["admin"])
		assert.Equal(t, "agent", cfg.API.Auth.APIKeyRoles["agent"])
	})

	t.Run("rejects unknown role", func(t *testing.T) {
		cfg := validControllerConfigForTest()
		cfg.API.Auth.APIKeyRoles = map[string]string{
			"admin": "readonly",
		}

		err := ValidateControllerConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api.auth.api_key_roles.admin")
	})

	t.Run("rejects role for unknown key", func(t *testing.T) {
		cfg := validControllerConfigForTest()
		cfg.API.Auth.APIKeyRoles = map[string]string{
			"admin": "admin",
			"agent": "agent",
		}

		err := ValidateControllerConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api.auth.api_key_roles.agent")
	})

	t.Run("requires at least one admin key", func(t *testing.T) {
		cfg := validControllerConfigForTest()
		cfg.API.Auth.APIKeyRoles = map[string]string{
			"admin": "agent",
		}

		err := ValidateControllerConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one admin")
	})

	t.Run("requires explicit role for every key", func(t *testing.T) {
		cfg := validControllerConfigForTest()
		cfg.API.Auth.APIKeyRoles = nil

		err := ValidateControllerConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing explicit role")
		assert.Contains(t, err.Error(), "api.auth.api_keys.admin")
	})

	t.Run("allows implicit admin roles only when explicitly enabled", func(t *testing.T) {
		cfg := validControllerConfigForTest()
		cfg.API.Auth.APIKeyRoles = nil
		cfg.API.Auth.AllowImplicitAdminRoles = true

		err := ValidateControllerConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, "admin", cfg.API.Auth.APIKeyRoles["admin"])
	})
}

func TestValidateControllerConfig_AuthDisabledAllowsEmptyAPIKeys(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.API.Listen = "127.0.0.1:8080"
	cfg.API.ArtifactSignatureKey = validTestArtifactSignatureKey
	cfg.API.Auth.Enabled = false
	cfg.API.Auth.APIKeys = nil
	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateControllerConfig_AuthDisabledRejectsNonLoopbackAPIListen(t *testing.T) {
	cfg := DefaultControllerConfig()
	cfg.API.ArtifactSignatureKey = validTestArtifactSignatureKey
	cfg.API.Auth.Enabled = false
	cfg.API.Auth.APIKeys = nil

	err := ValidateControllerConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api.auth.enabled")
	assert.Contains(t, err.Error(), "loopback")
}

func TestValidateControllerConfig_RejectsInvalidArtifactSignatureKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "placeholder",
			key:  "REPLACE_WITH_SHARED_SIGNATURE_KEY",
			want: "placeholder",
		},
		{
			name: "too short",
			key:  "short-secret",
			want: "at least 32 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			cfg.API.ArtifactSignatureKey = tc.key
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "api.artifact_signature_key")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateControllerConfig_NormalizesArtifactSignatureKeyID(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.ArtifactSignatureKeyID = "Primary-Key.1"

	err := ValidateControllerConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "primary-key.1", cfg.API.ArtifactSignatureKeyID)
}

func TestValidateControllerConfig_RejectsInvalidArtifactSignatureKeyID(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.ArtifactSignatureKeyID = "primary key"

	err := ValidateControllerConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api.artifact_signature_key_id")
}

func TestValidateControllerConfig_RejectsMissingArtifactSignatureKeyWhenAuthEnabled(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.ArtifactSignatureKey = ""

	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.artifact_signature_key")
	assert.Contains(t, err.Error(), "required")
}

func TestValidateControllerConfig_RejectsMissingArtifactSignatureKeyWhenAuthDisabled(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.Auth.Enabled = false
	cfg.API.Auth.APIKeys = nil
	cfg.API.ArtifactSignatureKey = ""

	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.artifact_signature_key")
	assert.Contains(t, err.Error(), "required")
}

func TestValidateControllerConfig_EmptyAPIListen(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.Listen = ""
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api.listen")
}

func TestValidateControllerConfig_EmptyObservabilityListen(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Observability.Listen = "  "
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "observability.listen")
}

func TestValidateControllerConfig_InvalidListenAddress(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ControllerConfig)
		want   string
	}{
		{
			name: "api missing port",
			mutate: func(cfg *ControllerConfig) {
				cfg.API.Listen = "127.0.0.1"
			},
			want: "api.listen",
		},
		{
			name: "api zero port",
			mutate: func(cfg *ControllerConfig) {
				cfg.API.Listen = "127.0.0.1:0"
			},
			want: "api.listen",
		},
		{
			name: "api port too high",
			mutate: func(cfg *ControllerConfig) {
				cfg.API.Listen = "127.0.0.1:65536"
			},
			want: "api.listen",
		},
		{
			name: "api non numeric port",
			mutate: func(cfg *ControllerConfig) {
				cfg.API.Listen = "127.0.0.1:http"
			},
			want: "api.listen",
		},
		{
			name: "api host with whitespace",
			mutate: func(cfg *ControllerConfig) {
				cfg.API.Listen = "127.0.0.1 :8080"
			},
			want: "api.listen",
		},
		{
			name: "observability missing port",
			mutate: func(cfg *ControllerConfig) {
				cfg.Observability.Listen = "127.0.0.1"
			},
			want: "observability.listen",
		},
		{
			name: "observability zero port",
			mutate: func(cfg *ControllerConfig) {
				cfg.Observability.Listen = "127.0.0.1:0"
			},
			want: "observability.listen",
		},
		{
			name: "observability non numeric port",
			mutate: func(cfg *ControllerConfig) {
				cfg.Observability.Listen = "127.0.0.1:http"
			},
			want: "observability.listen",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			tc.mutate(cfg)
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateControllerConfig_AllowsIPv6ListenAddresses(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.Listen = "[::1]:8080"
	cfg.Observability.Listen = "[::1]:9053"

	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateControllerConfig_RemoteObservabilityRequiresAuthToken(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Observability.Listen = "0.0.0.0:9053"
	cfg.Observability.AuthToken = ""

	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "observability.auth_token")
}

func TestValidateControllerConfig_RemoteObservabilityAcceptsAuthToken(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Observability.Listen = "0.0.0.0:9053"
	cfg.Observability.AuthToken = validStatusAuthToken

	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateControllerConfig_ObservabilityAuthTokenMustBeStrongEnough(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Observability.AuthToken = "short"

	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "observability.auth_token")
}

func TestValidateControllerConfig_RejectsPlaceholderObservabilityAuthToken(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Observability.AuthToken = "REPLACE_WITH_STATUS_AUTH_TOKEN"

	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "observability.auth_token")
	assert.Contains(t, err.Error(), "placeholder")
}

func TestValidateControllerConfig_ObservabilityListenMustNotOverlapAPIListen(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.API.Listen = "0.0.0.0:8080"
	cfg.Observability.Listen = "127.0.0.1:8080"
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "observability.listen")
	assert.Contains(t, err.Error(), "api.listen")
}

func TestValidateControllerConfig_InvalidBackendType(t *testing.T) {
	for _, backendType := range []string{"invalid", "memory"} {
		t.Run(backendType, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			cfg.Backend.Type = backendType
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "backend.type")
		})
	}
}

func TestValidateControllerConfig_RuntimeBackendRequiresActiveBackendSettings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ControllerConfig)
		want   string
	}{
		{
			name: "postgres empty dsn",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "postgres"
				cfg.Backend.Postgres.DSN = ""
			},
			want: "backend.postgres.dsn",
		},
		{
			name: "postgres placeholder dsn",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "postgres"
				cfg.Backend.Postgres.DSN = "postgres://REPLACE_WITH_USER:REPLACE_WITH_PASSWORD@db:5432/arca_dns"
			},
			want: "backend.postgres.dsn",
		},
		{
			name: "postgres negative max open conns",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "postgres"
				cfg.Backend.Postgres.DSN = "postgres://user:pass@db:5432/arca_dns?sslmode=require"
				cfg.Backend.Postgres.MaxOpenConns = -1
			},
			want: "backend.postgres.max_open_conns",
		},
		{
			name: "postgres max idle exceeds max open",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "postgres"
				cfg.Backend.Postgres.DSN = "postgres://user:pass@db:5432/arca_dns?sslmode=require"
				cfg.Backend.Postgres.MaxOpenConns = 5
				cfg.Backend.Postgres.MaxIdleConns = 6
			},
			want: "backend.postgres.max_idle_conns",
		},
		{
			name: "postgres negative conn max lifetime",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "postgres"
				cfg.Backend.Postgres.DSN = "postgres://user:pass@db:5432/arca_dns?sslmode=require"
				cfg.Backend.Postgres.ConnMaxLifetime = -time.Second
			},
			want: "backend.postgres.conn_max_lifetime",
		},
		{
			name: "mysql empty dsn",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "mysql"
				cfg.Backend.MySQL.DSN = ""
			},
			want: "backend.mysql.dsn",
		},
		{
			name: "mysql dsn control character",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "mysql"
				cfg.Backend.MySQL.DSN = "user:pass@tcp(db:3306)/arca_dns\nparseTime=true"
			},
			want: "backend.mysql.dsn",
		},
		{
			name: "mysql negative max idle conns",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "mysql"
				cfg.Backend.MySQL.DSN = "user:pass@tcp(db:3306)/arca_dns?parseTime=true"
				cfg.Backend.MySQL.MaxIdleConns = -1
			},
			want: "backend.mysql.max_idle_conns",
		},
		{
			name: "mysql max idle exceeds max open",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "mysql"
				cfg.Backend.MySQL.DSN = "user:pass@tcp(db:3306)/arca_dns?parseTime=true"
				cfg.Backend.MySQL.MaxOpenConns = 3
				cfg.Backend.MySQL.MaxIdleConns = 4
			},
			want: "backend.mysql.max_idle_conns",
		},
		{
			name: "mysql negative conn max lifetime",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "mysql"
				cfg.Backend.MySQL.DSN = "user:pass@tcp(db:3306)/arca_dns?parseTime=true"
				cfg.Backend.MySQL.ConnMaxLifetime = -time.Second
			},
			want: "backend.mysql.conn_max_lifetime",
		},
		{
			name: "git empty repository path",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "git"
				cfg.Backend.Git.RepositoryPath = ""
			},
			want: "backend.git.repository_path",
		},
		{
			name: "git negative pull interval",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "git"
				cfg.Backend.Git.RepositoryPath = "/var/lib/arca-dns/git"
				cfg.Backend.Git.PullInterval = -time.Second
			},
			want: "backend.git.pull_interval",
		},
		{
			name: "git invalid branch",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "git"
				cfg.Backend.Git.RepositoryPath = "/var/lib/arca-dns/git"
				cfg.Backend.Git.Branch = "feature branch"
			},
			want: "backend.git.branch",
		},
		{
			name: "git author control character",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "git"
				cfg.Backend.Git.RepositoryPath = "/var/lib/arca-dns/git"
				cfg.Backend.Git.Author = "test\nauthor"
			},
			want: "backend.git.author",
		},
		{
			name: "git email whitespace",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "git"
				cfg.Backend.Git.RepositoryPath = "/var/lib/arca-dns/git"
				cfg.Backend.Git.Email = "test user@example.com"
			},
			want: "backend.git.email",
		},
		{
			name: "git remote url control character",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "git"
				cfg.Backend.Git.RepositoryPath = "/var/lib/arca-dns/git"
				cfg.Backend.Git.RemoteURL = "https://example.com/arca-dns.git\nextra"
			},
			want: "backend.git.remote_url",
		},
		{
			name: "etcd empty endpoints",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = nil
			},
			want: "backend.etcd.endpoints",
		},
		{
			name: "etcd blank endpoint",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://etcd-a:2379", " "}
			},
			want: "backend.etcd.endpoints[1]",
		},
		{
			name: "etcd endpoint missing port",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://etcd-a"}
			},
			want: "backend.etcd.endpoints[0]",
		},
		{
			name: "etcd endpoint unsupported scheme",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"ftp://etcd-a:2379"}
			},
			want: "backend.etcd.endpoints[0]",
		},
		{
			name: "etcd endpoint with userinfo",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://user:pass@etcd-a:2379"}
			},
			want: "backend.etcd.endpoints[0]",
		},
		{
			name: "etcd endpoint invalid hostname",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://bad_host:2379"}
			},
			want: "backend.etcd.endpoints[0]",
		},
		{
			name: "etcd endpoint unspecified host",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://0.0.0.0:2379"}
			},
			want: "backend.etcd.endpoints[0]",
		},
		{
			name: "etcd endpoint zero port",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://etcd-a:0"}
			},
			want: "backend.etcd.endpoints[0]",
		},
		{
			name: "etcd placeholder password",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://etcd-a:2379"}
				cfg.Backend.Etcd.Password = "REPLACE_WITH_ETCD_PASSWORD"
			},
			want: "backend.etcd.password",
		},
		{
			name: "etcd negative request timeout",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{"http://etcd-a:2379"}
				cfg.Backend.Etcd.RequestTimeout = -time.Second
			},
			want: "backend.etcd.request_timeout",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			tc.mutate(cfg)

			err := ValidateControllerConfig(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateControllerConfig_RuntimeBackendAllowsValidActiveBackendSettings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ControllerConfig)
	}{
		{
			name: "postgres",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "postgres"
				cfg.Backend.Postgres.DSN = "postgres://user:pass@db:5432/arca_dns?sslmode=require"
			},
		},
		{
			name: "postgres pool settings",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "postgres"
				cfg.Backend.Postgres.DSN = "postgres://user:pass@db:5432/arca_dns?sslmode=require"
				cfg.Backend.Postgres.MaxOpenConns = 10
				cfg.Backend.Postgres.MaxIdleConns = 5
				cfg.Backend.Postgres.ConnMaxLifetime = 10 * time.Minute
			},
		},
		{
			name: "mysql",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "mysql"
				cfg.Backend.MySQL.DSN = "user:pass@tcp(db:3306)/arca_dns?parseTime=true"
			},
		},
		{
			name: "mysql pool settings",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "mysql"
				cfg.Backend.MySQL.DSN = "user:pass@tcp(db:3306)/arca_dns?parseTime=true"
				cfg.Backend.MySQL.MaxOpenConns = 10
				cfg.Backend.MySQL.MaxIdleConns = 5
				cfg.Backend.MySQL.ConnMaxLifetime = 10 * time.Minute
			},
		},
		{
			name: "git",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "git"
				cfg.Backend.Git.RepositoryPath = "/var/lib/arca-dns/git"
				cfg.Backend.Git.Branch = "main"
				cfg.Backend.Git.Author = "arca-dns-controller"
				cfg.Backend.Git.Email = "noreply@arca-dns"
				cfg.Backend.Git.RemoteURL = "git@github.com:akam1o/arca-dns.git"
				cfg.Backend.Git.PullInterval = time.Minute
			},
		},
		{
			name: "etcd",
			mutate: func(cfg *ControllerConfig) {
				cfg.Backend.Type = "etcd"
				cfg.Backend.Etcd.Endpoints = []string{" http://etcd-a:2379 ", "etcd-b:2379", "https://etcd-c.example.com:2379", "[::1]:2379"}
				cfg.Backend.Etcd.DialTimeout = 0
				cfg.Backend.Etcd.RequestTimeout = 0
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			tc.mutate(cfg)

			require.NoError(t, ValidateControllerConfig(cfg))
		})
	}
}

func TestValidateControllerConfig_RejectsInMemorySQLiteDSN(t *testing.T) {
	tests := []struct {
		name string
		dsn  string
	}{
		{
			name: "memory alias",
			dsn:  ":memory:",
		},
		{
			name: "file memory alias",
			dsn:  "file::memory:?cache=shared",
		},
		{
			name: "uri memory mode",
			dsn:  "file:controller?mode=memory&cache=shared",
		},
		{
			name: "case-insensitive uri memory mode",
			dsn:  "file:controller?cache=shared&mode=MEMORY",
		},
		{
			name: "encoded uri memory mode",
			dsn:  "file:controller?cache=shared&%6dode=%6demory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			cfg.Backend.Type = "sqlite"
			cfg.Backend.SQLite.DSN = tc.dsn
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "backend.sqlite.dsn")
			assert.Contains(t, err.Error(), "in-memory SQLite")
		})
	}
}

func TestValidateControllerConfig_AllowsFileBackedSQLiteDSN(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Backend.Type = "sqlite"
	cfg.Backend.SQLite.DSN = "file:/var/lib/arca-dns/controller-memory-name.db?_pragma=journal_mode(memory)"

	assert.NoError(t, ValidateControllerConfig(cfg))
}

func TestValidateControllerConfig_InvalidGitRepositoryPath(t *testing.T) {
	tests := []struct {
		name           string
		repositoryPath string
	}{
		{
			name:           "relative",
			repositoryPath: "var/lib/arca-dns/git",
		},
		{
			name:           "surrounding whitespace",
			repositoryPath: " /var/lib/arca-dns/git ",
		},
		{
			name:           "whitespace only",
			repositoryPath: "   ",
		},
		{
			name:           "newline",
			repositoryPath: "/var/lib/arca-dns/git\nextra",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			cfg.Backend.Type = "git"
			cfg.Backend.Git.RepositoryPath = tc.repositoryPath
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "backend.git.repository_path")
		})
	}
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

func TestValidateControllerConfig_InvalidLoggingFormat(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Logging.Format = "xml"

	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logging.format")
}

func TestValidateControllerConfig_AllowsEmptyLoggingFormatDefault(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Logging.Format = ""

	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateControllerConfig_InvalidLoggingOutputPath(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "relative",
			output: "arca-dns.log",
		},
		{
			name:   "surrounding whitespace",
			output: " /var/log/arca-dns/controller.log ",
		},
		{
			name:   "stdout surrounding whitespace",
			output: " stdout ",
		},
		{
			name:   "newline",
			output: "/var/log/arca-dns/controller.log\nextra",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			cfg.Logging.Output = tc.output
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "logging.output")
		})
	}
}

func TestValidateControllerConfig_EmptyKeyDirectory(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.Enabled = true
	cfg.DNSSEC.KeyDirectory = ""
	cfg.Storage.KeyDirectory = ""
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_directory")
}

func TestValidateControllerConfig_StorageKeyDirectoryAliasesDNSSECKeyDirectory(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.Enabled = true
	cfg.DNSSEC.KeyDirectory = ""
	cfg.Storage.KeyDirectory = "/tmp/storage-keys"

	err := ValidateControllerConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/storage-keys", cfg.DNSSEC.KeyDirectory)
	assert.Equal(t, "/tmp/storage-keys", cfg.DNSSECKeyDirectory())
}

func TestValidateControllerConfig_InvalidStoragePaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ControllerConfig)
		want   string
	}{
		{
			name: "relative artifact directory",
			mutate: func(cfg *ControllerConfig) {
				cfg.Storage.ArtifactDirectory = "var/lib/arca-dns/artifacts"
			},
			want: "storage.artifact_directory",
		},
		{
			name: "artifact directory with surrounding whitespace",
			mutate: func(cfg *ControllerConfig) {
				cfg.Storage.ArtifactDirectory = " /var/lib/arca-dns/artifacts "
			},
			want: "storage.artifact_directory",
		},
		{
			name: "relative storage key directory",
			mutate: func(cfg *ControllerConfig) {
				cfg.Storage.KeyDirectory = "var/lib/arca-dns/keys"
			},
			want: "storage.key_directory",
		},
		{
			name: "dnssec key directory with newline",
			mutate: func(cfg *ControllerConfig) {
				cfg.DNSSEC.KeyDirectory = "/var/lib/arca-dns/keys\nextra"
			},
			want: "dnssec.key_directory",
		},
		{
			name: "relative dnssec key directory",
			mutate: func(cfg *ControllerConfig) {
				cfg.DNSSEC.KeyDirectory = "var/lib/arca-dns/keys"
			},
			want: "dnssec.key_directory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			tc.mutate(cfg)
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateControllerConfig_InvalidMaxVersionsPerZone(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.Storage.MaxVersionsPerZone = 0
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max_versions_per_zone")
}

func TestValidateControllerConfig_InvalidAlgorithm(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.Algorithm = 99
	err := ValidateControllerConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")
}

func TestValidateControllerConfig_InvalidDNSSECKeySize(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ControllerConfig)
		want   string
	}{
		{
			name: "negative ksk key size",
			mutate: func(cfg *ControllerConfig) {
				cfg.DNSSEC.Algorithm = 8
				cfg.DNSSEC.KSKKeySize = -1
			},
			want: "dnssec.ksk_key_size",
		},
		{
			name: "negative zsk key size",
			mutate: func(cfg *ControllerConfig) {
				cfg.DNSSEC.Algorithm = 8
				cfg.DNSSEC.ZSKKeySize = -1
			},
			want: "dnssec.zsk_key_size",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfigForTest()
			tc.mutate(cfg)
			err := ValidateControllerConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateControllerConfig_AllowsDefaultDNSSECKeySizes(t *testing.T) {
	cfg := validControllerConfigForTest()
	cfg.DNSSEC.KSKKeySize = 0
	cfg.DNSSEC.ZSKKeySize = 0

	err := ValidateControllerConfig(cfg)
	assert.NoError(t, err)
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
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_PUBLIC_KEY", validTestArtifactSignatureKey)

	cfg, err := LoadAgentConfig("")
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080", cfg.Controller.URL)
	assert.Equal(t, DefaultControllerClientMaxResponseBytes, cfg.Controller.MaxResponseBytes)
	assert.Equal(t, "nsd", cfg.Authoritative)
	assert.True(t, cfg.NSD.Enabled)
	assert.True(t, cfg.Unbound.Enabled)
	assert.Equal(t, 1232, cfg.Unbound.EDNSBufferSize)
	assert.Equal(t, DefaultDNSTapSocketModeString, cfg.DNSTap.SocketMode)
	assert.Empty(t, cfg.DNSTap.SocketGroup)
	assert.True(t, cfg.Sync.VerifySignatures)
	assert.Equal(t, DefaultAgentSyncMinFreeBytes, cfg.Sync.MinFreeBytes)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerPublicKey)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerSignatureKey)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestLoadAgentConfig_FromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	configContent := `
controller:
  url: "https://controller.example.com"
  api_key: "test-key"
  max_response_bytes: 1048576
nsd:
  enabled: true
  zone_directory: "/tmp/nsd-zones"
unbound:
  enabled: false
dnstap:
  socket_mode: "0600"
  socket_group: "nsd"
sync:
  min_free_bytes: 123456789
  controller_signature_key: "` + validYAMLArtifactSignatureKey + `"
  controller_signature_keys:
    Primary: "` + validYAMLArtifactSignatureKey + `"
    Previous: "` + validTestArtifactSignatureKey + `"
metrics:
  auth_token: "` + validStatusAuthToken + `"
logging:
  level: "debug"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadAgentConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, "https://controller.example.com", cfg.Controller.URL)
	assert.Equal(t, "test-key", cfg.Controller.APIKey)
	assert.Equal(t, int64(1048576), cfg.Controller.MaxResponseBytes)
	assert.Equal(t, "/tmp/nsd-zones", cfg.NSD.ZoneDirectory)
	assert.False(t, cfg.Unbound.Enabled)
	assert.Equal(t, "0600", cfg.DNSTap.SocketMode)
	assert.Equal(t, "nsd", cfg.DNSTap.SocketGroup)
	assert.True(t, cfg.Sync.VerifySignatures)
	assert.Equal(t, int64(123456789), cfg.Sync.MinFreeBytes)
	assert.Equal(t, validYAMLArtifactSignatureKey, cfg.Sync.ControllerPublicKey)
	assert.Equal(t, validYAMLArtifactSignatureKey, cfg.Sync.ControllerSignatureKey)
	assert.Equal(t, map[string]string{
		"primary":  validYAMLArtifactSignatureKey,
		"previous": validTestArtifactSignatureKey,
	}, cfg.Sync.ControllerSignatureKeys)
	assert.Equal(t, validStatusAuthToken, cfg.Metrics.AuthToken)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoadAgentConfig_EnvOverrideWithYAML(t *testing.T) {
	t.Setenv("ARCA_DNS_CONTROLLER_URL", "https://env-controller.example.com")
	t.Setenv("ARCA_DNS_CONTROLLER_API_KEY", "env-api-key")
	t.Setenv("ARCA_DNS_CONTROLLER_TLS_ENABLED", "true")
	t.Setenv("ARCA_DNS_CONTROLLER_TLS_CA_FILE", "/env/controller-ca.crt")
	t.Setenv("ARCA_DNS_CONTROLLER_MAX_RESPONSE_BYTES", "2097152")
	t.Setenv("ARCA_DNS_NSD_ENABLED", "false")
	t.Setenv("ARCA_DNS_UNBOUND_STUB_ZONE_NSD_PORT", "5533")
	t.Setenv("ARCA_DNS_SYNC_VERIFY_CHECKSUMS", "false")
	t.Setenv("ARCA_DNS_SYNC_MIN_FREE_BYTES", "20971520")
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_SIGNATURE_KEY", validEnvArtifactSignatureKey)
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_SIGNATURE_KEYS_PREVIOUS", validTestArtifactSignatureKey)
	t.Setenv("ARCA_DNS_HEALTH_QUERY_TIMEOUT", "2s")
	t.Setenv("ARCA_DNS_METRICS_PATH", "/env-metrics")
	t.Setenv("ARCA_DNS_METRICS_AUTH_TOKEN", validStatusAuthToken)
	t.Setenv("ARCA_DNS_DNSTAP_SOCKET_MODE", "0600")
	t.Setenv("ARCA_DNS_DNSTAP_SOCKET_GROUP", "unbound")
	t.Setenv("ARCA_DNS_LOGGING_ENABLE_CALLER", "true")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	configContent := `
controller:
  url: "https://yaml-controller.example.com"
  api_key: "yaml-api-key"
  tls:
    ca_file: "/yaml/controller-ca.crt"
nsd:
  enabled: true
  zone_directory: "/tmp/nsd-zones"
unbound:
  enabled: false
  stub_zone:
    nsd_port: 5353
sync:
  verify_checksums: true
  controller_signature_key: "` + validYAMLArtifactSignatureKey + `"
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
	assert.True(t, cfg.Controller.TLS.Enabled)
	assert.Equal(t, "/env/controller-ca.crt", cfg.Controller.TLS.CAFile)
	assert.Equal(t, int64(2097152), cfg.Controller.MaxResponseBytes)
	assert.False(t, cfg.NSD.Enabled)
	assert.Equal(t, 5533, cfg.Unbound.StubZoneConfig.NSDPort)
	assert.False(t, cfg.Sync.VerifyChecksums)
	assert.Equal(t, int64(20971520), cfg.Sync.MinFreeBytes)
	assert.Equal(t, validEnvArtifactSignatureKey, cfg.Sync.ControllerPublicKey)
	assert.Equal(t, validEnvArtifactSignatureKey, cfg.Sync.ControllerSignatureKey)
	assert.Equal(t, map[string]string{"previous": validTestArtifactSignatureKey}, cfg.Sync.ControllerSignatureKeys)
	assert.Equal(t, 2*time.Second, cfg.Health.QueryTimeout)
	assert.Equal(t, "/env-metrics", cfg.Metrics.Path)
	assert.Equal(t, validStatusAuthToken, cfg.Metrics.AuthToken)
	assert.Equal(t, "0600", cfg.DNSTap.SocketMode)
	assert.Equal(t, "unbound", cfg.DNSTap.SocketGroup)
	assert.True(t, cfg.Logging.EnableCaller)
}

func TestLoadAgentConfig_EnvOverrideWithoutFile(t *testing.T) {
	t.Setenv("ARCA_DNS_CONTROLLER_URL", "https://env-only-controller.example.com")
	t.Setenv("ARCA_DNS_CONTROLLER_API_KEY", "env-only-api-key")
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_PUBLIC_KEY", validEnvArtifactSignatureKey)

	cfg, err := LoadAgentConfig("")
	require.NoError(t, err)

	assert.Equal(t, "https://env-only-controller.example.com", cfg.Controller.URL)
	assert.Equal(t, "env-only-api-key", cfg.Controller.APIKey)
	assert.Equal(t, validEnvArtifactSignatureKey, cfg.Sync.ControllerPublicKey)
}

func TestValidateAgentConfig_Valid(t *testing.T) {
	cfg := validAgentConfigForTest()
	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentControllerConfigSectionNormalizesURL(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Controller.URL = " https://controller.example.com/base/ "

	err := validateAgentControllerConfig(&cfg.Controller)
	require.NoError(t, err)

	assert.Equal(t, "https://controller.example.com/base", cfg.Controller.URL)
}

func TestValidateAgentSyncConfigSectionRejectsStalenessBelowInterval(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.SyncInterval = time.Minute
	cfg.Sync.MaxStaleness = time.Minute - time.Second

	err := validateAgentSyncConfig(&cfg.Sync)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sync.max_staleness")
}

func TestValidateAgentConfig_EmptyControllerURL(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Controller.URL = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "controller.url")
}

func TestValidateAgentConfig_InvalidControllerURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "missing scheme",
			url:  "controller.example.com",
			want: "missing scheme",
		},
		{
			name: "missing host",
			url:  "https:///api",
			want: "missing host",
		},
		{
			name: "unsupported scheme",
			url:  "ftp://controller.example.com",
			want: "unsupported scheme",
		},
		{
			name: "userinfo",
			url:  "https://agent:secret@controller.example.com",
			want: "userinfo",
		},
		{
			name: "query string",
			url:  "https://controller.example.com?tenant=prod",
			want: "query strings",
		},
		{
			name: "fragment",
			url:  "https://controller.example.com#agent",
			want: "fragments",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Controller.URL = tc.url
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "controller.url")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_NormalizesControllerURL(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Controller.URL = " https://controller.example.com/base/ "

	require.NoError(t, ValidateAgentConfig(cfg))
	assert.Equal(t, "https://controller.example.com/base", cfg.Controller.URL)
}

func TestValidateAgentConfig_PlaintextAPIKeyTransport(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AgentConfig)
		wantErr bool
	}{
		{
			name: "allows loopback http with api key",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "http://127.0.0.1:8080"
				cfg.Controller.APIKey = "secret"
			},
		},
		{
			name: "allows https with api key",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.APIKey = "secret"
			},
		},
		{
			name: "allows remote http without api key",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "http://controller.example.com"
			},
		},
		{
			name: "allows explicit plaintext opt in",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "http://controller.example.com"
				cfg.Controller.APIKey = "secret"
				cfg.Controller.AllowPlaintextAPIKey = true
			},
		},
		{
			name: "rejects remote http with api key",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "http://controller.example.com"
				cfg.Controller.APIKey = "secret"
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "controller.api_key")
				assert.Contains(t, err.Error(), "plaintext HTTP")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateAgentConfig_RejectsPlaceholderAPIKey(t *testing.T) {
	tests := []string{
		"REPLACE_WITH_RAW_AGENT_API_KEY",
		"changeme",
		"TODO-agent-key",
	}

	for _, apiKey := range tests {
		t.Run(apiKey, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Controller.URL = "https://controller.example.com"
			cfg.Controller.APIKey = apiKey

			err := ValidateAgentConfig(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "controller.api_key")
			assert.Contains(t, err.Error(), "replace placeholder")
		})
	}
}

func TestLoadAgentConfig_PlaintextAPIKeyOptInFromEnv(t *testing.T) {
	t.Setenv("ARCA_DNS_CONTROLLER_URL", "http://controller.example.com")
	t.Setenv("ARCA_DNS_CONTROLLER_API_KEY", "env-only-api-key")
	t.Setenv("ARCA_DNS_CONTROLLER_ALLOW_PLAINTEXT_API_KEY", "true")
	t.Setenv("ARCA_DNS_SYNC_CONTROLLER_PUBLIC_KEY", validEnvArtifactSignatureKey)

	cfg, err := LoadAgentConfig("")
	require.NoError(t, err)

	assert.Equal(t, "http://controller.example.com", cfg.Controller.URL)
	assert.Equal(t, "env-only-api-key", cfg.Controller.APIKey)
	assert.True(t, cfg.Controller.AllowPlaintextAPIKey)
}

func TestValidateAgentConfig_InvalidControllerClientSettings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "zero timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.Timeout = 0
			},
			want: "controller.timeout",
		},
		{
			name: "negative retry attempts",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.RetryAttempts = -1
			},
			want: "controller.retry_attempts",
		},
		{
			name: "negative retry delay",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.RetryDelay = -time.Second
			},
			want: "controller.retry_delay",
		},
		{
			name: "zero retry delay with retries",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.RetryAttempts = 1
				cfg.Controller.RetryDelay = 0
			},
			want: "controller.retry_delay",
		},
		{
			name: "zero max response bytes",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.MaxResponseBytes = 0
			},
			want: "controller.max_response_bytes",
		},
		{
			name: "tls enabled with http url",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.TLS.Enabled = true
			},
			want: "controller.tls.enabled",
		},
		{
			name: "ca file without tls enabled",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.CAFile = "/etc/arca-dns/controller-ca.crt"
			},
			want: "controller.tls.enabled",
		},
		{
			name: "cert file without tls enabled",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.CertFile = "/etc/arca-dns/client.crt"
			},
			want: "controller.tls.enabled",
		},
		{
			name: "client cert without client auth",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.Enabled = true
				cfg.Controller.TLS.CertFile = "/etc/arca-dns/client.crt"
				cfg.Controller.TLS.KeyFile = "/etc/arca-dns/client.key"
			},
			want: "controller.tls.client_auth",
		},
		{
			name: "client auth without tls enabled",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.ClientAuth = true
				cfg.Controller.TLS.CertFile = "/etc/arca-dns/client.crt"
				cfg.Controller.TLS.KeyFile = "/etc/arca-dns/client.key"
			},
			want: "controller.tls.client_auth",
		},
		{
			name: "client auth without cert file",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.Enabled = true
				cfg.Controller.TLS.ClientAuth = true
				cfg.Controller.TLS.KeyFile = "/etc/arca-dns/client.key"
			},
			want: "controller.tls.cert_file",
		},
		{
			name: "client auth without key file",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.Enabled = true
				cfg.Controller.TLS.ClientAuth = true
				cfg.Controller.TLS.CertFile = "/etc/arca-dns/client.crt"
			},
			want: "controller.tls.key_file",
		},
		{
			name: "relative tls ca file",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.Enabled = true
				cfg.Controller.TLS.CAFile = "controller-ca.crt"
			},
			want: "controller.tls.ca_file",
		},
		{
			name: "tls ca file with surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.Enabled = true
				cfg.Controller.TLS.CAFile = " /etc/arca-dns/controller-ca.crt "
			},
			want: "controller.tls.ca_file",
		},
		{
			name: "relative tls cert file",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.Enabled = true
				cfg.Controller.TLS.ClientAuth = true
				cfg.Controller.TLS.CertFile = "client.crt"
				cfg.Controller.TLS.KeyFile = "/etc/arca-dns/client.key"
			},
			want: "controller.tls.cert_file",
		},
		{
			name: "tls key file with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.Controller.URL = "https://controller.example.com"
				cfg.Controller.TLS.Enabled = true
				cfg.Controller.TLS.ClientAuth = true
				cfg.Controller.TLS.CertFile = "/etc/arca-dns/client.crt"
				cfg.Controller.TLS.KeyFile = "/etc/arca-dns/client.key\nextra"
			},
			want: "controller.tls.key_file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_AllowsControllerClientAuthTLS(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Controller.URL = "https://controller.example.com"
	cfg.Controller.TLS.Enabled = true
	cfg.Controller.TLS.ClientAuth = true
	cfg.Controller.TLS.CertFile = "/etc/arca-dns/client.crt"
	cfg.Controller.TLS.KeyFile = "/etc/arca-dns/client.key"

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_AllowsControllerCustomCATLS(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Controller.URL = "https://controller.example.com"
	cfg.Controller.TLS.Enabled = true
	cfg.Controller.TLS.CAFile = "/etc/arca-dns/controller-ca.crt"

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_InvalidAuthoritative(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Authoritative = "knot"
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authoritative")
	assert.Contains(t, err.Error(), "supported: nsd")
}

func TestValidateAgentConfig_NormalizesAuthoritative(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Authoritative = " NSD "
	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
	assert.Equal(t, "nsd", cfg.Authoritative)
}

func TestValidateAgentConfig_NSDMissingConfig(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.NSD.Enabled = true
	cfg.NSD.ConfigPath = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nsd.config_path")
}

func TestValidateAgentConfig_InvalidNSDExecutablePaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "relative control path",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ControlPath = "nsd-control"
			},
			want: "nsd.control_path",
		},
		{
			name: "control path with surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ControlPath = " /usr/sbin/nsd-control "
			},
			want: "nsd.control_path",
		},
		{
			name: "relative checkzone path",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.CheckzonePath = "nsd-checkzone"
			},
			want: "nsd.checkzone_path",
		},
		{
			name: "checkzone path with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.CheckzonePath = "/usr/sbin/nsd-checkzone\n--help"
			},
			want: "nsd.checkzone_path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_NSDZoneDirectoryRequiredWhenNSDDisabled(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.NSD.Enabled = false
	cfg.NSD.ZoneDirectory = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nsd.zone_directory")
}

func TestValidateAgentConfig_InvalidNSDRenderedConfigPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "zone directory with surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ZoneDirectory = " /var/lib/nsd/zones "
			},
			want: "nsd.zone_directory",
		},
		{
			name: "zone directory with quote",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ZoneDirectory = `/var/lib/nsd/zones"`
			},
			want: "nsd.zone_directory",
		},
		{
			name: "zone directory with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ZoneDirectory = "/var/lib/nsd/zones\ninclude: \"/tmp/pwn\""
			},
			want: "nsd.zone_directory",
		},
		{
			name: "relative zone directory",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ZoneDirectory = "var/lib/nsd/zones"
			},
			want: "nsd.zone_directory",
		},
		{
			name: "config path with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.Enabled = true
				cfg.NSD.ConfigPath = "/etc/nsd/nsd.conf\ninclude: \"/tmp/pwn\""
			},
			want: "nsd.config_path",
		},
		{
			name: "relative config path",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.Enabled = true
				cfg.NSD.ConfigPath = "etc/nsd/nsd.conf"
			},
			want: "nsd.config_path",
		},
		{
			name: "zone config path with quote",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.Enabled = true
				cfg.NSD.ZoneConfigPath = `/etc/nsd/arca-dns-zones".conf`
			},
			want: "nsd.zone_config_path",
		},
		{
			name: "relative zone config path",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.Enabled = true
				cfg.NSD.ZoneConfigPath = "etc/nsd/arca-dns-zones.conf"
			},
			want: "nsd.zone_config_path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_UnboundMissingConfig(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Unbound.Enabled = true
	cfg.Unbound.ConfigPath = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unbound.config_path")
}

func TestValidateAgentConfig_InvalidUnboundConfigPath(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
	}{
		{
			name:       "relative",
			configPath: "etc/unbound/unbound.conf",
		},
		{
			name:       "surrounding whitespace",
			configPath: " /etc/unbound/unbound.conf ",
		},
		{
			name:       "newline",
			configPath: "/etc/unbound/unbound.conf\ninclude: /tmp/pwn",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Unbound.Enabled = true
			cfg.Unbound.ConfigPath = tc.configPath
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "unbound.config_path")
		})
	}
}

func TestValidateAgentConfig_InvalidUnboundExecutablePaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "relative control path",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.ControlPath = "unbound-control"
			},
			want: "unbound.control_path",
		},
		{
			name: "control path with surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.ControlPath = " /usr/sbin/unbound-control "
			},
			want: "unbound.control_path",
		},
		{
			name: "relative checkconf path",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.CheckconfPath = "unbound-checkconf"
			},
			want: "unbound.checkconf_path",
		},
		{
			name: "checkconf path with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.CheckconfPath = "/usr/sbin/unbound-checkconf\n--help"
			},
			want: "unbound.checkconf_path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_InvalidRuntimeLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "zero nsd reload timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ReloadTimeout = 0
			},
			want: "nsd.reload_timeout",
		},
		{
			name: "negative nsd reload timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.NSD.ReloadTimeout = -time.Second
			},
			want: "nsd.reload_timeout",
		},
		{
			name: "zero unbound reload timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.ReloadTimeout = 0
			},
			want: "unbound.reload_timeout",
		},
		{
			name: "negative unbound reload timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.ReloadTimeout = -time.Second
			},
			want: "unbound.reload_timeout",
		},
		{
			name: "zero bird command timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.Enabled = true
				cfg.BIRD.CommandTimeout = 0
			},
			want: "bird.command_timeout",
		},
		{
			name: "negative bird command timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.Enabled = true
				cfg.BIRD.CommandTimeout = -time.Second
			},
			want: "bird.command_timeout",
		},
		{
			name: "negative sync jitter",
			mutate: func(cfg *AgentConfig) {
				cfg.Sync.Jitter = -time.Second
			},
			want: "sync.jitter",
		},
		{
			name: "zero dnstap buffer size",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.Enabled = true
				cfg.DNSTap.BufferSize = 0
			},
			want: "dnstap.buffer_size",
		},
		{
			name: "negative dnstap buffer size",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.Enabled = true
				cfg.DNSTap.BufferSize = -1
			},
			want: "dnstap.buffer_size",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_InvalidBIRDSocketPath(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
	}{
		{
			name:       "empty",
			socketPath: "",
		},
		{
			name:       "relative",
			socketPath: "bird.ctl",
		},
		{
			name:       "surrounding whitespace",
			socketPath: " /var/run/bird/bird.ctl ",
		},
		{
			name:       "newline",
			socketPath: "/var/run/bird/bird.ctl\nextra",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.BIRD.Enabled = true
			cfg.BIRD.SocketPath = tc.socketPath
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "bird.socket_path")
		})
	}
}

func TestValidateAgentConfig_InvalidBIRDConfigPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "empty",
			path: "",
		},
		{
			name: "relative",
			path: "etc/bird/arca-dns.conf",
		},
		{
			name: "surrounding whitespace",
			path: " /etc/bird/arca-dns.conf ",
		},
		{
			name: "newline",
			path: "/etc/bird/arca-dns.conf\ninclude \"/tmp/pwn\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.BIRD.Enabled = true
			cfg.BIRD.ConfigureOnStart.Enabled = true
			cfg.BIRD.ConfigureOnStart.Path = tc.path
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "bird.config.path")
		})
	}
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

func TestValidateAgentConfig_InvalidBIRDProtocolIdentifiers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "legacy protocol name with hyphen",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ProtocolName = "anycast-1"
			},
			want: "bird.protocol_name",
		},
		{
			name: "legacy protocol name starts with digit",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ProtocolName = "1anycast"
			},
			want: "bird.protocol_name",
		},
		{
			name: "protocol names entry with command separator",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ProtocolName = ""
				cfg.BIRD.ProtocolNames = []string{"anycast_1", "anycast; disable all;"}
			},
			want: "bird.protocol_names[1]",
		},
		{
			name: "protocol names empty entry",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ProtocolName = ""
				cfg.BIRD.ProtocolNames = []string{"anycast_1", ""}
			},
			want: "bird.protocol_names[1]",
		},
		{
			name: "protocol config name with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ProtocolName = ""
				cfg.BIRD.Protocols = []BIRDProtocolConfig{
					{Name: "anycast_1"},
					{Name: "anycast_2\nconfigure"},
				}
			},
			want: "bird.protocols[1].name",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.BIRD.Enabled = true
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_BIRDProtocolIdentifierPrecedence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
	}{
		{
			name: "protocols take precedence over legacy fields",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.Protocols = []BIRDProtocolConfig{{Name: "anycast_1"}}
				cfg.BIRD.ProtocolNames = []string{"anycast; disable all;"}
				cfg.BIRD.ProtocolName = "1anycast"
			},
		},
		{
			name: "protocol names take precedence over legacy protocol name",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ProtocolNames = []string{"anycast_1"}
				cfg.BIRD.ProtocolName = "1anycast"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.BIRD.Enabled = true
			cfg.Health.TestRecord = "health.example.com."
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.NoError(t, err)
		})
	}
}

func TestValidateAgentConfig_InvalidBIRDGeneratedConfigValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "invalid router id",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ConfigureOnStart.RouterID = "router.example.com"
			},
			want: "bird.config.router_id",
		},
		{
			name: "source ip with surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.ConfigureOnStart.SourceIP = " 192.0.2.53 "
			},
			want: "bird.config.source_ip",
		},
		{
			name: "invalid anycast prefix",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.AnycastPrefixes = []string{"192.0.2.53/32; import all;"}
			},
			want: "bird.anycast_prefixes[0]",
		},
		{
			name: "invalid protocol neighbor address",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.Protocols[0].NeighborAddress = "neighbor.example.com"
			},
			want: "bird.protocols[0].neighbor_address",
		},
		{
			name: "zero protocol neighbor asn",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.Protocols[0].NeighborASN = 0
			},
			want: "bird.protocols[0].neighbor_asn",
		},
		{
			name: "invalid legacy neighbor address",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.Protocols = nil
				cfg.BIRD.ConfigureOnStart.Neighbors = []BIRDNeighborConfig{
					{Address: "neighbor.example.com", ASN: 65001},
				}
			},
			want: "bird.config.neighbors[0].address",
		},
		{
			name: "zero legacy neighbor asn",
			mutate: func(cfg *AgentConfig) {
				cfg.BIRD.Protocols = nil
				cfg.BIRD.ConfigureOnStart.Neighbors = []BIRDNeighborConfig{
					{Address: "192.0.2.1", ASN: 0},
				}
			},
			want: "bird.config.neighbors[0].asn",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.BIRD.Enabled = true
			cfg.Health.TestRecord = "health.example.com."
			cfg.BIRD.ConfigureOnStart.Enabled = true
			cfg.BIRD.ConfigureOnStart.Path = "/etc/bird/arca-dns.conf"
			cfg.BIRD.ConfigureOnStart.RouterID = "192.0.2.53"
			cfg.BIRD.ConfigureOnStart.LocalAS = 65000
			cfg.BIRD.ConfigureOnStart.SourceIP = "192.0.2.53"
			cfg.BIRD.AnycastPrefixes = []string{"192.0.2.53/32", "2001:db8::53/128"}
			cfg.BIRD.Protocols = []BIRDProtocolConfig{
				{Name: "anycast_1", NeighborAddress: "192.0.2.1", NeighborASN: 65001},
			}

			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_AllowsTrimmedBIRDAnycastPrefixes(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.BIRD.Enabled = true
	cfg.Health.TestRecord = "health.example.com."
	cfg.BIRD.ConfigureOnStart.Enabled = true
	cfg.BIRD.ConfigureOnStart.Path = "/etc/bird/arca-dns.conf"
	cfg.BIRD.ConfigureOnStart.RouterID = "192.0.2.53"
	cfg.BIRD.ConfigureOnStart.LocalAS = 65000
	cfg.BIRD.ConfigureOnStart.SourceIP = "192.0.2.53"
	cfg.BIRD.AnycastPrefixes = []string{" 192.0.2.53/32 ", ""}
	cfg.BIRD.Protocols = []BIRDProtocolConfig{
		{Name: "anycast_1", NeighborAddress: "192.0.2.1", NeighborASN: 65001},
	}

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_InvalidSyncInterval(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.SyncInterval = 0
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync_interval")
}

func TestValidateAgentConfig_InvalidMaxStaleness(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
	}{
		{
			name: "zero",
			mutate: func(cfg *AgentConfig) {
				cfg.Sync.MaxStaleness = 0
			},
		},
		{
			name: "shorter than sync interval",
			mutate: func(cfg *AgentConfig) {
				cfg.Sync.SyncInterval = time.Minute
				cfg.Sync.MaxStaleness = time.Second
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "sync.max_staleness")
		})
	}
}

func TestValidateAgentConfig_InvalidHealthTiming(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "zero query timeout",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.QueryTimeout = 0
			},
			want: "health.query_timeout",
		},
		{
			name: "zero latency threshold",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.LatencyThreshold = 0
			},
			want: "health.latency_threshold",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_InvalidHealthServerAddress(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "nsd missing port",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.NSDServer = "127.0.0.1"
			},
			want: "health.nsd_server",
		},
		{
			name: "nsd surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.NSDServer = " 127.0.0.1:5353 "
			},
			want: "health.nsd_server",
		},
		{
			name: "nsd unspecified host",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.NSDServer = "0.0.0.0:5353"
			},
			want: "health.nsd_server",
		},
		{
			name: "unbound empty host",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.UnboundServer = ":53"
			},
			want: "health.unbound_server",
		},
		{
			name: "unbound zero port",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.UnboundServer = "127.0.0.1:0"
			},
			want: "health.unbound_server",
		},
		{
			name: "unbound invalid hostname",
			mutate: func(cfg *AgentConfig) {
				cfg.Health.UnboundServer = "bad_host:53"
			},
			want: "health.unbound_server",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_AllowsEmptyHealthServerAddressDefaults(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Health.NSDServer = ""
	cfg.Health.UnboundServer = ""

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_BIRDRequiresExplicitHealthRecord(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.BIRD.Enabled = true

	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health.test_record")
}

func TestValidateAgentConfig_BIRDRequiresHealthZoneForRelativeRecord(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.BIRD.Enabled = true
	cfg.Health.TestRecord = "www"

	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health.test_zone")
}

func TestValidateAgentConfig_BIRDRequiresHealthZoneForMultiLabelRelativeRecord(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.BIRD.Enabled = true
	cfg.Health.TestRecord = "www.edge"

	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health.test_zone")
}

func TestValidateAgentConfig_BIRDAllowsExplicitHealthTarget(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.BIRD.Enabled = true
	cfg.Health.TestZone = "example.com."
	cfg.Health.TestRecord = "www"

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_BIRDAllowsAbsoluteHealthTarget(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.BIRD.Enabled = true
	cfg.Health.TestRecord = "www.edge.example.com."

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_InvalidBackupVersions(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.BackupVersions = -1
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync.backup_versions")
}

func TestValidateAgentConfig_InvalidMinFreeBytes(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.MinFreeBytes = -1
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync.min_free_bytes")
}

func TestValidateAgentConfig_RequiresECMPSafeEDNSBufferSize(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Unbound.Enabled = true
	cfg.Unbound.EDNSBufferSize = 4096

	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unbound.edns_buffer_size")
	assert.Contains(t, err.Error(), "1232")
}

func TestValidateAgentConfig_VerifySignaturesRequiresKey(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Sync.VerifySignatures = true
	cfg.Sync.ControllerPublicKey = ""
	cfg.Sync.ControllerSignatureKey = ""
	cfg.Sync.ControllerSignatureKeys = nil
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sync.controller_signature_key")
}

func TestValidateAgentConfig_VerifySignaturesAcceptsKeyRing(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Sync.VerifySignatures = true
	cfg.Sync.ControllerPublicKey = ""
	cfg.Sync.ControllerSignatureKey = ""
	cfg.Sync.ControllerSignatureKeys = map[string]string{
		"Primary": validTestArtifactSignatureKey,
	}

	err := ValidateAgentConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"primary": validTestArtifactSignatureKey}, cfg.Sync.ControllerSignatureKeys)
}

func TestValidateAgentConfig_RejectsInvalidSignatureKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "placeholder",
			key:  "REPLACE_WITH_SHARED_SIGNATURE_KEY",
			want: "placeholder",
		},
		{
			name: "too short",
			key:  "short-secret",
			want: "at least 32 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Sync.VerifySignatures = true
			cfg.Sync.ControllerSignatureKey = tc.key
			cfg.Sync.ControllerPublicKey = ""
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "sync.controller_signature_key")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_RejectsInvalidSignatureKeyRing(t *testing.T) {
	tests := []struct {
		name string
		keys map[string]string
		want string
	}{
		{
			name: "invalid key id",
			keys: map[string]string{"primary key": validTestArtifactSignatureKey},
			want: "sync.controller_signature_keys.primary key",
		},
		{
			name: "placeholder key",
			keys: map[string]string{"primary": "REPLACE_WITH_SHARED_SIGNATURE_KEY"},
			want: "placeholder",
		},
		{
			name: "short key",
			keys: map[string]string{"primary": "short-secret"},
			want: "at least 32 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultAgentConfig()
			cfg.Sync.VerifySignatures = true
			cfg.Sync.ControllerSignatureKey = ""
			cfg.Sync.ControllerPublicKey = ""
			cfg.Sync.ControllerSignatureKeys = tc.keys

			err := ValidateAgentConfig(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_AcceptsLegacyControllerPublicKeyAlias(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Sync.ControllerPublicKey = validTestArtifactSignatureKey
	cfg.Sync.ControllerSignatureKey = ""

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerSignatureKey)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerPublicKey)
}

func TestValidateAgentConfig_PrefersControllerSignatureKeyAlias(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.ControllerPublicKey = "different-artifact-signature-key-32"

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerSignatureKey)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerPublicKey)
}

func TestValidateAgentConfig_ValidatesCanonicalControllerSignatureKey(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Sync.ControllerPublicKey = "short"

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerSignatureKey)
	assert.Equal(t, validTestArtifactSignatureKey, cfg.Sync.ControllerPublicKey)
}

func TestValidateAgentConfig_InvalidDNSTapSampleRate(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.DNSTap.Enabled = true
	cfg.DNSTap.SampleRate = 0
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dnstap.sample_rate")
}

func TestValidateAgentConfig_InvalidDNSTapLogFilePath(t *testing.T) {
	tests := []struct {
		name    string
		logFile string
	}{
		{
			name:    "relative",
			logFile: "dnstap.log",
		},
		{
			name:    "surrounding whitespace",
			logFile: " /var/log/arca-dns/dnstap.log ",
		},
		{
			name:    "newline",
			logFile: "/var/log/arca-dns/dnstap.log\nextra",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.DNSTap.Enabled = true
			cfg.DNSTap.LogFile = tc.logFile
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "dnstap.log_file")
		})
	}
}

func TestValidateAgentConfig_InvalidDNSTapLogRotation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*LogRotationConfig)
		want   string
	}{
		{
			name: "negative max size",
			mutate: func(cfg *LogRotationConfig) {
				cfg.MaxSize = -1
			},
			want: "dnstap.log_rotation.max_size",
		},
		{
			name: "negative max age",
			mutate: func(cfg *LogRotationConfig) {
				cfg.MaxAge = -1
			},
			want: "dnstap.log_rotation.max_age",
		},
		{
			name: "negative max backups",
			mutate: func(cfg *LogRotationConfig) {
				cfg.MaxBackups = -1
			},
			want: "dnstap.log_rotation.max_backups",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.DNSTap.Enabled = true
			tc.mutate(&cfg.DNSTap.LogRotation)

			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_AllowsDNSTapLogRotationZeroValues(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.DNSTap.Enabled = true
	cfg.DNSTap.LogRotation.MaxSize = 0
	cfg.DNSTap.LogRotation.MaxAge = 0
	cfg.DNSTap.LogRotation.MaxBackups = 0

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_InvalidUnboundStubZoneConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "empty nsd address",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.StubZoneConfig.NSDAddress = ""
			},
			want: "unbound.stub_zone.nsd_address",
		},
		{
			name: "address with surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.StubZoneConfig.NSDAddress = " 127.0.0.1 "
			},
			want: "unbound.stub_zone.nsd_address",
		},
		{
			name: "address with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.StubZoneConfig.NSDAddress = "127.0.0.1\nserver:"
			},
			want: "unbound.stub_zone.nsd_address",
		},
		{
			name: "address with embedded port",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.StubZoneConfig.NSDAddress = "127.0.0.1@5353"
			},
			want: "unbound.stub_zone.nsd_address",
		},
		{
			name: "malformed address",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.StubZoneConfig.NSDAddress = "server:"
			},
			want: "unbound.stub_zone.nsd_address",
		},
		{
			name: "zero port",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.StubZoneConfig.NSDPort = 0
			},
			want: "unbound.stub_zone.nsd_port",
		},
		{
			name: "port too high",
			mutate: func(cfg *AgentConfig) {
				cfg.Unbound.StubZoneConfig.NSDPort = 65536
			},
			want: "unbound.stub_zone.nsd_port",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Unbound.Enabled = true
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAgentConfig_AcceptsUnboundStubZoneAddressForms(t *testing.T) {
	tests := []string{
		"127.0.0.1",
		"::1",
		"localhost",
		"nsd.local.",
	}

	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Unbound.Enabled = true
			cfg.Unbound.StubZoneConfig.NSDAddress = address
			err := ValidateAgentConfig(cfg)
			assert.NoError(t, err)
		})
	}
}

func TestValidateAgentConfig_InvalidDNSTapSocketSettings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{
			name: "empty socket path",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketPath = ""
			},
			want: "dnstap.socket_path",
		},
		{
			name: "socket path with surrounding whitespace",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketPath = " /var/run/dnstap.sock "
			},
			want: "dnstap.socket_path",
		},
		{
			name: "relative socket path",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketPath = "run/dnstap.sock"
			},
			want: "dnstap.socket_path",
		},
		{
			name: "socket path with newline",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketPath = "/var/run/dnstap.sock\nserver:"
			},
			want: "dnstap.socket_path",
		},
		{
			name: "socket path with nul byte",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketPath = "/var/run/dnstap\x00.sock"
			},
			want: "dnstap.socket_path",
		},
		{
			name: "empty socket mode",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketMode = ""
			},
			want: "dnstap.socket_mode",
		},
		{
			name: "world writable socket mode",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketMode = "0666"
			},
			want: "dnstap.socket_mode",
		},
		{
			name: "invalid socket mode",
			mutate: func(cfg *AgentConfig) {
				cfg.DNSTap.SocketMode = "invalid"
			},
			want: "dnstap.socket_mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.DNSTap.Enabled = true
			tc.mutate(cfg)
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestParseDNSTapSocketMode(t *testing.T) {
	tests := []struct {
		value string
		want  os.FileMode
	}{
		{value: "0660", want: 0o660},
		{value: "660", want: 0o660},
		{value: "0o600", want: 0o600},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			mode, err := ParseDNSTapSocketMode(tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.want, mode)
		})
	}
}

func TestValidateAgentConfig_StatusServerRequiresListen(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Metrics.Enabled = false
	cfg.Metrics.Listen = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metrics.listen")
}

func TestValidateAgentConfig_InvalidMetricsListenAddress(t *testing.T) {
	tests := []string{
		"127.0.0.1",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"127.0.0.1:http",
		"127.0.0.1 :9090",
	}

	for _, listen := range tests {
		t.Run(listen, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Metrics.Listen = listen
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "metrics.listen")
		})
	}
}

func TestValidateAgentConfig_AllowsIPv6LoopbackMetricsListen(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Metrics.Listen = "[::1]:9090"

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_RemoteStatusServerRequiresAuthToken(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Metrics.Listen = "0.0.0.0:9090"
	cfg.Metrics.AuthToken = ""
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metrics.auth_token")
}

func TestValidateAgentConfig_RemoteStatusServerAcceptsAuthToken(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Metrics.Listen = "0.0.0.0:9090"
	cfg.Metrics.AuthToken = validStatusAuthToken
	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_StatusAuthTokenMustBeStrongEnough(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Metrics.AuthToken = "short"
	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metrics.auth_token")
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

func TestValidateAgentConfig_InvalidLoggingFormat(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Logging.Format = "xml"

	err := ValidateAgentConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logging.format")
}

func TestValidateAgentConfig_AllowsEmptyLoggingFormatDefault(t *testing.T) {
	cfg := validAgentConfigForTest()
	cfg.Logging.Format = ""

	err := ValidateAgentConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateAgentConfig_InvalidLoggingOutputPath(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "relative",
			output: "arca-dns-agent.log",
		},
		{
			name:   "surrounding whitespace",
			output: " /var/log/arca-dns/agent.log ",
		},
		{
			name:   "stderr surrounding whitespace",
			output: " stderr ",
		},
		{
			name:   "newline",
			output: "/var/log/arca-dns/agent.log\nextra",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfigForTest()
			cfg.Logging.Output = tc.output
			err := ValidateAgentConfig(cfg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "logging.output")
		})
	}
}
