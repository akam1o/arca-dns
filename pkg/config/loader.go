package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

const minArtifactSignatureKeyBytes = 32
const minStatusAuthTokenBytes = 16
const apiKeyRoleAdmin = "admin"
const apiKeyRoleAgent = "agent"

// LoadControllerConfig loads the controller configuration from the specified file.
// Priority: defaults < YAML file < environment variables
func LoadControllerConfig(path string) (*ControllerConfig, error) {
	cfg, err := loadControllerConfig(path, true)
	if err != nil {
		return nil, err
	}

	// Validate configuration
	if err := ValidateControllerConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadControllerBackendConfig loads only the controller backend configuration.
// It intentionally avoids validating unrelated API/DNSSEC secrets for offline
// maintenance commands such as migrations.
func LoadControllerBackendConfig(path string) (*ControllerConfig, error) {
	cfg, err := loadControllerConfig(path, false)
	if err != nil {
		return nil, err
	}
	if err := ValidateControllerBackendConfig(&cfg.Backend); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadControllerConfig(path string, applyKeyDirectoryAliases bool) (*ControllerConfig, error) {
	cfg := DefaultControllerConfig()

	if path != "" {
		v := viper.New()
		v.SetConfigFile(path)
		v.SetConfigType("yaml")

		// Set environment variable prefix and enable automatic env binding
		v.SetEnvPrefix("ARCA_DNS")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()

		// Read config file
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("load controller config: %w", err)
		}

		// Manually apply environment variables that need explicit binding.
		bindControllerEnvVars(v)

		// Unmarshal into config struct
		if err := v.Unmarshal(cfg); err != nil {
			return nil, fmt.Errorf("unmarshal controller config: %w", err)
		}
		if applyKeyDirectoryAliases {
			if err := applyControllerKeyDirectoryAliases(v, cfg); err != nil {
				return nil, err
			}
		}
	} else {
		// No config file, only apply environment variables
		v := viper.New()
		v.SetEnvPrefix("ARCA_DNS")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()

		// Manually bind key environment variables
		bindControllerEnvVars(v)

		if err := v.Unmarshal(cfg); err != nil {
			return nil, fmt.Errorf("unmarshal controller config from env: %w", err)
		}
		if applyKeyDirectoryAliases {
			if err := applyControllerKeyDirectoryAliases(v, cfg); err != nil {
				return nil, err
			}
		}
	}

	return cfg, nil
}

func applyControllerKeyDirectoryAliases(v *viper.Viper, cfg *ControllerConfig) error {
	storageKeySet := v.IsSet("storage.key_directory")
	dnssecKeySet := v.IsSet("dnssec.key_directory")

	if storageKeySet && !dnssecKeySet {
		cfg.DNSSEC.KeyDirectory = cfg.Storage.KeyDirectory
		return nil
	}

	if storageKeySet && dnssecKeySet && !sameConfigPath(cfg.Storage.KeyDirectory, cfg.DNSSEC.KeyDirectory) {
		return fmt.Errorf("invalid key_directory: storage.key_directory and dnssec.key_directory must match when both are set")
	}

	return nil
}

func sameConfigPath(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}

// LoadAgentConfig loads the agent configuration from the specified file.
// Priority: defaults < YAML file < environment variables
func LoadAgentConfig(path string) (*AgentConfig, error) {
	cfg := DefaultAgentConfig()

	if path != "" {
		v := viper.New()
		v.SetConfigFile(path)
		v.SetConfigType("yaml")

		// Set environment variable prefix and enable automatic env binding
		v.SetEnvPrefix("ARCA_DNS")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()

		// Read config file
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("load agent config: %w", err)
		}

		// Manually apply environment variables that need explicit binding.
		bindAgentEnvVars(v)

		// Unmarshal into config struct
		if err := v.Unmarshal(cfg); err != nil {
			return nil, fmt.Errorf("unmarshal agent config: %w", err)
		}
	} else {
		// No config file, only apply environment variables
		v := viper.New()
		v.SetEnvPrefix("ARCA_DNS")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()

		// Manually bind key environment variables
		bindAgentEnvVars(v)

		if err := v.Unmarshal(cfg); err != nil {
			return nil, fmt.Errorf("unmarshal agent config from env: %w", err)
		}
	}

	// Validate configuration
	if err := ValidateAgentConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ValidateControllerConfig validates the controller configuration.
func ValidateControllerConfig(cfg *ControllerConfig) error {
	cfg.API.Listen = strings.TrimSpace(cfg.API.Listen)
	if cfg.API.Listen == "" {
		return fmt.Errorf("invalid api.listen: empty")
	}
	if strings.TrimSpace(cfg.Observability.Listen) == "" {
		return fmt.Errorf("invalid observability.listen: empty")
	}
	cfg.Observability.Listen = strings.TrimSpace(cfg.Observability.Listen)
	if listenEndpointsOverlap(cfg.API.Listen, cfg.Observability.Listen) {
		return fmt.Errorf("invalid observability.listen: must not overlap api.listen")
	}

	trustedProxies, err := normalizeTrustedProxies(cfg.API.TrustedProxies)
	if err != nil {
		return err
	}
	cfg.API.TrustedProxies = trustedProxies

	if err := validateControllerAuthConfig(&cfg.API.Auth); err != nil {
		return err
	}

	if err := validateArtifactSignatureKey("api.artifact_signature_key", cfg.API.ArtifactSignatureKey, true); err != nil {
		return err
	}
	if err := validateControllerAuthExposure(cfg.API.Listen, cfg.API.Auth); err != nil {
		return err
	}

	if cfg.API.RateLimit.Enabled {
		if cfg.API.RateLimit.RequestsPerSecond <= 0 {
			return fmt.Errorf("invalid api.rate_limit.requests_per_second: must be positive when rate limiting is enabled")
		}
		if cfg.API.RateLimit.Burst <= 0 {
			return fmt.Errorf("invalid api.rate_limit.burst: must be positive when rate limiting is enabled")
		}
	}

	if err := ValidateControllerBackendConfig(&cfg.Backend); err != nil {
		return err
	}

	if err := validateAbsoluteLocalPath("storage.artifact_directory", cfg.Storage.ArtifactDirectory); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Storage.KeyDirectory) != "" {
		if err := validateAbsoluteLocalPath("storage.key_directory", cfg.Storage.KeyDirectory); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.DNSSEC.KeyDirectory) != "" {
		if err := validateAbsoluteLocalPath("dnssec.key_directory", cfg.DNSSEC.KeyDirectory); err != nil {
			return err
		}
	}

	if cfg.DNSSEC.Enabled {
		if cfg.DNSSECKeyDirectory() == "" {
			return fmt.Errorf("invalid dnssec.key_directory: empty when DNSSEC is enabled and storage.key_directory is not set")
		}

		validAlgorithms := map[uint8]bool{
			8:  true, // RSA-SHA256
			13: true, // ECDSA-P256
		}
		if !validAlgorithms[cfg.DNSSEC.Algorithm] {
			return fmt.Errorf("invalid dnssec.algorithm: %d (must be 8 or 13)", cfg.DNSSEC.Algorithm)
		}

		if cfg.DNSSEC.SignatureValidity <= 0 {
			return fmt.Errorf("invalid dnssec.signature_validity: must be positive")
		}

		if cfg.DNSSEC.SignatureInception < 0 {
			return fmt.Errorf("invalid dnssec.signature_inception: must be non-negative")
		}

		if cfg.DNSSEC.ResignThreshold <= 0 {
			return fmt.Errorf("invalid dnssec.resign_threshold: must be positive")
		}

		if cfg.DNSSEC.ResignThreshold >= cfg.DNSSEC.SignatureValidity {
			return fmt.Errorf("invalid dnssec.resign_threshold: must be less than signature_validity")
		}

		if cfg.DNSSEC.NSEC3SaltLength < 0 {
			return fmt.Errorf("invalid dnssec.nsec3_salt_length: must be non-negative")
		}

		// Validate scheduler configuration if enabled
		if cfg.DNSSEC.SchedulerEnabled {
			if cfg.DNSSEC.SchedulerCheckInterval <= 0 {
				return fmt.Errorf("invalid dnssec.scheduler_check_interval: must be positive when scheduler is enabled")
			}
		}
	}

	if cfg.DNSSEC.Enabled && strings.TrimSpace(cfg.Storage.KeyDirectory) == "" && strings.TrimSpace(cfg.DNSSEC.KeyDirectory) == "" {
		return fmt.Errorf("invalid storage.key_directory: empty when DNSSEC is enabled and dnssec.key_directory is not set")
	}

	if cfg.Storage.MaxVersionsPerZone < 1 {
		return fmt.Errorf("invalid storage.max_versions_per_zone: must be positive")
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[cfg.Logging.Level] {
		return fmt.Errorf("invalid logging.level: %s (must be one of: debug, info, warn, error)", cfg.Logging.Level)
	}

	return nil
}

// ValidateControllerBackendConfig validates backend fields shared by the
// controller and offline backend maintenance commands.
func ValidateControllerBackendConfig(cfg *BackendConfig) error {
	if cfg == nil {
		return fmt.Errorf("invalid backend: nil")
	}
	if cfg.Type == "" {
		return fmt.Errorf("invalid backend.type: empty")
	}

	validBackendTypes := map[string]bool{
		"mysql":    true,
		"git":      true,
		"etcd":     true,
		"sqlite":   true,
		"postgres": true,
	}
	if !validBackendTypes[cfg.Type] {
		return fmt.Errorf("invalid backend.type: %s (must be one of: sqlite, postgres, mysql, git, etcd)", cfg.Type)
	}
	if cfg.Type == "git" && cfg.Git.RepositoryPath != "" {
		if err := validateAbsoluteLocalPath("backend.git.repository_path", cfg.Git.RepositoryPath); err != nil {
			return err
		}
	}
	return nil
}

func normalizeTrustedProxies(trustedProxies []string) ([]string, error) {
	if len(trustedProxies) == 0 {
		return trustedProxies, nil
	}

	normalized := make([]string, len(trustedProxies))
	for i, proxy := range trustedProxies {
		value := strings.TrimSpace(proxy)
		if value == "" {
			return nil, fmt.Errorf("invalid api.trusted_proxies[%d]: empty", i)
		}
		if strings.Contains(value, "/") {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return nil, fmt.Errorf("invalid api.trusted_proxies[%d]: %q is not a valid CIDR: %w", i, proxy, err)
			}
			normalized[i] = value
			continue
		}
		if net.ParseIP(value) == nil {
			return nil, fmt.Errorf("invalid api.trusted_proxies[%d]: %q is not a valid IP address or CIDR", i, proxy)
		}
		normalized[i] = value
	}
	return normalized, nil
}

func listenEndpointsOverlap(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	aHost, aPort, aErr := net.SplitHostPort(a)
	bHost, bPort, bErr := net.SplitHostPort(b)
	if aErr != nil || bErr != nil {
		return a == b
	}
	if aPort != bPort {
		return false
	}
	return isWildcardListenHost(aHost) || isWildcardListenHost(bHost) || strings.EqualFold(aHost, bHost)
}

func isWildcardListenHost(host string) bool {
	host = strings.Trim(host, "[]")
	return host == "" || host == "0.0.0.0" || host == "::"
}

func validateControllerAuthConfig(auth *AuthConfig) error {
	if !auth.Enabled {
		return nil
	}

	if len(auth.APIKeys) == 0 {
		return fmt.Errorf("invalid api.auth.api_keys: at least one API key is required when api.auth.enabled is true; add api.auth.api_keys.<name>: sha256:<64-hex-sha256> (generate with: echo -n '<api-key>' | sha256sum), or set api.auth.enabled: false only for intentionally unauthenticated local development")
	}

	seenHashes := make(map[string]string, len(auth.APIKeys))
	for name, hash := range auth.APIKeys {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("invalid api.auth.api_keys: key name must not be empty")
		}
		normalizedHash, ok := normalizeSHA256APIKeyHash(hash)
		if !ok {
			return fmt.Errorf("invalid api.auth.api_keys.%s: expected sha256:<64 hex characters>; generate with: echo -n '<api-key>' | sha256sum", name)
		}
		if existingName, exists := seenHashes[normalizedHash]; exists {
			return fmt.Errorf("invalid api.auth.api_keys.%s: duplicate hash also used by api.auth.api_keys.%s", name, existingName)
		}
		seenHashes[normalizedHash] = name
		auth.APIKeys[name] = normalizedHash
	}

	normalizedRoles := make(map[string]string, len(auth.APIKeys))
	for name := range auth.APIKeys {
		normalizedRoles[name] = apiKeyRoleAdmin
	}
	for name, role := range auth.APIKeyRoles {
		keyName := strings.TrimSpace(name)
		if keyName == "" {
			return fmt.Errorf("invalid api.auth.api_key_roles: key name must not be empty")
		}
		if _, ok := auth.APIKeys[keyName]; !ok {
			return fmt.Errorf("invalid api.auth.api_key_roles.%s: role specified for unknown api.auth.api_keys entry", keyName)
		}

		normalizedRole := strings.ToLower(strings.TrimSpace(role))
		switch normalizedRole {
		case apiKeyRoleAdmin, apiKeyRoleAgent:
			normalizedRoles[keyName] = normalizedRole
		default:
			return fmt.Errorf("invalid api.auth.api_key_roles.%s: must be one of: admin, agent", keyName)
		}
	}

	hasAdmin := false
	for _, role := range normalizedRoles {
		if role == apiKeyRoleAdmin {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		return fmt.Errorf("invalid api.auth.api_key_roles: at least one admin API key is required when api.auth.enabled is true")
	}
	auth.APIKeyRoles = normalizedRoles

	return nil
}

func validateControllerAuthExposure(apiListen string, auth AuthConfig) error {
	if auth.Enabled {
		return nil
	}
	if isLoopbackListenEndpoint(apiListen) {
		return nil
	}
	return fmt.Errorf("invalid api.auth.enabled: false is only allowed when api.listen is loopback; bind api.listen to 127.0.0.1 or enable api.auth")
}

func normalizeSHA256APIKeyHash(hash string) (string, bool) {
	const prefix = "sha256:"

	value := strings.TrimSpace(hash)
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}

	hexPart := strings.TrimPrefix(value, prefix)
	if len(hexPart) != 64 {
		return "", false
	}

	_, err := hex.DecodeString(hexPart)
	if err != nil {
		return "", false
	}
	return prefix + strings.ToLower(hexPart), true
}

func validateArtifactSignatureKey(field string, key string, required bool) error {
	value := strings.TrimSpace(key)
	if value == "" {
		if required {
			return fmt.Errorf("invalid %s: required for artifact signature verification; generate a shared secret with: openssl rand -base64 32", field)
		}
		return nil
	}

	if isPlaceholderSecret(value) {
		return fmt.Errorf("invalid %s: replace placeholder value with a generated shared secret (generate with: openssl rand -base64 32)", field)
	}

	if len([]byte(value)) < minArtifactSignatureKeyBytes {
		return fmt.Errorf("invalid %s: must be at least %d bytes; generate with: openssl rand -base64 32", field, minArtifactSignatureKeyBytes)
	}

	return nil
}

func isPlaceholderSecret(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	return strings.Contains(normalized, "REPLACE") ||
		strings.Contains(normalized, "CHANGEME") ||
		strings.Contains(normalized, "CHANGE_ME") ||
		strings.Contains(normalized, "TODO")
}

// ValidateAgentConfig validates the agent configuration.
func ValidateAgentConfig(cfg *AgentConfig) error {
	if err := applyAgentSignatureKeyAliases(cfg); err != nil {
		return err
	}

	controllerURL, err := normalizeControllerURL(cfg.Controller.URL)
	if err != nil {
		return err
	}
	cfg.Controller.URL = controllerURL
	if cfg.Controller.Timeout <= 0 {
		return fmt.Errorf("invalid controller.timeout: must be greater than 0")
	}
	if cfg.Controller.RetryAttempts < 0 {
		return fmt.Errorf("invalid controller.retry_attempts: must be >= 0")
	}
	if cfg.Controller.RetryDelay < 0 {
		return fmt.Errorf("invalid controller.retry_delay: must be >= 0")
	}
	if cfg.Controller.RetryAttempts > 0 && cfg.Controller.RetryDelay == 0 {
		return fmt.Errorf("invalid controller.retry_delay: must be greater than 0 when controller.retry_attempts is greater than 0")
	}
	if cfg.Controller.MaxResponseBytes <= 0 {
		return fmt.Errorf("invalid controller.max_response_bytes: must be positive")
	}
	if err := validateAgentControllerAPIKeyTransport(cfg.Controller); err != nil {
		return err
	}
	if err := validateAgentControllerTLSConfig(cfg.Controller); err != nil {
		return err
	}

	cfg.Authoritative = strings.ToLower(strings.TrimSpace(cfg.Authoritative))
	if cfg.Authoritative == "" {
		return fmt.Errorf("invalid authoritative: empty")
	}
	if cfg.Authoritative != "nsd" {
		return fmt.Errorf("invalid authoritative: %s (supported: nsd)", cfg.Authoritative)
	}

	if err := ValidateNSDRenderedConfigPath("nsd.zone_directory", cfg.NSD.ZoneDirectory); err != nil {
		return fmt.Errorf("%w; required for zone sync storage", err)
	}
	if cfg.NSD.Enabled {
		if err := ValidateNSDRenderedConfigPath("nsd.config_path", cfg.NSD.ConfigPath); err != nil {
			return fmt.Errorf("%w when NSD is enabled", err)
		}
		if cfg.NSD.ZoneConfigPath != "" {
			if err := ValidateNSDRenderedConfigPath("nsd.zone_config_path", cfg.NSD.ZoneConfigPath); err != nil {
				return err
			}
		}
		if err := validateExecutablePath("nsd.control_path", cfg.NSD.ControlPath); err != nil {
			return fmt.Errorf("%w when NSD is enabled", err)
		}
		if err := validateExecutablePath("nsd.checkzone_path", cfg.NSD.CheckzonePath); err != nil {
			return fmt.Errorf("%w when NSD is enabled", err)
		}
	}

	if cfg.Unbound.Enabled {
		if err := validateAbsoluteLocalPath("unbound.config_path", cfg.Unbound.ConfigPath); err != nil {
			return fmt.Errorf("%w when Unbound is enabled", err)
		}
		if err := validateExecutablePath("unbound.control_path", cfg.Unbound.ControlPath); err != nil {
			return fmt.Errorf("%w when Unbound is enabled", err)
		}
		if err := validateExecutablePath("unbound.checkconf_path", cfg.Unbound.CheckconfPath); err != nil {
			return fmt.Errorf("%w when Unbound is enabled", err)
		}
		if err := cfg.Unbound.StubZoneConfig.Validate(); err != nil {
			return err
		}
		if cfg.Unbound.EDNSBufferSize != 1232 {
			return fmt.Errorf("invalid unbound.edns_buffer_size: must be 1232 for ECMP-safe DNSSEC responses")
		}
	}

	if cfg.BIRD.Enabled {
		if err := validateAbsoluteLocalPath("bird.socket_path", cfg.BIRD.SocketPath); err != nil {
			return fmt.Errorf("%w when BIRD is enabled", err)
		}
		if len(cfg.BIRD.Protocols) == 0 && cfg.BIRD.ProtocolName == "" && len(cfg.BIRD.ProtocolNames) == 0 {
			return fmt.Errorf("invalid bird.protocols: empty when BIRD is enabled (or set bird.protocol_names/protocol_name)")
		}
		// Note: AnycastPrefixes is optional - current implementation manages routes
		// via protocol enable/disable. Individual prefix management would require
		// more complex BIRD command generation.

		if cfg.BIRD.StateMachine.FailureThreshold < 1 {
			return fmt.Errorf("invalid bird.state_machine.failure_threshold: must be >= 1")
		}
		if cfg.BIRD.StateMachine.RecoveryThreshold < 1 {
			return fmt.Errorf("invalid bird.state_machine.recovery_threshold: must be >= 1")
		}
		if cfg.BIRD.StateMachine.MinStateDuration < 0 {
			return fmt.Errorf("invalid bird.state_machine.min_state_duration: must be >= 0")
		}

		if cfg.BIRD.ConfigureOnStart.Enabled {
			if cfg.BIRD.ConfigureOnStart.Path == "" {
				return fmt.Errorf("invalid bird.config.path: empty when bird.config.enabled is true")
			}
			if cfg.BIRD.ConfigureOnStart.RouterID == "" {
				return fmt.Errorf("invalid bird.config.router_id: empty when bird.config.enabled is true")
			}
			if cfg.BIRD.ConfigureOnStart.LocalAS == 0 {
				return fmt.Errorf("invalid bird.config.local_as: must be > 0 when bird.config.enabled is true")
			}
			if cfg.BIRD.ConfigureOnStart.SourceIP == "" {
				return fmt.Errorf("invalid bird.config.source_ip: empty when bird.config.enabled is true")
			}
			if len(cfg.BIRD.Protocols) == 0 && len(cfg.BIRD.ConfigureOnStart.Neighbors) == 0 {
				return fmt.Errorf("invalid bird.protocols: must be non-empty when bird.config.enabled is true (or set bird.config.neighbors for legacy config)")
			}
			for _, p := range cfg.BIRD.Protocols {
				if p.Name == "" {
					return fmt.Errorf("invalid bird.protocols.name: empty")
				}
				if p.NeighborAddress == "" {
					return fmt.Errorf("invalid bird.protocols.neighbor_address: empty")
				}
				if p.NeighborASN == 0 {
					return fmt.Errorf("invalid bird.protocols.neighbor_asn: must be > 0")
				}
			}
			if cfg.BIRD.ConfigureOnStart.BFD.Enabled {
				if cfg.BIRD.ConfigureOnStart.BFD.Multiplier < 1 {
					return fmt.Errorf("invalid bird.config.bfd.multiplier: must be >= 1")
				}
			}
		}
	}

	if cfg.Sync.SyncInterval <= 0 {
		return fmt.Errorf("invalid sync.sync_interval: must be positive")
	}

	if cfg.Sync.MaxStaleness <= 0 {
		return fmt.Errorf("invalid sync.max_staleness: must be positive")
	}

	if cfg.Sync.MaxStaleness < cfg.Sync.SyncInterval {
		return fmt.Errorf("invalid sync.max_staleness: must be greater than or equal to sync.sync_interval")
	}

	if cfg.Sync.BackupVersions < 0 {
		return fmt.Errorf("invalid sync.backup_versions: must be non-negative")
	}

	if cfg.Sync.VerifySignatures {
		if err := validateArtifactSignatureKey("sync.controller_signature_key", cfg.Sync.ControllerPublicKey, true); err != nil {
			return err
		}
	}

	if cfg.DNSTap.Enabled {
		if err := ValidateDNSTapSocketPath(cfg.DNSTap.SocketPath); err != nil {
			return fmt.Errorf("invalid dnstap.socket_path: %w", err)
		}
		if _, err := cfg.DNSTap.SocketFileMode(); err != nil {
			return fmt.Errorf("invalid dnstap.socket_mode: %w", err)
		}
		if cfg.DNSTap.SampleRate <= 0 {
			return fmt.Errorf("invalid dnstap.sample_rate: must be positive when DNSTap is enabled")
		}
	}

	if err := validateAgentMetricsConfig(&cfg.Metrics); err != nil {
		return err
	}

	if cfg.Health.CheckInterval <= 0 {
		return fmt.Errorf("invalid health.check_interval: must be positive")
	}

	if cfg.Health.QueryTimeout <= 0 {
		return fmt.Errorf("invalid health.query_timeout: must be positive")
	}

	if cfg.Health.LatencyThreshold <= 0 {
		return fmt.Errorf("invalid health.latency_threshold: must be positive")
	}

	if cfg.Health.FailureThreshold <= 0 {
		return fmt.Errorf("invalid health.failure_threshold: must be positive")
	}

	if cfg.Health.RecoveryThreshold <= 0 {
		return fmt.Errorf("invalid health.recovery_threshold: must be positive")
	}

	if cfg.BIRD.Enabled {
		if !cfg.NSD.Enabled && !cfg.Unbound.Enabled {
			return fmt.Errorf("invalid bird.enabled: requires nsd.enabled or unbound.enabled for DNS health checks")
		}
		if strings.TrimSpace(cfg.Health.TestRecord) == "" {
			return fmt.Errorf("invalid health.test_record: required when BIRD is enabled")
		}
		if healthTestRecordNeedsZone(cfg.Health.TestRecord) && strings.TrimSpace(cfg.Health.TestZone) == "" {
			return fmt.Errorf("invalid health.test_zone: required when health.test_record is relative and BIRD is enabled")
		}
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[cfg.Logging.Level] {
		return fmt.Errorf("invalid logging.level: %s (must be one of: debug, info, warn, error)", cfg.Logging.Level)
	}

	return nil
}

func validateExecutablePath(field string, path string) error {
	return validateAbsoluteLocalPath(field, path)
}

func validateAbsoluteLocalPath(field string, path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("invalid %s: empty", field)
	}
	if trimmed != path {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if strings.ContainsFunc(path, unsafeExecutablePathChar) {
		return fmt.Errorf("invalid %s: contains control characters", field)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("invalid %s: must be an absolute path", field)
	}
	return nil
}

func unsafeExecutablePathChar(r rune) bool {
	return r < ' ' || r == 0x7f
}

func normalizeControllerURL(rawURL string) (string, error) {
	value := strings.TrimSpace(rawURL)
	if value == "" {
		return "", fmt.Errorf("invalid controller.url: empty")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid controller.url: %w", err)
	}
	if parsed.Scheme == "" {
		return "", fmt.Errorf("invalid controller.url: missing scheme (use http or https)")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid controller.url: missing host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("invalid controller.url: userinfo is not supported")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("invalid controller.url: unsupported scheme %q (must be http or https)", parsed.Scheme)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid controller.url: query strings and fragments are not supported")
	}

	return strings.TrimRight(value, "/"), nil
}

func validateAgentControllerTLSConfig(controller ControllerClientConfig) error {
	caFile := strings.TrimSpace(controller.TLS.CAFile)
	certFile := strings.TrimSpace(controller.TLS.CertFile)
	keyFile := strings.TrimSpace(controller.TLS.KeyFile)

	if controller.TLS.ClientAuth && !controller.TLS.Enabled {
		return fmt.Errorf("invalid controller.tls.client_auth: requires controller.tls.enabled")
	}
	if (caFile != "" || certFile != "" || keyFile != "") && !controller.TLS.Enabled {
		return fmt.Errorf("invalid controller.tls.enabled: required when controller.tls.ca_file, cert_file, or key_file is set")
	}

	if controller.TLS.Enabled {
		parsed, err := url.Parse(controller.URL)
		if err != nil {
			return fmt.Errorf("invalid controller.url: %w", err)
		}
		if strings.ToLower(parsed.Scheme) != "https" {
			return fmt.Errorf("invalid controller.tls.enabled: requires controller.url to use https")
		}
	}

	if certFile == "" && keyFile != "" {
		return fmt.Errorf("invalid controller.tls.cert_file: empty when controller.tls.key_file is set")
	}
	if certFile != "" && keyFile == "" {
		return fmt.Errorf("invalid controller.tls.key_file: empty when controller.tls.cert_file is set")
	}
	if (certFile != "" || keyFile != "") && !controller.TLS.ClientAuth {
		return fmt.Errorf("invalid controller.tls.client_auth: required when controller.tls.cert_file or key_file is set")
	}

	if caFile != "" {
		if err := validateAbsoluteLocalPath("controller.tls.ca_file", controller.TLS.CAFile); err != nil {
			return err
		}
	}
	if certFile != "" {
		if err := validateAbsoluteLocalPath("controller.tls.cert_file", controller.TLS.CertFile); err != nil {
			return err
		}
	}
	if keyFile != "" {
		if err := validateAbsoluteLocalPath("controller.tls.key_file", controller.TLS.KeyFile); err != nil {
			return err
		}
	}

	if !controller.TLS.ClientAuth {
		return nil
	}
	if certFile == "" {
		return fmt.Errorf("invalid controller.tls.cert_file: empty when controller.tls.client_auth is true")
	}
	if keyFile == "" {
		return fmt.Errorf("invalid controller.tls.key_file: empty when controller.tls.client_auth is true")
	}
	return nil
}

func validateAgentControllerAPIKeyTransport(controller ControllerClientConfig) error {
	if strings.TrimSpace(controller.APIKey) == "" || controller.AllowPlaintextAPIKey {
		return nil
	}

	parsed, err := url.Parse(controller.URL)
	if err != nil {
		return fmt.Errorf("invalid controller.url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "http") {
		return nil
	}
	if isLoopbackHost(parsed.Hostname()) {
		return nil
	}

	return fmt.Errorf("invalid controller.api_key: plaintext HTTP controller.url is only allowed for loopback hosts; use https or set controller.allow_plaintext_api_key=true for an intentionally trusted transport")
}

func healthTestRecordNeedsZone(record string) bool {
	record = strings.TrimSpace(record)
	return record != "" && !strings.HasSuffix(record, ".")
}

func applyAgentSignatureKeyAliases(cfg *AgentConfig) error {
	signatureKey := strings.TrimSpace(cfg.Sync.ControllerSignatureKey)
	legacyPublicKey := strings.TrimSpace(cfg.Sync.ControllerPublicKey)

	if signatureKey != "" {
		cfg.Sync.ControllerPublicKey = signatureKey
		return nil
	}
	if legacyPublicKey != "" {
		cfg.Sync.ControllerSignatureKey = legacyPublicKey
	}
	return nil
}

func normalizeHTTPPath(path string, defaultPath string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return defaultPath
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func validateAgentMetricsConfig(metrics *MetricsConfig) error {
	metrics.Listen = strings.TrimSpace(metrics.Listen)
	if metrics.Listen == "" {
		return fmt.Errorf("invalid metrics.listen: empty")
	}

	metrics.AuthToken = strings.TrimSpace(metrics.AuthToken)
	if metrics.AuthToken != "" {
		if isPlaceholderSecret(metrics.AuthToken) {
			return fmt.Errorf("invalid metrics.auth_token: replace placeholder value with a generated status token")
		}
		if len([]byte(metrics.AuthToken)) < minStatusAuthTokenBytes {
			return fmt.Errorf("invalid metrics.auth_token: must be at least %d bytes", minStatusAuthTokenBytes)
		}
	}
	if !isLoopbackListenEndpoint(metrics.Listen) && metrics.AuthToken == "" {
		return fmt.Errorf("invalid metrics.auth_token: required when metrics.listen is not loopback; bind metrics.listen to 127.0.0.1 or set metrics.auth_token")
	}

	if metrics.Enabled {
		path := normalizeHTTPPath(metrics.Path, "/metrics")
		if strings.ContainsAny(path, ":*") {
			return fmt.Errorf("invalid metrics.path: must be a static HTTP path without ':' or '*'")
		}
		if isReservedAgentStatusPath(path) {
			return fmt.Errorf("invalid metrics.path: conflicts with reserved status endpoint %q", path)
		}
		metrics.Path = path
	}
	return nil
}

func isLoopbackListenEndpoint(listen string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isReservedAgentStatusPath(path string) bool {
	switch path {
	case "/health", "/ready", "/status":
		return true
	default:
		return false
	}
}

// bindControllerEnvVars binds all controller config leaves so environment
// variables are visible to Unmarshal even when a key is absent from YAML.
func bindControllerEnvVars(v *viper.Viper) {
	bindEnvVarsFromStruct(v, reflect.TypeOf(ControllerConfig{}), "")
	bindControllerAPIKeyEnvVars(v)
}

func bindControllerAPIKeyEnvVars(v *viper.Viper) {
	const keyPrefix = "ARCA_DNS_API_AUTH_API_KEYS_"
	const rolePrefix = "ARCA_DNS_API_AUTH_API_KEY_ROLES_"

	apiKeys := make(map[string]string)
	for name, hash := range v.GetStringMapString("api.auth.api_keys") {
		apiKeys[name] = hash
	}
	apiKeyRoles := make(map[string]string)
	for name, role := range v.GetStringMapString("api.auth.api_key_roles") {
		apiKeyRoles[name] = role
	}

	for _, env := range os.Environ() {
		name, value, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}

		switch {
		case strings.HasPrefix(name, keyPrefix):
			keyName := strings.TrimPrefix(name, keyPrefix)
			keyName = strings.ToLower(keyName)
			apiKeys[keyName] = value
		case strings.HasPrefix(name, rolePrefix):
			keyName := strings.TrimPrefix(name, rolePrefix)
			keyName = strings.ToLower(keyName)
			apiKeyRoles[keyName] = value
		}
	}

	if len(apiKeys) > 0 {
		v.Set("api.auth.api_keys", apiKeys)
	}
	if len(apiKeyRoles) > 0 {
		v.Set("api.auth.api_key_roles", apiKeyRoles)
	}
}

// bindAgentEnvVars binds all agent config leaves so environment variables are
// visible to Unmarshal even when a key is absent from the YAML file.
func bindAgentEnvVars(v *viper.Viper) {
	bindEnvVarsFromStruct(v, reflect.TypeOf(AgentConfig{}), "")
}

func bindEnvVarsFromStruct(v *viper.Viper, typ reflect.Type, prefix string) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}

		name := mapstructureName(field)
		if name == "" {
			continue
		}

		key := name
		if prefix != "" {
			key = prefix + "." + name
		}

		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct {
			bindEnvVarsFromStruct(v, fieldType, key)
			continue
		}

		_ = v.BindEnv(key)
	}
}

func mapstructureName(field reflect.StructField) string {
	tag := field.Tag.Get("mapstructure")
	if tag == "-" {
		return ""
	}
	if tag != "" {
		name, _, _ := strings.Cut(tag, ",")
		return name
	}
	return strings.ToLower(field.Name)
}
