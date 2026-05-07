package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

const minArtifactSignatureKeyBytes = 32

// LoadControllerConfig loads the controller configuration from the specified file.
// Priority: defaults < YAML file < environment variables
func LoadControllerConfig(path string) (*ControllerConfig, error) {
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
		if err := applyControllerKeyDirectoryAliases(v, cfg); err != nil {
			return nil, err
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
		if err := applyControllerKeyDirectoryAliases(v, cfg); err != nil {
			return nil, err
		}
	}

	// Validate configuration
	if err := ValidateControllerConfig(cfg); err != nil {
		return nil, err
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
	if cfg.API.Listen == "" {
		return fmt.Errorf("invalid api.listen: empty")
	}

	if err := validateArtifactSignatureKey("api.artifact_signature_key", cfg.API.ArtifactSignatureKey, false); err != nil {
		return err
	}

	if err := validateControllerAuthConfig(cfg.API.Auth); err != nil {
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

	if cfg.Backend.Type == "" {
		return fmt.Errorf("invalid backend.type: empty")
	}

	validBackendTypes := map[string]bool{
		"memory":   true,
		"mysql":    true,
		"git":      true,
		"etcd":     true,
		"sqlite":   true,
		"postgres": true,
	}
	if !validBackendTypes[cfg.Backend.Type] {
		return fmt.Errorf("invalid backend.type: %s (must be one of: memory, mysql, git, etcd, sqlite, postgres)", cfg.Backend.Type)
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

	if strings.TrimSpace(cfg.Storage.ArtifactDirectory) == "" {
		return fmt.Errorf("invalid storage.artifact_directory: empty")
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

func validateControllerAuthConfig(auth AuthConfig) error {
	if !auth.Enabled {
		return nil
	}

	if len(auth.APIKeys) == 0 {
		return fmt.Errorf("invalid api.auth.api_keys: at least one API key is required when api.auth.enabled is true; add api.auth.api_keys.<name>: sha256:<64-hex-sha256> (generate with: echo -n '<api-key>' | sha256sum), or set api.auth.enabled: false only for intentionally unauthenticated local development")
	}

	for name, hash := range auth.APIKeys {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("invalid api.auth.api_keys: key name must not be empty")
		}
		normalizedHash, ok := normalizeSHA256APIKeyHash(hash)
		if !ok {
			return fmt.Errorf("invalid api.auth.api_keys.%s: expected sha256:<64 hex characters>; generate with: echo -n '<api-key>' | sha256sum", name)
		}
		auth.APIKeys[name] = normalizedHash
	}

	return nil
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
			return fmt.Errorf("invalid %s: required when sync.verify_signatures is true; generate a shared secret with: openssl rand -base64 32", field)
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
	if cfg.Controller.URL == "" {
		return fmt.Errorf("invalid controller.url: empty")
	}
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

	cfg.Authoritative = strings.ToLower(strings.TrimSpace(cfg.Authoritative))
	if cfg.Authoritative == "" {
		return fmt.Errorf("invalid authoritative: empty")
	}
	if cfg.Authoritative != "nsd" {
		return fmt.Errorf("invalid authoritative: %s (supported: nsd)", cfg.Authoritative)
	}

	if cfg.NSD.Enabled {
		if cfg.NSD.ConfigPath == "" {
			return fmt.Errorf("invalid nsd.config_path: empty when NSD is enabled")
		}
		if cfg.NSD.ControlPath == "" {
			return fmt.Errorf("invalid nsd.control_path: empty when NSD is enabled")
		}
		if cfg.NSD.ZoneDirectory == "" {
			return fmt.Errorf("invalid nsd.zone_directory: empty when NSD is enabled")
		}
	}

	if cfg.Unbound.Enabled {
		if cfg.Unbound.ConfigPath == "" {
			return fmt.Errorf("invalid unbound.config_path: empty when Unbound is enabled")
		}
		if cfg.Unbound.ControlPath == "" {
			return fmt.Errorf("invalid unbound.control_path: empty when Unbound is enabled")
		}
		if cfg.Unbound.EDNSBufferSize != 1232 {
			return fmt.Errorf("invalid unbound.edns_buffer_size: must be 1232 for ECMP-safe DNSSEC responses")
		}
	}

	if cfg.BIRD.Enabled {
		if cfg.BIRD.SocketPath == "" {
			return fmt.Errorf("invalid bird.socket_path: empty when BIRD is enabled")
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
		if err := validateArtifactSignatureKey("sync.controller_public_key", cfg.Sync.ControllerPublicKey, true); err != nil {
			return err
		}
	}

	if cfg.DNSTap.Enabled {
		if strings.TrimSpace(cfg.DNSTap.SocketPath) == "" {
			return fmt.Errorf("invalid dnstap.socket_path: empty when DNSTap is enabled")
		}
		if _, err := cfg.DNSTap.SocketFileMode(); err != nil {
			return fmt.Errorf("invalid dnstap.socket_mode: %w", err)
		}
		if cfg.DNSTap.SampleRate <= 0 {
			return fmt.Errorf("invalid dnstap.sample_rate: must be positive when DNSTap is enabled")
		}
	}

	if strings.TrimSpace(cfg.Metrics.Listen) == "" {
		return fmt.Errorf("invalid metrics.listen: empty")
	}

	if cfg.Metrics.Enabled {
		path := normalizeHTTPPath(cfg.Metrics.Path, "/metrics")
		if strings.ContainsAny(path, ":*") {
			return fmt.Errorf("invalid metrics.path: must be a static HTTP path without ':' or '*'")
		}
		if isReservedAgentStatusPath(path) {
			return fmt.Errorf("invalid metrics.path: conflicts with reserved status endpoint %q", path)
		}
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
	const prefix = "ARCA_DNS_API_AUTH_API_KEYS_"

	apiKeys := make(map[string]string)
	for name, hash := range v.GetStringMapString("api.auth.api_keys") {
		apiKeys[name] = hash
	}

	for _, env := range os.Environ() {
		name, value, ok := strings.Cut(env, "=")
		if !ok || !strings.HasPrefix(name, prefix) {
			continue
		}

		keyName := strings.TrimPrefix(name, prefix)
		keyName = strings.ToLower(keyName)
		apiKeys[keyName] = value
	}

	if len(apiKeys) > 0 {
		v.Set("api.auth.api_keys", apiKeys)
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
