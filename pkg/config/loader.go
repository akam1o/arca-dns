package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-git/go-git/v5/plumbing"
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

	if storageKeySet && dnssecKeySet && !sameConfigPath(cfg.Storage.KeyDirectory, cfg.DNSSEC.KeyDirectory) {
		return fmt.Errorf("invalid key_directory: storage.key_directory and dnssec.key_directory must match when both are set")
	}

	if storageKeySet && !dnssecKeySet {
		cfg.DNSSEC.KeyDirectory = cfg.Storage.KeyDirectory
		return nil
	}

	applyControllerKeyDirectoryAlias(cfg)
	return nil
}

func applyControllerKeyDirectoryAlias(cfg *ControllerConfig) {
	if strings.TrimSpace(cfg.DNSSEC.KeyDirectory) == "" && strings.TrimSpace(cfg.Storage.KeyDirectory) != "" {
		cfg.DNSSEC.KeyDirectory = cfg.Storage.KeyDirectory
	}
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
	if err := validateControllerAPIConfig(&cfg.API, &cfg.Observability); err != nil {
		return err
	}
	if err := ValidateControllerBackendConfig(&cfg.Backend); err != nil {
		return err
	}
	if err := validateControllerRuntimeBackendConfig(&cfg.Backend); err != nil {
		return err
	}

	applyControllerKeyDirectoryAlias(cfg)

	if err := validateControllerStorageConfig(&cfg.Storage); err != nil {
		return err
	}
	if err := validateControllerDNSSECConfig(cfg); err != nil {
		return err
	}
	if err := validateControllerStorageRetentionConfig(&cfg.Storage); err != nil {
		return err
	}
	if err := validateLoggingConfig(&cfg.Logging); err != nil {
		return err
	}

	return nil
}

func validateControllerAPIConfig(api *APIConfig, observability *ObservabilityConfig) error {
	api.Listen = strings.TrimSpace(api.Listen)
	if api.Listen == "" {
		return fmt.Errorf("invalid api.listen: empty")
	}
	if strings.TrimSpace(observability.Listen) == "" {
		return fmt.Errorf("invalid observability.listen: empty")
	}
	observability.Listen = strings.TrimSpace(observability.Listen)
	if err := validateListenAddress("api.listen", api.Listen); err != nil {
		return err
	}
	if err := validateListenAddress("observability.listen", observability.Listen); err != nil {
		return err
	}
	if err := validateObservabilityAuthConfig(observability); err != nil {
		return err
	}
	if listenEndpointsOverlap(api.Listen, observability.Listen) {
		return fmt.Errorf("invalid observability.listen: must not overlap api.listen")
	}

	trustedProxies, err := normalizeTrustedProxies(api.TrustedProxies)
	if err != nil {
		return err
	}
	api.TrustedProxies = trustedProxies

	if err := validateControllerAuthConfig(&api.Auth); err != nil {
		return err
	}
	if err := validateArtifactSignatureKey("api.artifact_signature_key", api.ArtifactSignatureKey, true); err != nil {
		return err
	}
	keyID, err := normalizeArtifactSignatureKeyID("api.artifact_signature_key_id", api.ArtifactSignatureKeyID)
	if err != nil {
		return err
	}
	api.ArtifactSignatureKeyID = keyID
	if err := validateControllerAuthExposure(api.Listen, api.Auth); err != nil {
		return err
	}
	return validateControllerRateLimitConfig(&api.RateLimit)
}

func validateControllerRateLimitConfig(cfg *RateLimitConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.RequestsPerSecond <= 0 {
		return fmt.Errorf("invalid api.rate_limit.requests_per_second: must be positive when rate limiting is enabled")
	}
	if cfg.Burst <= 0 {
		return fmt.Errorf("invalid api.rate_limit.burst: must be positive when rate limiting is enabled")
	}
	return nil
}

func validateControllerStorageConfig(cfg *StorageConfig) error {
	if err := validateAbsoluteLocalPath("storage.artifact_directory", cfg.ArtifactDirectory); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.KeyDirectory) != "" {
		if err := validateAbsoluteLocalPath("storage.key_directory", cfg.KeyDirectory); err != nil {
			return err
		}
	}
	return nil
}

func validateControllerStorageRetentionConfig(cfg *StorageConfig) error {
	if cfg.MaxVersionsPerZone < 1 {
		return fmt.Errorf("invalid storage.max_versions_per_zone: must be positive")
	}
	return nil
}

func validateControllerDNSSECConfig(cfg *ControllerConfig) error {
	if strings.TrimSpace(cfg.DNSSEC.KeyDirectory) != "" {
		if err := validateAbsoluteLocalPath("dnssec.key_directory", cfg.DNSSEC.KeyDirectory); err != nil {
			return err
		}
	}

	if !cfg.DNSSEC.Enabled {
		return nil
	}
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
	if cfg.DNSSEC.KSKKeySize < 0 {
		return fmt.Errorf("invalid dnssec.ksk_key_size: must be non-negative")
	}
	if cfg.DNSSEC.ZSKKeySize < 0 {
		return fmt.Errorf("invalid dnssec.zsk_key_size: must be non-negative")
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
	if cfg.DNSSEC.SchedulerEnabled && cfg.DNSSEC.SchedulerCheckInterval <= 0 {
		return fmt.Errorf("invalid dnssec.scheduler_check_interval: must be positive when scheduler is enabled")
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
	if cfg.Type == "postgres" {
		if err := validateControllerSQLPoolConfig(
			"backend.postgres",
			cfg.Postgres.MaxOpenConns,
			cfg.Postgres.MaxIdleConns,
			cfg.Postgres.ConnMaxLifetime,
		); err != nil {
			return err
		}
	}
	if cfg.Type == "mysql" {
		if err := validateControllerSQLPoolConfig(
			"backend.mysql",
			cfg.MySQL.MaxOpenConns,
			cfg.MySQL.MaxIdleConns,
			cfg.MySQL.ConnMaxLifetime,
		); err != nil {
			return err
		}
	}
	if cfg.Type == "sqlite" {
		if err := validateSQLiteRuntimeDSN(cfg.SQLite.DSN); err != nil {
			return err
		}
	}
	if cfg.Type == "git" {
		if cfg.Git.RepositoryPath != "" {
			if err := validateAbsoluteLocalPath("backend.git.repository_path", cfg.Git.RepositoryPath); err != nil {
				return err
			}
		}
		if err := validateControllerGitBackendOptions(&cfg.Git); err != nil {
			return err
		}
	}
	return nil
}

func validateControllerGitBackendOptions(cfg *GitBackendConfig) error {
	if cfg.Branch != "" {
		if err := plumbing.NewBranchReferenceName(cfg.Branch).Validate(); err != nil {
			return fmt.Errorf("invalid backend.git.branch: %q", cfg.Branch)
		}
	}
	if cfg.Author != "" {
		if err := validateGitAuthorName("backend.git.author", cfg.Author); err != nil {
			return err
		}
	}
	if cfg.Email != "" {
		if err := validateGitAuthorEmail("backend.git.email", cfg.Email); err != nil {
			return err
		}
	}
	if cfg.RemoteURL != "" {
		if err := validateGitRemoteURL("backend.git.remote_url", cfg.RemoteURL); err != nil {
			return err
		}
	}
	if cfg.PullInterval < 0 {
		return fmt.Errorf("invalid backend.git.pull_interval: must be non-negative")
	}
	return nil
}

func validateGitAuthorName(field string, name string) error {
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if strings.ContainsFunc(name, unsafeExecutablePathChar) {
		return fmt.Errorf("invalid %s: contains control characters", field)
	}
	if strings.ContainsAny(name, "<>") {
		return fmt.Errorf("invalid %s: must not contain angle brackets", field)
	}
	return nil
}

func validateGitAuthorEmail(field string, email string) error {
	if strings.ContainsFunc(email, unicode.IsSpace) {
		return fmt.Errorf("invalid %s: must not contain whitespace", field)
	}
	if strings.ContainsFunc(email, unsafeExecutablePathChar) {
		return fmt.Errorf("invalid %s: contains control characters", field)
	}
	if strings.ContainsAny(email, "<>") {
		return fmt.Errorf("invalid %s: must not contain angle brackets", field)
	}
	return nil
}

func validateGitRemoteURL(field string, remoteURL string) error {
	if strings.TrimSpace(remoteURL) != remoteURL {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if strings.ContainsFunc(remoteURL, unsafeExecutablePathChar) {
		return fmt.Errorf("invalid %s: contains control characters", field)
	}
	return nil
}

func validateControllerSQLPoolConfig(prefix string, maxOpenConns int, maxIdleConns int, connMaxLifetime time.Duration) error {
	if maxOpenConns < 0 {
		return fmt.Errorf("invalid %s.max_open_conns: must be non-negative", prefix)
	}
	if maxIdleConns < 0 {
		return fmt.Errorf("invalid %s.max_idle_conns: must be non-negative", prefix)
	}
	if maxOpenConns > 0 && maxIdleConns > maxOpenConns {
		return fmt.Errorf("invalid %s.max_idle_conns: must be less than or equal to %s.max_open_conns when max_open_conns is set", prefix, prefix)
	}
	if connMaxLifetime < 0 {
		return fmt.Errorf("invalid %s.conn_max_lifetime: must be non-negative", prefix)
	}
	return nil
}

func validateControllerRuntimeBackendConfig(cfg *BackendConfig) error {
	switch cfg.Type {
	case "postgres":
		return validateControllerBackendDSN("backend.postgres.dsn", cfg.Postgres.DSN)
	case "mysql":
		return validateControllerBackendDSN("backend.mysql.dsn", cfg.MySQL.DSN)
	case "git":
		if strings.TrimSpace(cfg.Git.RepositoryPath) == "" {
			return fmt.Errorf("invalid backend.git.repository_path: empty")
		}
	case "etcd":
		return validateControllerEtcdRuntimeConfig(&cfg.Etcd)
	}
	return nil
}

func validateControllerBackendDSN(field string, dsn string) error {
	value := strings.TrimSpace(dsn)
	if value == "" {
		return fmt.Errorf("invalid %s: empty", field)
	}
	if value != dsn {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if strings.ContainsFunc(dsn, unsafeExecutablePathChar) {
		return fmt.Errorf("invalid %s: contains control characters", field)
	}
	if isPlaceholderSecret(value) {
		return fmt.Errorf("invalid %s: replace placeholder value with the backend connection string", field)
	}
	return nil
}

func validateControllerEtcdRuntimeConfig(cfg *EtcdBackendConfig) error {
	if len(cfg.Endpoints) == 0 {
		return fmt.Errorf("invalid backend.etcd.endpoints: empty")
	}

	normalized := make([]string, len(cfg.Endpoints))
	for i, endpoint := range cfg.Endpoints {
		value := strings.TrimSpace(endpoint)
		if value == "" {
			return fmt.Errorf("invalid backend.etcd.endpoints[%d]: empty", i)
		}
		if strings.ContainsFunc(value, unsafeExecutablePathChar) {
			return fmt.Errorf("invalid backend.etcd.endpoints[%d]: contains control characters", i)
		}
		if isPlaceholderSecret(value) {
			return fmt.Errorf("invalid backend.etcd.endpoints[%d]: replace placeholder value with an etcd endpoint", i)
		}
		if err := validateEtcdEndpoint(i, value); err != nil {
			return err
		}
		normalized[i] = value
	}
	cfg.Endpoints = normalized

	if isPlaceholderSecret(cfg.Password) {
		return fmt.Errorf("invalid backend.etcd.password: replace placeholder value with the etcd password")
	}
	if cfg.DialTimeout < 0 {
		return fmt.Errorf("invalid backend.etcd.dial_timeout: must be non-negative")
	}
	if cfg.RequestTimeout < 0 {
		return fmt.Errorf("invalid backend.etcd.request_timeout: must be non-negative")
	}
	return nil
}

func validateEtcdEndpoint(index int, endpoint string) error {
	hostPort := endpoint
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("invalid backend.etcd.endpoints[%d]: invalid URL: %w", index, err)
		}
		switch parsed.Scheme {
		case "http", "https":
		default:
			return fmt.Errorf("invalid backend.etcd.endpoints[%d]: scheme must be http or https", index)
		}
		if parsed.User != nil {
			return fmt.Errorf("invalid backend.etcd.endpoints[%d]: must not include userinfo", index)
		}
		hostPort = parsed.Host
	}
	if err := validateBackendEndpointHostPort(fmt.Sprintf("backend.etcd.endpoints[%d]", index), hostPort); err != nil {
		return err
	}
	return nil
}

func validateBackendEndpointHostPort(field string, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s: must be in host:port format", field)
	}
	if host == "" {
		return fmt.Errorf("invalid %s: host must not be empty", field)
	}
	if strings.ContainsFunc(host, unsafeListenHostChar) {
		return fmt.Errorf("invalid %s: host contains unsafe characters", field)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return fmt.Errorf("invalid %s: host must not be an unspecified address", field)
		}
	} else if !isValidStubZoneAddress(host) {
		return fmt.Errorf("invalid %s: host must be an IP address or DNS hostname", field)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid %s: port must be between 1 and 65535", field)
	}
	return nil
}

func validateSQLiteRuntimeDSN(dsn string) error {
	value := strings.TrimSpace(dsn)
	if value == "" {
		return nil
	}
	if sqliteDSNUsesMemoryDatabase(value) {
		return fmt.Errorf("invalid backend.sqlite.dsn: in-memory SQLite DSNs are not allowed for controller storage; use a file-backed SQLite database")
	}
	return nil
}

func sqliteDSNUsesMemoryDatabase(dsn string) bool {
	pathPart, query, hasQuery := strings.Cut(dsn, "?")
	if strings.EqualFold(pathPart, ":memory:") ||
		strings.EqualFold(pathPart, "file::memory:") ||
		strings.EqualFold(pathPart, "file::memory") {
		return true
	}
	if !hasQuery {
		return false
	}

	for _, part := range strings.Split(query, "&") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			decodedKey = key
		}
		if !strings.EqualFold(decodedKey, "mode") {
			continue
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			decodedValue = value
		}
		if strings.EqualFold(decodedValue, "memory") {
			return true
		}
	}
	return false
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
			if _, network, err := net.ParseCIDR(value); err != nil {
				return nil, fmt.Errorf("invalid api.trusted_proxies[%d]: %q is not a valid CIDR: %w", i, proxy, err)
			} else if cidrCoversAllAddresses(network) {
				return nil, fmt.Errorf("invalid api.trusted_proxies[%d]: must not trust all addresses", i)
			}
			normalized[i] = value
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid api.trusted_proxies[%d]: %q is not a valid IP address or CIDR", i, proxy)
		}
		if ip.IsUnspecified() {
			return nil, fmt.Errorf("invalid api.trusted_proxies[%d]: must not be an unspecified address", i)
		}
		normalized[i] = value
	}
	return normalized, nil
}

func cidrCoversAllAddresses(network *net.IPNet) bool {
	if network == nil {
		return false
	}
	ones, bits := network.Mask.Size()
	return bits > 0 && ones == 0
}

func validateListenAddress(field, listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid %s: must be in host:port format", field)
	}
	if strings.ContainsFunc(host, unsafeListenHostChar) {
		return fmt.Errorf("invalid %s: host contains unsafe characters", field)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid %s: port must be between 1 and 65535", field)
	}
	return nil
}

func unsafeListenHostChar(r rune) bool {
	return r <= ' ' || r == 0x7f
}

func validateObservabilityAuthConfig(observability *ObservabilityConfig) error {
	observability.AuthToken = strings.TrimSpace(observability.AuthToken)
	if observability.AuthToken != "" {
		if isPlaceholderSecret(observability.AuthToken) {
			return fmt.Errorf("invalid observability.auth_token: replace placeholder value with a generated status token")
		}
		if len([]byte(observability.AuthToken)) < minStatusAuthTokenBytes {
			return fmt.Errorf("invalid observability.auth_token: must be at least %d bytes", minStatusAuthTokenBytes)
		}
	}
	if !isLoopbackListenEndpoint(observability.Listen) && observability.AuthToken == "" {
		return fmt.Errorf("invalid observability.auth_token: required when observability.listen is not loopback; bind observability.listen to 127.0.0.1 or set observability.auth_token")
	}
	return nil
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

	missingRoleNames := make([]string, 0)
	for name := range auth.APIKeys {
		if _, ok := normalizedRoles[name]; ok {
			continue
		}
		if auth.AllowImplicitAdminRoles {
			normalizedRoles[name] = apiKeyRoleAdmin
			continue
		}
		missingRoleNames = append(missingRoleNames, name)
	}
	if len(missingRoleNames) > 0 {
		sort.Strings(missingRoleNames)
		return fmt.Errorf("invalid api.auth.api_key_roles: missing explicit role for api.auth.api_keys.%s; set api.auth.api_key_roles.%s to admin or agent", missingRoleNames[0], missingRoleNames[0])
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

func normalizeArtifactSignatureKeyID(field string, keyID string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(keyID))
	if value == "" {
		return "", nil
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", fmt.Errorf("invalid %s: must contain only letters, digits, dash, underscore, or dot", field)
	}
	return value, nil
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

	if err := validateAgentControllerConfig(&cfg.Controller); err != nil {
		return err
	}
	if err := validateAgentAuthoritativeConfig(cfg); err != nil {
		return err
	}
	if err := validateAgentNSDConfig(&cfg.NSD); err != nil {
		return err
	}
	if err := validateAgentUnboundConfig(&cfg.Unbound); err != nil {
		return err
	}
	if err := validateAgentBIRDConfig(&cfg.BIRD); err != nil {
		return err
	}
	if err := validateAgentSyncConfig(&cfg.Sync); err != nil {
		return err
	}
	if err := validateAgentDNSTapConfig(&cfg.DNSTap); err != nil {
		return err
	}
	if err := validateAgentMetricsConfig(&cfg.Metrics); err != nil {
		return err
	}
	if err := validateAgentHealthConfig(&cfg.Health, cfg.NSD.Enabled, cfg.Unbound.Enabled, cfg.BIRD.Enabled); err != nil {
		return err
	}
	if err := validateLoggingConfig(&cfg.Logging); err != nil {
		return err
	}

	return nil
}

func validateAgentControllerConfig(cfg *ControllerClientConfig) error {
	controllerURL, err := normalizeControllerURL(cfg.URL)
	if err != nil {
		return err
	}
	cfg.URL = controllerURL
	if cfg.Timeout <= 0 {
		return fmt.Errorf("invalid controller.timeout: must be greater than 0")
	}
	if cfg.RetryAttempts < 0 {
		return fmt.Errorf("invalid controller.retry_attempts: must be >= 0")
	}
	if cfg.RetryDelay < 0 {
		return fmt.Errorf("invalid controller.retry_delay: must be >= 0")
	}
	if cfg.RetryAttempts > 0 && cfg.RetryDelay == 0 {
		return fmt.Errorf("invalid controller.retry_delay: must be greater than 0 when controller.retry_attempts is greater than 0")
	}
	if cfg.MaxResponseBytes <= 0 {
		return fmt.Errorf("invalid controller.max_response_bytes: must be positive")
	}
	if err := validateAgentControllerAPIKey(cfg.APIKey); err != nil {
		return err
	}
	if err := validateAgentControllerAPIKeyTransport(*cfg); err != nil {
		return err
	}
	return validateAgentControllerTLSConfig(*cfg)
}

func validateAgentAuthoritativeConfig(cfg *AgentConfig) error {
	cfg.Authoritative = strings.ToLower(strings.TrimSpace(cfg.Authoritative))
	if cfg.Authoritative == "" {
		return fmt.Errorf("invalid authoritative: empty")
	}
	if cfg.Authoritative != "nsd" {
		return fmt.Errorf("invalid authoritative: %s (supported: nsd)", cfg.Authoritative)
	}
	return nil
}

func validateAgentNSDConfig(cfg *NSDConfig) error {
	if err := ValidateNSDRenderedConfigPath("nsd.zone_directory", cfg.ZoneDirectory); err != nil {
		return fmt.Errorf("%w; required for zone sync storage", err)
	}
	if !cfg.Enabled {
		return nil
	}
	if err := ValidateNSDRenderedConfigPath("nsd.config_path", cfg.ConfigPath); err != nil {
		return fmt.Errorf("%w when NSD is enabled", err)
	}
	if cfg.ZoneConfigPath != "" {
		if err := ValidateNSDRenderedConfigPath("nsd.zone_config_path", cfg.ZoneConfigPath); err != nil {
			return err
		}
	}
	if err := validateExecutablePath("nsd.control_path", cfg.ControlPath); err != nil {
		return fmt.Errorf("%w when NSD is enabled", err)
	}
	if err := validateExecutablePath("nsd.checkzone_path", cfg.CheckzonePath); err != nil {
		return fmt.Errorf("%w when NSD is enabled", err)
	}
	if cfg.ReloadTimeout <= 0 {
		return fmt.Errorf("invalid nsd.reload_timeout: must be positive when NSD is enabled")
	}
	return nil
}

func validateAgentUnboundConfig(cfg *UnboundConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if err := validateAbsoluteLocalPath("unbound.config_path", cfg.ConfigPath); err != nil {
		return fmt.Errorf("%w when Unbound is enabled", err)
	}
	if err := validateExecutablePath("unbound.control_path", cfg.ControlPath); err != nil {
		return fmt.Errorf("%w when Unbound is enabled", err)
	}
	if err := validateExecutablePath("unbound.checkconf_path", cfg.CheckconfPath); err != nil {
		return fmt.Errorf("%w when Unbound is enabled", err)
	}
	if err := cfg.StubZoneConfig.Validate(); err != nil {
		return err
	}
	if cfg.EDNSBufferSize != 1232 {
		return fmt.Errorf("invalid unbound.edns_buffer_size: must be 1232 for ECMP-safe DNSSEC responses")
	}
	if cfg.ReloadTimeout <= 0 {
		return fmt.Errorf("invalid unbound.reload_timeout: must be positive when Unbound is enabled")
	}
	return nil
}

func validateAgentBIRDConfig(cfg *BIRDConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if err := validateAbsoluteLocalPath("bird.socket_path", cfg.SocketPath); err != nil {
		return fmt.Errorf("%w when BIRD is enabled", err)
	}
	if len(cfg.Protocols) == 0 && cfg.ProtocolName == "" && len(cfg.ProtocolNames) == 0 {
		return fmt.Errorf("invalid bird.protocols: empty when BIRD is enabled (or set bird.protocol_names/protocol_name)")
	}
	if err := validateBIRDProtocolIdentifiers(cfg); err != nil {
		return err
	}
	if cfg.CommandTimeout <= 0 {
		return fmt.Errorf("invalid bird.command_timeout: must be positive when BIRD is enabled")
	}
	if cfg.StateMachine.FailureThreshold < 1 {
		return fmt.Errorf("invalid bird.state_machine.failure_threshold: must be >= 1")
	}
	if cfg.StateMachine.RecoveryThreshold < 1 {
		return fmt.Errorf("invalid bird.state_machine.recovery_threshold: must be >= 1")
	}
	if cfg.StateMachine.MinStateDuration < 0 {
		return fmt.Errorf("invalid bird.state_machine.min_state_duration: must be >= 0")
	}
	if cfg.ConfigureOnStart.Enabled {
		return validateAgentBIRDStartupConfig(cfg)
	}
	return nil
}

func validateAgentBIRDStartupConfig(cfg *BIRDConfig) error {
	if err := validateAbsoluteLocalPath("bird.config.path", cfg.ConfigureOnStart.Path); err != nil {
		return fmt.Errorf("%w when bird.config.enabled is true", err)
	}
	if err := validateBIRDIPAddress("bird.config.router_id", cfg.ConfigureOnStart.RouterID); err != nil {
		return fmt.Errorf("%w when bird.config.enabled is true", err)
	}
	if cfg.ConfigureOnStart.LocalAS == 0 {
		return fmt.Errorf("invalid bird.config.local_as: must be > 0 when bird.config.enabled is true")
	}
	if err := validateBIRDIPAddress("bird.config.source_ip", cfg.ConfigureOnStart.SourceIP); err != nil {
		return fmt.Errorf("%w when bird.config.enabled is true", err)
	}
	if err := validateBIRDAnycastPrefixes(cfg.AnycastPrefixes); err != nil {
		return fmt.Errorf("%w when bird.config.enabled is true", err)
	}
	if len(cfg.Protocols) == 0 && len(cfg.ConfigureOnStart.Neighbors) == 0 {
		return fmt.Errorf("invalid bird.protocols: must be non-empty when bird.config.enabled is true (or set bird.config.neighbors for legacy config)")
	}
	for i, p := range cfg.Protocols {
		if err := validateBIRDIPAddress(fmt.Sprintf("bird.protocols[%d].neighbor_address", i), p.NeighborAddress); err != nil {
			return err
		}
		if p.NeighborASN == 0 {
			return fmt.Errorf("invalid bird.protocols[%d].neighbor_asn: must be > 0", i)
		}
	}
	if len(cfg.Protocols) == 0 {
		for i, neighbor := range cfg.ConfigureOnStart.Neighbors {
			if err := validateBIRDIPAddress(fmt.Sprintf("bird.config.neighbors[%d].address", i), neighbor.Address); err != nil {
				return err
			}
			if neighbor.ASN == 0 {
				return fmt.Errorf("invalid bird.config.neighbors[%d].asn: must be > 0", i)
			}
		}
	}
	if cfg.ConfigureOnStart.BFD.Enabled && cfg.ConfigureOnStart.BFD.Multiplier < 1 {
		return fmt.Errorf("invalid bird.config.bfd.multiplier: must be >= 1")
	}
	return nil
}

func validateAgentSyncConfig(cfg *SyncConfig) error {
	if cfg.SyncInterval <= 0 {
		return fmt.Errorf("invalid sync.sync_interval: must be positive")
	}
	if cfg.MaxStaleness <= 0 {
		return fmt.Errorf("invalid sync.max_staleness: must be positive")
	}
	if cfg.MaxStaleness < cfg.SyncInterval {
		return fmt.Errorf("invalid sync.max_staleness: must be greater than or equal to sync.sync_interval")
	}
	if cfg.Jitter < 0 {
		return fmt.Errorf("invalid sync.jitter: must be non-negative")
	}
	if cfg.BackupVersions < 0 {
		return fmt.Errorf("invalid sync.backup_versions: must be non-negative")
	}
	if cfg.MinFreeBytes < 0 {
		return fmt.Errorf("invalid sync.min_free_bytes: must be non-negative")
	}
	if !cfg.VerifySignatures {
		return nil
	}
	if cfg.ControllerSignatureKey == "" && len(cfg.ControllerSignatureKeys) == 0 {
		return fmt.Errorf("invalid sync.controller_signature_key: required when sync.verify_signatures is true; set sync.controller_signature_key or sync.controller_signature_keys")
	}
	if err := validateArtifactSignatureKey("sync.controller_signature_key", cfg.ControllerSignatureKey, cfg.ControllerSignatureKey != ""); err != nil {
		return err
	}
	for keyID, key := range cfg.ControllerSignatureKeys {
		if err := validateArtifactSignatureKey("sync.controller_signature_keys."+keyID, key, true); err != nil {
			return err
		}
	}
	return nil
}

func validateAgentDNSTapConfig(cfg *DNSTapConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if err := ValidateDNSTapSocketPath(cfg.SocketPath); err != nil {
		return fmt.Errorf("invalid dnstap.socket_path: %w", err)
	}
	if cfg.LogFile != "" {
		if err := validateAbsoluteLocalPath("dnstap.log_file", cfg.LogFile); err != nil {
			return err
		}
		if err := validateDNSTapLogRotationConfig(cfg.LogRotation); err != nil {
			return err
		}
	}
	if _, err := cfg.SocketFileMode(); err != nil {
		return fmt.Errorf("invalid dnstap.socket_mode: %w", err)
	}
	if cfg.SampleRate <= 0 {
		return fmt.Errorf("invalid dnstap.sample_rate: must be positive when DNSTap is enabled")
	}
	if cfg.BufferSize <= 0 {
		return fmt.Errorf("invalid dnstap.buffer_size: must be positive when DNSTap is enabled")
	}
	return nil
}

func validateAgentHealthConfig(cfg *HealthConfig, nsdEnabled bool, unboundEnabled bool, birdEnabled bool) error {
	if cfg.CheckInterval <= 0 {
		return fmt.Errorf("invalid health.check_interval: must be positive")
	}
	if cfg.QueryTimeout <= 0 {
		return fmt.Errorf("invalid health.query_timeout: must be positive")
	}
	if cfg.LatencyThreshold <= 0 {
		return fmt.Errorf("invalid health.latency_threshold: must be positive")
	}
	if cfg.FailureThreshold <= 0 {
		return fmt.Errorf("invalid health.failure_threshold: must be positive")
	}
	if cfg.RecoveryThreshold <= 0 {
		return fmt.Errorf("invalid health.recovery_threshold: must be positive")
	}
	if nsdEnabled {
		if err := validateHealthServerAddress("health.nsd_server", cfg.NSDServer); err != nil {
			return err
		}
	}
	if unboundEnabled {
		if err := validateHealthServerAddress("health.unbound_server", cfg.UnboundServer); err != nil {
			return err
		}
	}
	if !birdEnabled {
		return nil
	}
	if !nsdEnabled && !unboundEnabled {
		return fmt.Errorf("invalid bird.enabled: requires nsd.enabled or unbound.enabled for DNS health checks")
	}
	if strings.TrimSpace(cfg.TestRecord) == "" {
		return fmt.Errorf("invalid health.test_record: required when BIRD is enabled")
	}
	if healthTestRecordNeedsZone(cfg.TestRecord) && strings.TrimSpace(cfg.TestZone) == "" {
		return fmt.Errorf("invalid health.test_zone: required when health.test_record is relative and BIRD is enabled")
	}
	return nil
}

func validateDNSTapLogRotationConfig(cfg LogRotationConfig) error {
	if cfg.MaxSize < 0 {
		return fmt.Errorf("invalid dnstap.log_rotation.max_size: must be non-negative")
	}
	if cfg.MaxAge < 0 {
		return fmt.Errorf("invalid dnstap.log_rotation.max_age: must be non-negative")
	}
	if cfg.MaxBackups < 0 {
		return fmt.Errorf("invalid dnstap.log_rotation.max_backups: must be non-negative")
	}
	return nil
}

func validateHealthServerAddress(field string, address string) error {
	value := strings.TrimSpace(address)
	if value == "" {
		return nil
	}
	if value != address {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s: must be in host:port format", field)
	}
	if host == "" {
		return fmt.Errorf("invalid %s: host must not be empty", field)
	}
	if strings.ContainsFunc(host, unsafeListenHostChar) {
		return fmt.Errorf("invalid %s: host contains unsafe characters", field)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return fmt.Errorf("invalid %s: host must not be an unspecified address", field)
		}
	} else if !isValidStubZoneAddress(host) {
		return fmt.Errorf("invalid %s: host must be an IP address or DNS hostname", field)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid %s: port must be between 1 and 65535", field)
	}
	return nil
}

func validateBIRDProtocolIdentifiers(cfg *BIRDConfig) error {
	if len(cfg.Protocols) > 0 {
		for i, protocol := range cfg.Protocols {
			if err := validateBIRDIdentifier(fmt.Sprintf("bird.protocols[%d].name", i), protocol.Name); err != nil {
				return err
			}
		}
		return nil
	}

	if len(cfg.ProtocolNames) > 0 {
		for i, name := range cfg.ProtocolNames {
			if err := validateBIRDIdentifier(fmt.Sprintf("bird.protocol_names[%d]", i), name); err != nil {
				return err
			}
		}
		return nil
	}

	if cfg.ProtocolName != "" {
		return validateBIRDIdentifier("bird.protocol_name", cfg.ProtocolName)
	}
	return nil
}

func validateBIRDIdentifier(field string, name string) error {
	if name == "" {
		return fmt.Errorf("invalid %s: empty", field)
	}
	for i, r := range name {
		if i == 0 {
			if isBIRDIdentifierFirstChar(r) {
				continue
			}
			return fmt.Errorf("invalid %s: %q must start with a letter or underscore", field, name)
		}
		if !isBIRDIdentifierChar(r) {
			return fmt.Errorf("invalid %s: %q must contain only letters, digits, and underscores", field, name)
		}
	}
	return nil
}

func validateBIRDIPAddress(field string, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("invalid %s: empty", field)
	}
	if trimmed != value {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if net.ParseIP(value) == nil {
		return fmt.Errorf("invalid %s: must be an IP address", field)
	}
	return nil
}

func validateBIRDAnycastPrefixes(prefixes []string) error {
	for i, raw := range prefixes {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("invalid bird.anycast_prefixes[%d]: %w", i, err)
		}
		if !prefix.Addr().Is4() && !prefix.Addr().Is6() {
			return fmt.Errorf("invalid bird.anycast_prefixes[%d]: unsupported IP family", i)
		}
	}
	return nil
}

func isBIRDIdentifierFirstChar(r rune) bool {
	return r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}

func isBIRDIdentifierChar(r rune) bool {
	return isBIRDIdentifierFirstChar(r) || r >= '0' && r <= '9'
}

func validateLoggingConfig(cfg *LoggingConfig) error {
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[cfg.Level] {
		return fmt.Errorf("invalid logging.level: %s (must be one of: debug, info, warn, error)", cfg.Level)
	}
	if err := validateLoggingFormat("logging.format", cfg.Format); err != nil {
		return err
	}
	return validateLoggingOutputPath("logging.output", cfg.Output)
}

func validateLoggingFormat(field string, format string) error {
	value := strings.ToLower(strings.TrimSpace(format))
	switch value {
	case "", "json", "console":
		return nil
	default:
		return fmt.Errorf("invalid %s: %s (must be json or console)", field, format)
	}
}

func validateLoggingOutputPath(field string, output string) error {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil
	}
	if trimmed != output {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if output == "stdout" || output == "stderr" {
		return nil
	}
	return validateAbsoluteLocalPath(field, output)
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

func validateAgentControllerAPIKey(apiKey string) error {
	value := strings.TrimSpace(apiKey)
	if value == "" {
		return nil
	}
	if isPlaceholderSecret(value) {
		return fmt.Errorf("invalid controller.api_key: replace placeholder value with the raw agent API key")
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
	signatureKeys, err := normalizeArtifactSignatureKeys("sync.controller_signature_keys", cfg.Sync.ControllerSignatureKeys)
	if err != nil {
		return err
	}
	cfg.Sync.ControllerSignatureKeys = signatureKeys

	if signatureKey != "" {
		cfg.Sync.ControllerSignatureKey = signatureKey
		cfg.Sync.ControllerPublicKey = signatureKey
		return nil
	}
	if legacyPublicKey != "" {
		cfg.Sync.ControllerSignatureKey = legacyPublicKey
		cfg.Sync.ControllerPublicKey = legacyPublicKey
	}
	return nil
}

func normalizeArtifactSignatureKeys(field string, keys map[string]string) (map[string]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	normalized := make(map[string]string, len(keys))
	for keyID, key := range keys {
		normalizedKeyID, err := normalizeArtifactSignatureKeyID(field+"."+keyID, keyID)
		if err != nil {
			return nil, err
		}
		if normalizedKeyID == "" {
			return nil, fmt.Errorf("invalid %s: key id must not be empty", field)
		}
		normalized[normalizedKeyID] = strings.TrimSpace(key)
	}
	return normalized, nil
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
	if err := validateListenAddress("metrics.listen", metrics.Listen); err != nil {
		return err
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
	bindAgentSignatureKeyEnvVars(v)
}

func bindAgentSignatureKeyEnvVars(v *viper.Viper) {
	const keyPrefix = "ARCA_DNS_SYNC_CONTROLLER_SIGNATURE_KEYS_"

	signatureKeys := make(map[string]string)
	for keyID, key := range v.GetStringMapString("sync.controller_signature_keys") {
		signatureKeys[keyID] = key
	}

	for _, env := range os.Environ() {
		name, value, ok := strings.Cut(env, "=")
		if !ok || !strings.HasPrefix(name, keyPrefix) {
			continue
		}
		keyID := strings.TrimPrefix(name, keyPrefix)
		keyID = strings.ToLower(keyID)
		signatureKeys[keyID] = value
	}

	if len(signatureKeys) > 0 {
		v.Set("sync.controller_signature_keys", signatureKeys)
	}
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
