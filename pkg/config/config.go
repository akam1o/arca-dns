package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultDNSTapSocketMode = os.FileMode(0o660)
const DefaultDNSTapSocketModeString = "0660"
const DefaultControllerClientMaxResponseBytes int64 = 64 * 1024 * 1024

// ControllerConfig is the configuration for the arca-dns-controller.
type ControllerConfig struct {
	// API configuration
	API APIConfig `mapstructure:"api"`

	// Observability configuration
	Observability ObservabilityConfig `mapstructure:"observability"`

	// Backend configuration
	Backend BackendConfig `mapstructure:"backend"`

	// DNSSEC configuration
	DNSSEC DNSSECConfig `mapstructure:"dnssec"`

	// Storage configuration (artifacts, keys)
	Storage StorageConfig `mapstructure:"storage"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging"`
}

// DNSSECKeyDirectory returns the effective directory used for DNSSEC key
// material. storage.key_directory is kept as a compatibility alias.
func (c *ControllerConfig) DNSSECKeyDirectory() string {
	if keyDirectory := strings.TrimSpace(c.DNSSEC.KeyDirectory); keyDirectory != "" {
		return keyDirectory
	}
	return strings.TrimSpace(c.Storage.KeyDirectory)
}

// AgentConfig is the configuration for the arca-dns-agent.
type AgentConfig struct {
	// Controller configuration
	Controller ControllerClientConfig `mapstructure:"controller"`

	// Authoritative is the authoritative DNS server type. Currently supported: "nsd".
	// Default: "nsd"
	Authoritative string `mapstructure:"authoritative"`

	// NSD configuration
	NSD NSDConfig `mapstructure:"nsd"`

	// Unbound configuration
	Unbound UnboundConfig `mapstructure:"unbound"`

	// BIRD configuration
	BIRD BIRDConfig `mapstructure:"bird"`

	// DNSTap configuration
	DNSTap DNSTapConfig `mapstructure:"dnstap"`

	// Metrics configuration
	Metrics MetricsConfig `mapstructure:"metrics"`

	// Health check configuration
	Health HealthConfig `mapstructure:"health"`

	// Sync configuration
	Sync SyncConfig `mapstructure:"sync"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging"`
}

// APIConfig configures the controller's REST API server.
type APIConfig struct {
	// Listen address (e.g., "0.0.0.0:8080")
	Listen string `mapstructure:"listen"`

	// ArtifactSignatureKey signs signed-zone artifact responses with HMAC-SHA256.
	// Agents use sync.controller_signature_key with the same shared secret to verify.
	ArtifactSignatureKey string `mapstructure:"artifact_signature_key"`

	// Authentication configuration
	Auth AuthConfig `mapstructure:"auth"`

	// TrustedProxies is a list of proxy IPs/CIDRs whose forwarded headers are trusted.
	// If empty, forwarded headers are not trusted (ClientIP uses remote address).
	TrustedProxies []string `mapstructure:"trusted_proxies"`

	// Rate limiting
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
}

// ObservabilityConfig configures the controller's unauthenticated operational endpoints.
type ObservabilityConfig struct {
	// Listen address for health, readiness, status, and Prometheus metrics.
	Listen string `mapstructure:"listen"`
}

// TLSConfig configures TLS for agent -> controller communication (typically terminated by a reverse proxy).
type TLSConfig struct {
	// Enabled enables TLS
	Enabled bool `mapstructure:"enabled"`

	// CertFile is the path to the TLS certificate
	CertFile string `mapstructure:"cert_file"`

	// KeyFile is the path to the TLS private key
	KeyFile string `mapstructure:"key_file"`

	// CAFile is the path to the CA certificate (for mutual TLS)
	CAFile string `mapstructure:"ca_file"`

	// ClientAuth enables mutual TLS (require client certificates)
	ClientAuth bool `mapstructure:"client_auth"`
}

// AuthConfig configures authentication for the API.
type AuthConfig struct {
	// Enabled enables authentication
	Enabled bool `mapstructure:"enabled"`

	// APIKeys is a map of API key name to hashed key
	APIKeys map[string]string `mapstructure:"api_keys"`

	// APIKeyRoles maps API key names to roles. Supported roles: admin, agent.
	// Keys without an explicit role default to admin for backward compatibility.
	APIKeyRoles map[string]string `mapstructure:"api_key_roles"`
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `mapstructure:"enabled"`

	// RequestsPerSecond is the maximum requests per second per client
	RequestsPerSecond int `mapstructure:"requests_per_second"`

	// Burst is the maximum burst size
	Burst int `mapstructure:"burst"`
}

// BackendConfig configures the zone storage backend.
type BackendConfig struct {
	// Type is the backend type (sqlite, postgres, mysql, git, etcd)
	Type string `mapstructure:"type"`

	// SQLite backend config (default)
	SQLite SQLiteBackendConfig `mapstructure:"sqlite"`

	// PostgreSQL backend config
	Postgres PostgresBackendConfig `mapstructure:"postgres"`

	// MySQL backend config
	MySQL MySQLBackendConfig `mapstructure:"mysql"`

	// Git backend config
	Git GitBackendConfig `mapstructure:"git"`

	// Etcd backend config
	Etcd EtcdBackendConfig `mapstructure:"etcd"`
}

// SQLiteBackendConfig configures the SQLite backend.
type SQLiteBackendConfig struct {
	// DSN is the SQLite data source name.
	// Runtime controller configuration must use a file-backed DSN.
	// Example: "file:arca-dns.db"
	DSN string `mapstructure:"dsn"`
}

// PostgresBackendConfig configures the PostgreSQL backend.
type PostgresBackendConfig struct {
	// DSN is the PostgreSQL connection string.
	// Example: "postgres://user:password@host:5432/arca_dns?sslmode=disable"
	DSN string `mapstructure:"dsn"`

	// MaxOpenConns is the maximum number of open connections
	MaxOpenConns int `mapstructure:"max_open_conns"`

	// MaxIdleConns is the maximum number of idle connections
	MaxIdleConns int `mapstructure:"max_idle_conns"`

	// ConnMaxLifetime is the maximum connection lifetime
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// MySQLBackendConfig configures the MySQL backend.
type MySQLBackendConfig struct {
	// DSN is the MySQL data source name
	DSN string `mapstructure:"dsn"`

	// MaxOpenConns is the maximum number of open connections
	MaxOpenConns int `mapstructure:"max_open_conns"`

	// MaxIdleConns is the maximum number of idle connections
	MaxIdleConns int `mapstructure:"max_idle_conns"`

	// ConnMaxLifetime is the maximum connection lifetime
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// GitBackendConfig configures the Git backend.
type GitBackendConfig struct {
	// RepositoryPath is the path to the Git repository
	RepositoryPath string `mapstructure:"repository_path"`

	// RemoteURL is the URL of the remote repository (optional)
	RemoteURL string `mapstructure:"remote_url"`

	// Branch is the Git branch to use
	Branch string `mapstructure:"branch"`

	// Author is the Git author name
	Author string `mapstructure:"author"`

	// Email is the Git author email
	Email string `mapstructure:"email"`

	// AutoPush enables automatic pushing to remote
	AutoPush bool `mapstructure:"auto_push"`

	// AutoPull enables automatic pulling from remote. Nil means not explicitly configured.
	AutoPull *bool `mapstructure:"auto_pull"`

	// PullInterval is the interval for automatic pulling
	PullInterval time.Duration `mapstructure:"pull_interval"`
}

// EtcdBackendConfig configures the etcd backend.
type EtcdBackendConfig struct {
	// Endpoints is the list of etcd endpoints
	Endpoints []string `mapstructure:"endpoints"`

	// Prefix is the key prefix for all zones
	Prefix string `mapstructure:"prefix"`

	// Username for authentication
	Username string `mapstructure:"username"`

	// Password for authentication
	Password string `mapstructure:"password"`

	// DialTimeout is the timeout for establishing connections
	DialTimeout time.Duration `mapstructure:"dial_timeout"`

	// RequestTimeout is the timeout for requests
	RequestTimeout time.Duration `mapstructure:"request_timeout"`
}

// DNSSECConfig configures DNSSEC signing.
type DNSSECConfig struct {
	// Enabled enables DNSSEC signing
	Enabled bool `mapstructure:"enabled"`

	// Algorithm is the DNSSEC algorithm (8=RSA-SHA256, 13=ECDSA-P256)
	Algorithm uint8 `mapstructure:"algorithm"`

	// KeyDirectory is the directory where keys are stored
	KeyDirectory string `mapstructure:"key_directory"`

	// KSKKeySize is the KSK key size in bits (for RSA)
	KSKKeySize int `mapstructure:"ksk_key_size"`

	// ZSKKeySize is the ZSK key size in bits (for RSA)
	ZSKKeySize int `mapstructure:"zsk_key_size"`

	// SignatureValidity is how long signatures are valid
	SignatureValidity time.Duration `mapstructure:"signature_validity"`

	// SignatureInception is how far back signatures are valid
	SignatureInception time.Duration `mapstructure:"signature_inception"`

	// ResignThreshold is when to re-sign (before expiration)
	ResignThreshold time.Duration `mapstructure:"resign_threshold"`

	// NSEC3 enables NSEC3 instead of NSEC
	NSEC3 bool `mapstructure:"nsec3"`

	// NSEC3Iterations is the number of NSEC3 hash iterations
	NSEC3Iterations uint16 `mapstructure:"nsec3_iterations"`

	// NSEC3SaltLength is the length of the NSEC3 salt
	NSEC3SaltLength int `mapstructure:"nsec3_salt_length"`

	// VaultEnabled enables Vault integration for key storage
	VaultEnabled bool `mapstructure:"vault_enabled"`

	// VaultAddress is the Vault server address
	VaultAddress string `mapstructure:"vault_address"`

	// VaultToken is the Vault authentication token
	VaultToken string `mapstructure:"vault_token"`

	// VaultPath is the Vault path for keys
	VaultPath string `mapstructure:"vault_path"`

	// SchedulerEnabled enables automatic signature freshness checking
	SchedulerEnabled bool `mapstructure:"scheduler_enabled"`

	// SchedulerCheckInterval is how often to check for expiring signatures
	SchedulerCheckInterval time.Duration `mapstructure:"scheduler_check_interval"`

	// MasterKeyAutoGenerate allows automatic generation of master key (dev only)
	MasterKeyAutoGenerate bool `mapstructure:"master_key_auto_generate"`
}

// StorageConfig configures artifact and key storage.
type StorageConfig struct {
	// ArtifactDirectory is where signed zone files are stored
	ArtifactDirectory string `mapstructure:"artifact_directory"`

	// KeyDirectory is where DNSSEC keys are stored
	KeyDirectory string `mapstructure:"key_directory"`

	// MaxVersionsPerZone is the maximum number of versions to keep
	MaxVersionsPerZone int `mapstructure:"max_versions_per_zone"`
}

// ControllerClientConfig configures agent's connection to controller.
type ControllerClientConfig struct {
	// URL is the controller API URL
	URL string `mapstructure:"url"`

	// APIKey is the authentication API key
	APIKey string `mapstructure:"api_key"`

	// AllowPlaintextAPIKey permits sending API keys to non-loopback HTTP URLs.
	// Prefer HTTPS; enable only for intentionally trusted transports.
	AllowPlaintextAPIKey bool `mapstructure:"allow_plaintext_api_key"`

	// TLS configuration
	TLS TLSConfig `mapstructure:"tls"`

	// Timeout is the HTTP request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// RetryAttempts is the number of retry attempts
	RetryAttempts int `mapstructure:"retry_attempts"`

	// RetryDelay is the delay between retries
	RetryDelay time.Duration `mapstructure:"retry_delay"`

	// MaxResponseBytes is the maximum controller response body size
	MaxResponseBytes int64 `mapstructure:"max_response_bytes"`
}

// NSDConfig configures NSD integration.
type NSDConfig struct {
	// Enabled enables NSD management
	Enabled bool `mapstructure:"enabled"`

	// ConfigPath is the path to nsd.conf
	ConfigPath string `mapstructure:"config_path"`

	// ZoneConfigPath is the generated NSD config file containing managed zone stanzas.
	// The main nsd.conf must include this file.
	ZoneConfigPath string `mapstructure:"zone_config_path"`

	// ControlPath is the path to nsd-control binary
	ControlPath string `mapstructure:"control_path"`

	// ZoneDirectory is where zone files are stored
	ZoneDirectory string `mapstructure:"zone_directory"`

	// CheckzonePath is the path to nsd-checkzone binary
	CheckzonePath string `mapstructure:"checkzone_path"`

	// ReloadTimeout is the timeout for reload operations
	ReloadTimeout time.Duration `mapstructure:"reload_timeout"`
}

// ValidateNSDRenderedConfigPath validates paths before they are rendered into
// generated NSD configuration.
func ValidateNSDRenderedConfigPath(field string, path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("invalid %s: empty", field)
	}
	if trimmed != path {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if strings.ContainsFunc(path, unsafeNSDRenderedConfigPathChar) {
		return fmt.Errorf("invalid %s: contains unsafe characters", field)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("invalid %s: must be an absolute path", field)
	}
	return nil
}

func unsafeNSDRenderedConfigPathChar(r rune) bool {
	switch r {
	case '"', '\\':
		return true
	default:
		return r < ' ' || r == 0x7f
	}
}

// UnboundConfig configures Unbound integration.
type UnboundConfig struct {
	// Enabled enables Unbound management
	Enabled bool `mapstructure:"enabled"`

	// ConfigPath is the path to unbound.conf
	ConfigPath string `mapstructure:"config_path"`

	// ControlPath is the path to unbound-control binary
	ControlPath string `mapstructure:"control_path"`

	// CheckconfPath is the path to unbound-checkconf binary
	CheckconfPath string `mapstructure:"checkconf_path"`

	// EDNSBufferSize is the EDNS buffer size (1232 for ECMP safety)
	EDNSBufferSize int `mapstructure:"edns_buffer_size"`

	// StubZoneConfig is the stub-zone configuration for NSD
	StubZoneConfig StubZoneConfig `mapstructure:"stub_zone"`

	// ReloadTimeout is the timeout for reload operations
	ReloadTimeout time.Duration `mapstructure:"reload_timeout"`
}

// StubZoneConfig configures Unbound's stub-zone for NSD.
type StubZoneConfig struct {
	// NSDAddress is the address of the local NSD instance
	NSDAddress string `mapstructure:"nsd_address"`

	// NSDPort is the port of the local NSD instance
	NSDPort int `mapstructure:"nsd_port"`
}

// Validate validates the Unbound stub-zone target rendered into generated
// configuration snippets.
func (c StubZoneConfig) Validate() error {
	address := strings.TrimSpace(c.NSDAddress)
	if address == "" {
		return fmt.Errorf("invalid unbound.stub_zone.nsd_address: empty")
	}
	if address != c.NSDAddress {
		return fmt.Errorf("invalid unbound.stub_zone.nsd_address: must not contain surrounding whitespace")
	}
	if strings.ContainsFunc(address, unsafeStubZoneAddressChar) {
		return fmt.Errorf("invalid unbound.stub_zone.nsd_address: contains unsafe characters")
	}
	if !isValidStubZoneAddress(address) {
		return fmt.Errorf("invalid unbound.stub_zone.nsd_address: must be an IP address or DNS hostname")
	}
	if c.NSDPort <= 0 || c.NSDPort > 65535 {
		return fmt.Errorf("invalid unbound.stub_zone.nsd_port: must be between 1 and 65535")
	}
	return nil
}

func unsafeStubZoneAddressChar(r rune) bool {
	switch r {
	case '"', '\'', '`', '\\', '#', ';', '@':
		return true
	default:
		return r <= ' ' || r == 0x7f
	}
}

func isValidStubZoneAddress(address string) bool {
	if net.ParseIP(address) != nil {
		return true
	}
	if strings.Contains(address, ":") || len(address) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(address, "."), ".")
	for _, label := range labels {
		if !isValidStubZoneAddressLabel(label) {
			return false
		}
	}
	return true
}

func isValidStubZoneAddressLabel(label string) bool {
	if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for _, r := range label {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// BIRDConfig configures BIRD BGP integration.
type BIRDConfig struct {
	// Enabled enables BIRD integration
	Enabled bool `mapstructure:"enabled"`

	// SocketPath is the path to BIRD control socket
	SocketPath string `mapstructure:"socket_path"`

	// AnycastPrefixes is the list of anycast IP prefixes to announce
	AnycastPrefixes []string `mapstructure:"anycast_prefixes"`

	// Protocols is the list of BIRD protocols to control.
	// When set, this is the preferred configuration surface for multi-neighbor setups.
	Protocols []BIRDProtocolConfig `mapstructure:"protocols"`

	// ProtocolName is the BIRD protocol name to control.
	// Deprecated in favor of ProtocolNames for multi-neighbor setups, but still supported.
	ProtocolName string `mapstructure:"protocol_name"`

	// ProtocolNames is the list of BIRD protocol names to enable/disable together.
	// If empty, ProtocolName is used.
	ProtocolNames []string `mapstructure:"protocol_names"`

	// CommandTimeout is the timeout for BIRD commands
	CommandTimeout time.Duration `mapstructure:"command_timeout"`

	// ConfigureOnStart generates a BIRD config snippet and runs "configure".
	ConfigureOnStart BIRDConfigGenerationConfig `mapstructure:"config"`

	// StateMachine configures how health signals are translated into route changes.
	StateMachine BIRDStateMachineConfig `mapstructure:"state_machine"`
}

// BIRDStateMachineConfig configures the BIRD health-to-routing state machine.
type BIRDStateMachineConfig struct {
	// FailureThreshold is consecutive failures before withdrawing routes.
	FailureThreshold int `mapstructure:"failure_threshold"`

	// RecoveryThreshold is consecutive successes before announcing routes.
	RecoveryThreshold int `mapstructure:"recovery_threshold"`

	// MinStateDuration is minimum time between route changes (debounce).
	MinStateDuration time.Duration `mapstructure:"min_state_duration"`
}

// BIRDConfigGenerationConfig configures generating a BIRD config file for anycast.
// This is roughly comparable to ip-anycast-service's BGP config surface.
type BIRDConfigGenerationConfig struct {
	Enabled bool `mapstructure:"enabled"`

	// Path is where the generated config will be written.
	// Your main bird.conf should include this file.
	Path string `mapstructure:"path"`

	// RouterID is the BIRD router id (e.g. "10.0.0.5").
	RouterID string `mapstructure:"router_id"`

	// LocalAS is the local ASN for BGP sessions.
	LocalAS uint32 `mapstructure:"local_as"`

	// SourceIP is the source address for BGP sessions.
	SourceIP string `mapstructure:"source_ip"`

	// Neighbors is a legacy list of upstream neighbors (address + ASN).
	// Prefer BIRDConfig.Protocols for a single, explicit config surface.
	Neighbors []BIRDNeighborConfig `mapstructure:"neighbors"`

	// BFD config (optional).
	BFD BIRDBFDConfig `mapstructure:"bfd"`
}

type BIRDNeighborConfig struct {
	Address string `mapstructure:"address"`
	ASN     uint32 `mapstructure:"asn"`
}

type BIRDProtocolConfig struct {
	// Name is the protocol name in bird.conf (e.g. "anycast_1").
	Name string `mapstructure:"name"`

	// Neighbor address for this BGP session.
	NeighborAddress string `mapstructure:"neighbor_address"`

	// Neighbor ASN for this BGP session.
	NeighborASN uint32 `mapstructure:"neighbor_asn"`
}

type BIRDBFDConfig struct {
	Enabled bool `mapstructure:"enabled"`

	MinRx time.Duration `mapstructure:"min_rx"`
	MinTx time.Duration `mapstructure:"min_tx"`

	Multiplier int `mapstructure:"multiplier"`
}

// DNSTapConfig configures DNSTap logging.
type DNSTapConfig struct {
	// Enabled enables DNSTap receiver
	Enabled bool `mapstructure:"enabled"`

	// SocketPath is the path to DNSTap Unix socket
	SocketPath string `mapstructure:"socket_path"`

	// SocketMode is the octal permission mode for the DNSTap Unix socket.
	SocketMode string `mapstructure:"socket_mode"`

	// SocketOwner is the optional user or numeric UID for the DNSTap socket.
	SocketOwner string `mapstructure:"socket_owner"`

	// SocketGroup is the optional group or numeric GID for the DNSTap socket.
	SocketGroup string `mapstructure:"socket_group"`

	// LogFile is the path to the DNSTap log file
	LogFile string `mapstructure:"log_file"`

	// LogRotation configures log rotation
	LogRotation LogRotationConfig `mapstructure:"log_rotation"`

	// SampleRate is the sampling rate (1/N) for normal queries
	SampleRate int `mapstructure:"sample_rate"`

	// AlwaysLogErrors enables logging all error responses
	AlwaysLogErrors bool `mapstructure:"always_log_errors"`

	// BufferSize is the size of the internal buffer
	BufferSize int `mapstructure:"buffer_size"`
}

// LogRotationConfig configures log file rotation.
type LogRotationConfig struct {
	// MaxSize is the maximum size in megabytes before rotation
	MaxSize int `mapstructure:"max_size"`

	// MaxAge is the maximum age in days to retain log files
	MaxAge int `mapstructure:"max_age"`

	// MaxBackups is the maximum number of old log files to retain
	MaxBackups int `mapstructure:"max_backups"`

	// Compress enables gzip compression of rotated files
	Compress bool `mapstructure:"compress"`
}

// MetricsConfig configures the agent status server and Prometheus metrics.
type MetricsConfig struct {
	// Enabled enables metrics endpoint
	Enabled bool `mapstructure:"enabled"`

	// Listen address for status and metrics endpoints
	Listen string `mapstructure:"listen"`

	// Path is the HTTP path for metrics (default: /metrics)
	Path string `mapstructure:"path"`

	// AuthToken protects /status and the metrics endpoint when set.
	AuthToken string `mapstructure:"auth_token"`
}

// HealthConfig configures health checking.
type HealthConfig struct {
	// CheckInterval is how often to run health checks
	CheckInterval time.Duration `mapstructure:"check_interval"`

	// FailureThreshold is consecutive failures before unhealthy
	FailureThreshold int `mapstructure:"failure_threshold"`

	// RecoveryThreshold is consecutive successes before healthy
	RecoveryThreshold int `mapstructure:"recovery_threshold"`

	// MinStateDuration is minimum time between state changes (debounce)
	MinStateDuration time.Duration `mapstructure:"min_state_duration"`

	// QueryTimeout is the timeout for DNS query checks
	QueryTimeout time.Duration `mapstructure:"query_timeout"`

	// LatencyThreshold is the maximum acceptable query latency
	LatencyThreshold time.Duration `mapstructure:"latency_threshold"`

	// NSDServer is the address for direct authoritative checks (host:port).
	// Default: 127.0.0.1:5353
	NSDServer string `mapstructure:"nsd_server"`

	// UnboundServer is the address for full-path checks through Unbound (host:port).
	// Default: 127.0.0.1:53
	UnboundServer string `mapstructure:"unbound_server"`

	// TestZone is the zone to query for health checks
	TestZone string `mapstructure:"test_zone"`

	// TestRecord is the record to query for health checks
	TestRecord string `mapstructure:"test_record"`
}

// SyncConfig configures zone synchronization.
type SyncConfig struct {
	// SyncInterval is how often to check for zone updates
	SyncInterval time.Duration `mapstructure:"sync_interval"`

	// Jitter is the maximum random jitter added to sync interval
	Jitter time.Duration `mapstructure:"jitter"`

	// MaxStaleness is the maximum time without successful sync before alerting
	MaxStaleness time.Duration `mapstructure:"max_staleness"`

	// BackupVersions is the number of old zone versions to keep
	BackupVersions int `mapstructure:"backup_versions"`

	// VerifyChecksums enables SHA256 checksum verification
	VerifyChecksums bool `mapstructure:"verify_checksums"`

	// VerifySignatures enables artifact signature verification
	VerifySignatures bool `mapstructure:"verify_signatures"`

	// ControllerSignatureKey is the shared HMAC key used to verify controller artifact signatures.
	ControllerSignatureKey string `mapstructure:"controller_signature_key"`

	// ControllerPublicKey is a deprecated alias for ControllerSignatureKey.
	ControllerPublicKey string `mapstructure:"controller_public_key"`
}

// LoggingConfig configures structured logging.
type LoggingConfig struct {
	// Level is the log level (debug, info, warn, error)
	Level string `mapstructure:"level"`

	// Format is the log format (json, console)
	Format string `mapstructure:"format"`

	// Output is the log output (stdout, stderr, file path)
	Output string `mapstructure:"output"`

	// EnableCaller adds caller information to logs
	EnableCaller bool `mapstructure:"enable_caller"`

	// EnableStacktrace adds stack traces to error logs
	EnableStacktrace bool `mapstructure:"enable_stacktrace"`
}

// DefaultControllerConfig returns the default controller configuration.
func DefaultControllerConfig() *ControllerConfig {
	return &ControllerConfig{
		API: APIConfig{
			Listen: "0.0.0.0:8080",
			Auth: AuthConfig{
				Enabled: true,
			},
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
		},
		Observability: ObservabilityConfig{
			Listen: "127.0.0.1:9053",
		},
		Backend: BackendConfig{
			Type: "sqlite",
			SQLite: SQLiteBackendConfig{
				DSN: "file:arca-dns.db",
			},
		},
		DNSSEC: DNSSECConfig{
			Enabled:                true,
			Algorithm:              13, // ECDSA-P256
			KeyDirectory:           "/var/lib/arca-dns/keys",
			SignatureValidity:      30 * 24 * time.Hour,
			SignatureInception:     1 * time.Hour,
			ResignThreshold:        7 * 24 * time.Hour,
			NSEC3:                  true,
			NSEC3Iterations:        1,
			NSEC3SaltLength:        8,
			SchedulerEnabled:       true,
			SchedulerCheckInterval: 1 * time.Hour,
			MasterKeyAutoGenerate:  false, // Disabled by default for production safety
		},
		Storage: StorageConfig{
			ArtifactDirectory:  "/var/lib/arca-dns/artifacts",
			KeyDirectory:       "/var/lib/arca-dns/keys",
			MaxVersionsPerZone: 10,
		},
		Logging: LoggingConfig{
			Level:            "info",
			Format:           "json",
			Output:           "stdout",
			EnableCaller:     false,
			EnableStacktrace: true,
		},
	}
}

// SocketFileMode parses the configured DNSTap socket permission mode.
func (c DNSTapConfig) SocketFileMode() (os.FileMode, error) {
	return ParseDNSTapSocketMode(c.SocketMode)
}

// ValidateDNSTapSocketPath validates a DNSTap Unix socket path before it is
// rendered into DNS server configuration snippets.
func ValidateDNSTapSocketPath(path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("empty")
	}
	if trimmed != path {
		return fmt.Errorf("must not contain surrounding whitespace")
	}
	if strings.ContainsFunc(path, unsafeDNSTapSocketPathChar) {
		return fmt.Errorf("contains control characters")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("must be an absolute path")
	}
	return nil
}

func unsafeDNSTapSocketPathChar(r rune) bool {
	return r < ' ' || r == 0x7f
}

// ParseDNSTapSocketMode parses a DNSTap Unix socket permission mode from an
// octal string such as "0660" or "0o660".
func ParseDNSTapSocketMode(value string) (os.FileMode, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("empty")
	}

	trimmed = strings.TrimPrefix(trimmed, "0o")
	trimmed = strings.TrimPrefix(trimmed, "0O")
	trimmed = strings.TrimPrefix(trimmed, "0")
	if trimmed == "" {
		return 0, fmt.Errorf("must include permission bits")
	}

	parsed, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("must be an octal permission string: %w", err)
	}

	mode := os.FileMode(parsed)
	if mode&^os.ModePerm != 0 {
		return 0, fmt.Errorf("must contain only permission bits")
	}
	if mode&0o600 != 0o600 {
		return 0, fmt.Errorf("must grant owner read and write")
	}
	if mode&0o007 != 0 {
		return 0, fmt.Errorf("must not grant permissions to other users")
	}

	return mode, nil
}

// DefaultAgentConfig returns the default agent configuration.
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		Controller: ControllerClientConfig{
			URL:              "http://localhost:8080",
			Timeout:          30 * time.Second,
			RetryAttempts:    3,
			RetryDelay:       5 * time.Second,
			MaxResponseBytes: DefaultControllerClientMaxResponseBytes,
		},
		Authoritative: "nsd",
		NSD: NSDConfig{
			Enabled:        true,
			ConfigPath:     "/etc/nsd/nsd.conf",
			ZoneConfigPath: "/etc/nsd/arca-dns-zones.conf",
			ControlPath:    "/usr/sbin/nsd-control",
			ZoneDirectory:  "/var/lib/nsd/zones",
			CheckzonePath:  "/usr/sbin/nsd-checkzone",
			ReloadTimeout:  10 * time.Second,
		},
		Unbound: UnboundConfig{
			Enabled:        true,
			ConfigPath:     "/etc/unbound/unbound.conf",
			ControlPath:    "/usr/sbin/unbound-control",
			CheckconfPath:  "/usr/sbin/unbound-checkconf",
			EDNSBufferSize: 1232, // ECMP-safe value
			StubZoneConfig: StubZoneConfig{
				NSDAddress: "127.0.0.1",
				NSDPort:    5353,
			},
			ReloadTimeout: 10 * time.Second,
		},
		BIRD: BIRDConfig{
			Enabled:        false, // Disabled by default, must be configured
			SocketPath:     "/var/run/bird/bird.ctl",
			ProtocolName:   "anycast_dns",
			CommandTimeout: 5 * time.Second,
			StateMachine: BIRDStateMachineConfig{
				FailureThreshold:  3,
				RecoveryThreshold: 3,
				MinStateDuration:  30 * time.Second,
			},
		},
		DNSTap: DNSTapConfig{
			Enabled:    true,
			SocketPath: "/var/run/dnstap.sock",
			SocketMode: DefaultDNSTapSocketModeString,
			LogFile:    "/var/log/arca-dns/dnstap.log",
			LogRotation: LogRotationConfig{
				MaxSize:    100, // 100 MB
				MaxAge:     7,   // 7 days
				MaxBackups: 10,
				Compress:   true,
			},
			SampleRate:      1000, // 1/1000
			AlwaysLogErrors: true,
			BufferSize:      10000,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Listen:  "127.0.0.1:9090",
			Path:    "/metrics",
		},
		Health: HealthConfig{
			CheckInterval:     10 * time.Second,
			FailureThreshold:  3,
			RecoveryThreshold: 5,
			MinStateDuration:  30 * time.Second,
			QueryTimeout:      5 * time.Second,
			LatencyThreshold:  100 * time.Millisecond,
			NSDServer:         "127.0.0.1:5353",
			UnboundServer:     "127.0.0.1:53",
		},
		Sync: SyncConfig{
			SyncInterval:     30 * time.Second,
			Jitter:           5 * time.Second,
			MaxStaleness:     5 * time.Minute,
			BackupVersions:   3,
			VerifyChecksums:  true,
			VerifySignatures: true,
		},
		Logging: LoggingConfig{
			Level:            "info",
			Format:           "json",
			Output:           "stdout",
			EnableCaller:     false,
			EnableStacktrace: true,
		},
	}
}
