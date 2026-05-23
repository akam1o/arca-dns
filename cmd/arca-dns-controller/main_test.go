package main

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type controllerStoreWithoutConditionalDelete struct {
	backend.ZoneStore
}

func TestRunServeReturnsConfigLoadError(t *testing.T) {
	origConfigFile := configFile
	t.Cleanup(func() {
		configFile = origConfigFile
	})

	configFile = filepath.Join(t.TempDir(), "missing.yaml")

	err := runServe(&cobra.Command{Use: "serve"}, nil)
	if err == nil {
		t.Fatal("expected config load error")
	}
	if !strings.Contains(err.Error(), "failed to load configuration") {
		t.Fatalf("expected config load error, got %v", err)
	}
}

func TestRunServeRevalidatesFlagOverridesBeforeBackendInit(t *testing.T) {
	origConfigFile := configFile
	origListenAddr := listenAddr
	origObservabilityListenAddr := observabilityListenAddr
	t.Cleanup(func() {
		configFile = origConfigFile
		listenAddr = origListenAddr
		observabilityListenAddr = origObservabilityListenAddr
	})

	tmpDir := t.TempDir()
	configFile = filepath.Join(tmpDir, "controller.yaml")
	configYAML := `
api:
  listen: "127.0.0.1:8080"
  artifact_signature_key: "test-artifact-signature-key-32-bytes"
  auth:
    enabled: false
observability:
  listen: "127.0.0.1:9053"
backend:
  type: "sqlite"
  sqlite:
    dsn: "` + filepath.Join(tmpDir, "arca-dns.db") + `"
dnssec:
  enabled: false
storage:
  artifact_directory: "` + filepath.Join(tmpDir, "artifacts") + `"
logging:
  level: "error"
  format: "json"
  output: "stdout"
`
	if err := os.WriteFile(configFile, []byte(configYAML), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().StringVar(&listenAddr, "listen", ":8080", "HTTP server listen address")
	cmd.Flags().StringVar(&observabilityListenAddr, "observability-listen", ":9053", "HTTP observability server listen address")
	if err := cmd.Flags().Set("listen", "127.0.0.1:19053"); err != nil {
		t.Fatalf("set listen flag: %v", err)
	}
	if err := cmd.Flags().Set("observability-listen", "127.0.0.1:19053"); err != nil {
		t.Fatalf("set observability listen flag: %v", err)
	}

	err := runServe(cmd, nil)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "invalid configuration after applying command-line flags") ||
		!strings.Contains(err.Error(), "observability.listen") {
		t.Fatalf("expected flag override validation error, got %v", err)
	}
}

func TestNewStoreFromConfig_SQLite(t *testing.T) {
	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "sqlite"
	cfg.Backend.SQLite.DSN = "file:" + filepath.Join(t.TempDir(), "arca-dns.db")

	store, err := newStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("newStoreFromConfig returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("store.Close returned error: %v", err)
		}
	})
}

func TestNewStoreFromConfig_PostgresRequiresDSN(t *testing.T) {
	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "postgres"
	cfg.Backend.Postgres.DSN = ""

	store, err := newStoreFromConfig(cfg)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected error for missing postgres DSN")
	}
	if !strings.Contains(err.Error(), "backend.postgres.dsn") {
		t.Fatalf("expected postgres DSN error, got %v", err)
	}
}

func TestNewStoreFromConfig_MySQLRequiresDSN(t *testing.T) {
	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "mysql"
	cfg.Backend.MySQL.DSN = ""

	store, err := newStoreFromConfig(cfg)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected error for missing mysql DSN")
	}
	if !strings.Contains(err.Error(), "backend.mysql.dsn") {
		t.Fatalf("expected mysql DSN error, got %v", err)
	}
}

func TestNewStoreFromConfig_GitRequiresRepositoryPath(t *testing.T) {
	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "git"
	cfg.Backend.Git.RepositoryPath = ""

	store, err := newStoreFromConfig(cfg)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected error for missing git repository path")
	}
	if !strings.Contains(err.Error(), "backend.git.repository_path") {
		t.Fatalf("expected git repository path error, got %v", err)
	}
}

func TestNewStoreFromConfig_Git(t *testing.T) {
	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "git"
	cfg.Backend.Git.RepositoryPath = t.TempDir()
	cfg.Backend.Git.Branch = "main"
	cfg.Backend.Git.Author = "Test User"
	cfg.Backend.Git.Email = "test@example.com"
	cfg.Backend.Git.AutoPush = false
	autoPull := false
	cfg.Backend.Git.AutoPull = &autoPull

	store, err := newStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("newStoreFromConfig returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("store.Close returned error: %v", err)
		}
	})

	infoStore, ok := store.(backend.Backend)
	if !ok {
		t.Fatal("git store does not expose backend metadata")
	}
	info := infoStore.Info()
	if info.Type != "git" {
		t.Fatalf("backend type = %q, want git", info.Type)
	}
	if !containsString(info.Capabilities, backend.CapabilityRevisionStore) {
		t.Fatalf("git backend capabilities missing %s: %v", backend.CapabilityRevisionStore, info.Capabilities)
	}
	if !containsString(info.Capabilities, backend.CapabilityConditionalDeleteStore) {
		t.Fatalf("git backend capabilities missing %s: %v", backend.CapabilityConditionalDeleteStore, info.Capabilities)
	}
}

func TestNewStoreFromConfig_EtcdRequiresEndpoints(t *testing.T) {
	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "etcd"
	cfg.Backend.Etcd.Endpoints = nil

	store, err := newStoreFromConfig(cfg)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected error for missing etcd endpoints")
	}
	if !strings.Contains(err.Error(), "backend.etcd.endpoints") {
		t.Fatalf("expected etcd endpoints error, got %v", err)
	}
}

func TestNewStoreFromConfig_RejectsMemory(t *testing.T) {
	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "memory"

	store, err := newStoreFromConfig(cfg)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected error for memory backend")
	}
	if !strings.Contains(err.Error(), "unsupported backend type: memory") {
		t.Fatalf("expected memory backend error, got %v", err)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestValidateControllerStoreCapabilities(t *testing.T) {
	store := backend.NewMemoryBackend()
	if err := validateControllerStoreCapabilities(store); err != nil {
		t.Fatalf("validateControllerStoreCapabilities returned error: %v", err)
	}

	if err := validateControllerStoreCapabilities(nil); err == nil || !strings.Contains(err.Error(), "backend store is nil") {
		t.Fatalf("expected nil store error, got %v", err)
	}

	err := validateControllerStoreCapabilities(&controllerStoreWithoutConditionalDelete{ZoneStore: store})
	if err == nil {
		t.Fatal("expected missing capability error")
	}
	if !strings.Contains(err.Error(), backend.CapabilityConditionalDeleteStore) {
		t.Fatalf("expected ConditionalDeleteStore error, got %v", err)
	}
}

func TestControllerHTTPServerError(t *testing.T) {
	wrapped := errors.New("listen tcp failed")
	err := controllerHTTPServerError{name: "api", err: wrapped}

	if got, want := err.Error(), "api server failed: listen tcp failed"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, wrapped) {
		t.Fatalf("errors.Is() did not match wrapped error")
	}
}

func TestNewControllerHTTPServer_HasTimeouts(t *testing.T) {
	server := newControllerHTTPServer("127.0.0.1:0", http.NewServeMux())

	if server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout=%s, want 5s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout=%s, want 15s", server.ReadTimeout)
	}
	if server.WriteTimeout != 15*time.Second {
		t.Fatalf("WriteTimeout=%s, want 15s", server.WriteTimeout)
	}
	if server.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout=%s, want 60s", server.IdleTimeout)
	}
}

func TestStartControllerHTTPServerReportsListenError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	server := newControllerHTTPServer(listener.Addr().String(), http.NewServeMux())
	errCh := make(chan controllerHTTPServerError, 1)
	startControllerHTTPServer(zap.NewNop(), "api", server, errCh)

	select {
	case serverErr := <-errCh:
		if serverErr.name != "api" {
			t.Fatalf("server name = %q, want api", serverErr.name)
		}
		if serverErr.err == nil {
			t.Fatal("server error is nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for listen error")
	}
}

func TestSignerOptionsFromConfig(t *testing.T) {
	cfg := config.DNSSECConfig{
		SignatureValidity:  48 * time.Hour,
		SignatureInception: 2 * time.Hour,
		ResignThreshold:    6 * time.Hour,
		NSEC3:              true,
		NSEC3Iterations:    7,
		NSEC3SaltLength:    4,
	}

	options := signerOptionsFromConfig(cfg)

	if options.Expiration != 48*time.Hour {
		t.Fatalf("Expiration = %s, want 48h", options.Expiration)
	}
	if options.Inception != -2*time.Hour {
		t.Fatalf("Inception = %s, want -2h", options.Inception)
	}
	if options.ResignThreshold != 6*time.Hour {
		t.Fatalf("ResignThreshold = %s, want 6h", options.ResignThreshold)
	}
	if !options.NSEC3Enabled {
		t.Fatal("NSEC3Enabled = false, want true")
	}
	if options.NSEC3Iterations != 7 {
		t.Fatalf("NSEC3Iterations = %d, want 7", options.NSEC3Iterations)
	}
	if options.NSEC3SaltLength != 4 {
		t.Fatalf("NSEC3SaltLength = %d, want 4", options.NSEC3SaltLength)
	}
}

func TestApplyServeFlagOverrides_OnlyOverridesExplicitListen(t *testing.T) {
	origListenAddr := listenAddr
	origObservabilityListenAddr := observabilityListenAddr
	t.Cleanup(func() {
		listenAddr = origListenAddr
		observabilityListenAddr = origObservabilityListenAddr
	})

	cfg := config.DefaultControllerConfig()
	cfg.API.Listen = "127.0.0.1:9090"
	cfg.Observability.Listen = "127.0.0.1:9053"

	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().StringVar(&listenAddr, "listen", ":8080", "HTTP server listen address")
	cmd.Flags().StringVar(&observabilityListenAddr, "observability-listen", ":9053", "HTTP observability server listen address")
	applyServeFlagOverrides(cmd, cfg)
	if cfg.API.Listen != "127.0.0.1:9090" {
		t.Fatalf("listen was overridden without explicit flag: %s", cfg.API.Listen)
	}
	if cfg.Observability.Listen != "127.0.0.1:9053" {
		t.Fatalf("observability listen was overridden without explicit flag: %s", cfg.Observability.Listen)
	}

	if err := cmd.Flags().Set("listen", "127.0.0.1:7070"); err != nil {
		t.Fatalf("set listen flag: %v", err)
	}
	if err := cmd.Flags().Set("observability-listen", "127.0.0.1:7053"); err != nil {
		t.Fatalf("set observability listen flag: %v", err)
	}
	applyServeFlagOverrides(cmd, cfg)
	if cfg.API.Listen != "127.0.0.1:7070" {
		t.Fatalf("listen was not overridden after explicit flag: %s", cfg.API.Listen)
	}
	if cfg.Observability.Listen != "127.0.0.1:7053" {
		t.Fatalf("observability listen was not overridden after explicit flag: %s", cfg.Observability.Listen)
	}
}

func TestApplyServeFlagOverrides_RevalidatesOverlap(t *testing.T) {
	origListenAddr := listenAddr
	origObservabilityListenAddr := observabilityListenAddr
	t.Cleanup(func() {
		listenAddr = origListenAddr
		observabilityListenAddr = origObservabilityListenAddr
	})

	cfg := config.DefaultControllerConfig()
	cfg.API.ArtifactSignatureKey = "test-artifact-signature-key-32-bytes"
	cfg.API.Auth.APIKeys = map[string]string{
		"admin": "sha256:" + strings.Repeat("a", 64),
	}
	cfg.API.Auth.APIKeyRoles = map[string]string{
		"admin": "admin",
	}

	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().StringVar(&listenAddr, "listen", ":8080", "HTTP server listen address")
	cmd.Flags().StringVar(&observabilityListenAddr, "observability-listen", ":9053", "HTTP observability server listen address")
	if err := cmd.Flags().Set("listen", "0.0.0.0:9053"); err != nil {
		t.Fatalf("set listen flag: %v", err)
	}
	if err := cmd.Flags().Set("observability-listen", "127.0.0.1:9053"); err != nil {
		t.Fatalf("set observability listen flag: %v", err)
	}

	applyServeFlagOverrides(cmd, cfg)
	if err := config.ValidateControllerConfig(cfg); err == nil || !strings.Contains(err.Error(), "observability.listen") {
		t.Fatalf("expected overlap validation error, got %v", err)
	}
}
