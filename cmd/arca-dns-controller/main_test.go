package main

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

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
