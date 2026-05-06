package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/spf13/cobra"
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
	t.Cleanup(func() { listenAddr = origListenAddr })

	cfg := config.DefaultControllerConfig()
	cfg.API.Listen = "127.0.0.1:9090"

	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().StringVar(&listenAddr, "listen", ":8080", "HTTP server listen address")
	applyServeFlagOverrides(cmd, cfg)
	if cfg.API.Listen != "127.0.0.1:9090" {
		t.Fatalf("listen was overridden without explicit flag: %s", cfg.API.Listen)
	}

	if err := cmd.Flags().Set("listen", "127.0.0.1:7070"); err != nil {
		t.Fatalf("set listen flag: %v", err)
	}
	applyServeFlagOverrides(cmd, cfg)
	if cfg.API.Listen != "127.0.0.1:7070" {
		t.Fatalf("listen was not overridden after explicit flag: %s", cfg.API.Listen)
	}
}
