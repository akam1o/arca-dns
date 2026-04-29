package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/akam1o/arca-dns/pkg/config"
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
