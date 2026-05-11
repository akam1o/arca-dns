package backend

import (
	"context"
	"os"
	"testing"
)

// setupPostgresBackend creates a test PostgreSQL backend with clean test data.
// Requires ARCA_POSTGRES_DSN environment variable to be set.
// Example: ARCA_POSTGRES_DSN="postgres://user:pass@localhost:5432/arca_dns_test?sslmode=disable" go test ./pkg/backend/ -run TestPostgresBackend
func setupPostgresBackend(t *testing.T) (*PostgresBackend, func()) {
	t.Helper()

	dsn := os.Getenv("ARCA_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARCA_POSTGRES_DSN not set, skipping PostgreSQL contract tests")
	}

	store, err := NewPostgresBackend(dsn)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL backend: %v", err)
	}

	if err := store.InitSchema(); err != nil {
		store.Close()
		t.Fatalf("Failed to init schema: %v", err)
	}

	cleanPostgresContractData(t, store)

	cleanup := func() {
		ctx := context.Background()
		_, _ = store.db.ExecContext(ctx, "DELETE FROM records")
		_, _ = store.db.ExecContext(ctx, "DELETE FROM zones")
		store.Close()
	}

	return store, cleanup
}

func cleanPostgresContractData(t *testing.T, store *PostgresBackend) {
	t.Helper()

	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, "DELETE FROM records"); err != nil {
		t.Fatalf("Failed to clean records table: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, "DELETE FROM zones"); err != nil {
		t.Fatalf("Failed to clean zones table: %v", err)
	}
}

// TestPostgresBackend_Contract runs the full contract test suite against PostgresBackend.
func TestPostgresBackend_Contract(t *testing.T) {
	store, cleanup := setupPostgresBackend(t)
	defer cleanup()

	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, store)
	})

	t.Run("TransactionalStore", func(t *testing.T) {
		RunTransactionalStoreSuite(t, store)
	})
}
