package backend

import (
	"os"
	"testing"
)

// TestPostgresBackend_Contract runs the full contract test suite against PostgresBackend.
// Requires ARCA_POSTGRES_DSN environment variable to be set.
// Example: ARCA_POSTGRES_DSN="postgres://user:pass@localhost:5432/arca_dns_test?sslmode=disable" go test ./pkg/backend/ -run TestPostgresBackend
func TestPostgresBackend_Contract(t *testing.T) {
	dsn := os.Getenv("ARCA_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARCA_POSTGRES_DSN not set, skipping PostgreSQL contract tests")
	}

	store, err := NewPostgresBackend(dsn)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL backend: %v", err)
	}
	defer store.Close()

	if err := store.InitSchema(); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}

	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, store)
	})

	t.Run("TransactionalStore", func(t *testing.T) {
		RunTransactionalStoreSuite(t, store)
	})
}
