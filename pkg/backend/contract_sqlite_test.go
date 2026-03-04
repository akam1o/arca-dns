package backend

import (
	"testing"
)

// TestSQLiteBackend_Contract runs the full contract test suite against SQLiteBackend.
// This uses an in-memory SQLite database so it always runs (no external dependency).
func TestSQLiteBackend_Contract(t *testing.T) {
	store, err := NewSQLiteBackend(":memory:")
	if err != nil {
		t.Fatalf("Failed to create SQLite backend: %v", err)
	}
	defer store.Close()

	if err := store.InitSchema(); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}

	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, store)
	})
}
