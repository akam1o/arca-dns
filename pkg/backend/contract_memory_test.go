package backend

import (
	"testing"
)

// TestMemoryBackend_Contract runs the full contract test suite against MemoryBackend.
func TestMemoryBackend_Contract(t *testing.T) {
	// Create a fresh memory backend for testing
	store := NewMemoryBackend()
	defer store.Close()

	// Run ZoneStore CRUD contract tests
	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, store)
	})
}
