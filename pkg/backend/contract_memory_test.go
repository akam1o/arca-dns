package backend

import (
	"testing"
)

// TestMemoryBackend_Contract runs the full contract test suite against the
// test-only MemoryBackend helper.
func TestMemoryBackend_Contract(t *testing.T) {
	store := NewMemoryBackend()
	defer store.Close()

	// Run ZoneStore CRUD contract tests
	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, store)
	})
}
