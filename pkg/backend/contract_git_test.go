package backend

import (
	"testing"
)

// TestGitBackend_Contract runs the full contract test suite against GitBackend.
func TestGitBackend_Contract(t *testing.T) {
	// Create a fresh git backend for testing
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	// Run ZoneStore CRUD contract tests
	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, backend)
	})
}
