//go:build integration
// +build integration

package backend

import (
	"testing"
)

// TestEtcdBackend_Contract runs the full contract test suite against EtcdBackend.
// Requires etcd to be running on localhost:2379 or ETCD_ENDPOINTS environment variable.
func TestEtcdBackend_Contract(t *testing.T) {
	// Create a fresh etcd backend for testing
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	// Run ZoneStore CRUD contract tests
	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, backend)
	})

	// Run RevisionStore contract tests
	t.Run("RevisionStore", func(t *testing.T) {
		RunRevisionStoreSuite(t, backend)
	})

	// Run WatchableStore contract tests
	t.Run("WatchableStore", func(t *testing.T) {
		RunWatchableStoreSuite(t, backend)
	})
}
