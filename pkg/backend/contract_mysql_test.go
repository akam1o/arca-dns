//go:build integration
// +build integration

package backend

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// setupMySQLBackend creates a test MySQL backend.
// Requires MySQL to be running and accessible via MYSQL_DSN environment variable.
// Example DSN: root:testpass@tcp(localhost:3306)/arca_dns_test?parseTime=true
func setupMySQLBackend(t *testing.T) (*MySQLBackend, func()) {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		t.Skip("MYSQL_DSN environment variable not set, skipping MySQL integration test")
	}

	backend, err := NewMySQLBackend(dsn)
	require.NoError(t, err, "Failed to create MySQL backend")

	// Clean up any existing test data
	ctx := context.Background()
	_, err = backend.db.ExecContext(ctx, "DELETE FROM records")
	require.NoError(t, err, "Failed to clean records table")
	_, err = backend.db.ExecContext(ctx, "DELETE FROM zones")
	require.NoError(t, err, "Failed to clean zones table")

	cleanup := func() {
		// Clean up test data
		backend.db.ExecContext(context.Background(), "DELETE FROM records")
		backend.db.ExecContext(context.Background(), "DELETE FROM zones")
		backend.Close()
	}

	return backend, cleanup
}

// TestMySQLBackend_Contract runs the full contract test suite against MySQLBackend.
// Requires MySQL to be running and accessible via MYSQL_DSN environment variable.
func TestMySQLBackend_Contract(t *testing.T) {
	// Create a fresh MySQL backend for testing
	backend, cleanup := setupMySQLBackend(t)
	defer cleanup()

	// Run ZoneStore CRUD contract tests
	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, backend)
	})
}

// TestMySQLBackend_Setup verifies the setup helper works correctly
func TestMySQLBackend_Setup(t *testing.T) {
	backend, cleanup := setupMySQLBackend(t)
	defer cleanup()

	// Verify tables exist and are empty
	ctx := context.Background()

	var count int
	err := backend.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM zones").Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 0, count, "zones table should be empty after setup")

	err = backend.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM records").Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 0, count, "records table should be empty after setup")
}

// normalizeZoneName is imported from mysql.go indirectly, but for clarity in tests:
// MySQL backend expects lowercase zone names with trailing dots.
