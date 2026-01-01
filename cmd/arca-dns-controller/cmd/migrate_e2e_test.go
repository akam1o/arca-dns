package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrationE2E_RoundTrip tests full export → import round-trip using Git backend.
func TestMigrationE2E_RoundTrip(t *testing.T) {
	// Create source Git repository
	sourceRepo := t.TempDir()

	// Create source Git backend
	sourceStore, err := backend.NewBackend("git", map[string]interface{}{
		"repository_path": sourceRepo,
		"branch":          "main",
		"author_name":     "Test User",
		"author_email":    "test@example.com",
		"auto_sync":       false,
	})
	require.NoError(t, err)
	defer sourceStore.Close()

	ctx := context.Background()

	// Create test zones
	testZones := []*model.Zone{
		{
			Name: "e2e1.example.com.",
			SOA:  model.DefaultSOA("ns1.e2e1.example.com.", "admin.e2e1.example.com."),
			Records: []model.Record{
				{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"},
				{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.2"},
			},
		},
		{
			Name: "e2e2.example.org.",
			SOA:  model.DefaultSOA("ns1.e2e2.example.org.", "admin.e2e2.example.org."),
			Records: []model.Record{
				{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.10"},
				{Name: "@", Type: "MX", TTL: 300, Value: "10 mail.e2e2.example.org."},
			},
		},
	}

	for _, zone := range testZones {
		err := sourceStore.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// Export zones
	exportDir := t.TempDir()

	migrateBackendType = "git"
	migrateBackendPath = sourceRepo
	migrateOutputDir = exportDir
	migrateDryRun = false

	err = runExport(nil, nil)
	require.NoError(t, err)

	// Verify exported files exist
	for _, zone := range testZones {
		filename := filepath.Join(exportDir, sanitizeFilename(zone.Name)+".json")
		require.FileExists(t, filename)

		// Verify JSON can be parsed
		data, err := os.ReadFile(filename)
		require.NoError(t, err)

		var exported model.Zone
		err = json.Unmarshal(data, &exported)
		require.NoError(t, err)
		assert.Equal(t, zone.Name, exported.Name)
	}

	// Create destination Git repository
	destRepo := t.TempDir()

	// Import zones to destination
	migrateBackendType = "git"
	migrateBackendPath = destRepo
	migrateInputDir = exportDir

	err = runImport(nil, nil)
	require.NoError(t, err)

	// Verify zones in destination
	destStore, err := backend.NewBackend("git", map[string]interface{}{
		"repository_path": destRepo,
		"branch":          "main",
		"author_name":     "Test User",
		"author_email":    "test@example.com",
		"auto_sync":       false,
	})
	require.NoError(t, err)
	defer destStore.Close()

	for _, zone := range testZones {
		imported, err := destStore.GetZone(ctx, zone.Name)
		require.NoError(t, err)
		assert.Equal(t, zone.Name, imported.Name)
		assert.Equal(t, len(zone.Records), len(imported.Records))
		assert.NotEmpty(t, imported.Version)
	}
}

// TestMigrationE2E_Copy tests direct copy between backends.
func TestMigrationE2E_Copy(t *testing.T) {
	// Create source Git repository
	sourceRepo := t.TempDir()

	// Create source Git backend and add zones
	sourceStore, err := backend.NewBackend("git", map[string]interface{}{
		"repository_path": sourceRepo,
		"branch":          "main",
		"author_name":     "Test User",
		"author_email":    "test@example.com",
		"auto_sync":       false,
	})
	require.NoError(t, err)
	defer sourceStore.Close()

	ctx := context.Background()

	testZone := &model.Zone{
		Name: "copy-test.example.com.",
		SOA:  model.DefaultSOA("ns1.copy-test.example.com.", "admin.copy-test.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.100"},
		},
	}

	err = sourceStore.CreateZone(ctx, testZone)
	require.NoError(t, err)

	// Copy zones (use new from-* and to-* flags for dry-run test)
	migrateFromBackend = "git"
	migrateToBackend = "git"
	migrateFromPath = sourceRepo
	migrateToPath = "" // Not needed for dry-run
	migrateFromDSN = ""
	migrateToDSN = ""
	migrateDryRun = true

	err = runCopy(nil, nil)
	require.NoError(t, err)
}

// TestMigrationE2E_DryRun tests dry-run mode doesn't modify anything.
func TestMigrationE2E_DryRun(t *testing.T) {
	// Create Git repository with test zone
	repoPath := t.TempDir()

	store, err := backend.NewBackend("git", map[string]interface{}{
		"repository_path": repoPath,
		"branch":          "main",
		"author_name":     "Test User",
		"author_email":    "test@example.com",
		"auto_sync":       false,
	})
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	testZone := &model.Zone{
		Name: "dryrun.example.com.",
		SOA:  model.DefaultSOA("ns1.dryrun.example.com.", "admin.dryrun.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.50"},
		},
	}

	err = store.CreateZone(ctx, testZone)
	require.NoError(t, err)

	// Test export dry-run
	exportDir := t.TempDir()

	migrateBackendType = "git"
	migrateBackendPath = repoPath
	migrateOutputDir = exportDir
	migrateDryRun = true

	err = runExport(nil, nil)
	require.NoError(t, err)

	// Verify no files were created
	files, err := filepath.Glob(filepath.Join(exportDir, "*.json"))
	require.NoError(t, err)
	assert.Empty(t, files, "Dry-run should not create files")
}
