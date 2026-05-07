package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrateExportMemory tests exporting zones from memory backend to JSON files.
func TestMigrateExportMemory(t *testing.T) {
	// Create test zones in memory backend
	store := backend.NewMemoryBackend()
	defer store.Close()

	ctx := context.Background()

	testZones := []*model.Zone{
		{
			Name: "example.com.",
			SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
			Records: []model.Record{
				{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"},
			},
		},
		{
			Name: "test.org.",
			SOA:  model.DefaultSOA("ns1.test.org.", "admin.test.org."),
			Records: []model.Record{
				{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.2"},
			},
		},
	}

	for _, zone := range testZones {
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// Create temporary output directory
	tmpDir := t.TempDir()

	// Run export directly against the prepared store
	_, err := exportFromStore(ctx, store, tmpDir, false)
	require.NoError(t, err)

	// Verify exported files
	for _, zone := range testZones {
		filename := filepath.Join(tmpDir, sanitizeFilename(zone.Name)+".json")
		require.FileExists(t, filename)

		// Verify file content
		data, err := os.ReadFile(filename)
		require.NoError(t, err)

		var exported model.Zone
		err = json.Unmarshal(data, &exported)
		require.NoError(t, err)

		assert.Equal(t, zone.Name, exported.Name)
		assert.NotEmpty(t, exported.Version)
	}
}

// TestMigrateImport tests importing zones from JSON files to memory backend.
func TestMigrateImport(t *testing.T) {
	// Create temporary input directory with test zone files
	tmpDir := t.TempDir()

	testZone := &model.Zone{
		Name:    "import.example.com.",
		Version: "v2024010101-abc12345", // Old version
		SOA:     model.DefaultSOA("ns1.import.example.com.", "admin.import.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.10"},
		},
	}

	// Write zone to JSON file
	data, err := json.MarshalIndent(testZone, "", "  ")
	require.NoError(t, err)

	filename := filepath.Join(tmpDir, "import_example_com.json")
	err = os.WriteFile(filename, data, 0644)
	require.NoError(t, err)

	store := backend.NewMemoryBackend()
	defer store.Close()

	// Run import directly against the target store
	_, err = importToStore(context.Background(), store, tmpDir, false, false)
	require.NoError(t, err)

	// Verify zone was imported with new version
	ctx := context.Background()
	imported, err := store.GetZone(ctx, testZone.Name)
	require.NoError(t, err)

	assert.Equal(t, testZone.Name, imported.Name)
	assert.NotEqual(t, testZone.Version, imported.Version, "Version should be recomputed")
	assert.NotEmpty(t, imported.Version)
}

func TestMigrateImport_RejectsInvalidZone(t *testing.T) {
	tmpDir := t.TempDir()

	invalidZone := &model.Zone{
		Name: "invalid.example.com.",
		SOA:  model.DefaultSOA("ns1.invalid.example.com.", "admin.invalid.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "not-an-ip"},
		},
	}

	data, err := json.MarshalIndent(invalidZone, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid_example_com.json"), data, 0644))

	store := backend.NewMemoryBackend()
	defer store.Close()

	_, err = importToStore(context.Background(), store, tmpDir, false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate file")
	assert.Contains(t, err.Error(), "invalid record")
}

// TestMigrateCopy tests copying zones between backends.
func TestMigrateCopy(t *testing.T) {
	// Create source backend with test zones
	sourceStore := backend.NewMemoryBackend()
	defer sourceStore.Close()

	ctx := context.Background()

	testZones := []*model.Zone{
		{
			Name: "source1.com.",
			SOA:  model.DefaultSOA("ns1.source1.com.", "admin.source1.com."),
			Records: []model.Record{
				{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.20"},
			},
		},
		{
			Name: "source2.com.",
			SOA:  model.DefaultSOA("ns1.source2.com.", "admin.source2.com."),
			Records: []model.Record{
				{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.21"},
			},
		},
	}

	for _, zone := range testZones {
		err := sourceStore.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// Create destination backend
	destStore := backend.NewMemoryBackend()
	defer destStore.Close()

	// Copy zones (simple in-test loop; CLI path is covered separately)
	zones, err := sourceStore.ListZones(ctx, backend.ListOptions{})
	require.NoError(t, err)
	for _, zone := range zones {
		err := destStore.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// Verify zones exist in destination
	_, err = destStore.GetZone(ctx, "source1.com.")
	require.NoError(t, err)
	_, err = destStore.GetZone(ctx, "source2.com.")
	require.NoError(t, err)
}

func TestCreateBackendDefaultsToSQLite(t *testing.T) {
	oldDSN := migrateBackendDSN
	t.Cleanup(func() {
		migrateBackendDSN = oldDSN
	})
	migrateBackendDSN = ":memory:"

	store, err := createBackend("", nil)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	err = store.CreateZone(ctx, &model.Zone{
		Name: "sqlite-default.example.com.",
		SOA:  model.DefaultSOA("ns1.sqlite-default.example.com.", "admin.sqlite-default.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.30"},
		},
	})
	require.NoError(t, err)

	_, err = store.GetZone(ctx, "sqlite-default.example.com.")
	require.NoError(t, err)
}

func TestCreateBackendForCopySupportsSQLite(t *testing.T) {
	store, err := createBackendForCopy("sqlite", ":memory:", "", nil)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	err = store.CreateZone(ctx, &model.Zone{
		Name: "sqlite-copy.example.com.",
		SOA:  model.DefaultSOA("ns1.sqlite-copy.example.com.", "admin.sqlite-copy.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.31"},
		},
	})
	require.NoError(t, err)
}

func TestCreateBackendPostgresRequiresDSN(t *testing.T) {
	oldDSN := migrateBackendDSN
	t.Cleanup(func() {
		migrateBackendDSN = oldDSN
	})
	migrateBackendDSN = ""

	cfg := config.DefaultControllerConfig()
	cfg.Backend.Type = "postgres"
	cfg.Backend.Postgres.DSN = ""

	_, err := createBackend("postgres", cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PostgreSQL backend requires --dsn")
}

func TestCreateBackendRejectsMemory(t *testing.T) {
	_, err := createBackend("memory", config.DefaultControllerConfig())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supported: sqlite, postgres, mysql, git, etcd")
}

// TestMigrateRoundTrip tests export → import round-trip.
func TestMigrateRoundTrip(t *testing.T) {
	// Create source backend with test zone
	sourceStore := backend.NewMemoryBackend()
	defer sourceStore.Close()

	ctx := context.Background()

	originalZone := &model.Zone{
		Name: "roundtrip.example.com.",
		SOA:  model.DefaultSOA("ns1.roundtrip.example.com.", "admin.roundtrip.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.100"},
			{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.101"},
			{Name: "@", Type: "MX", TTL: 300, Value: "10 mail.roundtrip.example.com."},
		},
	}

	err := sourceStore.CreateZone(ctx, originalZone)
	require.NoError(t, err)

	// Get the zone with its computed version
	stored, err := sourceStore.GetZone(ctx, originalZone.Name)
	require.NoError(t, err)

	// Create temporary directory for export/import
	tmpDir := t.TempDir()

	// Export directly from source store
	_, err = exportFromStore(ctx, sourceStore, tmpDir, false)
	require.NoError(t, err)

	// Import to new backend
	destStore := backend.NewMemoryBackend()
	defer destStore.Close()

	_, err = importToStore(ctx, destStore, tmpDir, false, false)
	require.NoError(t, err)

	// Verify round-trip
	imported, err := destStore.GetZone(ctx, originalZone.Name)
	require.NoError(t, err)

	// Zone data should match
	assert.Equal(t, stored.Name, imported.Name)
	assert.Equal(t, stored.SOA.MName, imported.SOA.MName)
	assert.Equal(t, stored.SOA.RName, imported.SOA.RName)
	assert.Equal(t, len(stored.Records), len(imported.Records))

	// Version should be regenerated on import.
	assert.NotEmpty(t, imported.Version)
	assert.NotEqual(t, stored.Version, imported.Version)
}

// TestMigrateGitBackend tests export/import with Git backend.
func TestMigrateGitBackend(t *testing.T) {
	// Create Git repository in temp directory
	repoPath := t.TempDir()

	// Create Git backend
	gitStore, err := backend.NewBackend("git", map[string]interface{}{
		"repository_path": repoPath,
		"branch":          "main",
		"author_name":     "Test User",
		"author_email":    "test@example.com",
		"auto_sync":       false,
	})
	require.NoError(t, err)
	defer gitStore.Close()

	ctx := context.Background()

	// Create test zone
	testZone := &model.Zone{
		Name: "git-test.example.com.",
		SOA:  model.DefaultSOA("ns1.git-test.example.com.", "admin.git-test.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.200"},
		},
	}

	err = gitStore.CreateZone(ctx, testZone)
	require.NoError(t, err)

	// Export from Git backend
	tmpDir := t.TempDir()

	_, err = exportFromStore(ctx, gitStore, tmpDir, false)
	require.NoError(t, err)

	// Verify exported file
	filename := filepath.Join(tmpDir, sanitizeFilename(testZone.Name)+".json")
	require.FileExists(t, filename)

	// Verify file content
	data, err := os.ReadFile(filename)
	require.NoError(t, err)

	var exported model.Zone
	err = json.Unmarshal(data, &exported)
	require.NoError(t, err)

	assert.Equal(t, testZone.Name, exported.Name)
	assert.NotEmpty(t, exported.Version)
}

// TestMigrateDryRun tests dry-run mode for all commands.
func TestMigrateDryRun(t *testing.T) {
	// Create test backend
	store := backend.NewMemoryBackend()
	defer store.Close()

	ctx := context.Background()

	testZone := &model.Zone{
		Name: "dryrun.example.com.",
		SOA:  model.DefaultSOA("ns1.dryrun.example.com.", "admin.dryrun.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.50"},
		},
	}

	err := store.CreateZone(ctx, testZone)
	require.NoError(t, err)

	// Test export dry-run
	tmpDir := t.TempDir()
	_, err = exportFromStore(ctx, store, tmpDir, true)
	require.NoError(t, err)

	// Verify no files were created
	files, err := filepath.Glob(filepath.Join(tmpDir, "*.json"))
	require.NoError(t, err)
	assert.Empty(t, files, "Dry-run should not create files")

	// Test import dry-run
	// First create a test file
	_, err = exportFromStore(ctx, store, tmpDir, false)
	require.NoError(t, err)

	// Import dry-run should not fail
	importStore := backend.NewMemoryBackend()
	defer importStore.Close()
	_, err = importToStore(ctx, importStore, tmpDir, true, false)
	require.NoError(t, err)
}

// TestSanitizeFilename tests the filename sanitization function.
func TestSanitizeFilename(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.com.", "example_com"},
		{"test.org.", "test_org"},
		{"sub.domain.example.com.", "sub_domain_example_com"},
		{"example.com", "example_com"},
		{"single", "single"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitizeFilename(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
