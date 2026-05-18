package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupGitBackend(t *testing.T) (*GitBackend, func()) {
	// Create temporary directory for test repository
	tempDir := t.TempDir()

	backend, err := NewGitBackend(
		tempDir,
		"main",
		"test-author",
		"test@example.com",
		false, // autoSync disabled for tests
	)
	require.NoError(t, err, "Failed to create GitBackend")

	cleanup := func() {
		backend.Close()
	}

	return backend, cleanup
}

func testGitZone(name string) *model.Zone {
	return &model.Zone{
		Name: name,
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords(name),
	}
}

func gitHeadHash(t *testing.T, backend *GitBackend) plumbing.Hash {
	t.Helper()

	head, err := backend.repo.Head()
	require.NoError(t, err)
	return head.Hash()
}

func gitZonePath(t *testing.T, backend *GitBackend, zoneName string) string {
	t.Helper()

	relPath, err := backend.zoneFilePath(zoneName)
	require.NoError(t, err)
	return filepath.Join(backend.repoPath, relPath)
}

func gitLegacyZonePath(t *testing.T, backend *GitBackend, zoneName string) string {
	t.Helper()

	relPath, err := backend.legacyZoneFilePath(zoneName)
	require.NoError(t, err)
	return filepath.Join(backend.repoPath, relPath)
}

func TestGitBackend_FreshRepoUsesConfiguredBranch(t *testing.T) {
	repoPath := filepath.Join(t.TempDir(), "repo")

	backend, err := NewGitBackendWithOptions(repoPath, GitBackendOptions{
		Branch:      "main",
		AuthorName:  "test-author",
		AuthorEmail: "test@example.com",
	})
	require.NoError(t, err)
	defer backend.Close()

	head, err := backend.repo.Storer.Reference(plumbing.HEAD)
	require.NoError(t, err)
	assert.Equal(t, plumbing.NewBranchReferenceName("main"), head.Target())

	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	require.NoError(t, backend.CreateZone(context.Background(), zone))

	_, err = backend.repo.Reference(plumbing.NewBranchReferenceName("main"), true)
	require.NoError(t, err)
	_, err = backend.repo.Reference(plumbing.NewBranchReferenceName("master"), true)
	assert.ErrorIs(t, err, plumbing.ErrReferenceNotFound)
}

func TestNewGitBackendRejectsSymlinkedZonesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "repo")
	targetDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.MkdirAll(repoPath, 0755))
	require.NoError(t, os.Mkdir(targetDir, 0755))
	if err := os.Symlink(targetDir, filepath.Join(repoPath, "zones")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	backend, err := NewGitBackendWithOptions(repoPath, GitBackendOptions{
		Branch:      "main",
		AuthorName:  "test-author",
		AuthorEmail: "test@example.com",
	})
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "zones directory")
	assert.Contains(t, err.Error(), "symlink")
}

func runGitCommand(t *testing.T, dir string, args ...string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git command not available")
	}

	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v failed:\n%s", args, string(output))
}

func TestGitBackend_CreateZone(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com.",
			model.Record{
				Name:  "example.com.",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
		),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Verify zone was created
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name)
	assert.Equal(t, uint32(2024010101), retrieved.SOA.Serial)
	assert.Len(t, retrieved.Records, 2)
	assert.NotEmpty(t, retrieved.Version)

	// Verify zone file exists
	zonePath := gitZonePath(t, backend, "example.com.")
	assert.Equal(t, filepath.Join(backend.repoPath, "zones", "example.com.json"), zonePath)
	_, err = os.Stat(zonePath)
	assert.NoError(t, err, "Zone file should exist")
}

func TestGitBackend_WriteZoneRejectsNonRegularZonePath(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zone := testGitZone("example.com.")
	zonePath := gitZonePath(t, backend, zone.Name)
	require.NoError(t, os.MkdirAll(zonePath, 0755))

	err := backend.writeZone(zone.Name, zone)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regular file")

	_, statErr := os.Stat(zonePath + ".tmp")
	assert.True(t, os.IsNotExist(statErr), "temporary zone file should not be created for non-regular target")
	matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(zonePath), "."+filepath.Base(zonePath)+".*.tmp"))
	require.NoError(t, globErr)
	assert.Empty(t, matches, "temporary zone files should not be created for non-regular target")
}

func TestGitBackend_WriteZoneRejectsSymlinkedZonesDirectory(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zone := testGitZone("example.com.")
	zonesDir := filepath.Join(backend.repoPath, "zones")
	targetDir := filepath.Join(backend.repoPath, "target-zones")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	require.NoError(t, os.RemoveAll(zonesDir))
	if err := os.Symlink(targetDir, zonesDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	err := backend.writeZone(zone.Name, zone)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zones directory")
	assert.Contains(t, err.Error(), "symlink")
	_, statErr := os.Stat(filepath.Join(targetDir, "example.com.json"))
	assert.True(t, os.IsNotExist(statErr), "zone file should not be written through symlink")
}

func TestGitBackend_WriteZoneDoesNotFollowPredictableTempSymlink(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zone := testGitZone("example.com.")
	zonePath := gitZonePath(t, backend, zone.Name)
	sentinelPath := filepath.Join(filepath.Dir(zonePath), "sentinel")
	sentinel := []byte("keep")
	require.NoError(t, os.WriteFile(sentinelPath, sentinel, 0600))
	if err := os.Symlink(sentinelPath, zonePath+".tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	err := backend.writeZone(zone.Name, zone)
	require.NoError(t, err)

	got, err := os.ReadFile(sentinelPath)
	require.NoError(t, err)
	assert.Equal(t, sentinel, got)

	linkInfo, err := os.Lstat(zonePath + ".tmp")
	require.NoError(t, err)
	assert.NotZero(t, linkInfo.Mode()&os.ModeSymlink, "predictable temp path should remain a symlink")

	written, err := os.ReadFile(zonePath)
	require.NoError(t, err)
	assert.Contains(t, string(written), `"name": "example.com."`)
}

func TestGitBackend_RestoreZoneFileDoesNotFollowSymlink(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	relPath, err := backend.zoneFilePath("example.com.")
	require.NoError(t, err)
	zonePath := filepath.Join(backend.repoPath, relPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(zonePath), 0755))

	sentinelPath := filepath.Join(backend.repoPath, "sentinel")
	sentinel := []byte("keep")
	require.NoError(t, os.WriteFile(sentinelPath, sentinel, 0600))
	if err := os.Symlink(sentinelPath, zonePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	restored := []byte(`{"name":"example.com."}`)
	point := &gitRollbackPoint{
		files: []gitRollbackFile{
			{
				relPath:    relPath,
				absPath:    zonePath,
				fileExists: true,
				fileMode:   0600,
				fileData:   restored,
			},
		},
	}

	require.NoError(t, backend.restoreZoneFile(point))

	got, err := os.ReadFile(sentinelPath)
	require.NoError(t, err)
	assert.Equal(t, sentinel, got)

	info, err := os.Lstat(zonePath)
	require.NoError(t, err)
	assert.Zero(t, info.Mode()&os.ModeSymlink, "restored zone path should not remain a symlink")
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	written, err := os.ReadFile(zonePath)
	require.NoError(t, err)
	assert.Equal(t, restored, written)
}

func TestGitBackend_ReadZoneRejectsSymlink(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zone := testGitZone("example.com.")
	relPath, err := backend.zoneFilePath(zone.Name)
	require.NoError(t, err)
	zonePath := filepath.Join(backend.repoPath, relPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(zonePath), 0755))

	outsidePath := filepath.Join(backend.repoPath, "outside-zone.json")
	outsideData, err := json.Marshal(zone)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(outsidePath, outsideData, 0600))
	if err := os.Symlink(outsidePath, zonePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err = backend.GetZone(context.Background(), zone.Name)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")
}

func TestGitBackend_ReadZoneRejectsSymlinkedZonesDirectory(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zone := testGitZone("example.com.")
	zonesDir := filepath.Join(backend.repoPath, "zones")
	targetDir := filepath.Join(backend.repoPath, "target-zones")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	data, err := json.Marshal(zone)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "example.com.json"), data, 0600))
	require.NoError(t, os.RemoveAll(zonesDir))
	if err := os.Symlink(targetDir, zonesDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err = backend.GetZone(context.Background(), zone.Name)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zones directory")
	assert.Contains(t, err.Error(), "symlink")
}

func TestGitBackend_ListZonesRejectsSymlinkedZonesDirectory(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zonesDir := filepath.Join(backend.repoPath, "zones")
	targetDir := filepath.Join(backend.repoPath, "target-zones")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "example.com.json"), []byte(`{"name":"example.com."}`), 0600))
	require.NoError(t, os.RemoveAll(zonesDir))
	if err := os.Symlink(targetDir, zonesDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err := backend.ListZones(context.Background(), ListOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zones directory")
	assert.Contains(t, err.Error(), "symlink")
}

func TestGitBackend_DeleteZoneRejectsSymlinkedZonesDirectory(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zone := testGitZone("example.com.")
	zonesDir := filepath.Join(backend.repoPath, "zones")
	targetDir := filepath.Join(backend.repoPath, "target-zones")
	targetPath := filepath.Join(targetDir, "example.com.json")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	data, err := json.Marshal(zone)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(targetPath, data, 0600))
	require.NoError(t, os.RemoveAll(zonesDir))
	if err := os.Symlink(targetDir, zonesDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	err = backend.DeleteZone(context.Background(), zone.Name)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zones directory")
	assert.Contains(t, err.Error(), "symlink")
	require.FileExists(t, targetPath)
}

func TestGitBackend_CreateZone_UsesSafeFilenameForLongZoneName(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	longZone := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 60),
	}, ".") + "."
	require.Len(t, longZone, 253)

	zone := &model.Zone{
		Name: longZone,
		SOA: model.SOARecord{
			MName:   "ns1.example.net.",
			RName:   "admin.example.net.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{
			{Name: "@", Type: model.RecordTypeNS, TTL: 300, Value: "ns1.example.net."},
		},
	}

	require.NoError(t, backend.CreateZone(ctx, zone))

	relPath, err := backend.zoneFilePath(longZone)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(filepath.Base(relPath)), 205)
	assert.FileExists(t, filepath.Join(backend.repoPath, relPath))

	retrieved, err := backend.GetZone(ctx, longZone)
	require.NoError(t, err)
	assert.Equal(t, longZone, retrieved.Name)
}

func TestGitBackend_ReadsAndUpdatesLegacyZoneFilename(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	zone := testGitZone("legacy.example.com.")
	data, err := json.Marshal(zone)
	require.NoError(t, err)

	legacyPath := gitLegacyZonePath(t, backend, zone.Name)
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyPath), 0755))
	require.NoError(t, os.WriteFile(legacyPath, data, 0644))

	retrieved, err := backend.GetZone(ctx, zone.Name)
	require.NoError(t, err)
	assert.Equal(t, zone.Name, retrieved.Name)

	retrieved.Records = testZoneRecords(zone.Name,
		model.Record{Name: "www.legacy.example.com.", Type: "A", TTL: 300, Value: "192.0.2.10"},
	)
	require.NoError(t, backend.UpdateZone(ctx, retrieved, ""))

	assert.FileExists(t, legacyPath)
	assert.NoFileExists(t, gitZonePath(t, backend, zone.Name))
}

func TestGitBackend_DeleteZone_RemovesSafeAndLegacyZoneFiles(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	zone := testGitZone("example.com.")
	require.NoError(t, backend.CreateZone(ctx, zone))

	data, err := json.Marshal(zone)
	require.NoError(t, err)
	legacyPath := gitLegacyZonePath(t, backend, zone.Name)
	require.NoError(t, os.WriteFile(legacyPath, data, 0644))

	require.NoError(t, backend.DeleteZone(ctx, zone.Name))

	_, err = backend.GetZone(ctx, zone.Name)
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
	assert.NoFileExists(t, gitZonePath(t, backend, zone.Name))
	assert.NoFileExists(t, legacyPath)
}

func TestGitBackend_DeleteZone_RemovesUntrackedZoneFile(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	zone := testGitZone("untracked.example.com.")
	data, err := json.Marshal(zone)
	require.NoError(t, err)

	zonePath := gitZonePath(t, backend, zone.Name)
	require.NoError(t, os.MkdirAll(filepath.Dir(zonePath), 0755))
	require.NoError(t, os.WriteFile(zonePath, data, 0644))

	retrieved, err := backend.GetZone(ctx, zone.Name)
	require.NoError(t, err)
	assert.Equal(t, zone.Name, retrieved.Name)

	require.NoError(t, backend.DeleteZone(ctx, zone.Name))

	_, err = backend.GetZone(ctx, zone.Name)
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
	assert.NoFileExists(t, zonePath)
}

func TestGitBackend_CreateZone_AlreadyExists(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	// Create zone
	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Try to create again
	err = backend.CreateZone(ctx, zone)
	assert.ErrorIs(t, err, model.ErrZoneAlreadyExists)
}

func TestGitBackend_GetZone_NotFound(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	_, err := backend.GetZone(ctx, "nonexistent.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestGitBackend_UpdateZone(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create initial zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com.",
			model.Record{
				Name:  "example.com.",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
		),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get current version
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	originalVersion := retrieved.Version

	// Update zone
	time.Sleep(100 * time.Millisecond) // Ensure timestamp difference
	zone.Records = append(zone.Records, model.Record{
		Name:  "www.example.com.",
		Type:  "A",
		TTL:   300,
		Value: "192.0.2.2",
	})

	err = backend.UpdateZone(ctx, zone, originalVersion)
	require.NoError(t, err)

	// Verify update
	updated, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Len(t, updated.Records, 3)
	assert.NotEqual(t, originalVersion, updated.Version, "Version should change")
}

func TestGitBackend_UpdateZone_Conflict(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Try to update with wrong version
	err = backend.UpdateZone(ctx, zone, "wrong-version")
	assert.ErrorIs(t, err, model.ErrConflict)
}

func TestGitBackend_DeleteZone(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Delete zone
	err = backend.DeleteZone(ctx, "example.com.")
	require.NoError(t, err)

	// Verify deletion
	_, err = backend.GetZone(ctx, "example.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)

	// Verify file was removed
	zonePath := gitZonePath(t, backend, "example.com.")
	_, err = os.Stat(zonePath)
	assert.True(t, os.IsNotExist(err), "Zone file should not exist")
}

func TestGitBackend_CreateZone_RetainsLocalCommitWhenAutoPushFails(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	backend.autoPush = true

	err := backend.CreateZone(ctx, testGitZone("example.com."))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git push failed")
	assert.Contains(t, err.Error(), "local commit was retained")

	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name)
	assert.FileExists(t, gitZonePath(t, backend, "example.com."))

	_, err = backend.repo.Head()
	assert.NoError(t, err)
}

func TestGitBackend_UpdateZone_RetainsLocalCommitWhenAutoPushFails(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	require.NoError(t, backend.CreateZone(ctx, testGitZone("example.com.")))

	created, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	headBefore := gitHeadHash(t, backend)

	updated := *created
	updated.Records = testZoneRecords("example.com.",
		model.Record{Name: "www.example.com.", Type: "A", TTL: 300, Value: "192.0.2.10"},
	)

	backend.autoPush = true
	err = backend.UpdateZone(ctx, &updated, created.Version)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git push failed")
	assert.Contains(t, err.Error(), "local commit was retained")
	assert.NotEqual(t, headBefore, gitHeadHash(t, backend))

	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotEqual(t, created.Version, retrieved.Version)
	assert.Equal(t, updated.Records, retrieved.Records)
}

func TestGitBackend_DeleteZone_RetainsLocalCommitWhenAutoPushFails(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	require.NoError(t, backend.CreateZone(ctx, testGitZone("example.com.")))
	headBefore := gitHeadHash(t, backend)

	backend.autoPush = true
	err := backend.DeleteZone(ctx, "example.com.")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git push failed")
	assert.Contains(t, err.Error(), "local commit was retained")
	assert.NotEqual(t, headBefore, gitHeadHash(t, backend))

	_, err = backend.GetZone(ctx, "example.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
	assert.NoFileExists(t, gitZonePath(t, backend, "example.com."))
}

func TestGitBackend_AutoPullUsesConfiguredBranch(t *testing.T) {
	remotePath := t.TempDir()
	runGitCommand(t, "", "init", remotePath)
	runGitCommand(t, remotePath, "checkout", "-b", "main")
	runGitCommand(t, remotePath, "config", "user.name", "Test User")
	runGitCommand(t, remotePath, "config", "user.email", "test@example.com")

	require.NoError(t, os.WriteFile(filepath.Join(remotePath, "README.md"), []byte("main\n"), 0644))
	runGitCommand(t, remotePath, "add", "README.md")
	runGitCommand(t, remotePath, "commit", "-m", "init main")

	runGitCommand(t, remotePath, "checkout", "-b", "zones")
	zonesDir := filepath.Join(remotePath, "zones")
	require.NoError(t, os.MkdirAll(zonesDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(zonesDir, "initial.example.com..json"), []byte(`{"name":"initial.example.com."}`), 0644))
	runGitCommand(t, remotePath, "add", "zones/initial.example.com..json")
	runGitCommand(t, remotePath, "commit", "-m", "add initial zone")
	runGitCommand(t, remotePath, "checkout", "main")

	localPath := filepath.Join(t.TempDir(), "local")
	runGitCommand(t, "", "clone", remotePath, localPath)
	runGitCommand(t, localPath, "checkout", "zones")

	runGitCommand(t, remotePath, "checkout", "zones")
	require.NoError(t, os.WriteFile(filepath.Join(zonesDir, "pulled.example.com..json"), []byte(`{"name":"pulled.example.com."}`), 0644))
	runGitCommand(t, remotePath, "add", "zones/pulled.example.com..json")
	runGitCommand(t, remotePath, "commit", "-m", "add pulled zone")
	runGitCommand(t, remotePath, "checkout", "main")

	backend, err := NewGitBackendWithOptions(localPath, GitBackendOptions{
		Branch:    "zones",
		RemoteURL: remotePath,
		AutoPull:  true,
	})
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	pulled, err := backend.GetZone(ctx, "pulled.example.com.")
	require.NoError(t, err)
	assert.Equal(t, "pulled.example.com.", pulled.Name)
	assert.FileExists(t, filepath.Join(localPath, "zones", "pulled.example.com..json"))

	runGitCommand(t, remotePath, "checkout", "zones")
	require.NoError(t, os.WriteFile(filepath.Join(zonesDir, "listed.example.com..json"), []byte(`{"name":"listed.example.com."}`), 0644))
	runGitCommand(t, remotePath, "add", "zones/listed.example.com..json")
	runGitCommand(t, remotePath, "commit", "-m", "add listed zone")
	runGitCommand(t, remotePath, "checkout", "main")

	zones, err := backend.ListZones(ctx, ListOptions{})
	require.NoError(t, err)
	assert.Contains(t, zoneNames(zones), "listed.example.com.")
}

func TestGitBackend_RepositoryLockSerializesWithinProcess(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	require.NoError(t, backend.acquireFileLock(context.Background()))
	lockHeld := true
	defer func() {
		if lockHeld {
			backend.releaseFileLock()
		}
	}()

	acquired := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		err := backend.acquireFileLock(context.Background())
		if err == nil {
			close(acquired)
			backend.releaseFileLock()
		}
		done <- err
	}()

	select {
	case <-acquired:
		t.Fatal("second repository lock acquired while first lock was still held")
	case <-time.After(100 * time.Millisecond):
	}

	backend.releaseFileLock()
	lockHeld = false

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("second repository lock did not acquire after first lock was released")
	}
}

func TestGitBackend_RepositoryLockHonorsContextCancellation(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	require.NoError(t, backend.acquireFileLock(context.Background()))
	defer backend.releaseFileLock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- backend.acquireFileLock(ctx)
	}()

	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("repository lock wait did not return after context cancellation")
	}
}

func zoneNames(zones []*model.Zone) []string {
	names := make([]string, 0, len(zones))
	for _, zone := range zones {
		names = append(names, zone.Name)
	}
	return names
}

func TestGitBackend_ListZones(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create multiple zones
	zones := []string{"aaa.com.", "bbb.com.", "ccc.com."}
	for _, name := range zones {
		zone := &model.Zone{
			Name: name,
			SOA: model.SOARecord{
				MName:   "ns1." + name,
				RName:   "admin." + name,
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
			},
			Records: testZoneRecords(name),
		}
		err := backend.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// List all zones
	result, err := backend.ListZones(ctx, ListOptions{Limit: 100})
	require.NoError(t, err)
	assert.Len(t, result, 3)

	// Verify ordering (should be alphabetical)
	assert.Equal(t, "aaa.com.", result[0].Name)
	assert.Equal(t, "bbb.com.", result[1].Name)
	assert.Equal(t, "ccc.com.", result[2].Name)

	// Negative offsets are normalized to zero.
	negativeOffset, err := backend.ListZones(ctx, ListOptions{Offset: -1, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, negativeOffset, 2)
	assert.Equal(t, "aaa.com.", negativeOffset[0].Name)

	// Test pagination
	page1, err := backend.ListZones(ctx, ListOptions{Offset: 0, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page1, 2)
	assert.Equal(t, "aaa.com.", page1[0].Name)

	page2, err := backend.ListZones(ctx, ListOptions{Offset: 2, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page2, 1)
	assert.Equal(t, "ccc.com.", page2[0].Name)
}

func TestGitBackend_ListZones_Empty(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	result, err := backend.ListZones(ctx, ListOptions{Limit: 100})
	require.NoError(t, err)
	assert.NotNil(t, result, "Should return empty slice, not nil")
	assert.Len(t, result, 0)
}

func TestGitBackend_ListZones_ReturnsErrorForMalformedZoneFile(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	zonesDir := filepath.Join(backend.repoPath, "zones")
	require.NoError(t, os.MkdirAll(zonesDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(zonesDir, "bad.example.com..json"), []byte("{"), 0644))

	zones, err := backend.ListZones(context.Background(), ListOptions{})
	require.Error(t, err)
	assert.Nil(t, zones)
	assert.Contains(t, err.Error(), "bad.example.com.")
}

func TestGitBackend_GetRevision(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com.",
			model.Record{
				Name:  "example.com.",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
		),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get version
	created, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	version1 := created.Version

	// Update zone
	time.Sleep(100 * time.Millisecond)
	zone.Records = append(zone.Records, model.Record{
		Name:  "www.example.com.",
		Type:  "A",
		TTL:   300,
		Value: "192.0.2.2",
	})
	err = backend.UpdateZone(ctx, zone, version1)
	require.NoError(t, err)

	// Retrieve old version
	oldVersion, err := backend.GetRevision(ctx, "example.com.", version1)
	require.NoError(t, err)
	assert.Equal(t, version1, oldVersion.Version)
	assert.Len(t, oldVersion.Records, 2, "Old version should have 2 records")
}

func TestGitBackend_ListRevisions(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Update zone multiple times
	for i := 0; i < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		retrieved, err := backend.GetZone(ctx, "example.com.")
		require.NoError(t, err)

		zone.Records = append(zone.Records, model.Record{
			Name:  "example.com.",
			Type:  "TXT",
			TTL:   300,
			Value: "update-" + string(rune('0'+i)),
		})

		err = backend.UpdateZone(ctx, zone, retrieved.Version)
		require.NoError(t, err)
	}

	// List revisions
	revisions, err := backend.ListRevisions(ctx, "example.com.", ListOptions{Limit: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(revisions), 4, "Should have at least 4 revisions (1 create + 3 updates)")

	// Verify revisions have versions
	for _, rev := range revisions {
		assert.NotEmpty(t, rev.Version)
		assert.NotZero(t, rev.Timestamp)
		assert.NotZero(t, rev.Serial)
	}
}

func TestGitBackend_UpdateDNSSECMetadataDoesNotAddRevision(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	require.NoError(t, backend.CreateZone(ctx, zone))
	created, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)

	require.NoError(t, backend.UpdateDNSSECMetadata(ctx, "example.com.", &model.DNSSECConfig{
		Enabled:      true,
		Algorithm:    13,
		KSKKeyTag:    12345,
		ZSKKeyTag:    23456,
		NSEC3Enabled: true,
		NSEC3Salt:    "ABCD",
	}))

	revisions, err := backend.ListRevisions(ctx, "example.com.", ListOptions{Limit: 100})
	require.NoError(t, err)
	require.Len(t, revisions, 1)
	assert.Equal(t, created.Version, revisions[0].Version)

	updated, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	require.NotNil(t, updated.DNSSEC)
	assert.Equal(t, created.Version, updated.Version)
	assert.True(t, updated.DNSSEC.Enabled)
}

func TestGitBackend_GetCurrentVersion(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get current version
	version, err := backend.GetCurrentVersion(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotEmpty(t, version)

	// Verify it matches GetZone
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, retrieved.Version, version)
}

func TestGitBackend_ConcurrentWrites(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create initial zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get version
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	version := retrieved.Version

	// Concurrent update attempts
	errChan := make(chan error, 2)

	// First update should succeed
	go func() {
		zone1 := *zone
		zone1.Records = testZoneRecords("example.com.",
			model.Record{Name: "test1.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		)
		errChan <- backend.UpdateZone(ctx, &zone1, version)
	}()

	// Second update should fail with conflict (same expectedVersion)
	go func() {
		time.Sleep(50 * time.Millisecond) // Slight delay to ensure first update starts
		zone2 := *zone
		zone2.Records = testZoneRecords("example.com.",
			model.Record{Name: "test2.example.com.", Type: "A", TTL: 300, Value: "192.0.2.2"},
		)
		errChan <- backend.UpdateZone(ctx, &zone2, version)
	}()

	// Collect results
	err1 := <-errChan
	err2 := <-errChan

	// One should succeed, one should fail
	if err1 == nil {
		assert.ErrorIs(t, err2, model.ErrConflict, "Second update should fail with conflict")
	} else {
		assert.ErrorIs(t, err1, model.ErrConflict, "One update should fail with conflict")
		assert.NoError(t, err2, "Other update should succeed")
	}
}

func TestGitBackend_ZoneNameNormalization(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone with uppercase name
	zone := &model.Zone{
		Name: "Example.COM.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("Example.COM."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Retrieve with lowercase
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name, "Name should be normalized to lowercase")

	// Retrieve with uppercase (should still work)
	retrieved2, err := backend.GetZone(ctx, "EXAMPLE.COM.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved2.Name)
}

// TestGitBackend_ListZones_LimitZero tests that Limit==0 returns all zones
func TestGitBackend_ListZones_LimitZero(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create 5 zones
	for i := 0; i < 5; i++ {
		zone := &model.Zone{
			Name: fmt.Sprintf("zone%d.com.", i),
			SOA: model.SOARecord{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
			},
			Records: testZoneRecords("example.com."),
		}
		err := backend.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// List with Limit==0 (should return all)
	zones, err := backend.ListZones(ctx, ListOptions{Offset: 0, Limit: 0})
	require.NoError(t, err)
	assert.Len(t, zones, 5, "Limit==0 should return all zones")
}

// TestGitBackend_SerialAutoGeneration tests SOA serial auto-generation when serial==0
func TestGitBackend_SerialAutoGeneration(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone with serial=0
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  0, // Should be auto-generated
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Retrieve and verify serial was generated
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotZero(t, retrieved.SOA.Serial, "Serial should be auto-generated")
	assert.Greater(t, retrieved.SOA.Serial, uint32(2024000000), "Serial should be in YYYYMMDDnn format")
}

// TestGitBackend_TimestampHandling tests CreatedAt preservation and UpdatedAt changes
func TestGitBackend_TimestampHandling(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get created zone
	created, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotZero(t, created.CreatedAt, "CreatedAt should be set")
	assert.NotZero(t, created.UpdatedAt, "UpdatedAt should be set")
	originalCreatedAt := created.CreatedAt
	originalUpdatedAt := created.UpdatedAt

	// Wait to ensure timestamp difference
	time.Sleep(100 * time.Millisecond)

	// Update zone
	zone.Records = testZoneRecords("example.com.",
		model.Record{Name: "test.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
	)
	err = backend.UpdateZone(ctx, zone, created.Version)
	require.NoError(t, err)

	// Verify timestamps
	updated, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, originalCreatedAt, updated.CreatedAt, "CreatedAt should be preserved")
	assert.NotEqual(t, originalUpdatedAt, updated.UpdatedAt, "UpdatedAt should change")
	assert.True(t, updated.UpdatedAt.After(originalUpdatedAt), "UpdatedAt should be newer")
}

// TestGitBackend_GetRevision_NotFound tests that GetRevision returns ErrVersionNotFound
func TestGitBackend_GetRevision_NotFound(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: testZoneRecords("example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Try to get non-existent version
	_, err = backend.GetRevision(ctx, "example.com.", "v2024010101-nonexist")
	assert.ErrorIs(t, err, model.ErrVersionNotFound, "Should return ErrVersionNotFound for missing version")
}

func TestGitBackend_GetRevision_RequiresExactVersionTrailer(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()
	zone := testGitZone("example.com.")
	require.NoError(t, backend.CreateZone(ctx, zone))

	created, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	require.Greater(t, len(created.Version), 2)

	versionPrefix := created.Version[:len(created.Version)-2]
	_, err = backend.GetRevision(ctx, "example.com.", versionPrefix)
	assert.ErrorIs(t, err, model.ErrVersionNotFound, "Should require an exact Version trailer match")
}

// TestGitBackend_PathTraversal tests path traversal protection
func TestGitBackend_PathTraversal(t *testing.T) {
	backend, cleanup := setupGitBackend(t)
	defer cleanup()

	ctx := context.Background()

	testCases := []struct {
		name     string
		zoneName string
	}{
		{"absolute path", "/tmp/evil.com."},
		{"parent directory", "../evil.com."},
		{"path separator", "sub/dir/evil.com."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			zone := &model.Zone{
				Name: tc.zoneName,
				SOA: model.SOARecord{
					MName:   "ns1.example.com.",
					RName:   "admin.example.com.",
					Serial:  2024010101,
					Refresh: 3600,
					Retry:   1800,
					Expire:  604800,
					Minimum: 86400,
				},
				Records: []model.Record{},
			}

			err := backend.CreateZone(ctx, zone)
			assert.Error(t, err, "Should reject zone name with path traversal: %s", tc.zoneName)
		})
	}
}
