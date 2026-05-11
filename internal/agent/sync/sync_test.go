package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSyncer_SyncAll(t *testing.T) {
	requireTCPListener(t)
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			// Return zone list
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"zones":[{"name":"example.com","version":"v1-abc123","soa":{"mname":"ns1.example.com","rname":"admin.example.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]}]}`)

		case "/api/v1/zones/example.com/signed":
			// Return signed zone
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-abc123")
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", "717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724")
			w.Header().Set("X-Zone-Hash8", "717fd058")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n")

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create temp directory
	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	// Create client
	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	// Create file manager
	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	// Create syncer
	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:    30 * time.Second,
		Jitter:          5 * time.Second,
		MaxStaleness:    5 * time.Minute,
		BackupVersions:  3,
		VerifyChecksums: true,
	}, logger)

	// Test sync
	ctx := context.Background()
	err = syncer.SyncAll(ctx)
	require.NoError(t, err)

	// Verify zone file was created
	zonePath := fileMgr.GetZonePath("example.com")
	assert.FileExists(t, zonePath)

	// Verify zone state
	state := syncer.GetZoneState("example.com")
	require.NotNil(t, state)
	assert.Equal(t, "example.com", state.ZoneName)
	assert.Equal(t, "v1-abc123", state.Version)
	assert.Equal(t, 0, state.FailCount)
}

func TestSyncer_SyncZoneRejectsOlderSignedSerial(t *testing.T) {
	requireTCPListener(t)

	localZoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010201 3600 1800 604800 86400\n"
	staleZoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	staleHash := sha256.Sum256([]byte(staleZoneContent))
	staleHashHex := hex.EncodeToString(staleHash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/zones/example.com/signed" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"`+staleHashHex+`"`)
		w.Header().Set("X-Zone-Serial", "2024010101")
		w.Header().Set("X-Zone-Hash", staleHashHex)
		w.Header().Set("X-Zone-Hash8", staleHashHex[:8])
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, staleZoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	zoneDir := filepath.Join(t.TempDir(), "zones")
	fileMgr := NewFileManager(zoneDir, 3, zap.NewNop())
	require.NoError(t, fileMgr.EnsureDirectory())
	require.NoError(t, fileMgr.WriteZoneFile("example.com", localZoneContent))

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:    30 * time.Second,
		Jitter:          5 * time.Second,
		MaxStaleness:    5 * time.Minute,
		BackupVersions:  3,
		VerifyChecksums: true,
	}, zap.NewNop())

	err = syncer.syncZone(context.Background(), ZoneInfo{Name: "example.com", Version: `"stale"`})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "older than local serial")

	content, err := fileMgr.ReadZoneFile("example.com")
	require.NoError(t, err)
	assert.Equal(t, localZoneContent, content)
}

func TestSyncer_DeleteRemovedZonesUsesCanonicalManagedZoneName(t *testing.T) {
	zoneDir := filepath.Join(t.TempDir(), "zones")
	fileMgr := NewFileManager(zoneDir, 3, zap.NewNop())

	labels := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		labels = append(labels, fmt.Sprintf("label%02d", i))
	}
	longZone := strings.Join(labels, ".") + ".example.com."
	if len(SafeZoneFilename(longZone)) >= len(strings.TrimSuffix(longZone, ".")) {
		t.Fatal("test zone name was not long enough to exercise filename truncation")
	}
	if err := fileMgr.recordManagedZone(longZone); err != nil {
		t.Fatalf("recordManagedZone failed: %v", err)
	}

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{}, zap.NewNop())
	deletedZone := ""
	syncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		deletedZone = zoneName
		return nil
	})

	deletedCount, errorCount := syncer.deleteRemovedZones(context.Background(), map[string]struct{}{}, map[string]struct{}{})
	if errorCount != 0 {
		t.Fatalf("deleteRemovedZones errors = %d, want 0", errorCount)
	}
	if deletedCount != 1 {
		t.Fatalf("deleteRemovedZones deleted = %d, want 1", deletedCount)
	}
	if deletedZone != longZone {
		t.Fatalf("delete hook zone = %q, want %q", deletedZone, longZone)
	}
}

func TestSyncer_DeleteRemovedZonesKeepsManagedIndexWhenHookFails(t *testing.T) {
	zoneDir := filepath.Join(t.TempDir(), "zones")
	fileMgr := NewFileManager(zoneDir, 3, zap.NewNop())
	require.NoError(t, fileMgr.EnsureDirectory())

	zoneName := "example.com."
	require.NoError(t, fileMgr.WriteZoneFile(zoneName, "$ORIGIN example.com.\n"))

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{}, zap.NewNop())
	syncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		return errors.New("reload failed")
	})

	deletedCount, errorCount := syncer.deleteRemovedZones(context.Background(), map[string]struct{}{}, map[string]struct{}{})
	require.Equal(t, 0, deletedCount)
	require.Equal(t, 1, errorCount)
	assert.True(t, fileMgr.ZoneExists(zoneName), "zone file should remain active when the delete hook fails")

	managedZones, err := fileMgr.listManagedZones()
	require.NoError(t, err)
	require.Len(t, managedZones, 1)
	assert.Equal(t, zoneName, managedZones[0].ZoneName)

	retrySyncer := NewSyncer(nil, fileMgr, config.SyncConfig{}, zap.NewNop())
	var retriedZone string
	retrySyncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		retriedZone = zoneName
		return nil
	})

	deletedCount, errorCount = retrySyncer.deleteRemovedZones(context.Background(), map[string]struct{}{}, map[string]struct{}{})
	require.Equal(t, 1, deletedCount)
	require.Equal(t, 0, errorCount)
	assert.Equal(t, zoneName, retriedZone)

	managedZones, err = fileMgr.listManagedZones()
	require.NoError(t, err)
	assert.Empty(t, managedZones)
}

func TestSyncer_DeleteRemovedZonesRollsBackWhenZoneFileDeleteFails(t *testing.T) {
	zoneDir := filepath.Join(t.TempDir(), "zones")
	fileMgr := NewFileManager(zoneDir, 3, zap.NewNop())
	require.NoError(t, fileMgr.EnsureDirectory())

	zoneName := "example.com."
	require.NoError(t, fileMgr.WriteZoneFile(zoneName, "$ORIGIN example.com.\n"))

	zonePath := fileMgr.GetZonePath(zoneName)
	require.NoError(t, os.Remove(zonePath))
	require.NoError(t, os.Mkdir(zonePath, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(zonePath, "child"), []byte("block remove"), 0644))

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{}, zap.NewNop())
	deleteHookCalled := false
	var rollbackZone string
	syncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		deleteHookCalled = true
		return nil
	})
	syncer.SetOnZoneDeleteRollback(func(ctx context.Context, zoneName string) error {
		rollbackZone = zoneName
		return nil
	})

	deletedCount, errorCount := syncer.deleteRemovedZones(context.Background(), map[string]struct{}{}, map[string]struct{}{})
	require.Equal(t, 0, deletedCount)
	require.Equal(t, 1, errorCount)
	assert.True(t, deleteHookCalled)
	assert.Equal(t, zoneName, rollbackZone)

	managedZones, err := fileMgr.listManagedZones()
	require.NoError(t, err)
	require.Len(t, managedZones, 1)
	assert.Equal(t, zoneName, managedZones[0].ZoneName)
}

func TestSyncer_SyncAll_ConditionalFetch(t *testing.T) {
	requireTCPListener(t)
	requestCount := 0
	zoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"zones":[{"name":"example.com","version":"v1-abc123","soa":{"mname":"ns1.example.com","rname":"admin.example.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]}]}`)

		case "/api/v1/zones/example.com/signed":
			requestCount++

			// Check If-None-Match header
			ifNoneMatch := r.Header.Get("If-None-Match")
			if ifNoneMatch == `"`+hashHex+`"` {
				// Return 304 Not Modified
				w.Header().Set("ETag", `"`+hashHex+`"`)
				w.Header().Set("X-Zone-Serial", "2024010101")
				w.Header().Set("X-Zone-Hash", hashHex)
				w.Header().Set("X-Zone-Hash8", hashHex[:8])
				w.WriteHeader(http.StatusNotModified)
				return
			}

			// First request: return zone
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", `"`+hashHex+`"`)
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", hashHex)
			w.Header().Set("X-Zone-Hash8", hashHex[:8])
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, zoneContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create temp directory
	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	// Create components
	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:    30 * time.Second,
		Jitter:          5 * time.Second,
		MaxStaleness:    5 * time.Minute,
		BackupVersions:  3,
		VerifyChecksums: true,
	}, logger)

	ctx := context.Background()

	// First sync: should download zone
	err = syncer.SyncAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// Second sync: should return 304 Not Modified
	err = syncer.SyncAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, requestCount)

	// Verify zone file exists
	zonePath := fileMgr.GetZonePath("example.com")
	assert.FileExists(t, zonePath)
}

func TestSyncer_SyncAll_SignedConditionalFetch(t *testing.T) {
	requireTCPListener(t)
	requestIfNoneMatch := make([]string, 0, 2)
	zoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	signatureKey := "test-signature-key"
	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"zones":[{"name":"example.com","version":"v1-abc123","soa":{"mname":"ns1.example.com","rname":"admin.example.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]}]}`)

		case "/api/v1/zones/example.com/signed":
			ifNoneMatch := r.Header.Get("If-None-Match")
			requestIfNoneMatch = append(requestIfNoneMatch, ifNoneMatch)
			w.Header().Set("ETag", `"`+hashHex+`"`)
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", hashHex)
			w.Header().Set("X-Zone-Hash8", hashHex[:8])
			w.Header().Set("X-Zone-Signature", artifactSignature([]byte(zoneContent), signatureKey))
			if ifNoneMatch == `"`+hashHex+`"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, zoneContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:        30 * time.Second,
		Jitter:              5 * time.Second,
		MaxStaleness:        5 * time.Minute,
		BackupVersions:      3,
		VerifyChecksums:     true,
		VerifySignatures:    true,
		ControllerPublicKey: signatureKey,
	}, logger)

	ctx := context.Background()
	require.NoError(t, syncer.SyncAll(ctx))
	require.NoError(t, syncer.SyncAll(ctx))

	require.Len(t, requestIfNoneMatch, 2)
	assert.Empty(t, requestIfNoneMatch[0])
	assert.Equal(t, `"`+hashHex+`"`, requestIfNoneMatch[1])
}

func TestSyncer_SyncAll_PartialFailureKeepsSyncUnhealthy(t *testing.T) {
	requireTCPListener(t)

	goodZoneContent := "$ORIGIN good.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	goodHash := sha256.Sum256([]byte(goodZoneContent))
	goodHashHex := hex.EncodeToString(goodHash[:])

	badZoneContent := "$ORIGIN bad.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	badHash := sha256.Sum256([]byte(badZoneContent))
	badHashHex := hex.EncodeToString(badHash[:])

	var badFixed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"zones":[{"name":"bad.com","version":"v1-bad","soa":{"mname":"ns1.bad.com","rname":"admin.bad.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]},{"name":"good.com","version":"v1-good","soa":{"mname":"ns1.good.com","rname":"admin.good.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]}]}`)

		case "/api/v1/zones/good.com/signed":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-good")
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", goodHashHex)
			w.Header().Set("X-Zone-Hash8", goodHashHex[:8])
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, goodZoneContent)

		case "/api/v1/zones/bad.com/signed":
			if !badFixed.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "signing failed")
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-bad")
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", badHashHex)
			w.Header().Set("X-Zone-Hash8", badHashHex[:8])
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, badZoneContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 0,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:    30 * time.Second,
		Jitter:          5 * time.Second,
		MaxStaleness:    5 * time.Minute,
		BackupVersions:  3,
		VerifyChecksums: true,
	}, logger)

	err = syncer.SyncAll(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zones failed to sync (1 errors)")
	assert.FileExists(t, fileMgr.GetZonePath("good.com"))
	assert.NoFileExists(t, fileMgr.GetZonePath("bad.com"))
	assert.True(t, syncer.GetLastSuccessTime().IsZero())
	assert.Equal(t, 1, syncer.FailedZoneCount())

	badFixed.Store(true)
	require.NoError(t, syncer.SyncAll(context.Background()))
	assert.FileExists(t, fileMgr.GetZonePath("bad.com"))
	assert.False(t, syncer.GetLastSuccessTime().IsZero())
	assert.Equal(t, 0, syncer.FailedZoneCount())
}

func TestSyncer_SyncZone_RollsBackNewZoneFileWhenApplyHookFails(t *testing.T) {
	requireTCPListener(t)

	zoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"zones":[{"name":"example.com","version":"v1-new"}]}`)
		case "/api/v1/zones/example.com/signed":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-new")
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", hashHex)
			w.Header().Set("X-Zone-Hash8", hashHex[:8])
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, zoneContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	zoneDir := filepath.Join(t.TempDir(), "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 0,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		VerifyChecksums: true,
	}, logger)
	syncer.SetOnZoneApplied(func(ctx context.Context, zoneName string) error {
		return errors.New("reload failed")
	})

	rollbackCalled := false
	rollbackHadPrevious := true
	syncer.SetOnZoneApplyRollback(func(ctx context.Context, zoneName string, hadPrevious bool) error {
		rollbackCalled = true
		rollbackHadPrevious = hadPrevious
		assert.FileExists(t, fileMgr.GetZonePath("example.com"))
		return nil
	})

	err = syncer.SyncZone(context.Background(), "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-apply hook failed")
	assert.True(t, rollbackCalled)
	assert.False(t, rollbackHadPrevious)
	assert.NoFileExists(t, fileMgr.GetZonePath("example.com"))
	state := syncer.GetZoneState("example.com")
	require.NotNil(t, state)
	assert.Equal(t, 1, state.FailCount)
	assert.False(t, state.LastAttempt.IsZero())

	managedZones, err := fileMgr.listManagedZones()
	require.NoError(t, err)
	assert.Empty(t, managedZones)
}

func TestSyncer_RollbackFailedApply_KeepsNewZoneFileWhenServiceRollbackFails(t *testing.T) {
	zoneDir := filepath.Join(t.TempDir(), "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	zoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	rollbackZoneFile, err := fileMgr.WriteZoneFileValidatedWithRollback("example.com", zoneContent, nil)
	require.NoError(t, err)

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{}, logger)
	syncer.SetOnZoneApplyRollback(func(ctx context.Context, zoneName string, hadPrevious bool) error {
		assert.False(t, hadPrevious)
		assert.FileExists(t, fileMgr.GetZonePath(zoneName))
		return errors.New("delete services failed")
	})

	err = syncer.rollbackFailedApply(context.Background(), "example.com", false, rollbackZoneFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete services failed")
	assert.FileExists(t, fileMgr.GetZonePath("example.com"))

	managedZones, err := fileMgr.listManagedZones()
	require.NoError(t, err)
	require.Len(t, managedZones, 1)
	assert.Equal(t, "example.com.", managedZones[0].ZoneName)
}

func TestSyncer_SyncZone_RestoresPreviousZoneFileWhenApplyHookFails(t *testing.T) {
	requireTCPListener(t)

	oldZoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	newZoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010102 3600 1800 604800 86400\n"
	hash := sha256.Sum256([]byte(newZoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"zones":[{"name":"example.com","version":"v1-new"}]}`)
		case "/api/v1/zones/example.com/signed":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-new")
			w.Header().Set("X-Zone-Serial", "2024010102")
			w.Header().Set("X-Zone-Hash", hashHex)
			w.Header().Set("X-Zone-Hash8", hashHex[:8])
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, newZoneContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	zoneDir := filepath.Join(t.TempDir(), "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 0,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())
	require.NoError(t, fileMgr.WriteZoneFile("example.com", oldZoneContent))

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		VerifyChecksums: true,
	}, logger)
	syncer.SetOnZoneApplied(func(ctx context.Context, zoneName string) error {
		return errors.New("reload failed")
	})

	rollbackCalled := false
	rollbackHadPrevious := false
	syncer.SetOnZoneApplyRollback(func(ctx context.Context, zoneName string, hadPrevious bool) error {
		rollbackCalled = true
		rollbackHadPrevious = hadPrevious
		content, err := fileMgr.ReadZoneFile("example.com")
		require.NoError(t, err)
		assert.Equal(t, oldZoneContent, content)
		return nil
	})

	err = syncer.SyncZone(context.Background(), "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-apply hook failed")
	assert.True(t, rollbackCalled)
	assert.True(t, rollbackHadPrevious)

	content, err := fileMgr.ReadZoneFile("example.com")
	require.NoError(t, err)
	assert.Equal(t, oldZoneContent, content)
	state := syncer.GetZoneState("example.com")
	require.NotNil(t, state)
	assert.Equal(t, 1, state.FailCount)
	assert.False(t, state.LastAttempt.IsZero())

	managedZones, err := fileMgr.listManagedZones()
	require.NoError(t, err)
	require.Len(t, managedZones, 1)
	assert.Equal(t, "example.com.", managedZones[0].ZoneName)
}

func TestSyncer_SyncAll_ForcesFetchWhenLocalZoneFileMissing(t *testing.T) {
	requireTCPListener(t)

	zoneContent := "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n"
	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])
	requestIfNoneMatch := make([]string, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"zones":[{"name":"example.com","version":"v1-abc123","soa":{"mname":"ns1.example.com","rname":"admin.example.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]}]}`)

		case "/api/v1/zones/example.com/signed":
			ifNoneMatch := r.Header.Get("If-None-Match")
			requestIfNoneMatch = append(requestIfNoneMatch, ifNoneMatch)
			w.Header().Set("ETag", `"`+hashHex+`"`)
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", hashHex)
			w.Header().Set("X-Zone-Hash8", hashHex[:8])
			if ifNoneMatch == `"`+hashHex+`"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, zoneContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:    30 * time.Second,
		Jitter:          5 * time.Second,
		MaxStaleness:    5 * time.Minute,
		BackupVersions:  3,
		VerifyChecksums: true,
	}, logger)

	ctx := context.Background()
	require.NoError(t, syncer.SyncAll(ctx))
	require.NoError(t, os.Remove(fileMgr.GetZonePath("example.com")))
	require.NoError(t, syncer.SyncAll(ctx))

	require.Len(t, requestIfNoneMatch, 2)
	assert.Empty(t, requestIfNoneMatch[0])
	assert.Empty(t, requestIfNoneMatch[1])
	assert.FileExists(t, fileMgr.GetZonePath("example.com"))
}

func TestSyncer_SyncAll_RemovesDeletedZones(t *testing.T) {
	requireTCPListener(t)
	var zoneDeleted atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if zoneDeleted.Load() {
				fmt.Fprintf(w, `{"zones":[]}`)
				return
			}
			fmt.Fprintf(w, `{"zones":[{"name":"example.com","version":"v1-abc123","soa":{"mname":"ns1.example.com","rname":"admin.example.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]}]}`)

		case "/api/v1/zones/example.com/signed":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-abc123")
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", "717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724")
			w.Header().Set("X-Zone-Hash8", "717fd058")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n")

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:    30 * time.Second,
		Jitter:          5 * time.Second,
		MaxStaleness:    5 * time.Minute,
		BackupVersions:  3,
		VerifyChecksums: true,
	}, logger)

	deletedZones := make([]string, 0)
	syncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		deletedZones = append(deletedZones, zoneName)
		return nil
	})

	ctx := context.Background()
	require.NoError(t, syncer.SyncAll(ctx))
	assert.FileExists(t, fileMgr.GetZonePath("example.com"))
	require.NotNil(t, syncer.GetZoneState("example.com"))

	zoneDeleted.Store(true)
	require.NoError(t, syncer.SyncAll(ctx))

	assert.NoFileExists(t, fileMgr.GetZonePath("example.com"))
	assert.Nil(t, syncer.GetZoneState("example.com"))
	assert.Equal(t, []string{"example.com"}, deletedZones)
}

func TestSyncer_SyncAll_RemovesOrphanZoneFiles(t *testing.T) {
	requireTCPListener(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"zones":[]}`)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())
	require.NoError(t, fileMgr.WriteZoneFile("deleted.com", "$ORIGIN deleted.com.\n"))
	require.NoError(t, fileMgr.WriteZoneFile("deleted.com", "$ORIGIN deleted.com.\n$TTL 3600\n"))
	require.NoError(t, os.WriteFile(filepath.Join(zoneDir, "manual.com.zone"), []byte("$ORIGIN manual.com.\n"), 0644))

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:   30 * time.Second,
		Jitter:         5 * time.Second,
		MaxStaleness:   5 * time.Minute,
		BackupVersions: 3,
	}, logger)

	deletedZones := make([]string, 0)
	syncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		deletedZones = append(deletedZones, zoneName)
		return nil
	})

	require.NoError(t, syncer.SyncAll(context.Background()))

	assert.NoFileExists(t, fileMgr.GetZonePath("deleted.com"))
	assert.FileExists(t, filepath.Join(zoneDir, "manual.com.zone"))
	backups, err := fileMgr.listBackups("deleted.com")
	require.NoError(t, err)
	assert.Empty(t, backups)
	assert.Equal(t, []string{"deleted.com."}, deletedZones)
}

func TestSyncer_SyncZone(t *testing.T) {
	requireTCPListener(t)
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/zones":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"zones":[{"name":"example.com","version":"v1-abc123","soa":{"mname":"ns1.example.com","rname":"admin.example.com","serial":2024010101,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[]}]}`)

		case "/api/v1/zones/example.com/signed":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-abc123")
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", "717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724")
			w.Header().Set("X-Zone-Hash8", "717fd058")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "$ORIGIN example.com.\n$TTL 3600\n@ SOA ns1 admin 2024010101 3600 1800 604800 86400\n")

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create temp directory
	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	// Create components
	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)
	require.NoError(t, fileMgr.EnsureDirectory())

	syncer := NewSyncer(client, fileMgr, config.SyncConfig{
		SyncInterval:    30 * time.Second,
		Jitter:          5 * time.Second,
		MaxStaleness:    5 * time.Minute,
		BackupVersions:  3,
		VerifyChecksums: true,
	}, logger)

	ctx := context.Background()

	// Test sync specific zone
	err = syncer.SyncZone(ctx, "example.com")
	require.NoError(t, err)

	// Verify zone file was created
	zonePath := fileMgr.GetZonePath("example.com")
	assert.FileExists(t, zonePath)
	state := syncer.GetZoneState("example.com")
	require.NotNil(t, state)
	assert.Equal(t, 0, state.FailCount)
	assert.False(t, state.LastSync.IsZero())
	assert.False(t, state.LastAttempt.IsZero())
	assert.False(t, syncer.GetLastSuccessTime().IsZero())

	// Test sync non-existent zone
	err = syncer.SyncZone(ctx, "notfound.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zone not found")
	state = syncer.GetZoneState("notfound.com")
	require.NotNil(t, state)
	assert.Equal(t, 1, state.FailCount)
	assert.False(t, state.LastAttempt.IsZero())
}

func TestSyncer_IsStale(t *testing.T) {
	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{
		MaxStaleness: 1 * time.Second,
	}, logger)

	// Initially stale (no successful sync yet, lastSuccess is zero)
	assert.True(t, syncer.IsStale())

	// Set last success to recent time (simulate successful sync)
	syncer.mu.Lock()
	syncer.lastSuccess = time.Now()
	syncer.mu.Unlock()

	// Should not be stale
	assert.False(t, syncer.IsStale())

	// Set last success to old time
	syncer.mu.Lock()
	syncer.lastSuccess = time.Now().Add(-2 * time.Second)
	syncer.mu.Unlock()

	// Should be stale
	assert.True(t, syncer.IsStale())
}

func TestNewSyncer_AppliesSignatureVerification(t *testing.T) {
	client := &Client{}
	syncer := NewSyncer(client, nil, config.SyncConfig{
		VerifyChecksums:     true,
		VerifySignatures:    true,
		ControllerPublicKey: "test-signature-key",
	}, zap.NewNop())

	require.NotNil(t, syncer)
	assert.True(t, client.verifyChecksums)
	assert.True(t, client.verifySignatures)
	assert.Equal(t, "test-signature-key", client.signatureKey)
}

func TestSyncer_GetAllZoneStates(t *testing.T) {
	tmpDir := t.TempDir()
	zoneDir := filepath.Join(tmpDir, "zones")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	logger := zap.NewNop()
	fileMgr := NewFileManager(zoneDir, 3, logger)

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{}, logger)

	// Add some states
	syncer.zoneStates["zone1.com"] = &ZoneSyncState{
		ZoneName: "zone1.com",
		Version:  "v1",
	}
	syncer.zoneStates["zone2.com"] = &ZoneSyncState{
		ZoneName: "zone2.com",
		Version:  "v2",
	}

	// Get all states
	states := syncer.GetAllZoneStates()
	assert.Len(t, states, 2)
	assert.Contains(t, states, "zone1.com")
	assert.Contains(t, states, "zone2.com")

	// Verify it's a copy (modifying returned value doesn't affect original)
	states["zone1.com"].Version = "modified"
	assert.Equal(t, "v1", syncer.zoneStates["zone1.com"].Version)
}

func TestSyncer_addJitter(t *testing.T) {
	logger := zap.NewNop()
	fileMgr := NewFileManager("", 3, logger)

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{
		Jitter: 5 * time.Second,
	}, logger)

	baseDuration := 30 * time.Second

	// Test jitter range
	for i := 0; i < 100; i++ {
		result := syncer.addJitter(baseDuration)

		// Should be within range: baseDuration ± jitter/2
		minDuration := baseDuration - (5 * time.Second / 2)
		maxDuration := baseDuration + (5 * time.Second / 2)

		assert.GreaterOrEqual(t, result, minDuration)
		assert.LessOrEqual(t, result, maxDuration)
	}

	// Test with zero jitter
	syncerNoJitter := NewSyncer(nil, fileMgr, config.SyncConfig{
		Jitter: 0,
	}, logger)

	result := syncerNoJitter.addJitter(baseDuration)
	assert.Equal(t, baseDuration, result)
}

func TestSyncer_addJitterClampsToPositiveDuration(t *testing.T) {
	logger := zap.NewNop()
	fileMgr := NewFileManager("", 3, logger)

	syncer := NewSyncer(nil, fileMgr, config.SyncConfig{
		Jitter: 10 * time.Second,
	}, logger)

	baseDuration := 1 * time.Second
	for i := 0; i < 100; i++ {
		result := syncer.addJitter(baseDuration)
		assert.GreaterOrEqual(t, result, baseDuration/2)
	}

	assert.Equal(t, time.Nanosecond, syncer.addJitter(0))
}
