package sync

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
			w.Header().Set("X-Zone-Hash", "717fd058")
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

func TestSyncer_SyncAll_ConditionalFetch(t *testing.T) {
	requireTCPListener(t)
	requestCount := 0

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
			if ifNoneMatch == "v1-abc123" {
				// Return 304 Not Modified
				w.Header().Set("ETag", "v1-abc123")
				w.Header().Set("X-Zone-Serial", "2024010101")
				w.Header().Set("X-Zone-Hash", "717fd058")
				w.WriteHeader(http.StatusNotModified)
				return
			}

			// First request: return zone
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "v1-abc123")
			w.Header().Set("X-Zone-Serial", "2024010101")
			w.Header().Set("X-Zone-Hash", "717fd058")
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
			w.Header().Set("X-Zone-Hash", "717fd058")
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

	// Test sync non-existent zone
	err = syncer.SyncZone(ctx, "notfound.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zone not found")
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
