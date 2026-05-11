package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/akam1o/arca-dns/internal/controller/service"
	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupSigningFailureTest(t *testing.T) (*httptest.Server, *backend.MemoryBackend) {
	t.Helper()

	logger := zap.NewNop()
	store := backend.NewMemoryBackend()
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keys")
	require.NoError(t, os.WriteFile(keyPath, []byte("not a directory"), 0600))

	masterKey, err := dnssec.GenerateMasterKey()
	require.NoError(t, err)

	keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: keyPath,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	signingService := service.NewSigningService(store, keyManager, filepath.Join(tmpDir, "artifacts"), nil, logger)
	handler := NewHandler(store, signingService, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)

	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false
	router := SetupRouter(handler, &apiCfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	server := httptest.NewUnstartedServer(router)
	server.Listener = ln
	server.Start()

	return server, store
}

func setupArtifactStoreFailureTest(t *testing.T) (*httptest.Server, *backend.MemoryBackend) {
	t.Helper()

	logger := zap.NewNop()
	store := backend.NewMemoryBackend()
	tmpDir := t.TempDir()

	masterKey, err := dnssec.GenerateMasterKey()
	require.NoError(t, err)

	keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: filepath.Join(tmpDir, "keys"),
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	artifactPath := filepath.Join(tmpDir, "artifacts")
	require.NoError(t, os.WriteFile(artifactPath, []byte("not a directory"), 0600))

	signingService := service.NewSigningService(store, keyManager, artifactPath, nil, logger)
	handler := NewHandler(store, signingService, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)

	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false
	router := SetupRouter(handler, &apiCfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	server := httptest.NewUnstartedServer(router)
	server.Listener = ln
	server.Start()

	return server, store
}

func TestDeleteZone_CleansDNSSECArtifactsAndKeys(t *testing.T) {
	logger := zap.NewNop()
	store := backend.NewMemoryBackend()
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "keys")
	artifactDir := filepath.Join(tmpDir, "artifacts")

	masterKey, err := dnssec.GenerateMasterKey()
	require.NoError(t, err)
	keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: keyDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	signingService := service.NewSigningService(store, keyManager, artifactDir, nil, logger)
	handler := NewHandler(store, signingService, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)

	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false
	router := SetupRouter(handler, &apiCfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	server := httptest.NewUnstartedServer(router)
	server.Listener = ln
	server.Start()
	defer server.Close()

	zoneName := "cleanup-delete.example.com."
	zone := &model.Zone{
		Name: zoneName,
		SOA:  model.DefaultSOA("ns1."+zoneName, "admin."+zoneName),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	body, err := json.Marshal(zone)
	require.NoError(t, err)

	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	current, err := store.GetZone(context.Background(), zoneName)
	require.NoError(t, err)
	artifactMatches, err := filepath.Glob(filepath.Join(artifactDir, "*", "*.zone.signed"))
	require.NoError(t, err)
	require.Len(t, artifactMatches, 1)
	artifactZoneDir := filepath.Dir(artifactMatches[0])
	zoneKeyName, err := dnssec.ZoneNameForFile(zoneName)
	require.NoError(t, err)
	zoneKeyDir := filepath.Join(keyDir, zoneKeyName)
	require.DirExists(t, zoneKeyDir)

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/"+zoneName, nil)
	require.NoError(t, err)
	req.Header.Set("If-Match", current.Version)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	_, err = os.Stat(artifactZoneDir)
	require.True(t, os.IsNotExist(err), "expected artifact directory to be removed, got %v", err)
	_, err = os.Stat(zoneKeyDir)
	require.True(t, os.IsNotExist(err), "expected key directory to be removed, got %v", err)
}

type mutateAfterFirstGetStore struct {
	inner   *backend.MemoryBackend
	target  string
	mu      sync.Mutex
	mutated bool
}

type postCreateReadFailureStore struct {
	*backend.MemoryBackend
	target    string
	mu        sync.Mutex
	failReads bool
}

func (s *postCreateReadFailureStore) CreateZone(ctx context.Context, zone *model.Zone) error {
	if err := s.MemoryBackend.CreateZone(ctx, zone); err != nil {
		return err
	}
	if model.NormalizeZoneName(zone.Name) == s.target {
		s.mu.Lock()
		s.failReads = true
		s.mu.Unlock()
	}
	return nil
}

func (s *postCreateReadFailureStore) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	s.mu.Lock()
	failReads := s.failReads && model.NormalizeZoneName(name) == s.target
	s.mu.Unlock()
	if failReads {
		return nil, fmt.Errorf("post-create read failed")
	}
	return s.MemoryBackend.GetZone(ctx, name)
}

func (s *mutateAfterFirstGetStore) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	zone, err := s.inner.GetZone(ctx, name)
	if err != nil {
		return nil, err
	}

	if model.NormalizeZoneName(name) != s.target {
		return zone, nil
	}

	s.mu.Lock()
	shouldMutate := !s.mutated
	if shouldMutate {
		s.mutated = true
	}
	s.mu.Unlock()

	if shouldMutate {
		updated := *zone
		updated.Records = append(append([]model.Record(nil), zone.Records...), model.Record{
			Name:  "new",
			Type:  model.RecordTypeA,
			TTL:   300,
			Value: "192.0.2.55",
		})
		if err := s.inner.UpdateZone(ctx, &updated, zone.Version); err != nil {
			return nil, err
		}
	}

	return zone, nil
}

func (s *mutateAfterFirstGetStore) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	return s.inner.ListZones(ctx, opts)
}

func (s *mutateAfterFirstGetStore) CreateZone(ctx context.Context, zone *model.Zone) error {
	return s.inner.CreateZone(ctx, zone)
}

func (s *mutateAfterFirstGetStore) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	return s.inner.UpdateZone(ctx, zone, expectedVersion)
}

func (s *mutateAfterFirstGetStore) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssecConfig *model.DNSSECConfig) error {
	return s.inner.UpdateDNSSECMetadata(ctx, zoneName, dnssecConfig)
}

func (s *mutateAfterFirstGetStore) DeleteZone(ctx context.Context, name string) error {
	return s.inner.DeleteZone(ctx, name)
}

func (s *mutateAfterFirstGetStore) Close() error {
	return s.inner.Close()
}

func TestGetSignedZone_UsesArtifactMetadataAfterSigningRefetch(t *testing.T) {
	logger := zap.NewNop()
	inner := backend.NewMemoryBackend()
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone.SOA.Serial = 2024010101
	require.NoError(t, inner.CreateZone(context.Background(), zone))

	initial, err := inner.GetZone(context.Background(), zone.Name)
	require.NoError(t, err)

	store := &mutateAfterFirstGetStore{
		inner:  inner,
		target: model.NormalizeZoneName(zone.Name),
	}

	tmpDir := t.TempDir()
	masterKey, err := dnssec.GenerateMasterKey()
	require.NoError(t, err)
	keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: filepath.Join(tmpDir, "keys"),
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	signingService := service.NewSigningService(store, keyManager, filepath.Join(tmpDir, "artifacts"), nil, logger)
	handler := NewHandler(store, signingService, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)

	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false
	router := SetupRouter(handler, &apiCfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	server := httptest.NewUnstartedServer(router)
	server.Listener = ln
	server.Start()
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/v1/zones/example.com./signed")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	updated, err := inner.GetZone(context.Background(), zone.Name)
	require.NoError(t, err)
	require.NotEqual(t, initial.SOA.Serial, updated.SOA.Serial)
	assert.Contains(t, string(body), "192.0.2.55")
	assert.Equal(t, fmt.Sprintf("%d", updated.SOA.Serial), resp.Header.Get("X-Zone-Serial"))
}

func TestCreateZone_DoesNotPersistWhenAutoSigningFails(t *testing.T) {
	server, store := setupSigningFailureTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "signing-fails.com.",
		SOA:  model.DefaultSOA("ns1.signing-fails.com.", "admin.signing-fails.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	body, err := json.Marshal(zone)
	require.NoError(t, err)

	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("ETag"))

	_, err = store.GetZone(context.Background(), "signing-fails.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestCreateZone_DoesNotPersistWhenSignedArtifactStoreFails(t *testing.T) {
	server, store := setupArtifactStoreFailureTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "artifact-store-fails.com.",
		SOA:  model.DefaultSOA("ns1.artifact-store-fails.com.", "admin.artifact-store-fails.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	body, err := json.Marshal(zone)
	require.NoError(t, err)

	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("ETag"))

	_, err = store.GetZone(context.Background(), "artifact-store-fails.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestCreateZone_KeepsSignedArtifactWhenPostCreateReadFails(t *testing.T) {
	logger := zap.NewNop()
	zoneName := "post-create-read-fails.com."
	store := &postCreateReadFailureStore{
		MemoryBackend: backend.NewMemoryBackend(),
		target:        model.NormalizeZoneName(zoneName),
	}
	tmpDir := t.TempDir()

	masterKey, err := dnssec.GenerateMasterKey()
	require.NoError(t, err)
	keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: filepath.Join(tmpDir, "keys"),
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	artifactDir := filepath.Join(tmpDir, "artifacts")
	signingService := service.NewSigningService(store, keyManager, artifactDir, nil, logger)
	handler := NewHandler(store, signingService, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)

	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false
	router := SetupRouter(handler, &apiCfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	server := httptest.NewUnstartedServer(router)
	server.Listener = ln
	server.Start()
	defer server.Close()

	zone := &model.Zone{
		Name: zoneName,
		SOA:  model.DefaultSOA("ns1."+zoneName, "admin."+zoneName),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	body, err := json.Marshal(zone)
	require.NoError(t, err)

	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	matches, err := filepath.Glob(filepath.Join(artifactDir, "*", "*.zone.signed"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
}

func TestCreateZoneRaw_DoesNotPersistWhenAutoSigningFails(t *testing.T) {
	server, store := setupSigningFailureTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
raw-signing-fails.com. IN SOA ns1.raw-signing-fails.com. admin.raw-signing-fails.com. (
    2024010101 3600 1800 604800 86400
)
raw-signing-fails.com. IN NS ns1.raw-signing-fails.com.
raw-signing-fails.com. IN A 192.0.2.1
`

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/raw?origin=raw-signing-fails.com.",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("ETag"))

	_, err = store.GetZone(context.Background(), "raw-signing-fails.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestUpdateZone_DoesNotPersistWhenAutoSigningFails(t *testing.T) {
	server, store := setupSigningFailureTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "signing-fails.com.",
		SOA:  model.DefaultSOA("ns1.signing-fails.com.", "admin.signing-fails.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.Background(), zone))

	current, err := store.GetZone(context.Background(), "signing-fails.com.")
	require.NoError(t, err)

	update := *current
	update.SOA.Refresh = 7200
	body, err := json.Marshal(&update)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/signing-fails.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("ETag"))

	unchanged, err := store.GetZone(context.Background(), "signing-fails.com.")
	require.NoError(t, err)
	assert.Equal(t, current.Version, unchanged.Version)
	assert.Equal(t, current.SOA.Serial, unchanged.SOA.Serial)
	assert.Equal(t, current.SOA.Refresh, unchanged.SOA.Refresh)
	assert.Equal(t, current.Records, unchanged.Records)
}

func TestCreateRecord_DoesNotPersistWhenAutoSigningFails(t *testing.T) {
	server, store := setupSigningFailureTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "signing-fails.com.",
		SOA:  model.DefaultSOA("ns1.signing-fails.com.", "admin.signing-fails.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.Background(), zone))

	current, err := store.GetZone(context.Background(), "signing-fails.com.")
	require.NoError(t, err)

	record := model.Record{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"}
	body, err := json.Marshal(&record)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/signing-fails.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("ETag"))

	unchanged, err := store.GetZone(context.Background(), "signing-fails.com.")
	require.NoError(t, err)
	assert.Equal(t, current.Version, unchanged.Version)
	assert.Equal(t, current.SOA.Serial, unchanged.SOA.Serial)
	assert.Equal(t, current.Records, unchanged.Records)
}
