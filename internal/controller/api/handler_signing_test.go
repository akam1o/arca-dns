package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestCreateZone_DoesNotPersistWhenAutoSigningFails(t *testing.T) {
	server, store := setupSigningFailureTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "signing-fails.com.",
		SOA:  model.DefaultSOA("ns1.signing-fails.com.", "admin.signing-fails.com."),
		Records: []model.Record{
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
