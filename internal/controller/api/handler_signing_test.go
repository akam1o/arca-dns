package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

type zoneStoreWithoutDNSSECMetadata struct {
	backend.ZoneStore
}

func setupSigningFailureTest(t *testing.T) (*httptest.Server, *backend.MemoryBackend) {
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

	signingStore := zoneStoreWithoutDNSSECMetadata{ZoneStore: store}
	signingService := service.NewSigningService(signingStore, keyManager, filepath.Join(tmpDir, "artifacts"), nil, logger)
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

func TestCreateZone_ReturnsErrorWhenAutoSigningFails(t *testing.T) {
	server, _ := setupSigningFailureTest(t)
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
}
