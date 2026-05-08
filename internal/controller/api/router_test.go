package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/middleware"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type trackingReadCloser struct {
	read bool
}

func (b *trackingReadCloser) Read(p []byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func (b *trackingReadCloser) Close() error {
	return nil
}

func TestSetupRouter_AuthEnabledWithoutKeysStillProtectsRoutes(t *testing.T) {
	logger := zap.NewNop()
	handler := NewHandler(backend.NewMemoryBackend(), nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = true
	apiCfg.Auth.APIKeys = nil
	apiCfg.RateLimit.Enabled = false

	router := SetupRouter(handler, &apiCfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "API key required")
}

func TestSetupRouter_AuthRejectsBeforeReadingBody(t *testing.T) {
	logger := zap.NewNop()
	handler := NewHandler(backend.NewMemoryBackend(), nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = true
	apiCfg.Auth.APIKeys = nil
	apiCfg.RateLimit.Enabled = false

	router := SetupRouter(handler, &apiCfg, logger)

	body := &trackingReadCloser{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", body)
	req.Body = body
	req.ContentLength = 128
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, body.read, "unauthenticated protected requests must not read the body")
}

func TestSetupRouter_ProtectedRoutesStillLimitBodySize(t *testing.T) {
	logger := zap.NewNop()
	handler := NewHandler(backend.NewMemoryBackend(), nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false

	router := SetupRouter(handler, &apiCfg, logger)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", strings.NewReader("{}"))
	req.ContentLength = middleware.MaxRequestBodySize + 1
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestSetupRouter_ObservabilityRoutesAreNotOnAPIRouter(t *testing.T) {
	logger := zap.NewNop()
	handler := NewHandler(backend.NewMemoryBackend(), nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = true
	apiCfg.Auth.APIKeys = nil
	apiCfg.RateLimit.Enabled = false

	router := SetupRouter(handler, &apiCfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestSetupObservabilityRouter_RoutesBypassAuth(t *testing.T) {
	logger := zap.NewNop()
	handler := NewHandler(backend.NewMemoryBackend(), nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = true
	apiCfg.Auth.APIKeys = nil
	apiCfg.RateLimit.Enabled = false

	router := SetupObservabilityRouter(handler, &apiCfg, logger)

	for _, path := range []string{"/health", "/api/v1/health"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
	}
}

func TestSetupRouter_AgentRoleCanOnlyReadSyncArtifacts(t *testing.T) {
	logger := zap.NewNop()
	store := backend.NewMemoryBackend()
	handler := NewHandler(store, nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}
	require.NoError(t, store.CreateZone(context.Background(), zone))

	adminKey := "admin-key"
	agentKey := "agent-key"
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = true
	apiCfg.Auth.APIKeys = map[string]string{
		"admin": routerTestAPIKeyHash(adminKey),
		"agent": routerTestAPIKeyHash(agentKey),
	}
	apiCfg.Auth.APIKeyRoles = map[string]string{
		"admin": middleware.AuthRoleAdmin,
		"agent": middleware.AuthRoleAgent,
	}
	apiCfg.RateLimit.Enabled = false

	router := SetupRouter(handler, &apiCfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones?fields=summary", nil)
	req.Header.Set("X-API-Key", agentKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	req.Header.Set("X-API-Key", agentKey)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "fields=summary")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./signed", nil)
	req.Header.Set("X-API-Key", agentKey)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	body := &trackingReadCloser{}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/zones", body)
	req.Body = body
	req.ContentLength = 2
	req.Header.Set("X-API-Key", agentKey)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, body.read, "unauthorized roles must not read the body")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	req.Header.Set("X-API-Key", adminKey)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestWriteRPSFromReadRPS_MinimumOne(t *testing.T) {
	assert.Equal(t, 1, writeRPSFromReadRPS(1))
	assert.Equal(t, 1, writeRPSFromReadRPS(9))
	assert.Equal(t, 1, writeRPSFromReadRPS(10))
	assert.Equal(t, 10, writeRPSFromReadRPS(100))
}

func routerTestAPIKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}
