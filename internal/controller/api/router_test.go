package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

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

func TestSetupRouter_HealthRoutesBypassAuth(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
}

func TestWriteRPSFromReadRPS_MinimumOne(t *testing.T) {
	assert.Equal(t, 1, writeRPSFromReadRPS(1))
	assert.Equal(t, 1, writeRPSFromReadRPS(9))
	assert.Equal(t, 1, writeRPSFromReadRPS(10))
	assert.Equal(t, 10, writeRPSFromReadRPS(100))
}
