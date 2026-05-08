package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestAuditLogger_Middleware_LogsAuthenticatedPrincipal(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testKey := "test-api-key-12345"
	hash := sha256.Sum256([]byte(testKey))
	hashStr := "sha256:" + hex.EncodeToString(hash[:])

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(NewAuditLogger(logger).Middleware())
	router.Use(NewAuthenticator(AuthConfig{
		APIKeys: map[string]string{
			"test_admin": hashStr,
		},
		HeaderName: "X-API-Key",
	}).Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", testKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	entries := logs.All()
	require.Len(t, entries, 1)
	assert.Equal(t, "api_request", entries[0].Message)
	assert.Equal(t, "test_admin", entries[0].ContextMap()["auth_principal"])
	assert.Equal(t, AuthRoleAdmin, entries[0].ContextMap()["auth_role"])
}
