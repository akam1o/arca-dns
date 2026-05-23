package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestAuditLogger_Middleware_RedactsSensitiveQueryValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(NewAuditLogger(logger).Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(
		http.MethodGet,
		"/test?origin=example.com.&api_key=secret-api-key&TOKEN=secret-token&password=secret-password&foo=bar",
		nil,
	)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	entries := logs.All()
	require.Len(t, entries, 1)

	query, ok := entries[0].ContextMap()["query"].(string)
	require.True(t, ok)
	assert.Contains(t, query, "origin=example.com.")
	assert.Contains(t, query, "foo=bar")
	assert.Contains(t, query, "api_key=REDACTED")
	assert.Contains(t, query, "TOKEN=REDACTED")
	assert.Contains(t, query, "password=REDACTED")
	assert.NotContains(t, query, "secret-api-key")
	assert.NotContains(t, query, "secret-token")
	assert.NotContains(t, query, "secret-password")
}

func TestAuditLogger_Middleware_RedactsExpandedSensitiveQueryKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(NewAuditLogger(logger).Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	rawQuery := strings.Join([]string{
		"x-api-key=secret-x-api-key",
		"metrics.auth_token=secret-auth-token",
		"sync.controller_signature_key=secret-signature-key",
		"artifact_signature_key=secret-artifact-key",
		"client.secret=secret-client-secret",
		"credentials%5Bapi-key%5D=secret-nested-api-key",
		"foo=bar",
	}, "&")
	req := httptest.NewRequest(
		http.MethodGet,
		"/test?"+rawQuery,
		nil,
	)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	entries := logs.All()
	require.Len(t, entries, 1)

	query, ok := entries[0].ContextMap()["query"].(string)
	require.True(t, ok)
	assert.Contains(t, query, "x-api-key=REDACTED")
	assert.Contains(t, query, "metrics.auth_token=REDACTED")
	assert.Contains(t, query, "sync.controller_signature_key=REDACTED")
	assert.Contains(t, query, "artifact_signature_key=REDACTED")
	assert.Contains(t, query, "client.secret=REDACTED")
	assert.Contains(t, query, "credentials%5Bapi-key%5D=REDACTED")
	assert.Contains(t, query, "foo=bar")
	assert.NotContains(t, query, "secret-x-api-key")
	assert.NotContains(t, query, "secret-auth-token")
	assert.NotContains(t, query, "secret-signature-key")
	assert.NotContains(t, query, "secret-artifact-key")
	assert.NotContains(t, query, "secret-client-secret")
	assert.NotContains(t, query, "secret-nested-api-key")
}

func TestAuditLogger_Middleware_TruncatesLongFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(NewAuditLogger(logger).Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	longValue := strings.Repeat("a", maxAuditLogFieldLength+100)
	req := httptest.NewRequest(http.MethodGet, "/test?q="+longValue, nil)
	req.Header.Set("User-Agent", longValue)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	entries := logs.All()
	require.Len(t, entries, 1)

	query, ok := entries[0].ContextMap()["query"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasSuffix(query, auditLogTruncatedMark))
	assert.LessOrEqual(t, len(query), maxAuditLogFieldLength+len(auditLogTruncatedMark))

	userAgent, ok := entries[0].ContextMap()["user_agent"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasSuffix(userAgent, auditLogTruncatedMark))
	assert.LessOrEqual(t, len(userAgent), maxAuditLogFieldLength+len(auditLogTruncatedMark))
}

func TestAuditLogger_Middleware_ValidatesRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		header    string
		generated bool
	}{
		{name: "valid request id", header: "request-123", generated: false},
		{name: "empty request id", header: "", generated: true},
		{name: "too long request id", header: strings.Repeat("a", maxAuditRequestIDLength+1), generated: true},
		{name: "control character request id", header: "request\x7fid", generated: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.InfoLevel)
			logger := zap.New(core)

			router := gin.New()
			router.Use(NewAuditLogger(logger).Middleware())
			router.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.header != "" {
				req.Header.Set("X-Request-ID", tt.header)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNoContent, w.Code)
			entries := logs.All()
			require.Len(t, entries, 1)

			requestID, ok := entries[0].ContextMap()["request_id"].(string)
			require.True(t, ok)
			assert.NotEmpty(t, requestID)
			assert.LessOrEqual(t, len(requestID), maxAuditRequestIDLength)
			assert.False(t, strings.ContainsFunc(requestID, isControlCharacter))

			if tt.generated {
				assert.NotEqual(t, tt.header, requestID)
				assert.Equal(t, requestID, w.Header().Get("X-Request-ID"))
			} else {
				assert.Equal(t, tt.header, requestID)
			}
		})
	}
}
