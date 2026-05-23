package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticator_Middleware_ValidKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create test API key and hash
	testKey := "test-api-key-12345"
	hash := sha256.Sum256([]byte(testKey))
	hashStr := "sha256:" + hex.EncodeToString(hash[:])

	config := AuthConfig{
		APIKeys: map[string]string{
			"test_admin": hashStr,
		},
		HeaderName: "X-API-Key",
	}

	auth := NewAuthenticator(config)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		principal := c.GetString("auth_principal")
		role := c.GetString("auth_role")
		c.JSON(200, gin.H{"principal": principal, "role": role})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", testKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "test_admin")
	assert.Contains(t, w.Body.String(), AuthRoleAdmin)
}

func TestAuthenticator_Middleware_SetsConfiguredRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testKey := "agent-api-key-12345"
	hash := sha256.Sum256([]byte(testKey))
	hashStr := "sha256:" + hex.EncodeToString(hash[:])

	auth := NewAuthenticator(AuthConfig{
		APIKeys: map[string]string{
			"agent": hashStr,
		},
		APIKeyRoles: map[string]string{
			"agent": AuthRoleAgent,
		},
	})
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"role": c.GetString("auth_role")})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", testKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), AuthRoleAgent)
}

func TestRequireRole_AllowsAdminForAgentEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_role", AuthRoleAdmin)
		c.Next()
	})
	router.Use(RequireRole(AuthRoleAgent))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestRequireRole_RejectsAgentForAdminEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_role", AuthRoleAgent)
		c.Next()
	})
	router.Use(RequireRole(AuthRoleAdmin))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.JSONEq(t, `{"code":"FORBIDDEN","message":"API key role is not allowed for this endpoint"}`, w.Body.String())
}

func TestRequirePermission_UsesRolePolicy(t *testing.T) {
	tests := []struct {
		name       string
		role       string
		permission string
		want       int
	}{
		{
			name:       "admin can manage zones",
			role:       AuthRoleAdmin,
			permission: AuthPermissionManageZones,
			want:       200,
		},
		{
			name:       "admin can read sync artifacts",
			role:       AuthRoleAdmin,
			permission: AuthPermissionReadSyncArtifacts,
			want:       200,
		},
		{
			name:       "agent can read sync artifacts",
			role:       AuthRoleAgent,
			permission: AuthPermissionReadSyncArtifacts,
			want:       200,
		},
		{
			name:       "agent cannot manage zones",
			role:       AuthRoleAgent,
			permission: AuthPermissionManageZones,
			want:       403,
		},
		{
			name:       "unknown role is denied",
			role:       "viewer",
			permission: AuthPermissionReadSyncArtifacts,
			want:       403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)

			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("auth_role", tt.role)
				c.Next()
			})
			router.Use(RequirePermission(tt.permission))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(200, gin.H{"status": "ok"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.want, w.Code)
			if tt.want == 403 {
				assert.JSONEq(t, `{"code":"FORBIDDEN","message":"API key role is not allowed for this endpoint"}`, w.Body.String())
			}
		})
	}
}

func TestAuthenticator_Middleware_NormalizesConfiguredHash(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testKey := "test-api-key-12345"
	hash := sha256.Sum256([]byte(testKey))
	hashStr := "  sha256:" + strings.ToUpper(hex.EncodeToString(hash[:])) + "  "

	config := AuthConfig{
		APIKeys: map[string]string{
			"test_admin": hashStr,
		},
	}

	auth := NewAuthenticator(config)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", testKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestNewAuthenticator_BuildsFixedHashCredentials(t *testing.T) {
	testKey := "agent-api-key-12345"
	hash := sha256.Sum256([]byte(testKey))
	hashStr := "  sha256:" + strings.ToUpper(hex.EncodeToString(hash[:])) + "  "

	auth := NewAuthenticator(AuthConfig{
		APIKeys: map[string]string{
			"malformed": "sha256:not-a-valid-hash",
			"agent":     hashStr,
		},
		APIKeyRoles: map[string]string{
			"agent": AuthRoleAgent,
		},
	})

	if len(auth.credentials) != 1 {
		t.Fatalf("credentials length=%d, want 1", len(auth.credentials))
	}
	credential := auth.credentials[0]
	assert.Equal(t, "agent", credential.name)
	assert.Equal(t, AuthRoleAgent, credential.role)
	assert.Equal(t, hash, credential.hash)
}

func TestAuthenticator_Middleware_InvalidKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	hash := sha256.Sum256([]byte("correct-key"))
	hashStr := "sha256:" + hex.EncodeToString(hash[:])

	config := AuthConfig{
		APIKeys: map[string]string{
			"admin": hashStr,
		},
	}

	auth := NewAuthenticator(config)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.JSONEq(t, `{"code":"UNAUTHORIZED","message":"Invalid API key"}`, w.Body.String())
}

func TestAuthenticator_Middleware_MissingKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := AuthConfig{
		APIKeys: map[string]string{
			"admin": "sha256:somehash",
		},
	}

	auth := NewAuthenticator(config)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.JSONEq(t, `{"code":"UNAUTHORIZED","message":"API key required"}`, w.Body.String())
}

func TestAuthenticator_Middleware_CustomHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testKey := "custom-key"
	hash := sha256.Sum256([]byte(testKey))
	hashStr := "sha256:" + hex.EncodeToString(hash[:])

	config := AuthConfig{
		APIKeys: map[string]string{
			"user": hashStr,
		},
		HeaderName: "Authorization",
	}

	auth := NewAuthenticator(config)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", testKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}
