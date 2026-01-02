package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
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
		c.JSON(200, gin.H{"principal": principal})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", testKey)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "test_admin")
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
	assert.Contains(t, w.Body.String(), "Invalid API key")
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
	assert.Contains(t, w.Body.String(), "API key required")
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
