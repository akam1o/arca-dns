package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthConfig configures API key authentication.
type AuthConfig struct {
	// APIKeys maps key names to SHA256 hashes of the actual keys
	// Format: "key_name" -> "sha256:hash"
	APIKeys map[string]string
	// HeaderName is the HTTP header to check for the API key
	HeaderName string
}

// Authenticator provides API key authentication middleware.
type Authenticator struct {
	config AuthConfig
}

// NewAuthenticator creates a new API key authenticator.
func NewAuthenticator(config AuthConfig) *Authenticator {
	if config.HeaderName == "" {
		config.HeaderName = "X-API-Key"
	}
	config.APIKeys = normalizeConfiguredAPIKeys(config.APIKeys)
	return &Authenticator{
		config: config,
	}
}

func normalizeConfiguredAPIKeys(apiKeys map[string]string) map[string]string {
	if len(apiKeys) == 0 {
		return apiKeys
	}

	normalized := make(map[string]string, len(apiKeys))
	for name, hash := range apiKeys {
		normalized[name] = strings.ToLower(strings.TrimSpace(hash))
	}
	return normalized
}

// Middleware returns a Gin middleware that enforces API key authentication.
func (a *Authenticator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from header
		apiKey := c.GetHeader(a.config.HeaderName)
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "API key required",
			})
			c.Abort()
			return
		}

		// Hash the provided key
		hash := sha256.Sum256([]byte(apiKey))
		providedHash := "sha256:" + hex.EncodeToString(hash[:])

		// Check against configured keys (constant-time comparison)
		authenticated := false
		var principal string
		for name, expectedHash := range a.config.APIKeys {
			if subtle.ConstantTimeCompare([]byte(providedHash), []byte(expectedHash)) == 1 {
				authenticated = true
				principal = name
				break
			}
		}

		if !authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid API key",
			})
			c.Abort()
			return
		}

		// Store auth principal in context for audit logging
		c.Set("auth_principal", principal)
		c.Next()
	}
}
