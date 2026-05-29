package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/gin-gonic/gin"
)

// AuthConfig configures API key authentication.
type AuthConfig struct {
	// APIKeys maps key names to SHA256 hashes of the actual keys
	// Format: "key_name" -> "sha256:hash"
	APIKeys map[string]string
	// APIKeyRoles maps key names to authorization roles.
	APIKeyRoles map[string]string
	// HeaderName is the HTTP header to check for the API key
	HeaderName string
	// AllowImplicitAdminRoles preserves legacy behavior where keys without an
	// explicit role are granted admin. Prefer explicit roles.
	AllowImplicitAdminRoles bool
}

const (
	// AuthRoleAdmin can access all management API endpoints.
	AuthRoleAdmin = "admin"
	// AuthRoleAgent can access only agent synchronization endpoints.
	AuthRoleAgent = "agent"
)

const (
	// AuthPermissionManageZones permits controller zone management operations.
	AuthPermissionManageZones = "zones:manage"
	// AuthPermissionReadSyncArtifacts permits reading synchronization artifacts.
	AuthPermissionReadSyncArtifacts = "sync_artifacts:read"
)

var rolePermissionPolicy = map[string]map[string]struct{}{
	AuthRoleAdmin: {
		AuthPermissionManageZones:       {},
		AuthPermissionReadSyncArtifacts: {},
	},
	AuthRoleAgent: {
		AuthPermissionReadSyncArtifacts: {},
	},
}

// Authenticator provides API key authentication middleware.
type Authenticator struct {
	config      AuthConfig
	credentials []apiKeyCredential
}

type apiKeyCredential struct {
	name string
	role string
	hash [sha256.Size]byte
}

// NewAuthenticator creates a new API key authenticator.
func NewAuthenticator(config AuthConfig) *Authenticator {
	if config.HeaderName == "" {
		config.HeaderName = "X-API-Key"
	}
	config.APIKeys = normalizeConfiguredAPIKeys(config.APIKeys)
	config.APIKeyRoles = normalizeConfiguredAPIKeyRoles(config.APIKeys, config.APIKeyRoles, config.AllowImplicitAdminRoles)
	return &Authenticator{
		config:      config,
		credentials: buildAPIKeyCredentials(config.APIKeys, config.APIKeyRoles),
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

func normalizeConfiguredAPIKeyRoles(apiKeys, apiKeyRoles map[string]string, allowImplicitAdminRoles bool) map[string]string {
	if len(apiKeys) == 0 {
		return apiKeyRoles
	}

	normalized := make(map[string]string, len(apiKeys))
	for name, role := range apiKeyRoles {
		normalized[name] = strings.ToLower(strings.TrimSpace(role))
	}
	if allowImplicitAdminRoles {
		for name := range apiKeys {
			if strings.TrimSpace(normalized[name]) == "" {
				normalized[name] = AuthRoleAdmin
			}
		}
	}
	return normalized
}

func buildAPIKeyCredentials(apiKeys, apiKeyRoles map[string]string) []apiKeyCredential {
	names := make([]string, 0, len(apiKeys))
	for name := range apiKeys {
		names = append(names, name)
	}
	sort.Strings(names)

	credentials := make([]apiKeyCredential, 0, len(names))
	for _, name := range names {
		hash, ok := parseSHA256APIKeyHash(apiKeys[name])
		if !ok {
			continue
		}
		role := strings.TrimSpace(apiKeyRoles[name])
		credentials = append(credentials, apiKeyCredential{
			name: name,
			role: role,
			hash: hash,
		})
	}
	return credentials
}

func parseSHA256APIKeyHash(value string) ([sha256.Size]byte, bool) {
	var hash [sha256.Size]byte
	const prefix = "sha256:"

	hexPart, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(value)), prefix)
	if !ok || len(hexPart) != sha256.Size*2 {
		return hash, false
	}
	decoded, err := hex.DecodeString(hexPart)
	if err != nil || len(decoded) != sha256.Size {
		return hash, false
	}
	copy(hash[:], decoded)
	return hash, true
}

// Middleware returns a Gin middleware that enforces API key authentication.
func (a *Authenticator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, role, authenticated := a.authenticateAPIKey(c.GetHeader(a.config.HeaderName))
		if !authenticated {
			if c.GetHeader(a.config.HeaderName) == "" {
				c.JSON(http.StatusUnauthorized, model.NewAPIError(model.ErrorCodeUnauthorized, "API key required"))
			} else {
				c.JSON(http.StatusUnauthorized, model.NewAPIError(model.ErrorCodeUnauthorized, "Invalid API key"))
			}
			c.Abort()
			return
		}

		// Store auth principal in context for audit logging
		c.Set("auth_principal", principal)
		c.Set("auth_role", role)
		c.Next()
	}
}

// FailureRateLimitMiddleware applies an IP-based rate limit only to requests
// that do not carry a configured API key. Successful requests should still use
// the regular rate limiter after authentication so principal-based limits apply.
func (a *Authenticator) FailureRateLimitMiddleware(rateLimiter *RateLimiter) gin.HandlerFunc {
	if rateLimiter == nil {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	rateLimitMiddleware := rateLimiter.Middleware()
	return func(c *gin.Context) {
		_, _, authenticated := a.authenticateAPIKey(c.GetHeader(a.config.HeaderName))
		if authenticated {
			c.Next()
			return
		}

		rateLimitMiddleware(c)
	}
}

func (a *Authenticator) authenticateAPIKey(apiKey string) (string, string, bool) {
	if apiKey == "" {
		return "", "", false
	}

	// Hash the provided key
	hash := sha256.Sum256([]byte(apiKey))

	// Check every configured key so successful authentication does not
	// change the number of hash comparisons performed.
	authenticated := false
	var principal string
	var role string
	for _, credential := range a.credentials {
		if subtle.ConstantTimeCompare(hash[:], credential.hash[:]) == 1 {
			if !authenticated {
				principal = credential.name
				role = credential.role
			}
			authenticated = true
		}
	}

	return principal, role, authenticated
}

// RequireRole returns a Gin middleware that authorizes authenticated requests by role.
// Admin keys are allowed through all role guards.
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		allowed[strings.ToLower(strings.TrimSpace(role))] = struct{}{}
	}

	return func(c *gin.Context) {
		role := strings.ToLower(strings.TrimSpace(c.GetString("auth_role")))
		if role == AuthRoleAdmin {
			c.Next()
			return
		}
		if _, ok := allowed[role]; ok {
			c.Next()
			return
		}

		c.JSON(http.StatusForbidden, model.NewAPIError(model.ErrorCodeForbidden, "API key role is not allowed for this endpoint"))
		c.Abort()
	}
}

// RequirePermission returns a Gin middleware that authorizes authenticated
// requests by permissions granted through the configured role policy.
func RequirePermission(requiredPermissions ...string) gin.HandlerFunc {
	required := make([]string, 0, len(requiredPermissions))
	for _, permission := range requiredPermissions {
		permission = strings.ToLower(strings.TrimSpace(permission))
		if permission != "" {
			required = append(required, permission)
		}
	}

	return func(c *gin.Context) {
		role := strings.ToLower(strings.TrimSpace(c.GetString("auth_role")))
		for _, permission := range required {
			if !roleHasPermission(role, permission) {
				c.JSON(http.StatusForbidden, model.NewAPIError(model.ErrorCodeForbidden, "API key role is not allowed for this endpoint"))
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func roleHasPermission(role string, permission string) bool {
	permissions, ok := rolePermissionPolicy[role]
	if !ok {
		return false
	}
	_, ok = permissions[permission]
	return ok
}
