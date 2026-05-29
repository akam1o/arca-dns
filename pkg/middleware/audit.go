package middleware

import (
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	maxAuditLogFieldLength  = 1024
	maxAuditRequestIDLength = 128
	auditLogRedactedValue   = "REDACTED"
	auditLogTruncatedMark   = "...(truncated)"
)

var sensitiveAuditQueryKeys = map[string]struct{}{
	"access_token":             {},
	"access_key":               {},
	"api_key":                  {},
	"apikey":                   {},
	"artifact_signature_key":   {},
	"auth_token":               {},
	"authorization":            {},
	"bearer":                   {},
	"client_secret":            {},
	"controller_signature_key": {},
	"id_token":                 {},
	"jwt":                      {},
	"password":                 {},
	"passwd":                   {},
	"refresh_token":            {},
	"secret":                   {},
	"secret_key":               {},
	"session":                  {},
	"session_id":               {},
	"signature":                {},
	"signature_key":            {},
	"token":                    {},
	"vault_token":              {},
	"x_api_key":                {},
}

var sensitiveAuditQueryKeySuffixes = []string{
	"_access_key",
	"_access_token",
	"_api_key",
	"_auth_token",
	"_authorization",
	"_bearer",
	"_id_token",
	"_jwt",
	"_passwd",
	"_password",
	"_refresh_token",
	"_secret",
	"_secret_key",
	"_signature",
	"_signature_key",
	"_session",
	"_session_id",
	"_token",
}

var auditQueryKeyReplacer = strings.NewReplacer("-", "_", ".", "_", "[", "_", "]", "")

// AuditLogger provides audit logging middleware for API requests.
type AuditLogger struct {
	logger *zap.Logger
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(logger *zap.Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger,
	}
}

// Middleware returns a Gin middleware that logs all API requests.
func (al *AuditLogger) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, generated := auditRequestID(c.GetHeader("X-Request-ID"))
		if generated {
			c.Header("X-Request-ID", requestID)
		}

		// Store request ID in context for other handlers
		c.Set("request_id", requestID)

		// Record start time
		start := time.Now()

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Extract auth info after downstream middleware has populated it.
		authPrincipal := c.GetString("auth_principal")
		if authPrincipal == "" {
			authPrincipal = "anonymous"
		}
		authRole := c.GetString("auth_role")
		if authRole == "" {
			authRole = "none"
		}

		// Log audit entry
		al.logger.Info("api_request",
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("query", sanitizeAuditQuery(c.Request.URL.RawQuery)),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", truncateAuditLogField(c.Request.UserAgent())),
			zap.String("auth_principal", authPrincipal),
			zap.String("auth_role", authRole),
			zap.Int("response_size", c.Writer.Size()),
		)
	}
}

func auditRequestID(headerValue string) (string, bool) {
	requestID := strings.TrimSpace(headerValue)
	if requestID == "" || len(requestID) > maxAuditRequestIDLength || strings.ContainsFunc(requestID, isControlCharacter) {
		return uuid.New().String(), true
	}
	return requestID, false
}

func isControlCharacter(r rune) bool {
	return r < 0x20 || r == 0x7f
}

func sanitizeAuditQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	parts := strings.Split(rawQuery, "&")
	for i, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		if !isSensitiveAuditQueryKey(key) {
			continue
		}

		parts[i] = key + "=" + auditLogRedactedValue
	}

	return truncateAuditLogField(strings.Join(parts, "&"))
}

func isSensitiveAuditQueryKey(key string) bool {
	decodedKey, err := url.QueryUnescape(key)
	if err != nil {
		decodedKey = key
	}

	normalizedKey := normalizeAuditQueryKey(decodedKey)
	if _, ok := sensitiveAuditQueryKeys[normalizedKey]; ok {
		return true
	}

	for _, suffix := range sensitiveAuditQueryKeySuffixes {
		if strings.HasSuffix(normalizedKey, suffix) {
			return true
		}
	}

	return false
}

func normalizeAuditQueryKey(key string) string {
	return auditQueryKeyReplacer.Replace(strings.ToLower(strings.TrimSpace(key)))
}

func truncateAuditLogField(value string) string {
	if len(value) <= maxAuditLogFieldLength {
		return value
	}

	return value[:maxAuditLogFieldLength] + auditLogTruncatedMark
}
