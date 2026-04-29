package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

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
		// Generate request ID if not already present
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
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

		// Log audit entry
		al.logger.Info("api_request",
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("query", c.Request.URL.RawQuery),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
			zap.String("auth_principal", authPrincipal),
			zap.Int("response_size", c.Writer.Size()),
		)
	}
}
