package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// MaxRequestBodySize is the maximum allowed request body size (10MB)
	MaxRequestBodySize = 10 * 1024 * 1024
)

// RequestValidator provides request validation middleware.
type RequestValidator struct {
	maxBodySize int64
}

// NewRequestValidator creates a new request validator with default settings.
func NewRequestValidator() *RequestValidator {
	return &RequestValidator{
		maxBodySize: MaxRequestBodySize,
	}
}

// NewRequestValidatorWithMaxSize creates a new request validator with custom max body size.
func NewRequestValidatorWithMaxSize(maxSize int64) *RequestValidator {
	return &RequestValidator{
		maxBodySize: maxSize,
	}
}

// Middleware returns a Gin middleware that validates requests.
func (rv *RequestValidator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check request body size
		if c.Request.ContentLength > rv.maxBodySize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":    "request_too_large",
				"message":  "Request body exceeds maximum size limit",
				"max_size": rv.maxBodySize,
			})
			c.Abort()
			return
		}

		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, rv.maxBodySize)
		}

		c.Next()
	}
}
