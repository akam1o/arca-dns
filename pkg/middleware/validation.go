package middleware

import (
	"bytes"
	"io"
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
				"error":   "request_too_large",
				"message": "Request body exceeds maximum size limit",
				"max_size": rv.maxBodySize,
			})
			c.Abort()
			return
		}

		// For requests with body, enforce size limit by reading with LimitReader
		// This handles both Content-Length and chunked/unknown-length bodies
		if c.Request.Body != nil {
			// Read body with size limit
			body, err := io.ReadAll(io.LimitReader(c.Request.Body, rv.maxBodySize+1))
			c.Request.Body.Close()

			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "invalid_request",
					"message": "Failed to read request body",
				})
				c.Abort()
				return
			}

			// Check if we read more than the limit
			if int64(len(body)) > rv.maxBodySize {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{
					"error":   "request_too_large",
					"message": "Request body exceeds maximum size limit",
					"max_size": rv.maxBodySize,
				})
				c.Abort()
				return
			}

			// Restore body for downstream handlers
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
			c.Request.ContentLength = int64(len(body))
		}

		c.Next()
	}
}
