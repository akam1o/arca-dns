package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

const (
	rateLimiterCleanupInterval = 5 * time.Minute
	rateLimiterClientTTL       = 10 * time.Minute
)

// RateLimiterConfig configures rate limiting.
type RateLimiterConfig struct {
	// ReadRPS is requests per second for read operations (GET)
	ReadRPS int
	// WriteRPS is requests per second for write operations (POST, PUT, DELETE)
	WriteRPS int
	// Burst is the maximum burst size
	Burst int
}

// DefaultRateLimiterConfig returns default rate limiter configuration.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		ReadRPS:  100, // 100 reads/sec per client
		WriteRPS: 10,  // 10 writes/sec per client
		Burst:    20,  // Allow burst of 20 requests
	}
}

// clientLimiter tracks rate limiters per client IP.
type clientLimiter struct {
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
	lastSeen     time.Time
}

// RateLimiter provides per-client rate limiting with separate read/write limits.
type RateLimiter struct {
	config      RateLimiterConfig
	clients     map[string]*clientLimiter
	lastCleanup time.Time
	mu          sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with the given configuration.
func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
	return &RateLimiter{
		config:      config,
		clients:     make(map[string]*clientLimiter),
		lastCleanup: time.Now(),
	}
}

// Middleware returns a Gin middleware that enforces rate limiting.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP (support X-Forwarded-For for proxied requests)
		clientIP := c.ClientIP()

		// Determine if this is a read or write operation
		isWrite := c.Request.Method == http.MethodPost ||
			c.Request.Method == http.MethodPut ||
			c.Request.Method == http.MethodDelete ||
			c.Request.Method == http.MethodPatch

		// Get or create limiter for this client
		limiter := rl.getLimiter(clientIP, isWrite)

		// Check if request is allowed
		if !limiter.Allow() {
			c.Header("Retry-After", "1")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please slow down.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getLimiter returns the appropriate rate limiter for the client.
func (rl *RateLimiter) getLimiter(clientIP string, isWrite bool) *rate.Limiter {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if now.Sub(rl.lastCleanup) >= rateLimiterCleanupInterval {
		rl.cleanupStaleClientsLocked(now)
		rl.lastCleanup = now
	}

	cl, exists := rl.clients[clientIP]
	if !exists {
		cl = &clientLimiter{
			readLimiter:  rate.NewLimiter(rate.Limit(rl.config.ReadRPS), rl.config.Burst),
			writeLimiter: rate.NewLimiter(rate.Limit(rl.config.WriteRPS), rl.config.Burst),
			lastSeen:     now,
		}
		rl.clients[clientIP] = cl
	}

	// Update last seen
	cl.lastSeen = now

	if isWrite {
		return cl.writeLimiter
	}
	return cl.readLimiter
}

// cleanupStaleClientsLocked removes clients that haven't been seen recently.
func (rl *RateLimiter) cleanupStaleClientsLocked(now time.Time) {
	for ip, cl := range rl.clients {
		if now.Sub(cl.lastSeen) > rateLimiterClientTTL {
			delete(rl.clients, ip)
		}
	}
}
