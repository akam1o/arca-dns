package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_Middleware_ReadLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter with low limits for testing
	config := RateLimiterConfig{
		ReadRPS:  2, // 2 reads per second
		WriteRPS: 1,
		Burst:    2,
	}
	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First 2 requests should succeed (burst)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited")
	assert.Contains(t, w.Header().Get("Retry-After"), "1")
}

func TestRateLimiter_Middleware_WriteLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter with low limits for testing
	config := RateLimiterConfig{
		ReadRPS:  5,
		WriteRPS: 1, // 1 write per second
		Burst:    1,
	}
	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(rl.Middleware())
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First request should succeed
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should be rate limited
	req = httptest.NewRequest(http.MethodPost, "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimiter_Middleware_SeparateLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RateLimiterConfig{
		ReadRPS:  10,
		WriteRPS: 1,
		Burst:    1,
	}
	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Exhaust write limit
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Write should be rate limited
	req = httptest.NewRequest(http.MethodPost, "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// But read should still work (separate limit)
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Read should not be affected by write limit")
}

func TestRateLimiter_Middleware_PerClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RateLimiterConfig{
		ReadRPS:  1,
		WriteRPS: 1,
		Burst:    1,
	}
	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First client exhausts limit
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "192.0.2.1:1234"
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// First client should be rate limited
	req1_2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1_2.RemoteAddr = "192.0.2.1:1234"
	w1_2 := httptest.NewRecorder()
	router.ServeHTTP(w1_2, req1_2)
	assert.Equal(t, http.StatusTooManyRequests, w1_2.Code)

	// Second client should still work (different IP)
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "192.0.2.2:1234"
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "Different client should not be affected")
}

func TestRateLimiter_Middleware_RecoveryAfterWait(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RateLimiterConfig{
		ReadRPS:  10, // 10 per second = 100ms per request
		WriteRPS: 10,
		Burst:    1,
	}
	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request immediately should be rate limited
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Wait for rate limit to recover (150ms should be enough for 10 RPS)
	time.Sleep(150 * time.Millisecond)

	// Third request should succeed after waiting
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Request should succeed after rate limit recovery")
}

func TestRateLimiter_CleansStaleClientsOnRequest(t *testing.T) {
	config := RateLimiterConfig{
		ReadRPS:  10,
		WriteRPS: 10,
		Burst:    1,
	}
	rl := NewRateLimiter(config)

	rl.getLimiter("192.0.2.1", false)

	rl.mu.Lock()
	rl.clients["192.0.2.1"].lastSeen = time.Now().Add(-(rateLimiterClientTTL + time.Second))
	rl.lastCleanup = time.Now().Add(-(rateLimiterCleanupInterval + time.Second))
	rl.mu.Unlock()

	rl.getLimiter("192.0.2.2", false)

	rl.mu.RLock()
	_, staleExists := rl.clients["192.0.2.1"]
	_, currentExists := rl.clients["192.0.2.2"]
	rl.mu.RUnlock()

	assert.False(t, staleExists)
	assert.True(t, currentExists)
}

func TestDefaultRateLimiterConfig(t *testing.T) {
	config := DefaultRateLimiterConfig()
	assert.Equal(t, 100, config.ReadRPS)
	assert.Equal(t, 10, config.WriteRPS)
	assert.Equal(t, 20, config.Burst)
}
