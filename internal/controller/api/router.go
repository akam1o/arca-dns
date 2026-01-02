package api

import (
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SetupRouter configures the Gin router with all routes.
func SetupRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Core middleware
	router.Use(gin.Recovery())

	// Configure trusted proxies for ClientIP().
	// - If cfg.TrustedProxies is provided, trust only those.
	// - Otherwise, trust none (disable forwarded headers).
	if cfg != nil && len(cfg.TrustedProxies) > 0 {
		if err := router.SetTrustedProxies(cfg.TrustedProxies); err != nil {
			logger.Warn("Failed to set trusted proxies", zap.Error(err))
		}
	} else {
		if err := router.SetTrustedProxies(nil); err != nil {
			logger.Warn("Failed to disable trusted proxies", zap.Error(err))
		}
	}

	// Security middleware
	auditLogger := middleware.NewAuditLogger(logger)
	router.Use(auditLogger.Middleware())

	requestValidator := middleware.NewRequestValidator()
	router.Use(requestValidator.Middleware())

	// Rate limiting
	if cfg != nil && cfg.RateLimit.Enabled {
		rateLimiterConfig := middleware.DefaultRateLimiterConfig()
		rateLimiterConfig.ReadRPS = cfg.RateLimit.RequestsPerSecond
		rateLimiterConfig.WriteRPS = cfg.RateLimit.RequestsPerSecond / 10
		rateLimiterConfig.Burst = cfg.RateLimit.Burst

		rateLimiter := middleware.NewRateLimiter(rateLimiterConfig)
		router.Use(rateLimiter.Middleware())
	}

	// Health check endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	router.GET("/ready", func(c *gin.Context) {
		// TODO: Check backend connectivity
		c.JSON(200, gin.H{"status": "ready"})
	})

	router.GET("/status", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "operational",
			"version": "v1.0.0",
		})
	})

	// API v1 routes (with authentication if enabled)
	v1 := router.Group("/api/v1")
	if cfg != nil && cfg.Auth.Enabled && len(cfg.Auth.APIKeys) > 0 {
		authConfig := middleware.AuthConfig{
			APIKeys:    cfg.Auth.APIKeys,
			HeaderName: "X-API-Key",
		}
		authenticator := middleware.NewAuthenticator(authConfig)
		v1.Use(authenticator.Middleware())
	}
	{
		// Zone management
		v1.POST("/zones", handler.CreateZone)
		v1.POST("/zones/raw", handler.CreateZoneRaw) // Raw BIND format
		v1.GET("/zones", handler.ListZones)
		v1.GET("/zones/:name", handler.GetZone)
		v1.PUT("/zones/:name", handler.UpdateZone)
		v1.DELETE("/zones/:name", handler.DeleteZone)

		// Zone file download (for agents)
		v1.GET("/zones/:name/signed", handler.GetSignedZone)
		v1.GET("/zones/:name/ds", handler.GetDSRecords)
	}

	return router
}
