package api

import (
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SetupRouter configures the Gin router with authenticated management API routes.
func SetupRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger) *gin.Engine {
	return SetupAPIRouter(handler, cfg, logger)
}

// SetupAPIRouter configures the Gin router with authenticated management API routes.
func SetupAPIRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	router := newControllerRouter(handler, cfg, logger, true)

	// Audit and rate limiting are scoped to the management API listener.
	auditLogger := middleware.NewAuditLogger(logger)
	router.Use(auditLogger.Middleware())

	if cfg != nil && cfg.RateLimit.Enabled {
		rateLimiterConfig := middleware.DefaultRateLimiterConfig()
		rateLimiterConfig.ReadRPS = cfg.RateLimit.RequestsPerSecond
		rateLimiterConfig.WriteRPS = writeRPSFromReadRPS(cfg.RateLimit.RequestsPerSecond)
		rateLimiterConfig.Burst = cfg.RateLimit.Burst

		rateLimiter := middleware.NewRateLimiter(rateLimiterConfig)
		router.Use(rateLimiter.Middleware())
	}

	// API v1 routes (with authentication if enabled)
	v1 := router.Group("/api/v1")

	requestValidator := middleware.NewRequestValidator()

	protected := v1.Group("")
	if cfg != nil && cfg.Auth.Enabled {
		authConfig := middleware.AuthConfig{
			APIKeys:    cfg.Auth.APIKeys,
			HeaderName: "X-API-Key",
		}
		authenticator := middleware.NewAuthenticator(authConfig)
		protected.Use(authenticator.Middleware())
	}
	protected.Use(requestValidator.Middleware())
	{
		// Zone management
		protected.POST("/zones", handler.CreateZone)
		protected.POST("/zones/raw", handler.CreateZoneRaw) // Raw BIND format
		protected.GET("/zones", handler.ListZones)
		protected.HEAD("/zones/:name", handler.HeadZone)
		protected.GET("/zones/:name", handler.GetZone)
		protected.GET("/zones/:name/versions", handler.ListZoneVersions)
		protected.GET("/zones/:name/versions/:version", handler.GetZoneRevision)
		protected.PUT("/zones/:name", handler.UpdateZone)
		protected.DELETE("/zones/:name", handler.DeleteZone)
		protected.GET("/zones/:name/records", handler.ListRecords)
		protected.POST("/zones/:name/records", handler.CreateRecord)
		protected.POST("/zones/:name/records/batch", handler.BulkRecords)
		protected.PUT("/zones/:name/records/:id", handler.UpdateRecord)
		protected.DELETE("/zones/:name/records/:id", handler.DeleteRecord)

		// Zone file download (for agents)
		protected.HEAD("/zones/:name/signed", handler.HeadSignedZone)
		protected.GET("/zones/:name/signed", handler.GetSignedZone)
		protected.GET("/zones/:name/signed/metadata", handler.GetSignedZoneMetadata)
		protected.GET("/zones/:name/ds", handler.GetDSRecords)
		protected.GET("/zones/:name/dnssec/ds", handler.GetDSRecords)
	}

	return router
}

// SetupObservabilityRouter configures unauthenticated operational endpoints for
// the controller observability listener.
func SetupObservabilityRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := newControllerRouter(handler, cfg, logger, false)
	registerObservabilityRoutes(router, handler)

	// Keep the historical /api/v1 aliases on the observability listener only.
	v1 := router.Group("/api/v1")
	registerObservabilityRoutes(v1, handler)

	return router
}

func newControllerRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger, includeMetrics bool) *gin.Engine {
	router := gin.New()

	router.Use(gin.Recovery())
	if includeMetrics && handler != nil && handler.metrics != nil {
		router.Use(handler.metrics.Middleware())
	}

	if cfg != nil && len(cfg.TrustedProxies) > 0 {
		if err := router.SetTrustedProxies(cfg.TrustedProxies); err != nil {
			logger.Warn("Failed to set trusted proxies", zap.Error(err))
		}
	} else {
		if err := router.SetTrustedProxies(nil); err != nil {
			logger.Warn("Failed to disable trusted proxies", zap.Error(err))
		}
	}

	return router
}

type routeGroup interface {
	GET(string, ...gin.HandlerFunc) gin.IRoutes
}

func registerObservabilityRoutes(routes routeGroup, handler *Handler) {
	routes.GET("/health", handler.Health)
	routes.GET("/ready", handler.Ready)
	routes.GET("/status", handler.Status)
	routes.GET("/metrics", handler.Metrics)
}

func writeRPSFromReadRPS(readRPS int) int {
	writeRPS := readRPS / 10
	if writeRPS < 1 {
		return 1
	}
	return writeRPS
}
