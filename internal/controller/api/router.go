package api

import (
	"net/http"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/middleware"
	"github.com/akam1o/arca-dns/pkg/model"
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
			APIKeys:     cfg.Auth.APIKeys,
			APIKeyRoles: cfg.Auth.APIKeyRoles,
			HeaderName:  "X-API-Key",
		}
		authenticator := middleware.NewAuthenticator(authConfig)
		protected.Use(authenticator.Middleware())
	}

	authEnabled := cfg != nil && cfg.Auth.Enabled
	adminOnly := protected.Group("")
	adminOnly.Use(roleGuard(authEnabled, middleware.AuthRoleAdmin), requestValidator.Middleware())
	agentReadable := protected.Group("")
	agentReadable.Use(roleGuard(authEnabled, middleware.AuthRoleAgent), requestValidator.Middleware())
	{
		// Zone management
		adminOnly.POST("/zones", handler.CreateZone)
		adminOnly.POST("/zones/raw", handler.CreateZoneRaw) // Raw BIND format
		agentReadable.GET("/zones", requireSummaryListForAgent(), handler.ListZones)
		adminOnly.HEAD("/zones/:name", handler.HeadZone)
		adminOnly.GET("/zones/:name", handler.GetZone)
		adminOnly.GET("/zones/:name/versions", handler.ListZoneVersions)
		adminOnly.GET("/zones/:name/versions/:version", handler.GetZoneRevision)
		adminOnly.PUT("/zones/:name", handler.UpdateZone)
		adminOnly.DELETE("/zones/:name", handler.DeleteZone)
		adminOnly.GET("/zones/:name/records", handler.ListRecords)
		adminOnly.POST("/zones/:name/records", handler.CreateRecord)
		adminOnly.POST("/zones/:name/records/batch", handler.BulkRecords)
		adminOnly.PUT("/zones/:name/records/:id", handler.UpdateRecord)
		adminOnly.DELETE("/zones/:name/records/:id", handler.DeleteRecord)

		// Zone file download (for agents)
		agentReadable.HEAD("/zones/:name/signed", handler.HeadSignedZone)
		agentReadable.GET("/zones/:name/signed", handler.GetSignedZone)
		agentReadable.GET("/zones/:name/signed/metadata", handler.GetSignedZoneMetadata)
		adminOnly.GET("/zones/:name/ds", handler.GetDSRecords)
		adminOnly.GET("/zones/:name/dnssec/ds", handler.GetDSRecords)
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

func roleGuard(authEnabled bool, allowedRoles ...string) gin.HandlerFunc {
	if !authEnabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	return middleware.RequireRole(allowedRoles...)
}

func requireSummaryListForAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("auth_role") != middleware.AuthRoleAgent || listZonesSummaryOnly(c) {
			c.Next()
			return
		}

		c.JSON(http.StatusForbidden, model.NewAPIErrorWithDetails(
			model.ErrorCodeForbidden,
			"Agent API keys may only list zone summaries",
			map[string]interface{}{"required_query": "fields=summary"},
		))
		c.Abort()
	}
}

func writeRPSFromReadRPS(readRPS int) int {
	writeRPS := readRPS / 10
	if writeRPS < 1 {
		return 1
	}
	return writeRPS
}
