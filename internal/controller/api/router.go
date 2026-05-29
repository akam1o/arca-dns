package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/middleware"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"go.uber.org/zap"
)

func init() {
	// Gin's JSON decoder strictness is process-global. Configure it once for
	// this API package so router construction does not repeatedly mutate it.
	binding.EnableDecoderDisallowUnknownFields = true
}

// SetupRouter configures status endpoints and authenticated management API routes.
func SetupRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger) *gin.Engine {
	return SetupAPIRouter(handler, cfg, logger)
}

// SetupAPIRouter configures status endpoints and authenticated management API routes.
func SetupAPIRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	router := newControllerRouter(handler, cfg, logger, true)

	registerHealthRoutes(router, handler)

	// Audit and rate limiting are scoped to the management API listener.
	auditLogger := middleware.NewAuditLogger(logger)
	router.Use(auditLogger.Middleware())

	// API v1 routes (with authentication if enabled)
	v1 := router.Group("/api/v1")

	requestValidator := middleware.NewRequestValidator()

	var authMiddleware gin.HandlerFunc
	var authFailureRateLimitMiddleware gin.HandlerFunc
	var rateLimitMiddleware gin.HandlerFunc
	var authenticator *middleware.Authenticator
	var rateLimiter *middleware.RateLimiter
	if cfg != nil && cfg.Auth.Enabled {
		authConfig := middleware.AuthConfig{
			APIKeys:                 cfg.Auth.APIKeys,
			APIKeyRoles:             cfg.Auth.APIKeyRoles,
			HeaderName:              "X-API-Key",
			AllowImplicitAdminRoles: cfg.Auth.AllowImplicitAdminRoles,
		}
		authenticator = middleware.NewAuthenticator(authConfig)
		authMiddleware = authenticator.Middleware()
	}
	if cfg != nil && cfg.RateLimit.Enabled {
		rateLimiterConfig := middleware.DefaultRateLimiterConfig()
		rateLimiterConfig.ReadRPS = cfg.RateLimit.RequestsPerSecond
		rateLimiterConfig.WriteRPS = writeRPSFromReadRPS(cfg.RateLimit.RequestsPerSecond)
		rateLimiterConfig.Burst = cfg.RateLimit.Burst

		rateLimiter = middleware.NewRateLimiter(rateLimiterConfig)
		rateLimitMiddleware = rateLimiter.Middleware()
	}
	if authenticator != nil && rateLimiter != nil {
		authFailureRateLimitMiddleware = authenticator.FailureRateLimitMiddleware(rateLimiter)
	}

	statusProtected := router.Group("")
	if authFailureRateLimitMiddleware != nil {
		statusProtected.Use(authFailureRateLimitMiddleware)
	}
	if authMiddleware != nil {
		statusProtected.Use(authMiddleware)
	}
	if rateLimitMiddleware != nil {
		statusProtected.Use(rateLimitMiddleware)
	}
	statusProtected.GET("/status", requestValidator.Middleware(), handler.Status)

	protected := v1.Group("")
	if authFailureRateLimitMiddleware != nil {
		protected.Use(authFailureRateLimitMiddleware)
	}
	if authMiddleware != nil {
		protected.Use(authMiddleware)
	}
	if rateLimitMiddleware != nil {
		protected.Use(rateLimitMiddleware)
	}

	authEnabled := cfg != nil && cfg.Auth.Enabled
	zoneManagement := protected.Group("")
	zoneManagement.Use(permissionGuard(authEnabled, middleware.AuthPermissionManageZones), requestValidator.Middleware())
	syncArtifacts := protected.Group("")
	syncArtifacts.Use(permissionGuard(authEnabled, middleware.AuthPermissionReadSyncArtifacts), requestValidator.Middleware())
	{
		// Zone management
		zoneManagement.POST("/zones", handler.CreateZone)
		zoneManagement.POST("/zones/raw", handler.CreateZoneRaw) // Raw BIND format
		syncArtifacts.GET("/zones", requireSummaryListForAgent(), handler.ListZones)
		zoneManagement.HEAD("/zones/:name", handler.HeadZone)
		zoneManagement.GET("/zones/:name", handler.GetZone)
		zoneManagement.GET("/zones/:name/versions", handler.ListZoneVersions)
		zoneManagement.GET("/zones/:name/versions/:version", handler.GetZoneRevision)
		zoneManagement.PUT("/zones/:name", handler.UpdateZone)
		zoneManagement.DELETE("/zones/:name", handler.DeleteZone)
		zoneManagement.GET("/zones/:name/records", handler.ListRecords)
		zoneManagement.POST("/zones/:name/records", handler.CreateRecord)
		zoneManagement.POST("/zones/:name/records/batch", handler.BulkRecords)
		zoneManagement.PUT("/zones/:name/records/:id", handler.UpdateRecord)
		zoneManagement.DELETE("/zones/:name/records/:id", handler.DeleteRecord)

		// Zone file download (for agents)
		syncArtifacts.HEAD("/zones/:name/signed", handler.HeadSignedZone)
		syncArtifacts.GET("/zones/:name/signed", handler.GetSignedZone)
		syncArtifacts.GET("/zones/:name/signed/metadata", handler.GetSignedZoneMetadata)
		zoneManagement.GET("/zones/:name/ds", handler.GetDSRecords)
		zoneManagement.GET("/zones/:name/dnssec/ds", handler.GetDSRecords)
	}

	return router
}

// SetupObservabilityRouter configures operational endpoints for the controller
// observability listener. It preserves the historical unauthenticated behavior;
// controller serving code should use SetupObservabilityRouterWithConfig.
func SetupObservabilityRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger) *gin.Engine {
	return SetupObservabilityRouterWithConfig(handler, cfg, nil, logger)
}

// SetupObservabilityRouterWithConfig configures operational endpoints for the
// controller observability listener.
func SetupObservabilityRouterWithConfig(handler *Handler, cfg *config.APIConfig, observability *config.ObservabilityConfig, logger *zap.Logger) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := newControllerRouter(handler, cfg, logger, false)
	statusAuth := observabilityAuthMiddleware(observabilityAuthToken(observability))
	registerObservabilityRoutes(router, handler, statusAuth)

	// Keep the historical /api/v1 aliases on the observability listener only.
	v1 := router.Group("/api/v1")
	registerObservabilityRoutes(v1, handler, statusAuth)

	return router
}

func newControllerRouter(handler *Handler, cfg *config.APIConfig, logger *zap.Logger, includeMetrics bool) *gin.Engine {
	router := gin.New()

	router.Use(controllerRecovery(logger))
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

func controllerRecovery(logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(c *gin.Context) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}

			logger.Error("request_panic_recovered",
				zap.Any("panic", recovered),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("request_id", c.GetString("request_id")),
				zap.String("client_ip", c.ClientIP()),
				zap.String("auth_principal", c.GetString("auth_principal")),
				zap.String("auth_role", c.GetString("auth_role")),
				zap.ByteString("stack", debug.Stack()),
			)

			if c.Writer.Written() {
				c.Abort()
				return
			}

			c.AbortWithStatusJSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
				model.ErrorCodeInternal,
				"Internal server error",
				map[string]interface{}{"error": "internal error"},
			))
		}()

		c.Next()
	}
}

type routeGroup interface {
	GET(string, ...gin.HandlerFunc) gin.IRoutes
}

func registerObservabilityRoutes(routes routeGroup, handler *Handler, statusAuth gin.HandlerFunc) {
	routes.GET("/health", handler.Health)
	routes.GET("/ready", handler.Ready)
	routes.GET("/status", statusAuth, handler.Status)
	routes.GET("/metrics", statusAuth, handler.Metrics)
}

func registerHealthRoutes(routes routeGroup, handler *Handler) {
	routes.GET("/health", handler.Health)
	routes.GET("/ready", handler.Ready)
}

func observabilityAuthToken(observability *config.ObservabilityConfig) string {
	if observability == nil {
		return ""
	}
	return observability.AuthToken
}

func observabilityAuthMiddleware(token string) gin.HandlerFunc {
	token = strings.TrimSpace(token)
	if token == "" {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		if observabilityAuthTokenMatches(c.GetHeader("Authorization"), token) {
			c.Next()
			return
		}

		c.Header("WWW-Authenticate", `Bearer realm="arca-dns-controller-observability"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func observabilityAuthTokenMatches(authHeader string, expected string) bool {
	const bearerPrefix = "bearer "
	value := strings.TrimSpace(authHeader)
	if len(value) < len(bearerPrefix) || !strings.EqualFold(value[:len(bearerPrefix)], bearerPrefix) {
		return false
	}
	provided := strings.TrimSpace(value[len(bearerPrefix):])
	if provided == "" {
		return false
	}
	providedHash := sha256.Sum256([]byte(provided))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) == 1
}

func permissionGuard(authEnabled bool, requiredPermissions ...string) gin.HandlerFunc {
	if !authEnabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	return middleware.RequirePermission(requiredPermissions...)
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
