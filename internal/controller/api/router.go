package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SetupRouter configures the Gin router with all routes.
func SetupRouter(handler *Handler, logger *zap.Logger) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(LoggerMiddleware(logger))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// API v1 routes
	v1 := router.Group("/api/v1")
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

// LoggerMiddleware is a Gin middleware that logs requests using zap.
func LoggerMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Process request
		c.Next()

		// Log request
		logger.Info("Request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}
