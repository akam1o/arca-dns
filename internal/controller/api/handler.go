package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/parser"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler handles HTTP requests for the controller API.
type Handler struct {
	store  backend.ZoneStore
	logger *zap.Logger
}

// NewHandler creates a new API handler.
func NewHandler(store backend.ZoneStore, logger *zap.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// CreateZone handles POST /api/v1/zones
func (h *Handler) CreateZone(c *gin.Context) {
	var zone model.Zone
	if err := c.ShouldBindJSON(&zone); err != nil {
		h.logger.Warn("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Invalid request body",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Validate zone
	if err := model.ValidateZone(&zone); err != nil {
		h.logger.Warn("Zone validation failed", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone validation failed",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Create zone in backend
	if err := h.store.CreateZone(c.Request.Context(), &zone); err != nil {
		if err == model.ErrZoneAlreadyExists {
			c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
				model.ErrorCodeAlreadyExists,
				"Zone already exists",
				map[string]interface{}{"zone": zone.Name},
			))
			return
		}
		h.logger.Error("Failed to create zone", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to create zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Retrieve created zone to get version
	created, err := h.store.GetZone(c.Request.Context(), zone.Name)
	if err != nil {
		h.logger.Error("Failed to retrieve created zone", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Zone created but failed to retrieve",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Set ETag header
	c.Header("ETag", created.Version)
	c.Header("Location", "/api/v1/zones/"+created.Name)

	h.logger.Info("Zone created", zap.String("zone", created.Name), zap.String("version", created.Version))
	c.JSON(http.StatusCreated, created)
}

// GetZone handles GET /api/v1/zones/:name
func (h *Handler) GetZone(c *gin.Context) {
	name := c.Param("name")

	zone, err := h.store.GetZone(c.Request.Context(), name)
	if err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": name},
			))
			return
		}
		h.logger.Error("Failed to get zone", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to retrieve zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Set ETag header
	c.Header("ETag", zone.Version)

	c.JSON(http.StatusOK, zone)
}

// ListZones handles GET /api/v1/zones
func (h *Handler) ListZones(c *gin.Context) {
	// Parse pagination parameters
	offset := 0
	limit := 100 // Default limit

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil && val >= 0 {
			offset = val
		}
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 1000 {
			limit = val
		}
	}

	zones, err := h.store.ListZones(c.Request.Context(), backend.ListOptions{
		Offset: offset,
		Limit:  limit,
	})
	if err != nil {
		h.logger.Error("Failed to list zones", zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to list zones",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Return zones with pagination metadata
	c.JSON(http.StatusOK, gin.H{
		"zones": zones,
		"pagination": gin.H{
			"offset": offset,
			"limit":  limit,
			"count":  len(zones),
		},
	})
}

// UpdateZone handles PUT /api/v1/zones/:name
func (h *Handler) UpdateZone(c *gin.Context) {
	name := c.Param("name")

	var zone model.Zone
	if err := c.ShouldBindJSON(&zone); err != nil {
		h.logger.Warn("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Invalid request body",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Ensure zone name matches URL
	if zone.Name != name {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone name in body does not match URL",
			map[string]interface{}{"url": name, "body": zone.Name},
		))
		return
	}

	// Validate zone
	if err := model.ValidateZone(&zone); err != nil {
		h.logger.Warn("Zone validation failed", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone validation failed",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Get If-Match header for optimistic locking (required)
	expectedVersion := c.GetHeader("If-Match")
	if expectedVersion == "" {
		c.JSON(http.StatusPreconditionRequired, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"If-Match header is required for zone updates",
			map[string]interface{}{"header": "If-Match"},
		))
		return
	}

	// Update zone in backend
	if err := h.store.UpdateZone(c.Request.Context(), &zone, expectedVersion); err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": name},
			))
			return
		}
		if err == model.ErrConflict {
			c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
				model.ErrorCodeConflict,
				"Zone version mismatch (optimistic lock failure)",
				map[string]interface{}{"expected_version": expectedVersion},
			))
			return
		}
		h.logger.Error("Failed to update zone", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to update zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Retrieve updated zone to get new version
	updated, err := h.store.GetZone(c.Request.Context(), zone.Name)
	if err != nil {
		h.logger.Error("Failed to retrieve updated zone", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Zone updated but failed to retrieve",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Set ETag header
	c.Header("ETag", updated.Version)

	h.logger.Info("Zone updated", zap.String("zone", updated.Name), zap.String("version", updated.Version))
	c.JSON(http.StatusOK, updated)
}

// DeleteZone handles DELETE /api/v1/zones/:name
func (h *Handler) DeleteZone(c *gin.Context) {
	name := c.Param("name")

	if err := h.store.DeleteZone(c.Request.Context(), name); err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": name},
			))
			return
		}
		h.logger.Error("Failed to delete zone", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to delete zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	h.logger.Info("Zone deleted", zap.String("zone", name))
	c.Status(http.StatusNoContent)
}

// GetSignedZone handles GET /api/v1/zones/:name/signed
// Returns the zone file in BIND format (unsigned for M1, will be signed in M4)
func (h *Handler) GetSignedZone(c *gin.Context) {
	name := c.Param("name")

	zone, err := h.store.GetZone(c.Request.Context(), name)
	if err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": name},
			))
			return
		}
		h.logger.Error("Failed to get zone", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to retrieve zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Check If-None-Match for conditional fetch BEFORE generating zone file (optimization)
	if match := c.GetHeader("If-None-Match"); match == zone.Version {
		// Set headers even on 304
		c.Header("ETag", zone.Version)
		c.Header("X-Zone-Serial", fmt.Sprintf("%d", zone.SOA.Serial))
		// Extract hash from version (format: v{serial}-{hash})
		parts := strings.Split(zone.Version, "-")
		if len(parts) == 2 {
			c.Header("X-Zone-Hash", parts[1])
		}
		c.Status(http.StatusNotModified)
		return
	}

	// Generate zone file
	zoneFile, err := parser.GenerateBINDZoneFile(zone)
	if err != nil {
		h.logger.Error("Failed to generate zone file", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to generate zone file",
			map[string]interface{}{"error": "zone generation failed"},
		))
		return
	}

	// Set headers for successful response
	c.Header("ETag", zone.Version)
	c.Header("X-Zone-Serial", fmt.Sprintf("%d", zone.SOA.Serial))
	// Extract hash from version (format: v{serial}-{hash})
	parts := strings.Split(zone.Version, "-")
	if len(parts) == 2 {
		c.Header("X-Zone-Hash", parts[1])
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone", strings.TrimSuffix(zone.Name, ".")))

	h.logger.Info("Zone file generated", zap.String("zone", name), zap.String("version", zone.Version))
	c.String(http.StatusOK, zoneFile)
}
