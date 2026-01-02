package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	ctrlmetrics "github.com/akam1o/arca-dns/internal/controller/metrics"
	"github.com/akam1o/arca-dns/internal/controller/service"
	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/parser"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler handles HTTP requests for the controller API.
type Handler struct {
	store          backend.ZoneStore
	signingService *service.SigningService
	logger         *zap.Logger
	metrics        *ctrlmetrics.ControllerMetrics
	buildInfo      BuildInfo
}

// BuildInfo is returned by /status.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// NewHandler creates a new API handler.
func NewHandler(store backend.ZoneStore, signingService *service.SigningService, metrics *ctrlmetrics.ControllerMetrics, buildInfo BuildInfo, logger *zap.Logger) *Handler {
	return &Handler{
		store:          store,
		signingService: signingService,
		logger:         logger,
		metrics:        metrics,
		buildInfo:      buildInfo,
	}
}

// Health handles GET /health (and /api/v1/health).
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Ready handles GET /ready (and /api/v1/ready).
// Readiness includes backend connectivity (best-effort) to match docs.
func (h *Handler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	_, err := h.store.ListZones(ctx, backend.ListOptions{Limit: 1, Offset: 0})
	if err != nil {
		h.logger.Warn("Readiness check failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"error":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// Status handles GET /status (and /api/v1/status).
func (h *Handler) Status(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "operational",
		"version": h.buildInfo.Version,
		"commit":  h.buildInfo.Commit,
		"date":    h.buildInfo.Date,
	})
}

// Metrics handles GET /metrics.
func (h *Handler) Metrics(c *gin.Context) {
	if h.metrics == nil {
		c.String(http.StatusNotImplemented, "# metrics disabled\n")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	zonesTotal, err := ctrlmetrics.CountZones(ctx, h.store)
	if err != nil {
		h.logger.Warn("Failed to count zones for metrics", zap.Error(err))
		zonesTotal = 0
	}

	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.String(http.StatusOK, h.metrics.Render(zonesTotal))
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

	// Sign zone automatically (M4.5: auto-signing after create)
	if h.signingService != nil {
		if err := h.signingService.SignAndStoreZone(c.Request.Context(), created); err != nil {
			// Log error but don't fail the request - zone was created successfully
			h.logger.Warn("Failed to sign zone after creation",
				zap.String("zone", created.Name),
				zap.Error(err))
		}
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

	// Conditional GET: return 304 when If-None-Match matches current version.
	ifNoneMatch := c.GetHeader("If-None-Match")
	if ifNoneMatch != "" && etagMatches(ifNoneMatch, zone.Version) {
		c.Status(http.StatusNotModified)
		return
	}

	c.JSON(http.StatusOK, zone)
}

func etagMatches(ifNoneMatch, current string) bool {
	// Handle wildcard
	if strings.TrimSpace(ifNoneMatch) == "*" {
		return true
	}

	// If-None-Match can be a comma-separated list. We accept exact match with optional quotes.
	for _, part := range strings.Split(ifNoneMatch, ",") {
		tag := strings.TrimSpace(part)
		tag = strings.Trim(tag, "\"")
		if tag == current {
			return true
		}
	}
	return false
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

func versionHash(version string) string {
	parts := strings.Split(version, "-")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// ListZoneVersions handles GET /api/v1/zones/:name/versions
// Returns version history when the backend supports RevisionStore.
func (h *Handler) ListZoneVersions(c *gin.Context) {
	name := c.Param("name")

	// Ensure zone exists (consistent 404 for all backends)
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

	revisionStore, ok := h.store.(backend.RevisionStore)
	if !ok {
		c.JSON(http.StatusNotImplemented, model.NewAPIErrorWithDetails(
			model.ErrorCodeUnavailable,
			"Zone version history is not supported by the configured backend",
			map[string]interface{}{"backend": "current", "zone": name},
		))
		return
	}

	// Parse pagination parameters
	offset := 0
	limit := 10 // Default limit (matches OpenAPI)

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, convErr := strconv.Atoi(offsetStr); convErr == nil && val >= 0 {
			offset = val
		}
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if val, convErr := strconv.Atoi(limitStr); convErr == nil && val > 0 && val <= 1000 {
			limit = val
		}
	}

	versions, err := revisionStore.ListRevisions(c.Request.Context(), name, backend.ListOptions{
		Offset: offset,
		Limit:  limit,
	})
	if err != nil {
		h.logger.Error("Failed to list zone versions", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to list zone versions",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	for _, v := range versions {
		if v == nil {
			continue
		}
		v.Hash = versionHash(v.Version)
	}

	c.Header("ETag", zone.Version)
	c.JSON(http.StatusOK, gin.H{
		"versions": versions,
		"pagination": gin.H{
			"offset": offset,
			"limit":  limit,
			"count":  len(versions),
		},
	})
}

// GetZoneRevision handles GET /api/v1/zones/:name/versions/:version
// Returns the zone content at the requested historical version when supported by the backend.
func (h *Handler) GetZoneRevision(c *gin.Context) {
	name := c.Param("name")
	version := c.Param("version")

	// Ensure zone exists (consistent 404 for all backends)
	_, err := h.store.GetZone(c.Request.Context(), name)
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

	revisionStore, ok := h.store.(backend.RevisionStore)
	if !ok {
		c.JSON(http.StatusNotImplemented, model.NewAPIErrorWithDetails(
			model.ErrorCodeUnavailable,
			"Zone version history is not supported by the configured backend",
			map[string]interface{}{"backend": "current", "zone": name},
		))
		return
	}

	rev, err := revisionStore.GetRevision(c.Request.Context(), name, version)
	if err != nil {
		if err == model.ErrVersionNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone version not found",
				map[string]interface{}{"zone": name, "version": version},
			))
			return
		}
		h.logger.Error("Failed to get zone revision", zap.String("zone", name), zap.String("version", version), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to retrieve zone version",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	c.Header("ETag", rev.Version)
	c.JSON(http.StatusOK, rev)
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

	// Sign zone automatically (M4.5: auto-signing after update)
	if h.signingService != nil {
		if err := h.signingService.SignAndStoreZone(c.Request.Context(), updated); err != nil {
			// Log error but don't fail the request - zone was updated successfully
			h.logger.Warn("Failed to sign zone after update",
				zap.String("zone", updated.Name),
				zap.Error(err))
		}
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
// Returns the DNSSEC-signed zone file in BIND format (M4.5)
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

	// Get signed zone from signing service (M4.5)
	var zoneFile string
	if h.signingService != nil {
		artifact, err := h.signingService.GetSignedZone(c.Request.Context(), name)
		if err != nil {
			h.logger.Error("Failed to get signed zone", zap.String("zone", name), zap.Error(err))
			c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
				model.ErrorCodeInternal,
				"Failed to retrieve signed zone",
				map[string]interface{}{"error": "signing failed"},
			))
			return
		}
		zoneFile = artifact.SignedZone
	} else {
		// Fallback to unsigned zone if signing service is not available
		zoneFile, err = parser.GenerateBINDZoneFile(zone)
		if err != nil {
			h.logger.Error("Failed to generate zone file", zap.String("zone", name), zap.Error(err))
			c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
				model.ErrorCodeInternal,
				"Failed to generate zone file",
				map[string]interface{}{"error": "zone generation failed"},
			))
			return
		}
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
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone.signed", strings.TrimSuffix(zone.Name, ".")))

	h.logger.Info("Signed zone file served", zap.String("zone", name), zap.String("version", zone.Version))
	c.String(http.StatusOK, zoneFile)
}

// GetSignedZoneMetadata handles GET /api/v1/zones/:name/signed/metadata
// Returns machine-readable metadata for the signed zone artifact without returning the zone file content.
func (h *Handler) GetSignedZoneMetadata(c *gin.Context) {
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

	// Set headers (same metadata headers as /signed).
	c.Header("ETag", zone.Version)
	c.Header("X-Zone-Serial", fmt.Sprintf("%d", zone.SOA.Serial))
	if hash := versionHash(zone.Version); hash != "" {
		c.Header("X-Zone-Hash", hash)
	}

	// Conditional GET: return 304 when If-None-Match matches current version.
	ifNoneMatch := c.GetHeader("If-None-Match")
	if ifNoneMatch != "" && etagMatches(ifNoneMatch, zone.Version) {
		c.Status(http.StatusNotModified)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"zone":           zone.Name,
		"version":        zone.Version,
		"serial":         zone.SOA.Serial,
		"hash":           versionHash(zone.Version),
		"dnssec_enabled": zone.DNSSEC != nil && zone.DNSSEC.Enabled,
	})
}

// GetDSRecords handles GET /api/v1/zones/:name/ds
// Returns DS records for parent zone delegation (M4.5)
func (h *Handler) GetDSRecords(c *gin.Context) {
	name := c.Param("name")

	// Check if signing service is available
	if h.signingService == nil {
		c.JSON(http.StatusServiceUnavailable, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"DNSSEC signing service not available",
			map[string]interface{}{"zone": name},
		))
		return
	}

	// Check if zone exists
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

	// Get DS records from signing service
	dsRecords, err := h.signingService.GetDSRecords(c.Request.Context(), name)
	if err != nil {
		h.logger.Error("Failed to get DS records", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to generate DS records",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Return DS records as plain text (one per line)
	response := strings.Join(dsRecords, "\n") + "\n"

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("X-Zone-Name", zone.Name)
	c.Header("X-Zone-Version", zone.Version)

	h.logger.Info("DS records served", zap.String("zone", name), zap.Int("count", len(dsRecords)))
	c.String(http.StatusOK, response)
}
