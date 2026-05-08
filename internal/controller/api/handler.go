package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	artifactSignatureKey string
}

// BuildInfo is returned by /status.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type createZoneRequest struct {
	Name    string          `json:"name"`
	SOA     model.SOARecord `json:"soa"`
	Records []model.Record  `json:"records"`
}

type updateZoneRequest struct {
	Name string          `json:"name"`
	SOA  model.SOARecord `json:"soa"`
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

// SetArtifactSignatureKey configures HMAC signing for signed-zone artifact responses.
func (h *Handler) SetArtifactSignatureKey(key string) {
	h.artifactSignatureKey = strings.TrimSpace(key)
}

// Health handles GET /health on the observability listener.
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Ready handles GET /ready on the observability listener.
// Readiness includes backend connectivity (best-effort) to match docs.
func (h *Handler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	_, err := h.store.ListZones(ctx, backend.ListOptions{Limit: 1, Offset: 0})
	if err != nil {
		h.logger.Warn("Readiness check failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"error":  "backend unavailable",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// Status handles GET /status on the observability listener.
func (h *Handler) Status(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "operational",
		"version": h.buildInfo.Version,
		"commit":  h.buildInfo.Commit,
		"date":    h.buildInfo.Date,
	})
}

// Metrics handles GET /metrics on the observability listener.
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
	var req createZoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Invalid request body",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	zone := model.Zone{
		Name:    req.Name,
		SOA:     req.SOA,
		Records: append([]model.Record(nil), req.Records...),
	}
	for i := range zone.Records {
		zone.Records[i].ID = ""
	}

	if err := model.NormalizeZoneDerivedFields(&zone); err != nil {
		h.logger.Warn("Zone normalization failed", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone validation failed",
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

	// Issue a new version (controller-generated).
	version, err := model.NewZoneVersion()
	if err != nil {
		h.logger.Error("Failed to generate zone version", zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to generate zone version",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}
	zone.Version = version

	signedWrite, ok := h.prepareSignedZoneCreate(c, &zone, "creation")
	if !ok {
		return
	}
	defer signedWrite.Abort()

	if !h.storeSignedZoneWrite(c, signedWrite, "zone creation") {
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

	if !h.commitSignedZoneWrite(c, signedWrite, "zone creation") {
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

	if !h.completeSignedZoneWrite(c, signedWrite, "zone creation") {
		return
	}

	// Set ETag header
	c.Header("ETag", formatETag(created.Version))
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
	c.Header("ETag", formatETag(zone.Version))

	// Conditional GET: return 304 when If-None-Match matches current version.
	ifNoneMatch := c.GetHeader("If-None-Match")
	if ifNoneMatch != "" && etagMatches(ifNoneMatch, zone.Version) {
		c.Status(http.StatusNotModified)
		return
	}

	c.JSON(http.StatusOK, zone)
}

// HeadZone handles HEAD /api/v1/zones/:name.
func (h *Handler) HeadZone(c *gin.Context) {
	name := c.Param("name")

	zone, err := h.store.GetZone(c.Request.Context(), name)
	if err != nil {
		if err == model.ErrZoneNotFound {
			c.Status(http.StatusNotFound)
			return
		}
		h.logger.Error("Failed to get zone", zap.String("zone", name), zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Header("ETag", formatETag(zone.Version))
	if ifNoneMatch := c.GetHeader("If-None-Match"); ifNoneMatch != "" && etagMatches(ifNoneMatch, zone.Version) {
		c.Status(http.StatusNotModified)
		return
	}

	c.Status(http.StatusOK)
}

func etagMatches(ifNoneMatch, current string) bool {
	// Handle wildcard
	if strings.TrimSpace(ifNoneMatch) == "*" {
		return true
	}

	// If-None-Match can be a comma-separated list. We accept exact match with optional quotes.
	for _, part := range strings.Split(ifNoneMatch, ",") {
		tag := strings.TrimSpace(part)
		tag = strings.TrimPrefix(tag, "W/")
		tag = strings.Trim(tag, "\"")
		if tag == current {
			return true
		}
	}
	return false
}

func formatETag(version string) string {
	// Strong ETag with quoted-string. Versions are URL-safe, so no escaping needed.
	return `"` + version + `"`
}

func rejectWildcardIfMatch(c *gin.Context, operation string) bool {
	if strings.TrimSpace(c.GetHeader("If-Match")) != "*" {
		return false
	}

	c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
		model.ErrorCodeInvalidInput,
		"If-Match wildcard is not supported for "+operation,
		map[string]interface{}{"header": "If-Match"},
	))
	return true
}

func sha256HexAndHash8(s string) (string, string) {
	sum := sha256.Sum256([]byte(s))
	hexSum := hex.EncodeToString(sum[:])
	if len(hexSum) < 8 {
		return hexSum, hexSum
	}
	return hexSum, hexSum[:8]
}

func signArtifact(body string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(body))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
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

	if listZonesSummaryOnly(c) {
		summaries, err := backend.ListZoneSummaries(c.Request.Context(), h.store, backend.ListOptions{
			Offset: offset,
			Limit:  limit,
		})
		if err != nil {
			h.logger.Error("Failed to list zone summaries", zap.Error(err))
			c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
				model.ErrorCodeInternal,
				"Failed to list zones",
				map[string]interface{}{"error": "internal error"},
			))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"zones": summaries,
			"pagination": gin.H{
				"offset": offset,
				"limit":  limit,
				"count":  len(summaries),
			},
		})
		return
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

func listZonesSummaryOnly(c *gin.Context) bool {
	fields := strings.ToLower(strings.TrimSpace(c.Query("fields")))
	return fields == "summary" || fields == "summaries"
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

	c.Header("ETag", formatETag(zone.Version))
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

	c.Header("ETag", formatETag(rev.Version))
	c.JSON(http.StatusOK, rev)
}

// UpdateZone handles PUT /api/v1/zones/:name
func (h *Handler) UpdateZone(c *gin.Context) {
	name := model.NormalizeZoneName(c.Param("name"))

	var req updateZoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Invalid request body",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	zone := model.Zone{
		Name: model.NormalizeZoneName(req.Name),
		SOA:  req.SOA,
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

	// Get If-Match header for optimistic locking (required)
	ifMatch := c.GetHeader("If-Match")
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"If-Match header is required for zone updates",
			map[string]interface{}{"header": "If-Match"},
		))
		return
	}
	if rejectWildcardIfMatch(c, "zone updates") {
		return
	}

	// Resolve If-Match into a concrete expected version (accepts quoted/unquoted, W/, and lists).
	expectedVersion := ""
	var current *model.Zone
	current, err := h.store.GetZone(c.Request.Context(), zone.Name)
	if err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": name},
			))
			return
		}
		h.logger.Error("Failed to get zone for If-Match evaluation", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to update zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	if !etagMatches(ifMatch, current.Version) {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeConflict,
			"Zone version mismatch (optimistic lock failure)",
			map[string]interface{}{"expected_version": ifMatch},
		))
		return
	}
	expectedVersion = current.Version

	zone.Records = current.Records
	zone.DNSSEC = current.DNSSEC

	if err := model.RepairZoneDerivedFields(&zone); err != nil {
		h.logger.Warn("Zone normalization failed", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone validation failed",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Validate zone after defaulting omitted fields.
	if err := model.ValidateZone(&zone); err != nil {
		h.logger.Warn("Zone validation failed", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone validation failed",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	if h.signingService == nil {
		// Keep update semantics controller-driven even though backends can accept
		// a trusted precomputed serial from the signing path.
		zone.SOA.Serial = 0
	}

	// Issue a new version (controller-generated).
	newVersion, err := model.NewZoneVersion()
	if err != nil {
		h.logger.Error("Failed to generate zone version", zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to generate zone version",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}
	zone.Version = newVersion

	signedWrite, ok := h.prepareSignedZoneUpdate(c, &zone, current.SOA.Serial, "update")
	if !ok {
		return
	}
	defer signedWrite.Abort()

	if !h.storeSignedZoneWrite(c, signedWrite, "zone update") {
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
				map[string]interface{}{"expected_version": ifMatch},
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

	if !h.commitSignedZoneWrite(c, signedWrite, "zone update") {
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

	if !h.completeSignedZoneWrite(c, signedWrite, "zone update") {
		return
	}

	// Set ETag header
	c.Header("ETag", formatETag(updated.Version))

	h.logger.Info("Zone updated", zap.String("zone", updated.Name), zap.String("version", updated.Version))
	c.JSON(http.StatusOK, updated)
}

// DeleteZone handles DELETE /api/v1/zones/:name
func (h *Handler) DeleteZone(c *gin.Context) {
	name := c.Param("name")

	ifMatch := c.GetHeader("If-Match")
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"If-Match header is required for zone deletes",
			map[string]interface{}{"header": "If-Match"},
		))
		return
	}
	if rejectWildcardIfMatch(c, "zone deletes") {
		return
	}

	current, err := h.store.GetZone(c.Request.Context(), name)
	if err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": name},
			))
			return
		}
		h.logger.Error("Failed to get zone for If-Match evaluation", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to delete zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	if !etagMatches(ifMatch, current.Version) {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeConflict,
			"Zone version mismatch (optimistic lock failure)",
			map[string]interface{}{"expected_version": ifMatch},
		))
		return
	}

	err = h.deleteZoneWithVersion(c.Request.Context(), name, current.Version)
	if err != nil {
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
				map[string]interface{}{"expected_version": ifMatch},
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

func (h *Handler) deleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	conditionalStore, ok := h.store.(backend.ConditionalDeleteStore)
	if ok {
		return conditionalStore.DeleteZoneWithVersion(ctx, name, expectedVersion)
	}

	// Custom backends may only implement the core ZoneStore contract. The
	// handler has already verified If-Match against the current version; without
	// ConditionalDeleteStore this fallback is best-effort rather than atomic.
	return h.store.DeleteZone(ctx, name)
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

	signedZone, err := h.signedZoneFile(c.Request.Context(), name, zone)
	if err != nil {
		h.logger.Error("Failed to get signed zone", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to retrieve signed zone",
			map[string]interface{}{"error": "signing failed"},
		))
		return
	}

	// Set headers for successful response
	hashHex, hash8 := sha256HexAndHash8(signedZone.zoneFile)
	artifactETag := formatETag(hashHex)
	c.Header("ETag", artifactETag)
	c.Header("X-Zone-Serial", fmt.Sprintf("%d", signedZone.serial))
	c.Header("X-Zone-Hash", hashHex)
	c.Header("X-Zone-Hash8", hash8)
	if h.artifactSignatureKey != "" {
		c.Header("X-Zone-Signature", signArtifact(signedZone.zoneFile, h.artifactSignatureKey))
	}

	if match := c.GetHeader("If-None-Match"); match != "" && etagMatches(match, hashHex) {
		c.Status(http.StatusNotModified)
		return
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone.signed", strings.TrimSuffix(signedZone.zoneName, ".")))

	h.logger.Info("Signed zone file served", zap.String("zone", name), zap.String("version", signedZone.version))
	c.String(http.StatusOK, signedZone.zoneFile)
}

// HeadSignedZone handles HEAD /api/v1/zones/:name/signed.
func (h *Handler) HeadSignedZone(c *gin.Context) {
	name := c.Param("name")

	zone, err := h.store.GetZone(c.Request.Context(), name)
	if err != nil {
		if err == model.ErrZoneNotFound {
			c.Status(http.StatusNotFound)
			return
		}
		h.logger.Error("Failed to get zone", zap.String("zone", name), zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	signedZone, err := h.signedZoneFile(c.Request.Context(), name, zone)
	if err != nil {
		h.logger.Error("Failed to get signed zone", zap.String("zone", name), zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	hashHex, hash8 := sha256HexAndHash8(signedZone.zoneFile)
	artifactETag := formatETag(hashHex)
	c.Header("ETag", artifactETag)
	c.Header("X-Zone-Serial", fmt.Sprintf("%d", signedZone.serial))
	c.Header("X-Zone-Hash", hashHex)
	c.Header("X-Zone-Hash8", hash8)
	if h.artifactSignatureKey != "" {
		c.Header("X-Zone-Signature", signArtifact(signedZone.zoneFile, h.artifactSignatureKey))
	}

	if match := c.GetHeader("If-None-Match"); match != "" && etagMatches(match, hashHex) {
		c.Status(http.StatusNotModified)
		return
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone.signed", strings.TrimSuffix(signedZone.zoneName, ".")))
	c.Header("Content-Length", strconv.Itoa(len(signedZone.zoneFile)))
	c.Status(http.StatusOK)
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

	signedZone, err := h.signedZoneFile(c.Request.Context(), name, zone)
	if err != nil {
		h.logger.Error("Failed to get signed zone for metadata", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to retrieve signed zone metadata",
			map[string]interface{}{"error": "signing failed"},
		))
		return
	}

	hashHex, hash8 := sha256HexAndHash8(signedZone.zoneFile)
	c.Header("ETag", formatETag(hashHex))
	c.Header("X-Zone-Serial", fmt.Sprintf("%d", signedZone.serial))
	c.Header("X-Zone-Hash", hashHex)
	c.Header("X-Zone-Hash8", hash8)

	if ifNoneMatch := c.GetHeader("If-None-Match"); ifNoneMatch != "" && etagMatches(ifNoneMatch, hashHex) {
		c.Status(http.StatusNotModified)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"zone":           signedZone.zoneName,
		"version":        signedZone.version,
		"serial":         signedZone.serial,
		"hash":           hashHex,
		"hash8":          hash8,
		"dnssec_enabled": signedZone.dnssecConfig != nil && signedZone.dnssecConfig.Enabled,
	})
}

type signedZoneResult struct {
	zoneName     string
	version      string
	serial       uint32
	zoneFile     string
	dnssecConfig *model.DNSSECConfig
}

func (h *Handler) signedZoneFile(ctx context.Context, name string, zone *model.Zone) (*signedZoneResult, error) {
	if h.signingService != nil {
		artifact, err := h.signingService.GetSignedZone(ctx, name)
		if err != nil {
			return nil, err
		}
		return &signedZoneResult{
			zoneName:     artifact.ZoneName,
			version:      artifact.Version,
			serial:       artifact.Serial,
			zoneFile:     artifact.SignedZone,
			dnssecConfig: artifact.DNSSEC,
		}, nil
	}

	zoneFile, err := parser.GenerateBINDZoneFile(zone)
	if err != nil {
		return nil, fmt.Errorf("generate zone file: %w", err)
	}
	return &signedZoneResult{
		zoneName:     zone.Name,
		version:      zone.Version,
		serial:       zone.SOA.Serial,
		zoneFile:     zoneFile,
		dnssecConfig: zone.DNSSEC,
	}, nil
}

func (h *Handler) prepareSignedZoneCreate(c *gin.Context, zone *model.Zone, operation string) (*service.SignedZoneWrite, bool) {
	if h.signingService == nil {
		return nil, true
	}
	zone.Name = model.NormalizeZoneName(zone.Name)
	if !h.ensureZoneAbsentBeforeSigning(c, zone.Name) {
		return nil, false
	}
	if zone.SOA.Serial == 0 {
		zone.SOA.Serial = backend.NextSOASerial(0)
	}
	return h.prepareSignedZoneWrite(c, zone, operation)
}

func (h *Handler) ensureZoneAbsentBeforeSigning(c *gin.Context, name string) bool {
	if _, err := h.store.GetZone(c.Request.Context(), name); err == nil {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeAlreadyExists,
			"Zone already exists",
			map[string]interface{}{"zone": name},
		))
		return false
	} else if err != model.ErrZoneNotFound {
		h.logger.Error("Failed to check zone before signing",
			zap.String("zone", name),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to create zone",
			map[string]interface{}{"error": "internal error"},
		))
		return false
	}
	return true
}

func (h *Handler) prepareSignedZoneUpdate(c *gin.Context, zone *model.Zone, currentSerial uint32, operation string) (*service.SignedZoneWrite, bool) {
	if h.signingService == nil {
		return nil, true
	}
	zone.Name = model.NormalizeZoneName(zone.Name)
	zone.SOA.Serial = backend.NextSOASerial(currentSerial)
	return h.prepareSignedZoneWrite(c, zone, operation)
}

func (h *Handler) prepareSignedZoneWrite(c *gin.Context, zone *model.Zone, operation string) (*service.SignedZoneWrite, bool) {
	if h.signingService == nil {
		return nil, true
	}

	signedWrite, err := h.signingService.PrepareSignedZoneWrite(c.Request.Context(), zone)
	if err != nil {
		h.logger.Error("Failed to sign zone before "+operation,
			zap.String("zone", zone.Name),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to sign zone",
			map[string]interface{}{"error": "signing failed"},
		))
		return nil, false
	}

	return signedWrite, true
}

func (h *Handler) storeSignedZoneWrite(c *gin.Context, signedWrite *service.SignedZoneWrite, operation string) bool {
	if h.signingService == nil || signedWrite == nil {
		return true
	}
	if err := signedWrite.Store(); err != nil {
		h.logger.Error("Failed to store signed zone artifact",
			zap.String("operation", operation),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to sign zone",
			map[string]interface{}{"error": "signing failed"},
		))
		return false
	}
	return true
}

func (h *Handler) commitSignedZoneWrite(c *gin.Context, signedWrite *service.SignedZoneWrite, operation string) bool {
	if h.signingService == nil || signedWrite == nil {
		return true
	}
	if err := signedWrite.Commit(); err != nil {
		h.logger.Error("Failed to commit signed zone write",
			zap.String("operation", operation),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to sign zone",
			map[string]interface{}{"error": "signing failed"},
		))
		return false
	}
	return true
}

func (h *Handler) completeSignedZoneWrite(c *gin.Context, signedWrite *service.SignedZoneWrite, operation string) bool {
	if h.signingService == nil || signedWrite == nil {
		return true
	}
	if err := signedWrite.Complete(); err != nil {
		h.logger.Error("Failed to complete signed zone write",
			zap.String("operation", operation),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to sign zone",
			map[string]interface{}{"error": "signing failed"},
		))
		return false
	}
	return true
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
