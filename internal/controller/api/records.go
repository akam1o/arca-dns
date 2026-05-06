package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ListRecords handles GET /api/v1/zones/:name/records.
func (h *Handler) ListRecords(c *gin.Context) {
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
		h.logger.Error("Failed to get zone records", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to retrieve zone records",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	c.Header("ETag", formatETag(zone.Version))
	c.JSON(http.StatusOK, gin.H{"records": recordsWithIDs(zone.Records)})
}

// CreateRecord handles POST /api/v1/zones/:name/records.
func (h *Handler) CreateRecord(c *gin.Context) {
	name := c.Param("name")

	var record model.Record
	if err := c.ShouldBindJSON(&record); err != nil {
		h.logger.Warn("Invalid record request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Invalid request body",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}
	record.ID = derivedRecordID(record)

	zone, expectedVersion, ok := h.loadZoneForRecordMutation(c, name)
	if !ok {
		return
	}
	if !h.validateRecordForZone(c, zone.Name, &record) {
		return
	}
	if recordExists(zone.Records, record, -1) {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeAlreadyExists,
			"Record already exists",
			map[string]interface{}{"zone": zone.Name},
		))
		return
	}

	zone.Records = append(zone.Records, record)
	updated, ok := h.commitRecordMutation(c, zone, expectedVersion)
	if !ok {
		return
	}

	if id := findRecordID(updated.Records, record); id != "" {
		c.Header("Location", fmt.Sprintf("/api/v1/zones/%s/records/%s", updated.Name, id))
	}
	h.logger.Info("Record created", zap.String("zone", updated.Name), zap.String("version", updated.Version))
	c.JSON(http.StatusCreated, zoneWithRecordIDs(updated))
}

// UpdateRecord handles PUT /api/v1/zones/:name/records/:id.
func (h *Handler) UpdateRecord(c *gin.Context) {
	name := c.Param("name")
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Record id is required",
			map[string]interface{}{"id": id},
		))
		return
	}

	var record model.Record
	if err := c.ShouldBindJSON(&record); err != nil {
		h.logger.Warn("Invalid record request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Invalid request body",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}
	record.ID = id

	zone, expectedVersion, ok := h.loadZoneForRecordMutation(c, name)
	if !ok {
		return
	}

	idx := findRecordByID(zone.Records, id)
	if idx == -1 {
		c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
			model.ErrorCodeNotFound,
			"Record not found",
			map[string]interface{}{"zone": zone.Name, "record_id": id},
		))
		return
	}
	if !h.validateRecordForZone(c, zone.Name, &record) {
		return
	}
	if recordExists(zone.Records, record, idx) {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeAlreadyExists,
			"Record already exists",
			map[string]interface{}{"zone": zone.Name, "record_id": id},
		))
		return
	}

	zone.Records[idx] = record
	updated, ok := h.commitRecordMutation(c, zone, expectedVersion)
	if !ok {
		return
	}

	h.logger.Info("Record updated", zap.String("zone", updated.Name), zap.String("record_id", id), zap.String("version", updated.Version))
	c.JSON(http.StatusOK, zoneWithRecordIDs(updated))
}

// DeleteRecord handles DELETE /api/v1/zones/:name/records/:id.
func (h *Handler) DeleteRecord(c *gin.Context) {
	name := c.Param("name")
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Record id is required",
			map[string]interface{}{"id": id},
		))
		return
	}

	zone, expectedVersion, ok := h.loadZoneForRecordMutation(c, name)
	if !ok {
		return
	}

	idx := findRecordByID(zone.Records, id)
	if idx == -1 {
		c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
			model.ErrorCodeNotFound,
			"Record not found",
			map[string]interface{}{"zone": zone.Name, "record_id": id},
		))
		return
	}

	zone.Records = append(zone.Records[:idx], zone.Records[idx+1:]...)
	updated, ok := h.commitRecordMutation(c, zone, expectedVersion)
	if !ok {
		return
	}

	h.logger.Info("Record deleted", zap.String("zone", updated.Name), zap.String("record_id", id), zap.String("version", updated.Version))
	c.JSON(http.StatusOK, zoneWithRecordIDs(updated))
}

func (h *Handler) loadZoneForRecordMutation(c *gin.Context, name string) (*model.Zone, string, bool) {
	ifMatch := c.GetHeader("If-Match")
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"If-Match header is required for record updates",
			map[string]interface{}{"header": "If-Match"},
		))
		return nil, "", false
	}

	zone, err := h.store.GetZone(c.Request.Context(), name)
	if err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": name},
			))
			return nil, "", false
		}
		h.logger.Error("Failed to get zone for record mutation", zap.String("zone", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to update record",
			map[string]interface{}{"error": "internal error"},
		))
		return nil, "", false
	}

	if strings.TrimSpace(ifMatch) == "*" {
		return zone, "", true
	}
	if !etagMatches(ifMatch, zone.Version) {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeConflict,
			"Zone version mismatch (optimistic lock failure)",
			map[string]interface{}{"expected_version": ifMatch},
		))
		return nil, "", false
	}

	return zone, zone.Version, true
}

func (h *Handler) validateRecordForZone(c *gin.Context, zoneName string, record *model.Record) bool {
	if err := model.ValidateRecord(record); err != nil {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Record validation failed",
			map[string]interface{}{"error": err.Error()},
		))
		return false
	}
	if err := model.ValidateRecordNameInZone(record.Name, zoneName); err != nil {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Record validation failed",
			map[string]interface{}{"error": err.Error()},
		))
		return false
	}
	return true
}

func (h *Handler) commitRecordMutation(c *gin.Context, zone *model.Zone, expectedVersion string) (*model.Zone, bool) {
	if err := model.ValidateZone(zone); err != nil {
		h.logger.Warn("Zone validation failed after record mutation", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone validation failed",
			map[string]interface{}{"error": err.Error()},
		))
		return nil, false
	}

	newVersion, err := model.NewZoneVersion()
	if err != nil {
		h.logger.Error("Failed to generate zone version", zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to generate zone version",
			map[string]interface{}{"error": "internal error"},
		))
		return nil, false
	}
	zone.Version = newVersion

	if err := h.store.UpdateZone(c.Request.Context(), zone, expectedVersion); err != nil {
		if err == model.ErrZoneNotFound {
			c.JSON(http.StatusNotFound, model.NewAPIErrorWithDetails(
				model.ErrorCodeNotFound,
				"Zone not found",
				map[string]interface{}{"zone": zone.Name},
			))
			return nil, false
		}
		if err == model.ErrConflict {
			c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
				model.ErrorCodeConflict,
				"Zone version mismatch (optimistic lock failure)",
				map[string]interface{}{"expected_version": expectedVersion},
			))
			return nil, false
		}
		h.logger.Error("Failed to update zone records", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to update record",
			map[string]interface{}{"error": "internal error"},
		))
		return nil, false
	}

	updated, err := h.store.GetZone(c.Request.Context(), zone.Name)
	if err != nil {
		h.logger.Error("Failed to retrieve updated zone", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Record updated but failed to retrieve zone",
			map[string]interface{}{"error": "internal error"},
		))
		return nil, false
	}

	if h.signingService != nil {
		if err := h.signingService.SignAndStoreZone(c.Request.Context(), updated); err != nil {
			h.logger.Warn("Failed to sign zone after record mutation",
				zap.String("zone", updated.Name),
				zap.Error(err))
		}
	}

	c.Header("ETag", formatETag(updated.Version))
	return updated, true
}

func findRecordByID(records []model.Record, id string) int {
	for i, record := range records {
		if recordID(record) == id {
			return i
		}
	}
	return -1
}

func recordExists(records []model.Record, record model.Record, skip int) bool {
	for i, candidate := range records {
		if i == skip {
			continue
		}
		if sameRecord(candidate, record) {
			return true
		}
	}
	return false
}

func findRecordID(records []model.Record, record model.Record) string {
	for _, candidate := range records {
		if sameRecord(candidate, record) {
			return recordID(candidate)
		}
	}
	return ""
}

func sameRecord(a, b model.Record) bool {
	return a.Name == b.Name &&
		a.Type == b.Type &&
		a.TTL == b.TTL &&
		a.Value == b.Value
}

func zoneWithRecordIDs(zone *model.Zone) *model.Zone {
	copied := *zone
	copied.Records = recordsWithIDs(zone.Records)
	return &copied
}

func recordsWithIDs(records []model.Record) []model.Record {
	copied := make([]model.Record, len(records))
	copy(copied, records)
	for i := range copied {
		if copied[i].ID == "" {
			copied[i].ID = derivedRecordID(copied[i])
		}
	}
	return copied
}

func recordID(record model.Record) string {
	if record.ID != "" {
		return record.ID
	}
	return derivedRecordID(record)
}

func derivedRecordID(record model.Record) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", record.Name, record.Type, record.TTL, record.Value)))
	return "r" + hex.EncodeToString(sum[:])[:16]
}
