package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const maxBulkRecordOperations = 1000

type bulkRecordRequest struct {
	Create []model.Record       `json:"create"`
	Update []bulkRecordUpdate   `json:"update"`
	Delete []bulkRecordDeletion `json:"delete"`
}

type bulkRecordUpdate struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	TTL      uint32  `json:"ttl"`
	Value    string  `json:"value"`
	Priority *uint16 `json:"priority,omitempty"`
}

type bulkRecordDeletion struct {
	ID string `json:"id"`
}

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
	record.ID = ""

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

// BulkRecords handles POST /api/v1/zones/:name/records/batch.
func (h *Handler) BulkRecords(c *gin.Context) {
	name := c.Param("name")

	var req bulkRecordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid bulk record request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Invalid request body",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}
	if len(req.Create) == 0 && len(req.Update) == 0 && len(req.Delete) == 0 {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Bulk request must include at least one operation",
			map[string]interface{}{"error": "empty operation set"},
		))
		return
	}

	zone, expectedVersion, ok := h.loadZoneForRecordMutation(c, name)
	if !ok {
		return
	}

	operationCount := len(req.Create) + len(req.Update) + len(req.Delete)
	if operationCount > maxBulkRecordOperations {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Bulk request includes too many operations",
			map[string]interface{}{
				"operations":     operationCount,
				"max_operations": maxBulkRecordOperations,
			},
		))
		return
	}

	records, ok := h.applyBulkRecordOperations(c, zone.Name, zone.Records, req)
	if !ok {
		return
	}
	zone.Records = records

	updated, ok := h.commitRecordMutation(c, zone, expectedVersion)
	if !ok {
		return
	}

	h.logger.Info("Bulk records updated",
		zap.String("zone", updated.Name),
		zap.Int("create", len(req.Create)),
		zap.Int("update", len(req.Update)),
		zap.Int("delete", len(req.Delete)),
		zap.String("version", updated.Version))
	c.JSON(http.StatusOK, zoneWithRecordIDs(updated))
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
	record.ID = preserveRecordID(zone.Records[idx], id)
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

func (h *Handler) applyBulkRecordOperations(c *gin.Context, zoneName string, current []model.Record, req bulkRecordRequest) ([]model.Record, bool) {
	records := append([]model.Record(nil), current...)

	deleteIDs := make(map[string]struct{}, len(req.Delete))
	deleteIndexes := make(map[int]struct{}, len(req.Delete))
	for i, op := range req.Delete {
		id := strings.TrimSpace(op.ID)
		if id == "" {
			h.recordBatchError(c, http.StatusBadRequest, "Delete operation is missing record id", i, "delete", map[string]interface{}{"index": i})
			return nil, false
		}
		idx := findRecordByID(records, id)
		if idx == -1 {
			h.recordBatchError(c, http.StatusNotFound, "Record not found", i, "delete", map[string]interface{}{"record_id": id})
			return nil, false
		}
		canonicalID := recordID(records[idx])
		if _, exists := deleteIDs[canonicalID]; exists {
			h.recordBatchError(c, http.StatusBadRequest, "Duplicate record id in delete operations", i, "delete", map[string]interface{}{"record_id": id})
			return nil, false
		}
		deleteIDs[canonicalID] = struct{}{}
		deleteIDs[derivedRecordID(records[idx])] = struct{}{}
		deleteIDs[id] = struct{}{}
		deleteIndexes[idx] = struct{}{}
	}

	if len(deleteIndexes) > 0 {
		filtered := records[:0]
		for i, record := range records {
			if _, deleted := deleteIndexes[i]; deleted {
				continue
			}
			filtered = append(filtered, record)
		}
		records = filtered
	}

	updateIDs := make(map[string]struct{}, len(req.Update))
	for i, op := range req.Update {
		id := strings.TrimSpace(op.ID)
		if id == "" {
			h.recordBatchError(c, http.StatusBadRequest, "Update operation is missing record id", i, "update", map[string]interface{}{"index": i})
			return nil, false
		}
		if _, deleted := deleteIDs[id]; deleted {
			h.recordBatchError(c, http.StatusBadRequest, "Record cannot be updated and deleted in the same batch", i, "update", map[string]interface{}{"record_id": id})
			return nil, false
		}
		idx := findRecordByID(records, id)
		if idx == -1 {
			h.recordBatchError(c, http.StatusNotFound, "Record not found", i, "update", map[string]interface{}{"record_id": id})
			return nil, false
		}
		canonicalID := recordID(records[idx])
		if _, exists := updateIDs[canonicalID]; exists {
			h.recordBatchError(c, http.StatusBadRequest, "Duplicate record id in update operations", i, "update", map[string]interface{}{"record_id": id})
			return nil, false
		}

		record := model.Record{
			ID:       preserveRecordID(records[idx], id),
			Name:     op.Name,
			Type:     op.Type,
			TTL:      op.TTL,
			Value:    op.Value,
			Priority: op.Priority,
		}
		if !h.validateRecordForZone(c, zoneName, &record) {
			return nil, false
		}
		records[idx] = record
		updateIDs[canonicalID] = struct{}{}
	}

	for i := range req.Create {
		record := req.Create[i]
		record.ID = ""
		if !h.validateRecordForZone(c, zoneName, &record) {
			return nil, false
		}
		records = append(records, record)
	}

	if duplicateIndex, exists := firstDuplicateRecord(records); exists {
		h.recordBatchError(c, http.StatusConflict, "Record already exists", duplicateIndex, "records", map[string]interface{}{"index": duplicateIndex})
		return nil, false
	}
	if duplicateIndex, duplicateID, exists := firstDuplicateRecordID(records); exists {
		h.recordBatchError(c, http.StatusConflict, "Record id already exists", duplicateIndex, "records", map[string]interface{}{"index": duplicateIndex, "record_id": duplicateID})
		return nil, false
	}

	return records, true
}

func (h *Handler) recordBatchError(c *gin.Context, status int, message string, index int, operation string, details map[string]interface{}) {
	if details == nil {
		details = map[string]interface{}{}
	}
	details["operation"] = operation
	details["index"] = index

	errorCode := model.ErrorCodeInvalidInput
	if status == http.StatusConflict {
		errorCode = model.ErrorCodeAlreadyExists
	}
	if status == http.StatusNotFound {
		errorCode = model.ErrorCodeNotFound
	}

	c.JSON(status, model.NewAPIErrorWithDetails(errorCode, message, details))
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
	if rejectWildcardIfMatch(c, "record updates") {
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

	if !strongETagMatches(ifMatch, zone.Version) {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeConflict,
			"Zone version mismatch (optimistic lock failure)",
			map[string]interface{}{"expected_version": ifMatch},
		))
		return nil, "", false
	}

	if err := model.RepairZoneDerivedFields(zone); err != nil {
		h.logger.Warn("Zone normalization failed before record mutation", zap.String("zone", zone.Name), zap.Error(err))
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Zone validation failed",
			map[string]interface{}{"error": err.Error()},
		))
		return nil, "", false
	}

	return zone, zone.Version, true
}

func (h *Handler) validateRecordForZone(c *gin.Context, zoneName string, record *model.Record) bool {
	if err := model.NormalizeRecordDerivedFields(record); err != nil {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Record validation failed",
			map[string]interface{}{"error": err.Error()},
		))
		return false
	}
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
	if err := model.ValidateRecordValueInZone(record.Type, record.Value, zoneName); err != nil {
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
	if duplicateIndex, duplicateID, exists := firstDuplicateRecordID(zone.Records); exists {
		c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
			model.ErrorCodeAlreadyExists,
			"Record id already exists",
			map[string]interface{}{"index": duplicateIndex, "record_id": duplicateID},
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

	signedWrite, ok := h.prepareSignedZoneUpdate(c, zone, zone.SOA.Serial, "record mutation")
	if !ok {
		return nil, false
	}
	defer signedWrite.Abort()

	if !h.storeSignedZoneWrite(c, signedWrite, "record mutation") {
		return nil, false
	}

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

	if !h.commitSignedZoneWrite(c, signedWrite, "record mutation") {
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

	if !h.completeSignedZoneWrite(c, signedWrite, "record mutation") {
		return nil, false
	}

	c.Header("ETag", formatETag(updated.Version))
	return updated, true
}

func findRecordByID(records []model.Record, id string) int {
	for i, record := range records {
		if recordIDMatches(record, id) {
			return i
		}
	}
	return -1
}

func recordIDMatches(record model.Record, id string) bool {
	if id == "" {
		return false
	}
	if recordID(record) == id {
		return true
	}
	return derivedRecordID(record) == id
}

func preserveRecordID(record model.Record, _ string) string {
	if record.ID == "" {
		return ""
	}
	if record.ID == derivedRecordID(record) {
		return ""
	}
	return record.ID
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

func firstDuplicateRecord(records []model.Record) (int, bool) {
	seen := make(map[string]int, len(records))
	for i, record := range records {
		key := recordIdentity(record)
		if _, exists := seen[key]; exists {
			return i, true
		}
		seen[key] = i
	}
	return -1, false
}

func firstDuplicateRecordID(records []model.Record) (int, string, bool) {
	seen := make(map[string]int, len(records))
	for i, record := range records {
		id := recordID(record)
		if _, exists := seen[id]; exists {
			return i, id, true
		}
		seen[id] = i
	}
	return -1, "", false
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
	return recordIdentity(a) == recordIdentity(b)
}

func recordIdentity(record model.Record) string {
	return record.Name + "\x00" + record.Type + "\x00" + strconv.FormatUint(uint64(record.TTL), 10) + "\x00" + record.Value
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
	sum := sha256.Sum256([]byte(recordIdentity(record)))
	return "r" + hex.EncodeToString(sum[:])[:16]
}
