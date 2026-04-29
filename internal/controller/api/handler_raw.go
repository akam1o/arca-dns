package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/parser"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// CreateZoneRaw handles POST /api/v1/zones/raw
// Accepts BIND zone files in multipart/form-data or text/plain format
func (h *Handler) CreateZoneRaw(c *gin.Context) {
	contentType := c.GetHeader("Content-Type")

	var rawZone string
	var origin string
	var err error

	// Handle different content types
	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Parse multipart form
		file, header, err := c.Request.FormFile("zonefile")
		if err != nil {
			c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
				model.ErrorCodeInvalidInput,
				"missing zonefile in form data",
				map[string]interface{}{"error": "internal error"},
			))
			return
		}
		defer file.Close()

		// Read file content
		content, err := io.ReadAll(file)
		if err != nil {
			c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
				model.ErrorCodeInvalidInput,
				"failed to read zonefile",
				map[string]interface{}{"error": "internal error"},
			))
			return
		}
		rawZone = string(content)

		// Try to get origin from form or filename
		origin = c.Request.FormValue("origin")
		if origin == "" {
			// Try to extract from filename (e.g., "example.com.zone")
			filename := header.Filename
			if strings.HasSuffix(filename, ".zone") {
				origin = strings.TrimSuffix(filename, ".zone")
			}
		}

	} else if strings.HasPrefix(contentType, "text/plain") || contentType == "" {
		// Read raw body
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
				model.ErrorCodeInvalidInput,
				"failed to read request body",
				map[string]interface{}{"error": "internal error"},
			))
			return
		}
		rawZone = string(body)

		// Origin must be provided via query parameter
		origin = c.Query("origin")

	} else {
		c.JSON(http.StatusUnsupportedMediaType, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			fmt.Sprintf("unsupported content type: %s (use text/plain or multipart/form-data)", contentType),
			map[string]interface{}{"content_type": contentType},
		))
		return
	}

	// Validate we have content
	if strings.TrimSpace(rawZone) == "" {
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"zone file content is empty",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Parse BIND zone file to model
	var modelZone *model.Zone

	if origin != "" {
		// Use provided origin
		modelZone, err = parser.BindToModel(rawZone, origin)
	} else {
		// Try to extract origin from zone file
		modelZone, err = parser.BindToModelWithDefaults(rawZone)
	}

	if err != nil {
		// Check if it's a parse error with details
		errStr := err.Error()
		if strings.Contains(errStr, "$GENERATE") {
			c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
				model.ErrorCodeInvalidInput,
				"zone file uses unsupported $GENERATE directive",
				map[string]interface{}{"error": "internal error"},
			))
			return
		}
		if strings.Contains(errStr, "$INCLUDE") {
			c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
				model.ErrorCodeInvalidInput,
				"zone file contains $INCLUDE directive (not supported via API for security)",
				map[string]interface{}{"error": "internal error"},
			))
			return
		}
		if strings.Contains(errStr, "validation failed") {
			c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
				model.ErrorCodeInvalidInput,
				fmt.Sprintf("zone validation failed: %s", extractValidationError(errStr)),
				map[string]interface{}{"error": "internal error"},
			))
			return
		}

		// Generic parse error
		c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			fmt.Sprintf("failed to parse zone file: %s", sanitizeError(errStr)),
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

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
	modelZone.Version = version

	// Create zone in backend (same pattern as CreateZone)
	if err := h.store.CreateZone(c.Request.Context(), modelZone); err != nil {
		if err == model.ErrZoneAlreadyExists {
			c.JSON(http.StatusConflict, model.NewAPIErrorWithDetails(
				model.ErrorCodeAlreadyExists,
				fmt.Sprintf("zone %s already exists", modelZone.Name),
				map[string]interface{}{"zone": modelZone.Name},
			))
			return
		}

		h.logger.Error("failed to create zone", zap.Error(err), zap.String("zone", modelZone.Name))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Failed to create zone",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Retrieve created zone to get version (same pattern as CreateZone)
	createdZone, err := h.store.GetZone(c.Request.Context(), modelZone.Name)
	if err != nil {
		h.logger.Error("Failed to retrieve created zone", zap.String("zone", modelZone.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.NewAPIErrorWithDetails(
			model.ErrorCodeInternal,
			"Zone created but failed to retrieve",
			map[string]interface{}{"error": "internal error"},
		))
		return
	}

	// Sign zone automatically, matching the JSON create path.
	if h.signingService != nil {
		if err := h.signingService.SignAndStoreZone(c.Request.Context(), createdZone); err != nil {
			// Log error but don't fail the request - zone was created successfully.
			h.logger.Warn("Failed to sign zone after raw creation",
				zap.String("zone", createdZone.Name),
				zap.Error(err))
		}
	}

	// Set response headers
	c.Header("ETag", formatETag(createdZone.Version))
	c.Header("Location", "/api/v1/zones/"+createdZone.Name)

	h.logger.Info("Zone created from raw BIND format", zap.String("zone", createdZone.Name), zap.String("version", createdZone.Version))

	// Return created zone summary
	c.JSON(http.StatusCreated, gin.H{
		"name":    createdZone.Name,
		"version": createdZone.Version,
		"soa": gin.H{
			"serial":  createdZone.SOA.Serial,
			"mname":   createdZone.SOA.MName,
			"rname":   createdZone.SOA.RName,
			"refresh": createdZone.SOA.Refresh,
			"retry":   createdZone.SOA.Retry,
			"expire":  createdZone.SOA.Expire,
			"minimum": createdZone.SOA.Minimum,
		},
		"records_count": len(createdZone.Records),
		"message":       "zone successfully parsed and created from BIND format",
	})
}

// extractValidationError extracts the validation error message from a wrapped error
func extractValidationError(errStr string) string {
	// Extract the part after "validation failed:"
	parts := strings.Split(errStr, "validation failed:")
	if len(parts) > 1 {
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return errStr
}

// sanitizeError removes sensitive internal details from error messages
func sanitizeError(errStr string) string {
	// Remove file paths
	if idx := strings.Index(errStr, ":"); idx != -1 {
		return strings.TrimSpace(errStr[idx+1:])
	}
	return errStr
}
