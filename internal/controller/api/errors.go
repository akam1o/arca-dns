package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/gin-gonic/gin"
)

const maxValidationDetailLength = 512

func invalidRequestBodyDetails(err error) map[string]interface{} {
	return validationErrorDetails("invalid_request_body", "body", err)
}

func writeInvalidRequestBody(c *gin.Context, err error) {
	if maxBytesErr := requestBodyTooLargeError(err); maxBytesErr != nil {
		c.JSON(http.StatusRequestEntityTooLarge, model.NewAPIErrorWithDetails(
			model.ErrorCodeInvalidInput,
			"Request body exceeds maximum size limit",
			map[string]interface{}{
				"reason":   "request_too_large",
				"field":    "body",
				"max_size": maxBytesErr.Limit,
			},
		))
		return
	}

	c.JSON(http.StatusBadRequest, model.NewAPIErrorWithDetails(
		model.ErrorCodeInvalidInput,
		"Invalid request body",
		invalidRequestBodyDetails(err),
	))
}

func requestBodyTooLargeError(err error) *http.MaxBytesError {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return maxBytesErr
	}
	return nil
}

func validationFailureDetails(field string, err error) map[string]interface{} {
	return validationErrorDetails("validation_failed", field, err)
}

func validationErrorDetails(reason string, field string, err error) map[string]interface{} {
	return map[string]interface{}{
		"reason": reason,
		"field":  field,
		"error":  sanitizedValidationMessage(err),
	}
}

func sanitizedValidationMessage(err error) string {
	if err == nil {
		return "invalid input"
	}

	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "invalid input"
	}
	runes := []rune(msg)
	if len(runes) <= maxValidationDetailLength {
		return msg
	}
	return string(runes[:maxValidationDetailLength]) + "..."
}
