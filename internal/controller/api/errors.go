package api

import "strings"

const maxValidationDetailLength = 512

func invalidRequestBodyDetails(err error) map[string]interface{} {
	return validationErrorDetails("invalid_request_body", "body", err)
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
