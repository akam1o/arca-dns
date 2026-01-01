package model

import "errors"

// Common errors returned by arca-dns components.
var (
	// ErrZoneNotFound indicates the requested zone does not exist.
	ErrZoneNotFound = errors.New("zone not found")

	// ErrZoneAlreadyExists indicates a zone with the given name already exists.
	ErrZoneAlreadyExists = errors.New("zone already exists")

	// ErrRecordNotFound indicates the requested record does not exist.
	ErrRecordNotFound = errors.New("record not found")

	// ErrInvalidZoneName indicates the zone name is not a valid DNS name.
	ErrInvalidZoneName = errors.New("invalid zone name")

	// ErrInvalidRecordType indicates an unsupported DNS record type.
	ErrInvalidRecordType = errors.New("invalid record type")

	// ErrInvalidRecordValue indicates the record value is malformed.
	ErrInvalidRecordValue = errors.New("invalid record value")

	// ErrInvalidTTL indicates the TTL value is out of acceptable range.
	ErrInvalidTTL = errors.New("invalid TTL")

	// ErrConflict indicates a concurrent modification conflict (ETag mismatch).
	ErrConflict = errors.New("conflict: resource has been modified")

	// ErrVersionNotFound indicates the requested zone version does not exist.
	ErrVersionNotFound = errors.New("version not found")

	// ErrBackendUnavailable indicates the storage backend is temporarily unavailable.
	ErrBackendUnavailable = errors.New("backend unavailable")

	// ErrIntegrityCheckFailed indicates zone file checksum verification failed.
	ErrIntegrityCheckFailed = errors.New("integrity check failed")

	// ErrDNSSECSigningFailed indicates DNSSEC signing operation failed.
	ErrDNSSECSigningFailed = errors.New("DNSSEC signing failed")

	// ErrKeyNotFound indicates the requested DNSSEC key does not exist.
	ErrKeyNotFound = errors.New("key not found")
)

// ErrorCode represents standardized error codes for API responses.
type ErrorCode string

const (
	ErrorCodeNotFound          ErrorCode = "NOT_FOUND"
	ErrorCodeAlreadyExists     ErrorCode = "ALREADY_EXISTS"
	ErrorCodeInvalidInput      ErrorCode = "INVALID_INPUT"
	ErrorCodeConflict          ErrorCode = "CONFLICT"
	ErrorCodeInternal          ErrorCode = "INTERNAL_ERROR"
	ErrorCodeUnavailable       ErrorCode = "UNAVAILABLE"
	ErrorCodeUnauthorized      ErrorCode = "UNAUTHORIZED"
	ErrorCodeForbidden         ErrorCode = "FORBIDDEN"
	ErrorCodeRateLimitExceeded ErrorCode = "RATE_LIMIT_EXCEEDED"
)

// APIError represents a structured error response for the API.
type APIError struct {
	// Code is the standardized error code
	Code ErrorCode `json:"code"`

	// Message is a human-readable error message
	Message string `json:"message"`

	// Details provides additional context (optional)
	Details map[string]interface{} `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return string(e.Code) + ": " + e.Message
}

// NewAPIError creates a new API error with the given code and message.
func NewAPIError(code ErrorCode, message string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
	}
}

// NewAPIErrorWithDetails creates a new API error with additional details.
func NewAPIErrorWithDetails(code ErrorCode, message string, details map[string]interface{}) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Details: details,
	}
}
