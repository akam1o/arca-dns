package util

import (
	"regexp"
	"strings"
)

// SafeZoneFilename converts a DNS zone name to a safe filename.
// It sanitizes the zone name to prevent path traversal and filesystem issues.
//
// Rules:
// - Removes trailing dots (e.g., "example.com." -> "example.com")
// - Converts to lowercase
// - Only allows: a-z, 0-9, hyphen, underscore, dot
// - Replaces invalid characters with underscore
// - Limits length to 200 characters
// - Prevents path traversal (no "..", "/", etc.)
//
// Examples:
//   - "example.com." -> "example.com"
//   - "sub.example.com." -> "sub.example.com"
//   - "../etc/passwd" -> "__etc_passwd"
//   - "very/long/name" -> "very_long_name"
func SafeZoneFilename(zoneName string) string {
	// Remove trailing dots
	zoneName = strings.TrimRight(zoneName, ".")

	// Convert to lowercase
	zoneName = strings.ToLower(zoneName)

	// Replace any character that's not alphanumeric, hyphen, underscore, or dot
	// This prevents path traversal and filesystem issues
	validChars := regexp.MustCompile(`[^a-z0-9._-]`)
	zoneName = validChars.ReplaceAllString(zoneName, "_")

	// Prevent path traversal patterns
	zoneName = strings.ReplaceAll(zoneName, "..", "_")

	// Limit length to 200 characters (filesystem limit - reserve space for extensions)
	if len(zoneName) > 200 {
		zoneName = zoneName[:200]
	}

	// Ensure the result is not empty
	if zoneName == "" {
		zoneName = "unnamed"
	}

	return zoneName
}
