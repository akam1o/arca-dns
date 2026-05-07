package util

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSafeZoneFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal FQDN with trailing dot",
			input:    "example.com.",
			expected: "example.com",
		},
		{
			name:     "path traversal attempt",
			input:    "../etc/passwd",
			expected: "__etc_passwd",
		},
		{
			name:     "absolute path attempt",
			input:    "/etc/passwd",
			expected: "_etc_passwd",
		},
		{
			name:     "double dot pattern",
			input:    "zone..name",
			expected: "zone_name",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "unnamed",
		},
		{
			name:     "very long name",
			input:    strings.Repeat("a", 300) + ".com.",
			expected: expectedLongSafeZoneFilename(strings.Repeat("a", 300) + ".com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeZoneFilename(tt.input)
			if result != tt.expected {
				t.Errorf("SafeZoneFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}

			// Additional safety checks
			if strings.Contains(result, "..") {
				t.Errorf("Result contains path traversal pattern: %q", result)
			}
			if strings.Contains(result, "/") {
				t.Errorf("Result contains path separator: %q", result)
			}
			if len(result) > 200 {
				t.Errorf("Result exceeds max length: %d > 200", len(result))
			}
		})
	}
}

func TestSafeZoneFilename_LongNamesDoNotCollideAfterTruncation(t *testing.T) {
	prefix := strings.Repeat("a", 220)

	first := SafeZoneFilename(prefix + "x.example.")
	second := SafeZoneFilename(prefix + "y.example.")

	if first == second {
		t.Fatalf("long zone filenames collided: %q", first)
	}
	if len(first) > 200 || len(second) > 200 {
		t.Fatalf("long zone filenames exceeded length limit: %d %d", len(first), len(second))
	}
}

func expectedLongSafeZoneFilename(name string) string {
	sum := sha256.Sum256([]byte(name))
	hash := hex.EncodeToString(sum[:])[:12]
	return name[:187] + "-" + hash
}
