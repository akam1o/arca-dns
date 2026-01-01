package util

import (
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
			expected: strings.Repeat("a", 200),
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
