package sync

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
			name:     "normal FQDN without trailing dot",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "subdomain",
			input:    "sub.example.com.",
			expected: "sub.example.com",
		},
		{
			name:     "uppercase converted to lowercase",
			input:    "Example.COM.",
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
			name:     "special characters",
			input:    "zone@#$%name.com",
			expected: "zone____name.com",
		},
		{
			name:     "spaces",
			input:    "zone name.com",
			expected: "zone_name.com",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "unnamed",
		},
		{
			name:     "only dots",
			input:    "....",
			expected: "unnamed",
		},
		{
			name:     "valid with hyphens and underscores",
			input:    "my-zone_1.example.com.",
			expected: "my-zone_1.example.com",
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

func TestZoneFilePath(t *testing.T) {
	tests := []struct {
		name     string
		zoneDir  string
		zoneName string
		expected string
	}{
		{
			name:     "normal zone",
			zoneDir:  "/var/lib/nsd/zones",
			zoneName: "example.com.",
			expected: "/var/lib/nsd/zones/example.com.zone",
		},
		{
			name:     "zone with path traversal attempt",
			zoneDir:  "/var/lib/nsd/zones",
			zoneName: "../etc/passwd",
			expected: "/var/lib/nsd/zones/__etc_passwd.zone",
		},
		{
			name:     "subdomain zone",
			zoneDir:  "/zones",
			zoneName: "sub.example.com.",
			expected: "/zones/sub.example.com.zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ZoneFilePath(tt.zoneDir, tt.zoneName)
			if result != tt.expected {
				t.Errorf("ZoneFilePath(%q, %q) = %q, want %q", tt.zoneDir, tt.zoneName, result, tt.expected)
			}

			// Ensure the path doesn't escape the zone directory
			if !strings.HasPrefix(result, tt.zoneDir) {
				t.Errorf("Result doesn't start with zone directory: %q", result)
			}
		})
	}
}

func TestZoneBackupPattern(t *testing.T) {
	tests := []struct {
		name     string
		zoneDir  string
		zoneName string
		expected string
	}{
		{
			name:     "normal zone",
			zoneDir:  "/var/lib/nsd/zones",
			zoneName: "example.com.",
			expected: "/var/lib/nsd/zones/example.com.zone.backup.*",
		},
		{
			name:     "zone with path traversal attempt",
			zoneDir:  "/var/lib/nsd/zones",
			zoneName: "../etc/passwd",
			expected: "/var/lib/nsd/zones/__etc_passwd.zone.backup.*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ZoneBackupPattern(tt.zoneDir, tt.zoneName)
			if result != tt.expected {
				t.Errorf("ZoneBackupPattern(%q, %q) = %q, want %q", tt.zoneDir, tt.zoneName, result, tt.expected)
			}

			// Ensure the pattern doesn't escape the zone directory
			if !strings.HasPrefix(result, tt.zoneDir) {
				t.Errorf("Result doesn't start with zone directory: %q", result)
			}
		})
	}
}
