package dnstap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNSDDNSTapConfig tests NSD DNSTap configuration generation.
func TestNSDDNSTapConfig(t *testing.T) {
	socketPath := "/var/run/dnstap/dnstap.sock"

	config, err := NSDDNSTapConfig(socketPath)
	require.NoError(t, err)
	require.NotEmpty(t, config)

	// Verify required directives
	assert.Contains(t, config, "dnstap-enable: yes")
	assert.Contains(t, config, "dnstap-socket-path: "+socketPath)
	assert.Contains(t, config, "dnstap-log-client-query-messages: yes")
	assert.Contains(t, config, "dnstap-log-client-response-messages: yes")

	// Verify identity and version are disabled
	assert.Contains(t, config, "dnstap-send-identity: no")
	assert.Contains(t, config, "dnstap-send-version: no")
}

// TestUnboundDNSTapConfig tests Unbound DNSTap configuration generation.
func TestUnboundDNSTapConfig(t *testing.T) {
	socketPath := "/var/run/dnstap/dnstap.sock"

	config, err := UnboundDNSTapConfig(socketPath)
	require.NoError(t, err)
	require.NotEmpty(t, config)

	// Verify required directives
	assert.Contains(t, config, "dnstap-enable: yes")
	assert.Contains(t, config, "dnstap-socket-path: "+socketPath)
	assert.Contains(t, config, "dnstap-log-client-query-messages: yes")
	assert.Contains(t, config, "dnstap-log-client-response-messages: yes")

	// Verify identity and version are disabled
	assert.Contains(t, config, "dnstap-send-identity: no")
	assert.Contains(t, config, "dnstap-send-version: no")
}

// TestConfigFormat tests that generated config is valid YAML-like format.
func TestConfigFormat(t *testing.T) {
	socketPath := "/var/run/dnstap/dnstap.sock"

	tests := []struct {
		name   string
		config func(string) (string, error)
	}{
		{"NSD", NSDDNSTapConfig},
		{"Unbound", UnboundDNSTapConfig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := tt.config(socketPath)
			require.NoError(t, err)

			// Config should be non-empty
			assert.NotEmpty(t, config)

			// Should contain server: section
			assert.Contains(t, config, "server:")

			// Should not contain template placeholders
			assert.NotContains(t, config, "{{")
			assert.NotContains(t, config, "}}")

			// Lines should have proper indentation (4 spaces for server options)
			lines := strings.Split(config, "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					// Server-level options should be indented with 4 spaces
					if strings.Contains(line, "dnstap-") {
						assert.True(t, strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t"),
							"DNSTap options should be indented: %q", line)
					}
				}
			}
		})
	}
}

// TestSocketPathEscaping tests handling of socket paths with special characters.
func TestSocketPathEscaping(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
	}{
		{"simple", "/var/run/dnstap.sock"},
		{"with spaces", "/var/run/dnstap test.sock"},
		{"with dots", "/var/run/dnstap.test.sock"},
		{"absolute", "/tmp/dnstap/socket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsdConfig, err := NSDDNSTapConfig(tt.socketPath)
			require.NoError(t, err)
			assert.Contains(t, nsdConfig, tt.socketPath)

			unboundConfig, err := UnboundDNSTapConfig(tt.socketPath)
			require.NoError(t, err)
			assert.Contains(t, unboundConfig, tt.socketPath)
		})
	}
}

func TestDNSTapConfigRejectsUnsafeSocketPath(t *testing.T) {
	paths := map[string]string{
		"empty":                  "",
		"surrounding whitespace": " /var/run/dnstap.sock ",
		"relative":               "run/dnstap.sock",
		"newline":                "/var/run/dnstap.sock\nserver:",
		"nul byte":               "/var/run/dnstap\x00.sock",
	}
	configs := []struct {
		name   string
		config func(string) (string, error)
	}{
		{"NSD", NSDDNSTapConfig},
		{"Unbound", UnboundDNSTapConfig},
	}

	for pathName, socketPath := range paths {
		for _, tt := range configs {
			t.Run(tt.name+"/"+pathName, func(t *testing.T) {
				generated, err := tt.config(socketPath)
				require.Error(t, err)
				assert.Empty(t, generated)
				assert.Contains(t, err.Error(), "dnstap socket path")
			})
		}
	}
}
