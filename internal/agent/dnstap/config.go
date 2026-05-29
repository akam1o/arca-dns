package dnstap

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/akam1o/arca-dns/pkg/config"
)

// NSDDNSTapConfig generates NSD configuration for DNSTap logging.
func NSDDNSTapConfig(socketPath string) (string, error) {
	if err := config.ValidateDNSTapSocketPath(socketPath); err != nil {
		return "", fmt.Errorf("invalid dnstap socket path: %w", err)
	}

	tmpl := `
# DNSTap configuration for arca-dns agent
server:
    dnstap-enable: yes
    dnstap-socket-path: {{.SocketPath}}

    # Log both query and response for client messages
    dnstap-send-identity: no
    dnstap-send-version: no
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
`

	t, err := template.New("nsd-dnstap").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse NSD DNSTap template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, map[string]string{
		"SocketPath": socketPath,
	}); err != nil {
		return "", fmt.Errorf("failed to execute NSD DNSTap template: %w", err)
	}

	return buf.String(), nil
}

// UnboundDNSTapConfig generates Unbound configuration for DNSTap logging.
func UnboundDNSTapConfig(socketPath string) (string, error) {
	if err := config.ValidateDNSTapSocketPath(socketPath); err != nil {
		return "", fmt.Errorf("invalid dnstap socket path: %w", err)
	}

	tmpl := `
# DNSTap configuration for arca-dns agent
server:
    dnstap-enable: yes
    dnstap-socket-path: {{.SocketPath}}

    # Log both query and response for client messages
    dnstap-send-identity: no
    dnstap-send-version: no
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
`

	t, err := template.New("unbound-dnstap").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse Unbound DNSTap template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, map[string]string{
		"SocketPath": socketPath,
	}); err != nil {
		return "", fmt.Errorf("failed to execute Unbound DNSTap template: %w", err)
	}

	return buf.String(), nil
}

// BIRDConfig is a placeholder for potential BIRD configuration integration.
// BIRD does not support DNSTap, so this is for future extensibility.
