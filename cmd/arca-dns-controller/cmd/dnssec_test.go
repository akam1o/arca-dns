package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestNewDNSSECCmdWiresSubcommands(t *testing.T) {
	cmd := NewDNSSECCmd()

	require.Equal(t, "dnssec", cmd.Use)

	names := make(map[string]struct{})
	for _, subcommand := range cmd.Commands() {
		names[subcommand.Name()] = struct{}{}
	}
	require.Contains(t, names, "export-ds")
	require.Contains(t, names, "generate-keys")
	require.Contains(t, names, "remove-old-keys")
}

func TestDNSSECSubcommandsRequireZone(t *testing.T) {
	tests := []struct {
		name string
		cmd  func() *cobra.Command
	}{
		{name: "export-ds", cmd: newExportDSCmd},
		{name: "generate-keys", cmd: newGenerateKeysCmd},
		{name: "remove-old-keys", cmd: newRemoveOldKeysCmd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmd()
			cmd.SetArgs(nil)

			err := cmd.Execute()
			require.ErrorContains(t, err, "zone is required")
		})
	}
}

func TestValidateGenerateKeysFlags(t *testing.T) {
	tests := []struct {
		name        string
		rotate      bool
		activateNow bool
		wantErr     string
	}{
		{
			name: "initial generation",
		},
		{
			name:        "confirmed rotation",
			rotate:      true,
			activateNow: true,
		},
		{
			name:    "rotation requires explicit activation confirmation",
			rotate:  true,
			wantErr: "--activate-now",
		},
		{
			name:        "activation confirmation requires rotation",
			activateNow: true,
			wantErr:     "requires --rotate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGenerateKeysFlags(tt.rotate, tt.activateNow)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestOutputDS(t *testing.T) {
	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     "abcdef",
	}

	var bind bytes.Buffer
	require.NoError(t, outputDS(&bind, ds, "bind"))
	require.Contains(t, bind.String(), "example.com.")
	require.Contains(t, bind.String(), "\tDS\t")

	var jsonOut bytes.Buffer
	require.NoError(t, outputDS(&jsonOut, ds, "json"))
	require.Contains(t, jsonOut.String(), `"name": "example.com."`)
	require.Contains(t, jsonOut.String(), `"key_tag": 12345`)
	require.Contains(t, jsonOut.String(), `"digest": "abcdef"`)

	var unsupported bytes.Buffer
	err := outputDS(&unsupported, ds, "yaml")
	require.ErrorContains(t, err, "unsupported output format")
	require.True(t, strings.Contains(err.Error(), "bind, json"))
}
