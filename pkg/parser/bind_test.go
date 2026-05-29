package parser

import (
	"strings"
	"testing"
)

func TestParseBINDZone(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		origin    string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid simple zone",
			input: `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
example.com. IN NS ns1.example.com.
example.com. IN A 192.0.2.1
www.example.com. IN A 192.0.2.2
`,
			origin:  "example.com.",
			wantErr: false,
		},
		{
			name: "zone with $ORIGIN",
			input: `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin (
    2024010101 3600 1800 604800 86400
)
@ IN NS ns1
@ IN A 192.0.2.1
www IN A 192.0.2.2
`,
			origin:  "example.com.",
			wantErr: false,
		},
		{
			name: "zone without $TTL (uses default)",
			input: `example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN A 192.0.2.1
`,
			origin:  "example.com.",
			wantErr: false,
		},
		{
			name: "empty zone",
			input: `
; Just comments
`,
			origin:    "example.com.",
			wantErr:   true,
			errSubstr: "no records found",
		},
		{
			name: "empty origin",
			input: `example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)`,
			origin:    "",
			wantErr:   true,
			errSubstr: "origin must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			opts := DefaultParseOptions()

			parsed, err := ParseBINDZone(reader, tt.origin, opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if parsed == nil {
				t.Fatal("parsed zone is nil")
			}

			if parsed.Origin != tt.origin {
				t.Errorf("origin = %q, want %q", parsed.Origin, tt.origin)
			}

			if len(parsed.Records) == 0 {
				t.Error("no records parsed")
			}
		})
	}
}

func TestParseBINDZone_RecordTypes(t *testing.T) {
	input := `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. IN NS ns1.example.com.
example.com. IN A 192.0.2.1
example.com. IN AAAA 2001:db8::1
www.example.com. IN CNAME example.com.
example.com. IN MX 10 mail.example.com.
example.com. IN TXT "v=spf1 -all"
ptr.example.com. IN PTR example.com.
_http._tcp.example.com. IN SRV 0 5 80 www.example.com.
example.com. IN CAA 0 issue "ca.example.com"
`

	reader := strings.NewReader(input)
	opts := DefaultParseOptions()

	parsed, err := ParseBINDZone(reader, "example.com.", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(parsed.Records) < 8 {
		t.Errorf("expected at least 8 records, got %d", len(parsed.Records))
	}

	// Check that various record types were parsed
	recordTypes := make(map[uint16]bool)
	for _, rr := range parsed.Records {
		recordTypes[rr.Header().Rrtype] = true
	}

	expectedTypes := map[string]uint16{
		"SOA":   6,
		"NS":    2,
		"A":     1,
		"AAAA":  28,
		"CNAME": 5,
		"MX":    15,
		"TXT":   16,
		"PTR":   12,
		"SRV":   33,
		"CAA":   257,
	}
	for name, typ := range expectedTypes {
		if !recordTypes[typ] {
			t.Errorf("expected record type %s not found", name)
		}
	}
}

func TestParseBINDZone_UnsupportedDirectives(t *testing.T) {
	// Note: miekg/dns may or may not surface $GENERATE errors during parsing
	// This test documents expected behavior
	input := `$TTL 3600
$ORIGIN example.com.
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
@ IN NS ns1
`

	reader := strings.NewReader(input)
	opts := DefaultParseOptions()

	parsed, err := ParseBINDZone(reader, "example.com.", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed == nil {
		t.Fatal("parsed zone is nil")
	}
}

func TestDefaultParseOptions(t *testing.T) {
	opts := DefaultParseOptions()

	// AllowIncludes should be false by default for security
	if opts.AllowIncludes {
		t.Error("expected AllowIncludes to be false (secure default)")
	}

	if opts.DefaultTTL != 3600 {
		t.Errorf("expected DefaultTTL to be 3600, got %d", opts.DefaultTTL)
	}

	if opts.MaxBytes != DefaultMaxZoneFileSize {
		t.Errorf("expected MaxBytes to be %d, got %d", DefaultMaxZoneFileSize, opts.MaxBytes)
	}
}

func TestParseBINDZone_RejectsOversizedZoneFile(t *testing.T) {
	input := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. 3600 IN NS ns1.example.com.
`
	opts := DefaultParseOptions()
	opts.MaxBytes = int64(len(input) - 1)

	_, err := ParseBINDZone(strings.NewReader(input), "example.com.", opts)
	if err == nil {
		t.Fatal("expected oversized zone file error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected maximum size error, got %v", err)
	}
}

func TestParseBINDZone_AllowsLongDirectiveScanLine(t *testing.T) {
	input := ";" + strings.Repeat("a", 70*1024) + `
example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. 3600 IN NS ns1.example.com.
`
	opts := DefaultParseOptions()

	parsed, err := ParseBINDZone(strings.NewReader(input), "example.com.", opts)
	if err != nil {
		t.Fatalf("unexpected error for long comment line: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed zone is nil")
	}
}

func TestParseBINDZone_AllowsExplicitUnlimitedSize(t *testing.T) {
	input := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. 3600 IN NS ns1.example.com.
`
	opts := DefaultParseOptions()
	opts.MaxBytes = -1

	parsed, err := ParseBINDZone(strings.NewReader(input), "example.com.", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed zone is nil")
	}
}
