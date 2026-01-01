package parser

import (
	"strings"
	"testing"
)

func TestValidateDirectives_Generate(t *testing.T) {
	tests := []struct {
		name    string
		content string
		opts    ParseOptions
		wantErr bool
	}{
		{
			name: "$GENERATE directive rejected",
			content: `$TTL 3600
$ORIGIN example.com.
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
$GENERATE 1-254 host-$ A 192.0.2.$
@ IN NS ns1
`,
			opts:    DefaultParseOptions(),
			wantErr: true,
		},
		{
			name: "$GENERATE in middle of file rejected",
			content: `$TTL 3600
$ORIGIN example.com.
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
@ IN NS ns1
$GENERATE 1-10 www$ A 192.0.2.$
`,
			opts:    DefaultParseOptions(),
			wantErr: true,
		},
		{
			name: "No $GENERATE passes",
			content: `$TTL 3600
$ORIGIN example.com.
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
@ IN NS ns1
@ IN A 192.0.2.1
`,
			opts:    DefaultParseOptions(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDirectives(tt.content, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateDirectives() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), "$GENERATE") {
				t.Errorf("expected error to mention $GENERATE, got: %v", err)
			}
		})
	}
}

func TestValidateDirectives_Include(t *testing.T) {
	tests := []struct {
		name    string
		content string
		opts    ParseOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "single $INCLUDE allowed when enabled",
			content: `$TTL 3600
$ORIGIN example.com.
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
$INCLUDE /path/to/hosts.zone
@ IN NS ns1
`,
			opts: ParseOptions{
				AllowIncludes: true,
				DefaultTTL:    3600,
			},
			wantErr: false,
		},
		{
			name: "multiple $INCLUDE rejected",
			content: `$TTL 3600
$ORIGIN example.com.
$INCLUDE /path/to/hosts1.zone
$INCLUDE /path/to/hosts2.zone
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
`,
			opts: ParseOptions{
				AllowIncludes: true,
				DefaultTTL:    3600,
			},
			wantErr: true,
			errMsg:  "multiple $INCLUDE",
		},
		{
			name: "$INCLUDE not allowed when disabled",
			content: `$TTL 3600
$ORIGIN example.com.
$INCLUDE /path/to/hosts.zone
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
`,
			opts: ParseOptions{
				AllowIncludes: false,
				DefaultTTL:    3600,
			},
			wantErr: true,
			errMsg:  "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDirectives(tt.content, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateDirectives() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.errMsg, err)
			}
		})
	}
}

func TestParseBINDZone_GenerateRejection(t *testing.T) {
	input := `$TTL 3600
$ORIGIN example.com.
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
$GENERATE 1-254 host-$ A 192.0.2.$
@ IN NS ns1
`

	reader := strings.NewReader(input)
	opts := DefaultParseOptions()

	_, err := ParseBINDZone(reader, "example.com.", opts)
	if err == nil {
		t.Fatal("expected error for $GENERATE directive, got nil")
	}

	if !strings.Contains(err.Error(), "$GENERATE") {
		t.Errorf("expected error to mention $GENERATE, got: %v", err)
	}
}

func TestParseBINDZone_IncludeSupport(t *testing.T) {
	// Note: This test can't fully verify $INCLUDE functionality without actual include files
	// It primarily tests that SetIncludeAllowed is called correctly
	input := `$TTL 3600
$ORIGIN example.com.
@ IN SOA ns1.example.com. admin.example.com. (2024010101 3600 1800 604800 86400)
@ IN NS ns1.example.com.
@ IN A 192.0.2.1
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

	// With AllowIncludes=false, the parser should still work for zones without $INCLUDE
	reader2 := strings.NewReader(input)
	opts2 := ParseOptions{
		AllowIncludes: false,
		DefaultTTL:    3600,
	}

	parsed2, err := ParseBINDZone(reader2, "example.com.", opts2)
	if err != nil {
		t.Fatalf("unexpected error with includes disabled: %v", err)
	}

	if parsed2 == nil {
		t.Fatal("parsed zone is nil")
	}
}

func TestValidateDirectives_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name    string
		content string
		opts    ParseOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "lowercase $generate rejected",
			content: `$TTL 3600
$generate 1-10 host-$ A 192.0.2.$
`,
			opts:    DefaultParseOptions(),
			wantErr: true,
			errMsg:  "$GENERATE",
		},
		{
			name: "mixed case $Generate rejected",
			content: `$TTL 3600
$Generate 1-10 host-$ A 192.0.2.$
`,
			opts:    DefaultParseOptions(),
			wantErr: true,
			errMsg:  "$GENERATE",
		},
		{
			name: "lowercase $include rejected when disabled",
			content: `$TTL 3600
$include /path/to/file.zone
`,
			opts:    DefaultParseOptions(),
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name: "mixed case $Include rejected when disabled",
			content: `$TTL 3600
$Include /path/to/file.zone
`,
			opts:    DefaultParseOptions(),
			wantErr: true,
			errMsg:  "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDirectives(tt.content, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateDirectives() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.errMsg, err)
			}
		})
	}
}

func TestDefaultParseOptions_SecureDefaults(t *testing.T) {
	opts := DefaultParseOptions()

	if opts.AllowIncludes {
		t.Error("expected AllowIncludes to be false (secure default for API usage)")
	}

	if opts.DefaultTTL != 3600 {
		t.Errorf("expected DefaultTTL to be 3600, got %d", opts.DefaultTTL)
	}
}
