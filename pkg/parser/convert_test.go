package parser

import (
	"strings"
	"testing"
)

func TestBindToModel(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		origin  string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid simple zone",
			raw: `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. IN NS ns1.example.com.
example.com. IN A 192.0.2.1
`,
			origin:  "example.com.",
			wantErr: false,
		},
		{
			name: "zone with mixed case (canonicalized)",
			raw: `$TTL 3600
EXAMPLE.COM. IN SOA NS1.EXAMPLE.COM. ADMIN.EXAMPLE.COM. (
    2024010101 3600 1800 604800 86400
)
EXAMPLE.COM. IN NS NS1.EXAMPLE.COM.
WWW.EXAMPLE.COM. IN A 192.0.2.1
`,
			origin:  "example.com.",
			wantErr: false,
		},
		{
			name: "invalid zone (no SOA)",
			raw: `$TTL 3600
example.com. IN NS ns1.example.com.
example.com. IN A 192.0.2.1
`,
			origin:  "example.com.",
			wantErr: true,
			errMsg:  "no SOA record found",
		},
		{
			name: "empty zone",
			raw:  ``,
			origin:  "example.com.",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone, err := BindToModel(tt.raw, tt.origin)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if zone == nil {
				t.Fatal("zone is nil")
			}

			// Verify canonicalization
			if zone.Name != strings.ToLower(tt.origin) {
				t.Errorf("zone name = %q, want %q", zone.Name, strings.ToLower(tt.origin))
			}
		})
	}
}

func TestBindToModelWithDefaults(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		origin  string
	}{
		{
			name: "zone with $ORIGIN",
			raw: `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
@ IN NS ns1
`,
			wantErr: false,
			origin:  "example.com.",
		},
		{
			name: "zone with explicit origin in SOA",
			raw: `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. IN NS ns1.example.com.
`,
			wantErr: false,
			origin:  "example.com.",
		},
		{
			name: "zone with @ and no $ORIGIN",
			raw: `$TTL 3600
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
@ IN NS ns1
`,
			wantErr: true,
		},
		{
			name: "zone with no origin indicators",
			raw: `$TTL 3600
; No SOA or $ORIGIN
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone, err := BindToModelWithDefaults(tt.raw)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if zone == nil {
				t.Fatal("zone is nil")
			}

			if tt.origin != "" && zone.Name != strings.ToLower(tt.origin) {
				t.Errorf("zone name = %q, want %q", zone.Name, strings.ToLower(tt.origin))
			}
		})
	}
}

func TestModelToBind(t *testing.T) {
	// This test requires a valid model.Zone
	// We'll test the basic functionality
	tests := []struct {
		name    string
		zoneStr string
		wantErr bool
	}{
		{
			name: "valid zone roundtrip",
			zoneStr: `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. IN NS ns1.example.com.
example.com. IN A 192.0.2.1
www.example.com. IN A 192.0.2.2
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse BIND -> Model
			zone, err := BindToModel(tt.zoneStr, "example.com.")
			if err != nil {
				t.Fatalf("BindToModel failed: %v", err)
			}

			// Model -> BIND
			output, err := ModelToBind(zone)
			if (err != nil) != tt.wantErr {
				t.Errorf("ModelToBind() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify output is not empty
				if len(output) == 0 {
					t.Error("ModelToBind() returned empty string")
				}

				// Verify output contains key elements
				if !strings.Contains(output, "SOA") {
					t.Error("ModelToBind() output missing SOA record")
				}
			}
		})
	}
}

func TestExtractOrigin(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "$ORIGIN directive",
			raw: `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
`,
			want:    "example.com.",
			wantErr: false,
		},
		{
			name: "$ORIGIN without trailing dot",
			raw: `$ORIGIN example.com
$TTL 3600
`,
			want:    "example.com.",
			wantErr: false,
		},
		{
			name: "SOA record with explicit origin",
			raw: `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
`,
			want:    "example.com.",
			wantErr: false,
		},
		{
			name: "@ symbol without $ORIGIN",
			raw: `$TTL 3600
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
`,
			want:    "",
			wantErr: true,
		},
		{
			name: "no origin information",
			raw: `$TTL 3600
; Just comments
`,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractOrigin(tt.raw)

			if (err != nil) != tt.wantErr {
				t.Errorf("extractOrigin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("extractOrigin() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	// Test BIND -> Model -> BIND preserves semantics
	original := `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
example.com. IN NS ns1.example.com.
example.com. IN NS ns2.example.com.
example.com. IN A 192.0.2.1
www.example.com. IN A 192.0.2.2
mail.example.com. IN A 192.0.2.3
example.com. IN MX 10 mail.example.com.
example.com. IN TXT "v=spf1 -all"
`

	// Parse BIND -> Model
	zone1, err := BindToModel(original, "example.com.")
	if err != nil {
		t.Fatalf("first BindToModel failed: %v", err)
	}

	// Model -> BIND
	generated, err := ModelToBind(zone1)
	if err != nil {
		t.Fatalf("ModelToBind failed: %v", err)
	}

	// BIND -> Model again
	zone2, err := BindToModel(generated, "example.com.")
	if err != nil {
		t.Fatalf("second BindToModel failed: %v", err)
	}

	// Compare semantic equality (not string equality)
	if zone1.Name != zone2.Name {
		t.Errorf("zone names differ: %q vs %q", zone1.Name, zone2.Name)
	}

	if len(zone1.Records) != len(zone2.Records) {
		t.Errorf("record counts differ: %d vs %d", len(zone1.Records), len(zone2.Records))
	}

	// SOA comparison
	if zone1.SOA.Serial != zone2.SOA.Serial {
		t.Errorf("SOA serials differ: %d vs %d", zone1.SOA.Serial, zone2.SOA.Serial)
	}
}
