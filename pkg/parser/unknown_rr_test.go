package parser

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestNormalizeParsedZone_UnknownRRType(t *testing.T) {
	tests := []struct {
		name    string
		rrType  uint16
		wantErr bool
		errMsg  string
	}{
		{
			name:    "DNSKEY record (DNSSEC) rejected",
			rrType:  dns.TypeDNSKEY,
			wantErr: true,
			errMsg:  "DNSKEY",
		},
		{
			name:    "RRSIG record (DNSSEC) rejected",
			rrType:  dns.TypeRRSIG,
			wantErr: true,
			errMsg:  "RRSIG",
		},
		{
			name:    "NSEC record (DNSSEC) rejected",
			rrType:  dns.TypeNSEC,
			wantErr: true,
			errMsg:  "NSEC",
		},
		{
			name:    "DS record (DNSSEC) rejected",
			rrType:  dns.TypeDS,
			wantErr: true,
			errMsg:  "DS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a zone with SOA and the test RR type
			parsed := &ParsedZone{
				Origin:     "example.com.",
				DefaultTTL: 3600,
				Records: []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeSOA,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						Ns:      "ns1.example.com.",
						Mbox:    "admin.example.com.",
						Serial:  2024010101,
						Refresh: 3600,
						Retry:   1800,
						Expire:  604800,
						Minttl:  86400,
					},
					// Create a generic RR with the unsupported type
					&dns.RFC3597{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: tt.rrType,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
					},
				},
			}

			opts := DefaultNormalizeOptions()
			zone, err := NormalizeParsedZone(parsed, opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeParsedZone() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.errMsg, err)
			}

			if zone != nil && tt.wantErr {
				t.Error("expected nil zone for unsupported RR type")
			}
		})
	}
}

func TestBindToModel_UnknownRRTypeRejection(t *testing.T) {
	// This test verifies that unknown RR types in real BIND zone files are rejected
	input := `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 3600 1800 604800 86400
)
example.com. IN NS ns1.example.com.
example.com. IN DNSKEY 256 3 13 (
    mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF
    +KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
)
`

	zone, err := BindToModel(input, "example.com.")
	if err == nil {
		t.Fatal("expected error for DNSKEY record, got nil")
	}

	if !strings.Contains(err.Error(), "DNSKEY") && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected error about unsupported DNSKEY, got: %v", err)
	}

	if zone != nil {
		t.Error("expected nil zone when unsupported RR type is present")
	}
}

func TestBindToModel_OnlySupportedTypes(t *testing.T) {
	// Verify that all explicitly supported types still work
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

	zone, err := BindToModel(input, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error for supported types: %v", err)
	}

	if zone == nil {
		t.Fatal("zone is nil")
	}

	// Should have all records except SOA (which is in zone.SOA)
	if len(zone.Records) < 8 {
		t.Errorf("expected at least 8 records, got %d", len(zone.Records))
	}
}
