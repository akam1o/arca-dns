package parser

import (
	"net"
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
)

func TestNormalizeParsedZone(t *testing.T) {
	tests := []struct {
		name    string
		parsed  *ParsedZone
		opts    NormalizeOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid zone with SOA",
			parsed: &ParsedZone{
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
					&dns.NS{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						Ns: "ns1.example.com.",
					},
				},
			},
			opts:    DefaultNormalizeOptions(),
			wantErr: false,
		},
		{
			name: "missing SOA",
			parsed: &ParsedZone{
				Origin:     "example.com.",
				DefaultTTL: 3600,
				Records: []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						Ns: "ns1.example.com.",
					},
				},
			},
			opts:    DefaultNormalizeOptions(),
			wantErr: true,
			errMsg:  "no SOA record found",
		},
		{
			name: "multiple SOA records",
			parsed: &ParsedZone{
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
					&dns.SOA{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeSOA,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						Ns:      "ns2.example.com.",
						Mbox:    "admin2.example.com.",
						Serial:  2024010102,
						Refresh: 3600,
						Retry:   1800,
						Expire:  604800,
						Minttl:  86400,
					},
				},
			},
			opts:    DefaultNormalizeOptions(),
			wantErr: true,
			errMsg:  "multiple SOA records found",
		},
		{
			name:    "nil parsed zone",
			parsed:  nil,
			opts:    DefaultNormalizeOptions(),
			wantErr: true,
			errMsg:  "parsed zone is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone, err := NormalizeParsedZone(tt.parsed, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if zone == nil {
				t.Fatal("normalized zone is nil")
			}
		})
	}
}

func TestCanonicalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"EXAMPLE.COM", "example.com."},
		{"Example.Com.", "example.com."},
		{"www.example.com", "www.example.com."},
		{"WWW.EXAMPLE.COM.", "www.example.com."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := canonicalizeDomain(tt.input)
			if got != tt.want {
				t.Errorf("canonicalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeParsedZone_TXTChunksConcatenateWithoutSpaces(t *testing.T) {
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
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   "selector._domainkey.example.com.",
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Txt: []string{"v=DKIM1; p=abc", "def"},
			},
		},
	}

	zone, err := NormalizeParsedZone(parsed, DefaultNormalizeOptions())
	if err != nil {
		t.Fatalf("NormalizeParsedZone failed: %v", err)
	}
	if len(zone.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(zone.Records))
	}
	if zone.Records[0].Value != "v=DKIM1; p=abcdef" {
		t.Fatalf("TXT value = %q, want %q", zone.Records[0].Value, "v=DKIM1; p=abcdef")
	}
}

func TestDeduplicateRecords(t *testing.T) {
	tests := []struct {
		name   string
		input  []model.Record
		output int // expected number of records after deduplication
	}{
		{
			name: "no duplicates",
			input: []model.Record{
				{Name: "example.com.", Type: "A", TTL: 3600, Value: "192.0.2.1"},
				{Name: "example.com.", Type: "A", TTL: 3600, Value: "192.0.2.2"},
			},
			output: 2,
		},
		{
			name: "exact duplicates",
			input: []model.Record{
				{Name: "example.com.", Type: "A", TTL: 3600, Value: "192.0.2.1"},
				{Name: "example.com.", Type: "A", TTL: 3600, Value: "192.0.2.1"},
				{Name: "example.com.", Type: "A", TTL: 3600, Value: "192.0.2.1"},
			},
			output: 1,
		},
		{
			name: "different TTL (not duplicates)",
			input: []model.Record{
				{Name: "example.com.", Type: "A", TTL: 3600, Value: "192.0.2.1"},
				{Name: "example.com.", Type: "A", TTL: 7200, Value: "192.0.2.1"},
			},
			output: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateRecords(tt.input)
			if len(result) != tt.output {
				t.Errorf("expected %d records after deduplication, got %d", tt.output, len(result))
			}
		})
	}
}

func TestNormalizeParsedZoneWithMetadataReportsDeduplicatedRecords(t *testing.T) {
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
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "www.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: net.IPv4(192, 0, 2, 1),
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "www.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: net.IPv4(192, 0, 2, 1),
			},
		},
	}

	zone, metadata, err := NormalizeParsedZoneWithMetadata(parsed, DefaultNormalizeOptions())
	if err != nil {
		t.Fatalf("NormalizeParsedZoneWithMetadata failed: %v", err)
	}
	if len(zone.Records) != 1 {
		t.Fatalf("expected 1 deduplicated record, got %d", len(zone.Records))
	}
	if metadata.DuplicateRecords != 1 {
		t.Fatalf("expected 1 duplicate record, got %d", metadata.DuplicateRecords)
	}
}

func TestSortRecords(t *testing.T) {
	records := []model.Record{
		{Name: "zzz.example.com.", Type: "A", TTL: 3600, Value: "192.0.2.3"},
		{Name: "aaa.example.com.", Type: "AAAA", TTL: 3600, Value: "2001:db8::1"},
		{Name: "aaa.example.com.", Type: "A", TTL: 3600, Value: "192.0.2.2"},
		{Name: "example.com.", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
		{Name: "example.com.", Type: "A", TTL: 3600, Value: "192.0.2.1"},
	}

	sortRecords(records)

	// After sorting, records should be ordered by name, then type, then value
	if records[0].Name != "aaa.example.com." {
		t.Errorf("expected first record name to be aaa.example.com., got %s", records[0].Name)
	}

	if records[0].Type != "A" {
		t.Errorf("expected first record type to be A, got %s", records[0].Type)
	}
}

func TestDefaultNormalizeOptions(t *testing.T) {
	opts := DefaultNormalizeOptions()

	if !opts.Canonicalize {
		t.Error("expected Canonicalize to be true")
	}

	if !opts.Deduplicate {
		t.Error("expected Deduplicate to be true")
	}

	if !opts.SortRecords {
		t.Error("expected SortRecords to be true")
	}
}
