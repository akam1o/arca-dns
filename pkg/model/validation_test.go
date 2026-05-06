package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid FQDN", "example.com.", false},
		{"valid without trailing dot", "example.com", false},
		{"valid subdomain", "sub.example.com.", false},
		{"valid @", "@", false},
		{"valid root", ".", false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 254), true},
		{"label too long", strings.Repeat("a", 64) + ".com", true},
		{"invalid characters", "example!.com", true},
		{"starts with hyphen", "-example.com", true},
		{"ends with hyphen", "example-.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomainName(tt.domain)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPv4(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid", "192.0.2.1", false},
		{"valid localhost", "127.0.0.1", false},
		{"invalid format", "256.0.0.1", true},
		{"not IPv4", "2001:db8::1", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPv4(tt.ip)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPv6(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid", "2001:db8::1", false},
		{"valid full", "2001:0db8:0000:0000:0000:0000:0000:0001", false},
		{"not IPv6", "192.0.2.1", true},
		{"invalid format", "gggg::1", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPv6(tt.ip)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMXValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid", "10 mail.example.com.", false},
		{"valid priority 0", "0 mail.example.com.", false},
		{"missing priority", "mail.example.com.", true},
		{"invalid priority", "abc mail.example.com.", true},
		{"negative priority", "-1 mail.example.com.", true},
		{"priority too high", "65536 mail.example.com.", true},
		{"invalid domain", "10 invalid!.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMXValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTXTValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid simple", "v=spf1 include:_spf.example.com ~all", false},
		{"valid with quotes", "\"v=DKIM1; k=rsa; p=...\"", false},
		{"empty", "", false}, // TXT records can be empty
		{"too long", strings.Repeat("a", 65536), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTXTValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSRVValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid", "10 60 5060 sip.example.com.", false},
		{"valid zeros", "0 0 80 www.example.com.", false},
		{"missing field", "10 60 5060", true},
		{"invalid priority", "abc 60 5060 sip.example.com.", true},
		{"invalid weight", "10 abc 5060 sip.example.com.", true},
		{"invalid port", "10 60 abc sip.example.com.", true},
		{"port too high", "10 60 65536 sip.example.com.", true},
		{"invalid domain", "10 60 5060 invalid!.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSRVValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCAAValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid issue", "0 issue \"letsencrypt.org\"", false},
		{"valid issuewild", "0 issuewild \"ca.example.com\"", false},
		{"valid iodef", "0 iodef \"mailto:security@example.com\"", false},
		{"missing fields", "0 issue", true},
		{"invalid flags", "abc issue \"letsencrypt.org\"", true},
		{"flags too high", "256 issue \"letsencrypt.org\"", true},
		{"invalid tag", "0 issue! \"letsencrypt.org\"", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCAAValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  *Record
		wantErr bool
	}{
		{
			name: "valid A record",
			record: &Record{
				Name:  "www",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
			wantErr: false,
		},
		{
			name: "valid AAAA record",
			record: &Record{
				Name:  "www",
				Type:  "AAAA",
				TTL:   300,
				Value: "2001:db8::1",
			},
			wantErr: false,
		},
		{
			name: "valid MX record",
			record: &Record{
				Name:  "@",
				Type:  "MX",
				TTL:   3600,
				Value: "10 mail.example.com.",
			},
			wantErr: false,
		},
		{
			name: "SOA is not allowed as a regular record",
			record: &Record{
				Name:  "@",
				Type:  RecordTypeSOA,
				TTL:   3600,
				Value: "ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400",
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			record: &Record{
				Name:  "www",
				Type:  "INVALID",
				TTL:   300,
				Value: "192.0.2.1",
			},
			wantErr: true,
		},
		{
			name: "zero TTL",
			record: &Record{
				Name:  "www",
				Type:  "A",
				TTL:   0,
				Value: "192.0.2.1",
			},
			wantErr: true,
		},
		{
			name: "empty name",
			record: &Record{
				Name:  "",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
			wantErr: true,
		},
		{
			name: "valid SRV owner labels",
			record: &Record{
				Name:  "_sip._tcp",
				Type:  "SRV",
				TTL:   300,
				Value: "10 20 5060 sip.example.com.",
			},
			wantErr: false,
		},
		{
			name: "valid wildcard owner",
			record: &Record{
				Name:  "*.www",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
			wantErr: false,
		},
		{
			name: "invalid newline in name",
			record: &Record{
				Name:  "www\nbad",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
			wantErr: true,
		},
		{
			name: "invalid wildcard position",
			record: &Record{
				Name:  "www.*",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
			wantErr: true,
		},
		{
			name:    "nil record",
			record:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecord(tt.record)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateZone_RecordNameMustStayInZone(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		SOA: SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []Record{
			{Name: "www.other.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	err := ValidateZone(zone)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside zone")
}

func TestValidateZone_PTRRecordNameMustStayInZone(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		SOA: SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []Record{
			{Name: "1.2.0.192.in-addr.arpa.", Type: "PTR", TTL: 300, Value: "host.example.com."},
		},
	}

	err := ValidateZone(zone)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside zone")
}

func TestValidateZone_PTRRecordNameAllowsReverseZone(t *testing.T) {
	zone := &Zone{
		Name: "0.192.in-addr.arpa.",
		SOA: SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []Record{
			{Name: "1.2.0.192.in-addr.arpa.", Type: "PTR", TTL: 300, Value: "host.example.com."},
		},
	}

	assert.NoError(t, ValidateZone(zone))
}

func TestValidateSOA(t *testing.T) {
	tests := []struct {
		name    string
		soa     *SOARecord
		wantErr bool
	}{
		{
			name: "valid",
			soa: &SOARecord{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Serial:  2024122801,
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
			},
			wantErr: false,
		},
		{
			name: "zero refresh",
			soa: &SOARecord{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Refresh: 0,
			},
			wantErr: true,
		},
		{
			name:    "nil",
			soa:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSOA(tt.soa)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateZone(t *testing.T) {
	tests := []struct {
		name    string
		zone    *Zone
		wantErr bool
	}{
		{
			name: "valid zone",
			zone: &Zone{
				Name: "example.com.",
				SOA: SOARecord{
					MName:   "ns1.example.com.",
					RName:   "admin.example.com.",
					Serial:  2024122801,
					Refresh: 3600,
					Retry:   1800,
					Expire:  604800,
					Minimum: 86400,
				},
				Records: []Record{
					{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
					{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
				},
			},
			wantErr: false,
		},
		{
			name:    "nil zone",
			zone:    nil,
			wantErr: true,
		},
		{
			name: "invalid zone name",
			zone: &Zone{
				Name: "invalid!.com",
				SOA:  DefaultSOA("ns1.example.com.", "admin.example.com."),
			},
			wantErr: true,
		},
		{
			name: "invalid record",
			zone: &Zone{
				Name: "example.com.",
				SOA:  DefaultSOA("ns1.example.com.", "admin.example.com."),
				Records: []Record{
					{Name: "www", Type: "INVALID", TTL: 300, Value: "192.0.2.1"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateZone(tt.zone)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
