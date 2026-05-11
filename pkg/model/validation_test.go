package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testApexNSRecord() Record {
	return Record{Name: "@", Type: RecordTypeNS, TTL: 300, Value: "ns1.example.com."}
}

func withTestApexNS(records ...Record) []Record {
	return append([]Record{testApexNSRecord()}, records...)
}

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

func TestValidateDomainTargetRejectsApexShorthand(t *testing.T) {
	assert.Error(t, ValidateDomainTarget("@"))
	assert.NoError(t, ValidateDomainTarget("."))
	assert.NoError(t, ValidateDomainTarget("example.com."))
}

func TestValidateZoneNameRejectsShorthandAndRoot(t *testing.T) {
	assert.Error(t, ValidateZoneName("@"))
	assert.Error(t, ValidateZoneName("."))
	assert.NoError(t, ValidateZoneName("example.com."))
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
		{"apex shorthand target", "10 @", true},
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
		{"valid long chunked value", strings.Repeat("a", MaxTXTValueLength), false},
		{"empty", "", false}, // TXT records can be empty
		{"too long", strings.Repeat("a", MaxTXTValueLength+1), true},
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

func TestSplitTXTValue(t *testing.T) {
	value := strings.Repeat("a", 300)
	chunks := SplitTXTValue(value)

	assert.Len(t, chunks, 2)
	assert.Len(t, chunks[0], MaxTXTCharacterStringLength)
	assert.Len(t, chunks[1], 45)
	assert.Equal(t, value, strings.Join(chunks, ""))
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
		{"apex shorthand target", "10 60 5060 @", true},
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

func TestNormalizeRecordDerivedFields_DerivesPriority(t *testing.T) {
	tests := []struct {
		name     string
		record   Record
		priority uint16
	}{
		{
			name: "MX zero priority",
			record: Record{
				Name:  "@",
				Type:  RecordTypeMX,
				TTL:   300,
				Value: "0 mail.example.com.",
			},
			priority: 0,
		},
		{
			name: "SRV priority",
			record: Record{
				Name:  "_sip._tcp",
				Type:  RecordTypeSRV,
				TTL:   300,
				Value: "20 10 5060 sip.example.com.",
			},
			priority: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := tt.record
			err := NormalizeRecordDerivedFields(&record)

			assert.NoError(t, err)
			if assert.NotNil(t, record.Priority) {
				assert.Equal(t, tt.priority, *record.Priority)
			}
		})
	}
}

func TestNormalizeRecordDerivedFields_RejectsPriorityMismatch(t *testing.T) {
	priority := uint16(20)
	record := &Record{
		Name:     "@",
		Type:     RecordTypeMX,
		TTL:      300,
		Value:    "10 mail.example.com.",
		Priority: &priority,
	}

	err := NormalizeRecordDerivedFields(record)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "priority")
	assert.Equal(t, priority, *record.Priority)
}

func TestRepairRecordDerivedFields_OverwritesPriorityMismatch(t *testing.T) {
	priority := uint16(20)
	record := &Record{
		Name:     "@",
		Type:     RecordTypeMX,
		TTL:      300,
		Value:    "10 mail.example.com.",
		Priority: &priority,
	}

	err := RepairRecordDerivedFields(record)

	assert.NoError(t, err)
	require.NotNil(t, record.Priority)
	assert.Equal(t, uint16(10), *record.Priority)
}

func TestNormalizeRecordDerivedFields_ClearsNonDerivedPriority(t *testing.T) {
	priority := uint16(10)
	record := &Record{
		Name:     "www",
		Type:     RecordTypeA,
		TTL:      300,
		Value:    "192.0.2.1",
		Priority: &priority,
	}

	err := NormalizeRecordDerivedFields(record)

	assert.NoError(t, err)
	assert.Nil(t, record.Priority)
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
			name: "MX priority must match value",
			record: &Record{
				Name:     "@",
				Type:     "MX",
				TTL:      3600,
				Value:    "10 mail.example.com.",
				Priority: uint16Ptr(20),
			},
			wantErr: true,
		},
		{
			name: "valid empty TXT record",
			record: &Record{
				Name:  "@",
				Type:  "TXT",
				TTL:   3600,
				Value: "",
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
			name: "CNAME target cannot use apex shorthand",
			record: &Record{
				Name:  "www",
				Type:  "CNAME",
				TTL:   300,
				Value: "@",
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
			testApexNSRecord(),
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
			testApexNSRecord(),
			{Name: "1.2.0.192.in-addr.arpa.", Type: "PTR", TTL: 300, Value: "host.example.com."},
		},
	}

	assert.NoError(t, ValidateZone(zone))
}

func TestValidateZone_RejectsInconsistentRRsetTTL(t *testing.T) {
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
			testApexNSRecord(),
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www.example.com.", Type: "A", TTL: 600, Value: "192.0.2.2"},
		},
	}

	err := ValidateZone(zone)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "inconsistent TTL")
}

func TestValidateZone_RejectsDuplicateRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []Record
	}{
		{
			name: "exact duplicate",
			records: []Record{
				{Name: "www", Type: RecordTypeA, TTL: 300, Value: "192.0.2.1"},
				{Name: "www", Type: RecordTypeA, TTL: 300, Value: "192.0.2.1"},
			},
		},
		{
			name: "canonical duplicate",
			records: []Record{
				{Name: "@", Type: RecordTypeNS, TTL: 300, Value: "ns1.example.com."},
				{Name: "example.com.", Type: RecordTypeNS, TTL: 300, Value: "ns1.example.com"},
			},
		},
		{
			name: "relative RDATA target duplicate",
			records: []Record{
				{Name: "@", Type: RecordTypeMX, TTL: 300, Value: "10 mail"},
				{Name: "example.com.", Type: RecordTypeMX, TTL: 300, Value: "10 mail.example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := &Zone{
				Name:    "example.com.",
				SOA:     DefaultSOA("ns1.example.com.", "admin.example.com."),
				Records: tt.records,
			}

			err := ValidateZone(zone)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "duplicate record")
		})
	}
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
			name: "apex shorthand mname",
			soa: &SOARecord{
				MName:   "@",
				RName:   "admin.example.com.",
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
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
					testApexNSRecord(),
					{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
					{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing apex NS",
			zone: &Zone{
				Name: "example.com.",
				SOA:  DefaultSOA("ns1.example.com.", "admin.example.com."),
				Records: []Record{
					{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
				},
			},
			wantErr: true,
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
			name: "apex shorthand zone name",
			zone: &Zone{
				Name: "@",
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

func TestValidateZone_CNAMEConstraints(t *testing.T) {
	tests := []struct {
		name       string
		records    []Record
		wantErr    bool
		errContain string
	}{
		{
			name: "cname without sibling records",
			records: withTestApexNS(
				Record{Name: "www", Type: RecordTypeCNAME, TTL: 300, Value: "target.example.com."},
			),
		},
		{
			name: "cname cannot coexist with a record",
			records: withTestApexNS(
				Record{Name: "www", Type: RecordTypeCNAME, TTL: 300, Value: "target.example.com."},
				Record{Name: "www", Type: RecordTypeA, TTL: 300, Value: "192.0.2.1"},
			),
			wantErr:    true,
			errContain: "cannot coexist",
		},
		{
			name: "absolute cname owner cannot coexist with relative sibling",
			records: withTestApexNS(
				Record{Name: "www.example.com.", Type: RecordTypeCNAME, TTL: 300, Value: "target.example.com."},
				Record{Name: "www", Type: RecordTypeAAAA, TTL: 300, Value: "2001:db8::1"},
			),
			wantErr:    true,
			errContain: "cannot coexist",
		},
		{
			name: "multiple cname records for one owner",
			records: withTestApexNS(
				Record{Name: "www", Type: RecordTypeCNAME, TTL: 300, Value: "target1.example.com."},
				Record{Name: "www", Type: RecordTypeCNAME, TTL: 300, Value: "target2.example.com."},
			),
			wantErr:    true,
			errContain: "multiple CNAME",
		},
		{
			name: "apex cname",
			records: withTestApexNS(
				Record{Name: "@", Type: RecordTypeCNAME, TTL: 300, Value: "target.example.com."},
			),
			wantErr:    true,
			errContain: "zone apex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := &Zone{
				Name:    "example.com.",
				SOA:     DefaultSOA("ns1.example.com.", "admin.example.com."),
				Records: tt.records,
			}

			err := ValidateZone(zone)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContain)
				return
			}
			assert.NoError(t, err)
		})
	}
}
