package parser

import (
	"strings"
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBINDZoneFile(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-abc123",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024122801,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
			{Name: "@", Type: "MX", TTL: 3600, Value: "10 mail.example.com."},
			{Name: "@", Type: "TXT", TTL: 300, Value: "v=spf1 include:_spf.example.com ~all"},
		},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)
	assert.NotEmpty(t, zoneFile)

	// Check that zone file contains expected elements
	assert.Contains(t, zoneFile, "$ORIGIN example.com.")
	assert.Contains(t, zoneFile, "ns1.example.com.")
	assert.Contains(t, zoneFile, "admin.example.com.")
	assert.Contains(t, zoneFile, "192.0.2.1")
	assert.Contains(t, zoneFile, "192.0.2.2")
	assert.Contains(t, zoneFile, "mail.example.com.")
	assert.Contains(t, zoneFile, "v=spf1")

	// Check version comment
	assert.Contains(t, zoneFile, "v2024122801-abc123")

	// Verify SOA record contains all fields
	assert.Contains(t, zoneFile, "2024122801") // Serial
	assert.Contains(t, zoneFile, "3600")       // Refresh
	assert.Contains(t, zoneFile, "1800")       // Retry
	assert.Contains(t, zoneFile, "604800")     // Expire
	assert.Contains(t, zoneFile, "86400")      // Minimum
}

func TestGenerateBINDZoneFile_AllRecordTypes(t *testing.T) {
	zone := &model.Zone{
		Name:    "test.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.test.com.", "admin.test.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "@", Type: "AAAA", TTL: 300, Value: "2001:db8::1"},
			{Name: "www", Type: "CNAME", TTL: 300, Value: "example.com."},
			{Name: "@", Type: "NS", TTL: 86400, Value: "ns1.test.com."},
			{Name: "@", Type: "MX", TTL: 3600, Value: "10 mail.test.com."},
			{Name: "@", Type: "TXT", TTL: 300, Value: "v=spf1 ~all"},
			{Name: "_sip._tcp", Type: "SRV", TTL: 300, Value: "10 60 5060 sip.test.com."},
			{Name: "@", Type: "CAA", TTL: 3600, Value: "0 issue \"letsencrypt.org\""},
		},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)
	assert.NotEmpty(t, zoneFile)

	// Check all record types are present
	assert.Contains(t, zoneFile, "\tA\t")
	assert.Contains(t, zoneFile, "\tAAAA\t")
	assert.Contains(t, zoneFile, "\tCNAME\t")
	assert.Contains(t, zoneFile, "\tNS\t")
	assert.Contains(t, zoneFile, "\tMX\t")
	assert.Contains(t, zoneFile, "\tTXT\t")
	assert.Contains(t, zoneFile, "\tSRV\t")
	assert.Contains(t, zoneFile, "\tCAA\t")
}

func TestGenerateBINDZoneFile_RelativeNames(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	// Relative names should be converted to FQDN
	assert.Contains(t, zoneFile, "www.example.com.")
	assert.Contains(t, zoneFile, "mail.example.com.")
}

func TestGenerateBINDZoneFile_RelativeRDATATargets(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "alias", Type: "CNAME", TTL: 300, Value: "target"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1"},
			{Name: "@", Type: "MX", TTL: 300, Value: "10 mail"},
			{Name: "ptr", Type: "PTR", TTL: 300, Value: "host"},
			{Name: "_sip._tcp", Type: "SRV", TTL: 300, Value: "10 60 5060 sip"},
		},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	assert.Contains(t, zoneFile, "target.example.com.")
	assert.Contains(t, zoneFile, "ns1.example.com.")
	assert.Contains(t, zoneFile, "mail.example.com.")
	assert.Contains(t, zoneFile, "host.example.com.")
	assert.Contains(t, zoneFile, "sip.example.com.")
	assert.NotContains(t, zoneFile, "\tMX\t10 mail.\n")
}

func TestGenerateBINDZoneFile_FQDNWithoutTrailingDot(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "www.example.com", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	assert.Contains(t, zoneFile, "www.example.com.\t300\tIN\tA\t192.0.2.1")
	assert.NotContains(t, zoneFile, "www.example.com.example.com.")
}

func TestGenerateBINDZoneFile_NormalizesSOATargets(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA: model.SOARecord{
			MName:   "ns1.example.com",
			RName:   "admin.example.com",
			Serial:  2024122801,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	assert.Contains(t, zoneFile, "\tSOA\tns1.example.com. admin.example.com.")
	assert.NotContains(t, zoneFile, "\tSOA\tns1.example.com admin.example.com")
}

func TestGenerateBINDZoneFile_RelativeSOATargets(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA: model.SOARecord{
			MName:   "ns1",
			RName:   "admin",
			Serial:  2024122801,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	assert.Contains(t, zoneFile, "\tSOA\tns1.example.com. admin.example.com.")
	assert.NotContains(t, zoneFile, "\tSOA\tns1. admin.")
}

func TestGenerateBINDZoneFile_AtSymbol(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	// @ should be converted to zone name
	assert.Contains(t, zoneFile, "example.com.\t")
}

func TestGenerateBINDZoneFile_EmptyZone(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	// Should still have SOA and $ORIGIN
	assert.Contains(t, zoneFile, "$ORIGIN")
	assert.Contains(t, zoneFile, "SOA")
}

func TestGenerateBINDZoneFile_NilZone(t *testing.T) {
	_, err := GenerateBINDZoneFile(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zone is nil")
}

func TestConvertRecordToRR_InvalidMX(t *testing.T) {
	record := &model.Record{
		Name:  "@",
		Type:  "MX",
		TTL:   3600,
		Value: "invalid-mx-value", // Missing priority
	}

	_, err := convertRecordToRR("example.com.", record)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MX value must be")
}

func TestConvertRecordToRR_SplitsLongTXT(t *testing.T) {
	value := strings.Repeat("a", 300)
	record := &model.Record{
		Name:  "@",
		Type:  "TXT",
		TTL:   300,
		Value: value,
	}

	rr, err := convertRecordToRR("example.com.", record)
	require.NoError(t, err)

	txt, ok := rr.(*dns.TXT)
	require.True(t, ok)
	require.Len(t, txt.Txt, 2)
	assert.Len(t, txt.Txt[0], model.MaxTXTCharacterStringLength)
	assert.Len(t, txt.Txt[1], 45)
	assert.Equal(t, value, strings.Join(txt.Txt, ""))
}

func TestConvertRecordToRR_InvalidSRV(t *testing.T) {
	record := &model.Record{
		Name:  "_sip._tcp",
		Type:  "SRV",
		TTL:   300,
		Value: "10 60", // Missing port and target
	}

	_, err := convertRecordToRR("example.com.", record)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SRV value must be")
}

func TestConvertRecordToRR_InvalidCAA(t *testing.T) {
	record := &model.Record{
		Name:  "@",
		Type:  "CAA",
		TTL:   3600,
		Value: "0", // Missing tag and value
	}

	_, err := convertRecordToRR("example.com.", record)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CAA value must be")
}

func TestConvertRecordToRR_CAAUsesParsedValue(t *testing.T) {
	record := &model.Record{
		Name:  "@",
		Type:  "CAA",
		TTL:   3600,
		Value: "128 issue \"ca.example.com\"",
	}

	rr, err := convertRecordToRR("example.com.", record)
	require.NoError(t, err)

	caa, ok := rr.(*dns.CAA)
	require.True(t, ok)
	assert.Equal(t, uint8(128), caa.Flag)
	assert.Equal(t, "issue", caa.Tag)
	assert.Equal(t, "ca.example.com", caa.Value)
}

func TestConvertRecordToRR_UnsupportedType(t *testing.T) {
	record := &model.Record{
		Name:  "@",
		Type:  "UNKNOWN",
		TTL:   300,
		Value: "test",
	}

	_, err := convertRecordToRR("example.com.", record)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported record type")
}

func TestGenerateBINDZoneFile_ValidStructure(t *testing.T) {
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	zoneFile, err := GenerateBINDZoneFile(zone)
	require.NoError(t, err)

	// Check structure: should have header comments, $ORIGIN, SOA, and records
	lines := strings.Split(zoneFile, "\n")
	assert.True(t, len(lines) > 5, "Zone file should have multiple lines")

	// First non-empty line should be a comment
	assert.True(t, strings.HasPrefix(strings.TrimSpace(lines[0]), ";"),
		"First line should be a comment")

	// Should contain $ORIGIN
	hasOrigin := false
	for _, line := range lines {
		if strings.Contains(line, "$ORIGIN") {
			hasOrigin = true
			break
		}
	}
	assert.True(t, hasOrigin, "Zone file should contain $ORIGIN directive")
}
