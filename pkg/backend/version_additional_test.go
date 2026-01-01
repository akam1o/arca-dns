package backend

import (
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

// TestComputeZoneVersion_RelativeVsFQDN tests that relative and FQDN owner names produce the same version
func TestComputeZoneVersion_RelativeVsFQDN(t *testing.T) {
	// Zone with relative owner name
	zone1 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"}, // Relative
		},
	}
	zone1.SOA.Serial = 2024122801

	// Zone with FQDN owner name
	zone2 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "www.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"}, // FQDN
		},
	}
	zone2.SOA.Serial = 2024122801

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone1) failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone2) failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Versions differ for relative vs FQDN: %q vs %q", v1, v2)
	}
}

// TestComputeZoneVersion_WhitespaceNormalization tests MX/SRV whitespace normalization
func TestComputeZoneVersion_WhitespaceNormalization(t *testing.T) {
	tests := []struct {
		name     string
		records1 []model.Record
		records2 []model.Record
	}{
		{
			name: "MX with extra spaces",
			records1: []model.Record{
				{Name: "@", Type: "MX", TTL: 3600, Value: "10   mail.example.com"}, // Multiple spaces
			},
			records2: []model.Record{
				{Name: "@", Type: "MX", TTL: 3600, Value: "10 mail.example.com"}, // Single space
			},
		},
		{
			name: "SRV with extra spaces",
			records1: []model.Record{
				{Name: "_sip._tcp", Type: "SRV", TTL: 3600, Value: "10  60  5060  sipserver.example.com"}, // Multiple spaces
			},
			records2: []model.Record{
				{Name: "_sip._tcp", Type: "SRV", TTL: 3600, Value: "10 60 5060 sipserver.example.com"}, // Single spaces
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone1 := &model.Zone{
				Name:    "example.com.",
				SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
				Records: tt.records1,
			}
			zone1.SOA.Serial = 2024122801

			zone2 := &model.Zone{
				Name:    "example.com.",
				SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
				Records: tt.records2,
			}
			zone2.SOA.Serial = 2024122801

			v1, err := ComputeZoneVersion(zone1)
			if err != nil {
				t.Fatalf("ComputeZoneVersion(zone1) failed: %v", err)
			}

			v2, err := ComputeZoneVersion(zone2)
			if err != nil {
				t.Fatalf("ComputeZoneVersion(zone2) failed: %v", err)
			}

			if v1 != v2 {
				t.Errorf("Versions differ despite only whitespace differences: %q vs %q", v1, v2)
			}
		})
	}
}

// TestComputeZoneVersion_PriorityExcluded tests that Priority field is excluded from hash
func TestComputeZoneVersion_PriorityExcluded(t *testing.T) {
	zone1 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "MX", TTL: 3600, Value: "10 mail.example.com", Priority: nil}, // No priority
		},
	}
	zone1.SOA.Serial = 2024122801

	priority := uint16(10)
	zone2 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "MX", TTL: 3600, Value: "10 mail.example.com", Priority: &priority}, // With priority
		},
	}
	zone2.SOA.Serial = 2024122801

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone1) failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone2) failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Versions differ despite only Priority field being different: %q vs %q", v1, v2)
	}
}

// TestComputeZoneVersion_SignatureExpirationExcluded tests that SignatureExpiration is excluded
func TestComputeZoneVersion_SignatureExpirationExcluded(t *testing.T) {
	now := time.Now()
	expiration1 := now.Add(7 * 24 * time.Hour)  // 7 days from now
	expiration2 := now.Add(30 * 24 * time.Hour) // 30 days from now

	zone1 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
		DNSSEC: &model.DNSSECConfig{
			Enabled:             true,
			Algorithm:           13,
			SignatureExpiration: &expiration1, // 7 days
		},
	}
	zone1.SOA.Serial = 2024122801

	zone2 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
		DNSSEC: &model.DNSSECConfig{
			Enabled:             true,
			Algorithm:           13,
			SignatureExpiration: &expiration2, // 30 days (different!)
		},
	}
	zone2.SOA.Serial = 2024122801

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone1) failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone2) failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Versions differ despite only SignatureExpiration being different: %q vs %q", v1, v2)
	}
}

// TestComputeZoneVersion_SortingWithTTL tests that records are sorted by TTL as well
func TestComputeZoneVersion_SortingWithTTL(t *testing.T) {
	// Same records with different TTL values in different orders
	zone1 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "@", Type: "A", TTL: 600, Value: "192.0.2.1"}, // Different TTL
		},
	}
	zone1.SOA.Serial = 2024122801

	zone2 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 600, Value: "192.0.2.1"}, // Reversed order
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone2.SOA.Serial = 2024122801

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone1) failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone2) failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Versions differ despite same records in different order: %q vs %q", v1, v2)
	}
}
