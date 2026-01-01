package backend

import (
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

func TestComputeZoneVersion(t *testing.T) {
	now := time.Now()

	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-old12345", // Should be excluded from hash
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
			{ID: "1", Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{ID: "2", Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
		CreatedAt: now,       // Should be excluded from hash
		UpdatedAt: now,       // Should be excluded from hash
	}

	version, err := ComputeZoneVersion(zone)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}

	// Check format: v{serial}-{hash8}
	// "v" (1) + "2024122801" (10) + "-" (1) + "abcd1234" (8) = 20 chars
	if len(version) != 20 {
		t.Errorf("Version length = %d, want 20 (got: %q)", len(version), version)
	}

	if version[:11] != "v2024122801" {
		t.Errorf("Version prefix = %q, want %q", version[:11], "v2024122801")
	}

	if version[11] != '-' {
		t.Errorf("Version separator = %q, want '-'", version[11])
	}

	// Verify hash part is 8 hex characters
	hashPart := version[12:]
	if len(hashPart) != 8 {
		t.Errorf("Hash length = %d, want 8", len(hashPart))
	}
	for _, c := range hashPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Hash contains non-hex character: %c", c)
		}
	}
}

func TestComputeZoneVersion_Deterministic(t *testing.T) {
	zone1 := &model.Zone{
		Name: "example.com.",
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
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	zone2 := &model.Zone{
		Name: "example.com.",
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
		},
		CreatedAt: time.Now().Add(1 * time.Hour), // Different timestamp
		UpdatedAt: time.Now().Add(2 * time.Hour), // Different timestamp
	}

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}


	if v1 != v2 {
		t.Errorf("Versions differ despite identical content: %q vs %q", v1, v2)
	}
}

func TestComputeZoneVersion_OrderIndependent(t *testing.T) {
	zoneA := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
			{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.3"},
		},
	}
	zoneA.SOA.Serial = 2024122801

	zoneB := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.3"}, // Different order
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}
	zoneB.SOA.Serial = 2024122801

	vA, err := ComputeZoneVersion(zoneA)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}

	vB, err := ComputeZoneVersion(zoneB)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}


	if vA != vB {
		t.Errorf("Versions differ despite same records in different order: %q vs %q", vA, vB)
	}
}

func TestComputeZoneVersion_VersionFieldExcluded(t *testing.T) {
	zone1 := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-oldversion",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone1.SOA.Serial = 2024122801

	zone2 := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-differentversion",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone2.SOA.Serial = 2024122801

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}


	if v1 != v2 {
		t.Errorf("Versions differ despite only Version field being different: %q vs %q", v1, v2)
	}
}

func TestComputeZoneVersion_CaseInsensitive(t *testing.T) {
	zone1 := &model.Zone{
		Name: "EXAMPLE.COM.",
		SOA: model.SOARecord{
			MName:   "NS1.EXAMPLE.COM.",
			RName:   "ADMIN.EXAMPLE.COM.",
			Serial:  2024122801,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{
			{Name: "WWW", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	zone2 := &model.Zone{
		Name: "example.com.",
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
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}


	if v1 != v2 {
		t.Errorf("Versions differ despite only case differences: %q vs %q", v1, v2)
	}
}

func TestComputeZoneVersion_RDATANormalization(t *testing.T) {
	tests := []struct {
		name     string
		records1 []model.Record
		records2 []model.Record
		wantSame bool
	}{
		{
			name: "NS records normalized",
			records1: []model.Record{
				{Name: "@", Type: "NS", TTL: 3600, Value: "NS1.EXAMPLE.COM"},
			},
			records2: []model.Record{
				{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
			},
			wantSame: true,
		},
		{
			name: "CNAME records normalized",
			records1: []model.Record{
				{Name: "www", Type: "CNAME", TTL: 300, Value: "TARGET.EXAMPLE.COM"},
			},
			records2: []model.Record{
				{Name: "www", Type: "CNAME", TTL: 300, Value: "target.example.com."},
			},
			wantSame: true,
		},
		{
			name: "MX records normalized",
			records1: []model.Record{
				{Name: "@", Type: "MX", TTL: 3600, Value: "10 MAIL.EXAMPLE.COM"},
			},
			records2: []model.Record{
				{Name: "@", Type: "MX", TTL: 3600, Value: "10 mail.example.com."},
			},
			wantSame: true,
		},
		{
			name: "SRV records normalized",
			records1: []model.Record{
				{Name: "_sip._tcp", Type: "SRV", TTL: 3600, Value: "10 60 5060 SIPSERVER.EXAMPLE.COM"},
			},
			records2: []model.Record{
				{Name: "_sip._tcp", Type: "SRV", TTL: 3600, Value: "10 60 5060 sipserver.example.com."},
			},
			wantSame: true,
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

			if tt.wantSame && v1 != v2 {
				t.Errorf("Versions differ but should be same: %q vs %q", v1, v2)
			} else if !tt.wantSame && v1 == v2 {
				t.Errorf("Versions same but should differ: %q", v1)
			}
		})
	}
}

func TestComputeZoneVersion_DNSSECIncluded(t *testing.T) {
	zone1 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
		DNSSEC: nil,
	}
	zone1.SOA.Serial = 2024122801

	zone2 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
		DNSSEC: &model.DNSSECConfig{
			Enabled:   true,
			Algorithm: 13,
		},
	}
	zone2.SOA.Serial = 2024122801

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}
	if err != nil {
		t.Fatalf("ComputeZoneVersion failed: %v", err)
	}


	if v1 == v2 {
		t.Errorf("Versions same despite different DNSSEC config: %q", v1)
	}
}
