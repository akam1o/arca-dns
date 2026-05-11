package backend

import (
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

func TestComputeZoneHash8(t *testing.T) {
	now := time.Now()

	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v01ARZ3NDEKTSV4RRFFQ69G5FAV", // Should be excluded from hash
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
		CreatedAt: now, // Should be excluded from hash
		UpdatedAt: now, // Should be excluded from hash
	}

	hash8, err := ComputeZoneHash8(zone)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	if len(hash8) != 8 {
		t.Errorf("Hash length = %d, want 8 (got: %q)", len(hash8), hash8)
	}
	for _, c := range hash8 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Hash contains non-hex character: %c", c)
		}
	}
}

func TestComputeZoneHash8_Deterministic(t *testing.T) {
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

	v1, err := ComputeZoneHash8(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	v2, err := ComputeZoneHash8(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Hashes differ despite identical content: %q vs %q", v1, v2)
	}
}

func TestComputeZoneHash8_OrderIndependent(t *testing.T) {
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

	vA, err := ComputeZoneHash8(zoneA)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	vB, err := ComputeZoneHash8(zoneB)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	if vA != vB {
		t.Errorf("Hashes differ despite same records in different order: %q vs %q", vA, vB)
	}
}

func TestComputeZoneHash8_VersionFieldExcluded(t *testing.T) {
	zone1 := &model.Zone{
		Name:    "example.com.",
		Version: "v01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone1.SOA.Serial = 2024122801

	zone2 := &model.Zone{
		Name:    "example.com.",
		Version: "v01ARZ3NDEKTSV4RRFFQ69G5FB0",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone2.SOA.Serial = 2024122801

	v1, err := ComputeZoneHash8(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	v2, err := ComputeZoneHash8(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Hashes differ despite only Version field being different: %q vs %q", v1, v2)
	}
}

func TestComputeZoneHash8_CaseInsensitive(t *testing.T) {
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

	v1, err := ComputeZoneHash8(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	v2, err := ComputeZoneHash8(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Hashes differ despite only case differences: %q vs %q", v1, v2)
	}
}

func TestComputeZoneHash8_RDATANormalization(t *testing.T) {
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

			v1, err := ComputeZoneHash8(zone1)
			if err != nil {
				t.Fatalf("ComputeZoneHash8(zone1) failed: %v", err)
			}
			v2, err := ComputeZoneHash8(zone2)
			if err != nil {
				t.Fatalf("ComputeZoneHash8(zone2) failed: %v", err)
			}

			if tt.wantSame && v1 != v2 {
				t.Errorf("Hashes differ but should be same: %q vs %q", v1, v2)
			} else if !tt.wantSame && v1 == v2 {
				t.Errorf("Hashes same but should differ: %q", v1)
			}
		})
	}
}

func TestComputeZoneHash8_DNSSECIncluded(t *testing.T) {
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

	v1, err := ComputeZoneHash8(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	v2, err := ComputeZoneHash8(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneHash8 failed: %v", err)
	}

	if v1 == v2 {
		t.Errorf("Hashes same despite different DNSSEC config: %q", v1)
	}
}
