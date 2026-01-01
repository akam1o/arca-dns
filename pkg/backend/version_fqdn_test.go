package backend

import (
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
)

// TestExpandOwnerName_FQDNWithoutDot tests that FQDNs without trailing dots are correctly identified
func TestExpandOwnerName_FQDNWithoutDot(t *testing.T) {
	tests := []struct {
		name       string
		ownerName  string
		zoneOrigin string
		want       string
	}{
		{
			name:       "relative name",
			ownerName:  "www",
			zoneOrigin: "example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "FQDN with trailing dot",
			ownerName:  "www.example.com.",
			zoneOrigin: "example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "FQDN without trailing dot",
			ownerName:  "www.example.com",
			zoneOrigin: "example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "apex with @",
			ownerName:  "@",
			zoneOrigin: "example.com.",
			want:       "example.com.",
		},
		{
			name:       "subdomain FQDN without dot",
			ownerName:  "mail.sub.example.com",
			zoneOrigin: "example.com.",
			want:       "mail.sub.example.com.",
		},
		{
			name:       "subdomain relative",
			ownerName:  "mail.sub",
			zoneOrigin: "example.com.",
			want:       "mail.sub.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandOwnerName(tt.ownerName, tt.zoneOrigin)
			if got != tt.want {
				t.Errorf("expandOwnerName(%q, %q) = %q, want %q", tt.ownerName, tt.zoneOrigin, got, tt.want)
			}
		})
	}
}

// TestComputeZoneVersion_FQDNVariants tests that all FQDN variants produce the same version
func TestComputeZoneVersion_FQDNVariants(t *testing.T) {
	// Zone with relative name
	zone1 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone1.SOA.Serial = 2024122801

	// Zone with FQDN (no trailing dot)
	zone2 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "www.example.com", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone2.SOA.Serial = 2024122801

	// Zone with FQDN (with trailing dot)
	zone3 := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "www.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	zone3.SOA.Serial = 2024122801

	v1, err := ComputeZoneVersion(zone1)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone1) failed: %v", err)
	}

	v2, err := ComputeZoneVersion(zone2)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone2) failed: %v", err)
	}

	v3, err := ComputeZoneVersion(zone3)
	if err != nil {
		t.Fatalf("ComputeZoneVersion(zone3) failed: %v", err)
	}

	if v1 != v2 {
		t.Errorf("Versions differ for relative vs FQDN without dot: %q vs %q", v1, v2)
	}

	if v1 != v3 {
		t.Errorf("Versions differ for relative vs FQDN with dot: %q vs %q", v1, v3)
	}

	if v2 != v3 {
		t.Errorf("Versions differ for FQDN without dot vs with dot: %q vs %q", v2, v3)
	}
}
