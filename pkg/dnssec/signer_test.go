package dnssec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
)

func TestZoneSigner_SignZone(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tempDir,
		MasterKey:    masterKey,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKBits:      0, // ECDSA doesn't use bits
		ZSKBits:      0,
	})
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	signer := NewZoneSigner(km, DefaultSignerOptions())

	// Test zone
	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-testtest",
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
			{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
			{Name: "@", Type: "NS", TTL: 3600, Value: "ns2.example.com."},
			{Name: "@", Type: "A", TTL: 300, Value: "203.0.113.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "203.0.113.2"},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Sign the zone
	signedZone, signedRRs, err := signer.SignZone(zone)
	if err != nil {
		t.Fatalf("failed to sign zone: %v", err)
	}

	// Verify DNSSEC config is set
	if signedZone.DNSSEC == nil {
		t.Fatal("DNSSEC config not set after signing")
	}
	if !signedZone.DNSSEC.Enabled {
		t.Error("DNSSEC not enabled")
	}
	if signedZone.DNSSEC.Algorithm != dns.ECDSAP256SHA256 {
		t.Errorf("wrong algorithm: got %d, want %d", signedZone.DNSSEC.Algorithm, dns.ECDSAP256SHA256)
	}
	if signedZone.DNSSEC.KSKKeyTag == 0 {
		t.Error("KSK key tag not set")
	}
	if signedZone.DNSSEC.ZSKKeyTag == 0 {
		t.Error("ZSK key tag not set")
	}
	if signedZone.DNSSEC.SignatureExpiration == nil {
		t.Error("signature expiration not set")
	}

	// Verify signature expiration is approximately 30 days in the future
	expectedExpiration := time.Now().Add(30 * 24 * time.Hour)
	if signedZone.DNSSEC.SignatureExpiration.Before(expectedExpiration.Add(-1 * time.Hour)) ||
		signedZone.DNSSEC.SignatureExpiration.After(expectedExpiration.Add(1*time.Hour)) {
		t.Errorf("signature expiration not in expected range: got %v", signedZone.DNSSEC.SignatureExpiration)
	}

	// Verify signed RRs contain DNSKEY and RRSIG records
	var hasDNSKEY, hasRRSIG, hasKSKSig, hasZSKSig bool
	kskTag := signedZone.DNSSEC.KSKKeyTag
	zskTag := signedZone.DNSSEC.ZSKKeyTag

	for _, rr := range signedRRs {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			hasDNSKEY = true
		case *dns.RRSIG:
			hasRRSIG = true
			// Check if DNSKEY is signed with KSK
			if r.TypeCovered == dns.TypeDNSKEY && r.KeyTag == kskTag {
				hasKSKSig = true
			}
			// Check if other types are signed with ZSK
			if r.TypeCovered != dns.TypeDNSKEY && r.KeyTag == zskTag {
				hasZSKSig = true
			}
		}
	}

	if !hasDNSKEY {
		t.Error("signed RRs missing DNSKEY records")
	}
	if !hasRRSIG {
		t.Error("signed RRs missing RRSIG records")
	}
	if !hasKSKSig {
		t.Error("DNSKEY not signed with KSK")
	}
	if !hasZSKSig {
		t.Error("other RRsets not signed with ZSK")
	}
}

func TestZoneSigner_SignRRset(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tempDir,
		MasterKey:    masterKey,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKBits:      0,
		ZSKBits:      0,
	})
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	zoneName := "example.com."
	_, zsk, err := km.EnsureZoneKeys(zoneName)
	if err != nil {
		t.Fatalf("failed to ensure zone keys: %v", err)
	}

	signer := NewZoneSigner(km, DefaultSignerOptions())

	// Create a test RRset
	rrset := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "www.example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{203, 0, 113, 1},
		},
	}

	// Sign the RRset with ZSK
	rrsig, err := signer.signRRset(rrset, zsk, zoneName)
	if err != nil {
		t.Fatalf("failed to sign RRset: %v", err)
	}

	// Verify RRSIG
	sig, ok := rrsig.(*dns.RRSIG)
	if !ok {
		t.Fatal("returned RR is not RRSIG")
	}

	if sig.TypeCovered != dns.TypeA {
		t.Errorf("wrong type covered: got %d, want %d", sig.TypeCovered, dns.TypeA)
	}
	if sig.Algorithm != dns.ECDSAP256SHA256 {
		t.Errorf("wrong algorithm: got %d, want %d", sig.Algorithm, dns.ECDSAP256SHA256)
	}
	if sig.KeyTag != zsk.DNSKEY.KeyTag() {
		t.Errorf("wrong key tag: got %d, want %d", sig.KeyTag, zsk.DNSKEY.KeyTag())
	}
	if sig.SignerName != zoneName {
		t.Errorf("wrong signer name: got %s, want %s", sig.SignerName, zoneName)
	}

	// Verify the signature is valid
	err = sig.Verify(&zsk.DNSKEY, rrset)
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestZoneSigner_GroupRRsets(t *testing.T) {
	rrs := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{203, 0, 113, 1},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{203, 0, 113, 2},
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{203, 0, 113, 3},
		},
	}

	rrsets, err := groupRRsets(rrs)
	if err != nil {
		t.Fatalf("failed to group RRsets: %v", err)
	}

	// Should have 3 RRsets: example.com/A, example.com/NS, www.example.com/A
	if len(rrsets) != 3 {
		t.Errorf("wrong number of RRsets: got %d, want 3", len(rrsets))
	}

	// Find the example.com/A RRset
	var exampleASet []dns.RR
	for _, rrset := range rrsets {
		if rrset[0].Header().Name == "example.com." && rrset[0].Header().Rrtype == dns.TypeA {
			exampleASet = rrset
			break
		}
	}

	if len(exampleASet) != 2 {
		t.Errorf("example.com/A RRset should have 2 records, got %d", len(exampleASet))
	}
}

func TestZoneSigner_GenerateSignedZoneFile(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tempDir,
		MasterKey:    masterKey,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKBits:      0,
		ZSKBits:      0,
	})
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	signer := NewZoneSigner(km, DefaultSignerOptions())

	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-testtest",
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
			{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
			{Name: "@", Type: "A", TTL: 300, Value: "203.0.113.1"},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Sign the zone
	signedZone, signedRRs, err := signer.SignZone(zone)
	if err != nil {
		t.Fatalf("failed to sign zone: %v", err)
	}

	// Generate signed zone file
	zoneFile, err := signer.GenerateSignedZoneFile(signedZone, signedRRs)
	if err != nil {
		t.Fatalf("failed to generate signed zone file: %v", err)
	}

	// Verify the zone file contains expected elements
	if zoneFile == "" {
		t.Fatal("generated zone file is empty")
	}

	// Check for SOA record
	if !contains(zoneFile, "SOA") {
		t.Error("zone file missing SOA record")
	}

	// Check for DNSKEY records
	if !contains(zoneFile, "DNSKEY") {
		t.Error("zone file missing DNSKEY records")
	}

	// Check for RRSIG records
	if !contains(zoneFile, "RRSIG") {
		t.Error("zone file missing RRSIG records")
	}

	// Optional: Write to file for manual inspection
	testFile := filepath.Join(tempDir, "test.zone.signed")
	if err := os.WriteFile(testFile, []byte(zoneFile), 0644); err != nil {
		t.Logf("warning: failed to write test zone file: %v", err)
	} else {
		t.Logf("signed zone file written to: %s", testFile)
	}
}

func TestZoneSigner_ClockInjection(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tempDir,
		MasterKey:    masterKey,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKBits:      0,
		ZSKBits:      0,
	})
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	signer := NewZoneSigner(km, DefaultSignerOptions())

	// Inject fixed time
	fixedTime := time.Date(2024, 12, 28, 12, 0, 0, 0, time.UTC)
	signer.clock = func() time.Time { return fixedTime }

	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-testtest",
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
			{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
		},
		CreatedAt: fixedTime,
		UpdatedAt: fixedTime,
	}

	signedZone, _, err := signer.SignZone(zone)
	if err != nil {
		t.Fatalf("failed to sign zone: %v", err)
	}

	// Verify UpdatedAt uses injected clock (not time.Now())
	if !signedZone.UpdatedAt.Equal(fixedTime) {
		t.Errorf("UpdatedAt mismatch: got %v, want %v (clock injection not working)",
			signedZone.UpdatedAt, fixedTime)
	}

	// Verify signature expiration matches the fixed time
	expectedExpiration := fixedTime.Add(30 * 24 * time.Hour)
	if !signedZone.DNSSEC.SignatureExpiration.Equal(expectedExpiration) {
		t.Errorf("signature expiration mismatch: got %v, want %v",
			signedZone.DNSSEC.SignatureExpiration, expectedExpiration)
	}
}

func TestZoneSigner_ZoneNameNormalization(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tempDir,
		MasterKey:    masterKey,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKBits:      0,
		ZSKBits:      0,
	})
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	signer := NewZoneSigner(km, DefaultSignerOptions())

	testCases := []struct {
		name           string
		inputZoneName  string
		expectedOutput string
	}{
		{
			name:           "uppercase domain",
			inputZoneName:  "EXAMPLE.COM.",
			expectedOutput: "example.com.",
		},
		{
			name:           "mixed case",
			inputZoneName:  "Example.COM.",
			expectedOutput: "example.com.",
		},
		{
			name:           "missing trailing dot",
			inputZoneName:  "example.com",
			expectedOutput: "example.com.",
		},
		{
			name:           "already normalized",
			inputZoneName:  "example.com.",
			expectedOutput: "example.com.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			zone := &model.Zone{
				Name:    tc.inputZoneName,
				Version: "v1-test",
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
					{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			signedZone, signedRRs, err := signer.SignZone(zone)
			if err != nil {
				t.Fatalf("failed to sign zone: %v", err)
			}

			// Verify zone name is normalized
			if signedZone.Name != tc.expectedOutput {
				t.Errorf("zone name not normalized: got %s, want %s", signedZone.Name, tc.expectedOutput)
			}

			// Verify RRSIG SignerName is normalized
			for _, rr := range signedRRs {
				if sig, ok := rr.(*dns.RRSIG); ok {
					if sig.SignerName != tc.expectedOutput {
						t.Errorf("RRSIG SignerName not normalized: got %s, want %s", sig.SignerName, tc.expectedOutput)
					}
				}
			}
		})
	}
}

func TestZoneSigner_IPv4InAAAARejection(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tempDir,
		MasterKey:    masterKey,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKBits:      0,
		ZSKBits:      0,
	})
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	signer := NewZoneSigner(km, DefaultSignerOptions())

	zone := &model.Zone{
		Name:    "example.com.",
		Version: "v1-test",
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
			{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
			{Name: "@", Type: "AAAA", TTL: 300, Value: "203.0.113.1"}, // IPv4 in AAAA!
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, _, err = signer.SignZone(zone)
	if err == nil {
		t.Fatal("expected error for IPv4 address in AAAA record, got nil")
	}

	if !strings.Contains(err.Error(), "IPv4 detected") && !strings.Contains(err.Error(), "not an IPv6 address") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestZoneSigner_TTLMismatchError(t *testing.T) {
	// Create RRs with mismatched TTLs in same RRset
	rrs := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{203, 0, 113, 1},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}, // Different TTL!
			A:   []byte{203, 0, 113, 2},
		},
	}

	_, err := groupRRsets(rrs)
	if err == nil {
		t.Fatal("expected error for TTL mismatch, got nil")
	}

	if !strings.Contains(err.Error(), "TTL mismatch") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestZoneSigner_CanonicalOrdering verifies that RRSIG verification succeeds
// regardless of RRset order, proving that miekg/dns handles canonical sorting.
func TestZoneSigner_CanonicalOrdering(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tempDir,
		MasterKey:    masterKey,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKBits:      0,
		ZSKBits:      0,
	})
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Create two zones with same records in different order
	zone1 := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-testtest",
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
			{Name: "@", Type: "A", TTL: 3600, Value: "192.0.2.1"},
			{Name: "@", Type: "A", TTL: 3600, Value: "192.0.2.2"},
			{Name: "@", Type: "A", TTL: 3600, Value: "192.0.2.3"},
			{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
		},
	}

	zone2 := &model.Zone{
		Name:    "example.com.",
		Version: "v2024122801-testtest",
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
			// Same records in different order
			{Name: "@", Type: "A", TTL: 3600, Value: "192.0.2.3"},
			{Name: "@", Type: "A", TTL: 3600, Value: "192.0.2.1"},
			{Name: "@", Type: "NS", TTL: 3600, Value: "ns1.example.com."},
			{Name: "@", Type: "A", TTL: 3600, Value: "192.0.2.2"},
		},
	}

	signer := NewZoneSigner(km, DefaultSignerOptions())

	// Sign both zones
	_, signedRRs1, err := signer.SignZone(zone1)
	if err != nil {
		t.Fatalf("failed to sign zone1: %v", err)
	}

	_, signedRRs2, err := signer.SignZone(zone2)
	if err != nil {
		t.Fatalf("failed to sign zone2: %v", err)
	}

	// Find A record RRSIGs
	var rrsig1, rrsig2 *dns.RRSIG
	for _, rr := range signedRRs1 {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
			rrsig1 = sig
			break
		}
	}
	for _, rr := range signedRRs2 {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
			rrsig2 = sig
			break
		}
	}

	if rrsig1 == nil || rrsig2 == nil {
		t.Fatal("failed to find A record RRSIGs")
	}

	// Extract A records from both zones
	var aRecords1, aRecords2 []dns.RR
	for _, rr := range signedRRs1 {
		if rr.Header().Rrtype == dns.TypeA {
			aRecords1 = append(aRecords1, rr)
		}
	}
	for _, rr := range signedRRs2 {
		if rr.Header().Rrtype == dns.TypeA {
			aRecords2 = append(aRecords2, rr)
		}
	}

	// Get public keys
	ksk, zsk, err := km.EnsureZoneKeys("example.com.")
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	// Verify both signatures against both RRset orders
	// This proves canonical sorting works correctly in miekg/dns
	if err := rrsig1.Verify(&zsk.DNSKEY, aRecords1); err != nil {
		t.Errorf("rrsig1 failed to verify aRecords1: %v", err)
	}
	if err := rrsig1.Verify(&zsk.DNSKEY, aRecords2); err != nil {
		t.Errorf("rrsig1 failed to verify aRecords2 (different order): %v", err)
	}
	if err := rrsig2.Verify(&zsk.DNSKEY, aRecords1); err != nil {
		t.Errorf("rrsig2 failed to verify aRecords1 (different order): %v", err)
	}
	if err := rrsig2.Verify(&zsk.DNSKEY, aRecords2); err != nil {
		t.Errorf("rrsig2 failed to verify aRecords2: %v", err)
	}

	// Suppress unused variable warning for ksk
	_ = ksk

	t.Log("canonical sorting verification passed: signatures verify regardless of RRset order")
}
