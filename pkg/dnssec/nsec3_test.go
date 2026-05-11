package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestGenerateNSEC3Chain_Basic(t *testing.T) {
	zoneApex := "example.com."

	// Create basic zone records
	rrs := []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2024122801,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minttl:  86400,
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		},
	}

	params := NSEC3Params{
		HashAlg:    dns.SHA1,
		Flags:      0,
		Iterations: 1,
		Salt:       "A1B2", // fixed salt for deterministic testing
		TTL:        86400,
	}

	result, err := GenerateNSEC3Chain(zoneApex, rrs, params)
	if err != nil {
		t.Fatalf("GenerateNSEC3Chain failed: %v", err)
	}

	// Verify NSEC3PARAM exists
	var nsec3param *dns.NSEC3PARAM
	for _, rr := range result {
		if param, ok := rr.(*dns.NSEC3PARAM); ok {
			nsec3param = param
			break
		}
	}
	if nsec3param == nil {
		t.Fatal("NSEC3PARAM not found")
	}
	if nsec3param.Header().Name != zoneApex {
		t.Errorf("NSEC3PARAM owner mismatch: got %s, want %s", nsec3param.Header().Name, zoneApex)
	}

	// Count NSEC3 records
	nsec3Count := 0
	for _, rr := range result {
		if _, ok := rr.(*dns.NSEC3); ok {
			nsec3Count++
		}
	}

	// Should have NSEC3 for: apex + www.example.com
	expectedCount := 2
	if nsec3Count != expectedCount {
		t.Errorf("NSEC3 count mismatch: got %d, want %d", nsec3Count, expectedCount)
	}

	// Verify all NSEC3 owners end with zone apex
	for _, rr := range result {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			if !dns.IsSubDomain(zoneApex, nsec3.Header().Name) {
				t.Errorf("NSEC3 owner %s not in zone %s", nsec3.Header().Name, zoneApex)
			}
		}
	}

	t.Logf("Generated %d NSEC3 records + 1 NSEC3PARAM", nsec3Count)
}

func TestGenerateNSEC3Chain_CyclicChain(t *testing.T) {
	zoneApex := "example.com."

	rrs := []dns.RR{
		&dns.SOA{
			Hdr:  dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:   "ns1.example.com.",
			Mbox: "admin.example.com.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "mail.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 2},
		},
	}

	params := DefaultNSEC3Params(86400)

	result, err := GenerateNSEC3Chain(zoneApex, rrs, params)
	if err != nil {
		t.Fatalf("GenerateNSEC3Chain failed: %v", err)
	}

	// Extract NSEC3 records and build chain map
	nsec3Map := make(map[string]string) // hash -> next hash
	for _, rr := range result {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			// Extract hash from owner name (remove zone apex suffix)
			hash := nsec3.Header().Name[:len(nsec3.Header().Name)-len(zoneApex)-1]
			nsec3Map[hash] = nsec3.NextDomain
		}
	}

	if len(nsec3Map) == 0 {
		t.Fatal("no NSEC3 records found")
	}

	// Verify chain is cyclic: follow the chain and ensure we return to start
	start := ""
	for hash := range nsec3Map {
		start = hash
		break
	}

	current := start
	visited := 0
	maxVisits := len(nsec3Map) + 1 // prevent infinite loop

	for visited < maxVisits {
		next, ok := nsec3Map[current]
		if !ok {
			t.Fatalf("broken chain: hash %s has no next pointer", current)
		}
		current = next
		visited++
		if current == start {
			// Successfully returned to start
			if visited != len(nsec3Map) {
				t.Errorf("chain length mismatch: visited %d, expected %d", visited, len(nsec3Map))
			}
			t.Logf("chain is cyclic: %d hashes", visited)
			return
		}
	}

	t.Fatal("chain is not cyclic or has infinite loop")
}

func TestGenerateNSEC3Chain_EmptyNonTerminals(t *testing.T) {
	zoneApex := "example.com."

	// Only record at a.b.example.com (should create ENT for b.example.com)
	rrs := []dns.RR{
		&dns.SOA{
			Hdr:  dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:   "ns1.example.com.",
			Mbox: "admin.example.com.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "a.b.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		},
	}

	params := NSEC3Params{
		HashAlg:    dns.SHA1,
		Flags:      0,
		Iterations: 1,
		Salt:       "ABCD",
		TTL:        86400,
	}

	result, err := GenerateNSEC3Chain(zoneApex, rrs, params)
	if err != nil {
		t.Fatalf("GenerateNSEC3Chain failed: %v", err)
	}

	// Verify we have NSEC3 for: apex, b.example.com (ENT), a.b.example.com
	nsec3Count := 0
	emptyBitmapCount := 0
	for _, rr := range result {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3Count++
			if len(nsec3.TypeBitMap) == 0 {
				emptyBitmapCount++
				t.Logf("found ENT with empty bitmap: %s", nsec3.Header().Name)
			}
		}
	}

	expectedNSEC3 := 3 // apex + b.example.com + a.b.example.com
	if nsec3Count != expectedNSEC3 {
		t.Errorf("NSEC3 count mismatch: got %d, want %d", nsec3Count, expectedNSEC3)
	}

	// Should have exactly one ENT (b.example.com)
	if emptyBitmapCount != 1 {
		t.Errorf("empty bitmap count mismatch: got %d, want 1", emptyBitmapCount)
	}
}

func TestGenerateNSEC3Chain_TypeBitmaps(t *testing.T) {
	zoneApex := "example.com."

	rrs := []dns.RR{
		&dns.SOA{
			Hdr:  dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:   "ns1.example.com.",
			Mbox: "admin.example.com.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     257,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
			PublicKey: "dGVzdGtleQ==",
		},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeSOA,
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA,
		},
	}

	params := DefaultNSEC3Params(86400)

	result, err := GenerateNSEC3Chain(zoneApex, rrs, params)
	if err != nil {
		t.Fatalf("GenerateNSEC3Chain failed: %v", err)
	}

	// Find apex NSEC3 and verify bitmap includes SOA, NS, DNSKEY, RRSIG, NSEC3PARAM
	apexHash := dns.HashName(zoneApex, params.HashAlg, params.Iterations, params.Salt)
	var apexNSEC3 *dns.NSEC3
	for _, rr := range result {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			hash := nsec3.Header().Name[:len(nsec3.Header().Name)-len(zoneApex)-1]
			if hash == apexHash {
				apexNSEC3 = nsec3
				break
			}
		}
	}

	if apexNSEC3 == nil {
		t.Fatal("apex NSEC3 not found")
	}

	expectedTypes := []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeNSEC3PARAM}
	for _, expected := range expectedTypes {
		found := false
		for _, actual := range apexNSEC3.TypeBitMap {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("apex bitmap missing type %s", dns.TypeToString[expected])
		}
	}

	t.Logf("apex bitmap: %v", apexNSEC3.TypeBitMap)
}

func TestGenerateNSEC3Chain_OutOfZoneFiltering(t *testing.T) {
	zoneApex := "example.com."

	rrs := []dns.RR{
		&dns.SOA{
			Hdr:  dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:   "ns1.example.com.",
			Mbox: "admin.example.com.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		// Out-of-zone record (should be ignored)
		&dns.A{
			Hdr: dns.RR_Header{Name: "evil.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 99},
		},
	}

	params := DefaultNSEC3Params(86400)

	result, err := GenerateNSEC3Chain(zoneApex, rrs, params)
	if err != nil {
		t.Fatalf("GenerateNSEC3Chain failed: %v", err)
	}

	// Verify no NSEC3 for evil.org
	evilHash := dns.HashName("evil.org.", params.HashAlg, params.Iterations, params.Salt)
	for _, rr := range result {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			hash := nsec3.Header().Name[:len(nsec3.Header().Name)-len(zoneApex)-1]
			if hash == evilHash {
				t.Error("out-of-zone name generated NSEC3 record")
			}
		}
	}

	// Should only have apex NSEC3
	nsec3Count := 0
	for _, rr := range result {
		if _, ok := rr.(*dns.NSEC3); ok {
			nsec3Count++
		}
	}
	if nsec3Count != 1 {
		t.Errorf("NSEC3 count mismatch: got %d, want 1 (apex only)", nsec3Count)
	}
}

func TestDefaultNSEC3Params(t *testing.T) {
	params := DefaultNSEC3Params(86400)

	if params.HashAlg != dns.SHA1 {
		t.Errorf("hash algorithm mismatch: got %d, want %d", params.HashAlg, dns.SHA1)
	}
	if params.Flags != 0 {
		t.Errorf("flags mismatch: got %d, want 0", params.Flags)
	}
	if params.Iterations != 1 {
		t.Errorf("iterations mismatch: got %d, want 1", params.Iterations)
	}
	if params.TTL != 86400 {
		t.Errorf("TTL mismatch: got %d, want 86400", params.TTL)
	}
	if params.Salt == "" && params.Salt != "-" {
		t.Error("salt is empty (should be random or '-')")
	}
}

func TestNewNSEC3Params_ZeroSaltLengthUsesEmptySalt(t *testing.T) {
	params := NewNSEC3Params(86400, 1, 0)

	if params.Salt != "" {
		t.Fatalf("salt = %q, want empty string for no salt", params.Salt)
	}
}

func TestGenerateNSEC3Chain_NoSaltUsesEmptyWireSalt(t *testing.T) {
	zoneApex := "example.com."
	rrs := []dns.RR{
		&dns.SOA{
			Hdr:  dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:   "ns1.example.com.",
			Mbox: "admin.example.com.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		},
	}
	params := NSEC3Params{
		HashAlg:    dns.SHA1,
		Flags:      0,
		Iterations: 1,
		Salt:       "",
		TTL:        86400,
	}

	result, err := GenerateNSEC3Chain(zoneApex, rrs, params)
	if err != nil {
		t.Fatalf("GenerateNSEC3Chain failed: %v", err)
	}

	wantApexHash := dns.HashName(zoneApex, params.HashAlg, params.Iterations, "")
	foundApex := false
	for _, rr := range result {
		switch typed := rr.(type) {
		case *dns.NSEC3PARAM:
			if typed.Salt != "" {
				t.Fatalf("NSEC3PARAM salt = %q, want empty", typed.Salt)
			}
			if typed.SaltLength != 0 {
				t.Fatalf("NSEC3PARAM salt length = %d, want 0", typed.SaltLength)
			}
		case *dns.NSEC3:
			if typed.Salt != "" {
				t.Fatalf("NSEC3 salt = %q, want empty", typed.Salt)
			}
			if typed.SaltLength != 0 {
				t.Fatalf("NSEC3 salt length = %d, want 0", typed.SaltLength)
			}
			hash := typed.Header().Name[:len(typed.Header().Name)-len(zoneApex)-1]
			if hash == wantApexHash {
				foundApex = true
			}
		}
	}
	if !foundApex {
		t.Fatalf("apex NSEC3 hash for empty salt was not generated: %s", wantApexHash)
	}
}

func TestParentDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"subdomain", "www.example.com.", "example.com."},
		{"apex", "example.com.", "com."},
		{"tld", "com.", ""},
		{"deep", "a.b.c.example.com.", "b.c.example.com."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parentDomain(tt.input)
			if result != tt.expected {
				t.Errorf("parentDomain(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}
