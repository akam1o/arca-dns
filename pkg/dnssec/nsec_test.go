package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestGenerateNSECChain_UsesDNSSECCanonicalOrder(t *testing.T) {
	zoneApex := "example.com."
	rrs := []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2026051101,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 1},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "z.a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 2},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 3},
		},
	}

	nsecRecords, err := GenerateNSECChain(zoneApex, rrs, 300)
	if err != nil {
		t.Fatalf("GenerateNSECChain failed: %v", err)
	}

	nextByName := make(map[string]string, len(nsecRecords))
	for _, rr := range nsecRecords {
		nsec, ok := rr.(*dns.NSEC)
		if !ok {
			t.Fatalf("GenerateNSECChain returned %T, want *dns.NSEC", rr)
		}
		nextByName[nsec.Hdr.Name] = nsec.NextDomain
	}

	want := map[string]string{
		"example.com.":     "a.example.com.",
		"a.example.com.":   "z.a.example.com.",
		"z.a.example.com.": "b.example.com.",
		"b.example.com.":   "example.com.",
	}
	for name, next := range want {
		if got := nextByName[name]; got != next {
			t.Fatalf("NSEC next domain for %s = %s, want %s", name, got, next)
		}
	}
}

func TestGenerateNSECChain_EmptyNonTerminalBitmapIncludesNSECAndRRSIG(t *testing.T) {
	zoneApex := "example.com."
	rrs := []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2026051101,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: zoneApex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "a.b.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 1},
		},
	}

	nsecRecords, err := GenerateNSECChain(zoneApex, rrs, 300)
	if err != nil {
		t.Fatalf("GenerateNSECChain failed: %v", err)
	}

	var ent *dns.NSEC
	for _, rr := range nsecRecords {
		nsec := rr.(*dns.NSEC)
		if nsec.Hdr.Name == "b.example.com." {
			ent = nsec
			break
		}
	}
	if ent == nil {
		t.Fatal("empty non-terminal NSEC not found")
	}
	if !containsRRType(ent.TypeBitMap, dns.TypeNSEC) {
		t.Fatalf("empty non-terminal bitmap missing NSEC: %v", ent.TypeBitMap)
	}
	if !containsRRType(ent.TypeBitMap, dns.TypeRRSIG) {
		t.Fatalf("empty non-terminal bitmap missing RRSIG: %v", ent.TypeBitMap)
	}
	if containsRRType(ent.TypeBitMap, dns.TypeA) {
		t.Fatalf("empty non-terminal bitmap unexpectedly contains A: %v", ent.TypeBitMap)
	}
}

func containsRRType(types []uint16, rrtype uint16) bool {
	for _, candidate := range types {
		if candidate == rrtype {
			return true
		}
	}
	return false
}
