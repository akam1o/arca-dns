package dnssec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// NSEC3Params holds parameters for NSEC3 generation.
type NSEC3Params struct {
	HashAlg    uint8  // dns.SHA1
	Flags      uint8  // 0 (no opt-out)
	Iterations uint16 // 1 (standard)
	Salt       string // hex string
	TTL        uint32 // negative TTL (SOA minimum)
}

// DefaultNSEC3Params returns standard NSEC3 parameters per PLAN.md.
func DefaultNSEC3Params(ttl uint32) NSEC3Params {
	return NewNSEC3Params(ttl, 1, 8)
}

// NewNSEC3Params returns NSEC3 parameters for the configured policy.
func NewNSEC3Params(ttl uint32, iterations uint16, saltLength int) NSEC3Params {
	return NSEC3Params{
		HashAlg:    dns.SHA1,
		Flags:      0, // no opt-out
		Iterations: iterations,
		Salt:       generateRandomSalt(saltLength),
		TTL:        ttl,
	}
}

// generateRandomSalt creates a random hex salt with the requested byte length.
func generateRandomSalt(length int) string {
	if length <= 0 {
		return ""
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "" // fallback to empty salt on error
	}
	return hex.EncodeToString(b)
}

// GenerateNSECChain creates NSEC records for a zone.
// rrs should be the signed RRs before NSEC records are added.
func GenerateNSECChain(zoneApex string, rrs []dns.RR, ttl uint32) ([]dns.RR, error) {
	zoneApex = dns.Fqdn(zoneApex)

	names, emptyNonTerminals, err := collectAuthoritativeNames(zoneApex, rrs)
	if err != nil {
		return nil, fmt.Errorf("failed to collect names: %w", err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no authoritative names found")
	}

	typeBitmaps, err := typeBitmapByName(zoneApex, rrs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute type bitmaps: %w", err)
	}

	sort.Strings(names)

	nsecRecords := make([]dns.RR, 0, len(names))
	for i, name := range names {
		nextName := names[(i+1)%len(names)]
		bitmap := typeBitmaps[name]
		if emptyNonTerminals[name] {
			bitmap = []uint16{}
		}
		bitmap = appendUnique(bitmap, dns.TypeNSEC)
		sort.Slice(bitmap, func(i, j int) bool { return bitmap[i] < bitmap[j] })

		nsecRecords = append(nsecRecords, &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			NextDomain: nextName,
			TypeBitMap: bitmap,
		})
	}

	return nsecRecords, nil
}

// GenerateNSEC3Chain creates NSEC3 + NSEC3PARAM records for a zone.
// rrs should be the signed RRs (including RRSIG but not including NSEC3).
func GenerateNSEC3Chain(zoneApex string, rrs []dns.RR, params NSEC3Params) ([]dns.RR, error) {
	// Normalize zone apex
	zoneApex = dns.Fqdn(zoneApex)

	// Collect authoritative names and compute empty non-terminals
	names, emptyNonTerminals, err := collectAuthoritativeNames(zoneApex, rrs)
	if err != nil {
		return nil, fmt.Errorf("failed to collect names: %w", err)
	}

	// Build type bitmaps per original name
	typeBitmaps, err := typeBitmapByName(zoneApex, rrs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute type bitmaps: %w", err)
	}

	// Add NSEC3PARAM to apex bitmap (since we'll be adding it)
	if apexBitmap, ok := typeBitmaps[zoneApex]; ok {
		typeBitmaps[zoneApex] = appendUnique(apexBitmap, dns.TypeNSEC3PARAM)
	} else {
		typeBitmaps[zoneApex] = []uint16{dns.TypeNSEC3PARAM}
	}

	// Compute hashes for all names
	hashToName := make(map[string]string)
	for _, name := range names {
		hash := dns.HashName(name, params.HashAlg, params.Iterations, params.Salt)
		if existingName, exists := hashToName[hash]; exists {
			return nil, fmt.Errorf("NSEC3 hash collision: %s and %s both hash to %s (regenerate salt)",
				name, existingName, hash)
		}
		hashToName[hash] = name
	}

	// Sort hashes
	hashes := make([]string, 0, len(hashToName))
	for hash := range hashToName {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes) // Base32hex sorts correctly as strings

	// Create NSEC3 chain
	nsec3Records := make([]dns.RR, 0, len(hashes))
	for i, hash := range hashes {
		name := hashToName[hash]
		nextHash := hashes[(i+1)%len(hashes)]

		// Get type bitmap (empty for ENTs)
		bitmap := typeBitmaps[name]
		if emptyNonTerminals[name] {
			bitmap = []uint16{} // empty non-terminals have no types
		}

		// HashLength is the byte length of the hash output (not base32 string length)
		// For SHA1, this is always 20 bytes
		var hashLength uint8
		switch params.HashAlg {
		case dns.SHA1:
			hashLength = 20
		default:
			hashLength = 20 // default to SHA1 size
		}

		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   hash + "." + zoneApex,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    params.TTL,
			},
			Hash:       params.HashAlg,
			Flags:      params.Flags,
			Iterations: params.Iterations,
			SaltLength: uint8(len(params.Salt) / 2), // hex string length / 2 = byte length
			Salt:       params.Salt,
			HashLength: hashLength, // byte length of hash (20 for SHA1)
			NextDomain: nextHash,
			TypeBitMap: bitmap,
		}

		nsec3Records = append(nsec3Records, nsec3)
	}

	// Create NSEC3PARAM at apex
	nsec3param := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name:   zoneApex,
			Rrtype: dns.TypeNSEC3PARAM,
			Class:  dns.ClassINET,
			Ttl:    params.TTL,
		},
		Hash:       params.HashAlg,
		Flags:      params.Flags,
		Iterations: params.Iterations,
		SaltLength: uint8(len(params.Salt) / 2),
		Salt:       params.Salt,
	}

	// Return NSEC3PARAM first, then all NSEC3 records
	result := make([]dns.RR, 0, 1+len(nsec3Records))
	result = append(result, nsec3param)
	result = append(result, nsec3Records...)

	return result, nil
}

// collectAuthoritativeNames collects all owner names from RRs and derives empty non-terminals.
func collectAuthoritativeNames(zoneApex string, rrs []dns.RR) (names []string, emptyNonTerminals map[string]bool, err error) {
	// Collect owner names from RRs
	nameSet := make(map[string]bool)
	for _, rr := range rrs {
		name := rr.Header().Name
		// Filter: only in-zone names, exclude NSEC3 records
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			continue
		}
		if !dns.IsSubDomain(zoneApex, name) {
			continue
		}
		nameSet[dns.Fqdn(name)] = true
	}

	// Derive empty non-terminals
	emptyNonTerminals = make(map[string]bool)
	for name := range nameSet {
		// Walk up to apex (but not past it)
		parent := name
		for {
			parent = parentDomain(parent)
			// Stop at root or at/above zone apex
			if parent == "" || parent == zoneApex || !dns.IsSubDomain(zoneApex, parent) {
				break
			}
			if !nameSet[parent] {
				emptyNonTerminals[parent] = true
				nameSet[parent] = true // add to overall name set
			}
		}
	}

	// Convert set to slice
	names = make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}

	return names, emptyNonTerminals, nil
}

// typeBitmapByName computes type bitmaps for each owner name.
func typeBitmapByName(zoneApex string, rrs []dns.RR) (map[string][]uint16, error) {
	bitmaps := make(map[string]map[uint16]bool)

	for _, rr := range rrs {
		name := dns.Fqdn(rr.Header().Name)
		rrtype := rr.Header().Rrtype

		// Skip NSEC3 records (they don't belong in original name bitmaps)
		if rrtype == dns.TypeNSEC3 {
			continue
		}

		// Only in-zone names
		if !dns.IsSubDomain(zoneApex, name) {
			continue
		}

		if bitmaps[name] == nil {
			bitmaps[name] = make(map[uint16]bool)
		}
		bitmaps[name][rrtype] = true
	}

	// Convert to sorted slices
	result := make(map[string][]uint16)
	for name, typeSet := range bitmaps {
		types := make([]uint16, 0, len(typeSet))
		for t := range typeSet {
			types = append(types, t)
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		result[name] = types
	}

	return result, nil
}

// parentDomain returns the parent domain name or empty string if at root.
func parentDomain(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return ""
	}
	// Join remaining labels
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// appendUnique appends a value to a slice if not already present.
func appendUnique(slice []uint16, val uint16) []uint16 {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}
