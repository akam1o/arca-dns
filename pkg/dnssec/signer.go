package dnssec

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
)

// SignerOptions configures the zone signer.
type SignerOptions struct {
	// Inception is the duration before now when signatures become valid.
	// Default: -1 hour (to account for clock skew)
	Inception time.Duration

	// Expiration is the duration from now when signatures expire.
	// Default: 30 days
	Expiration time.Duration

	// ResignThreshold is how soon before expiration cached signed artifacts
	// should be refreshed. Default: 7 days.
	ResignThreshold time.Duration

	// NSEC3Enabled selects NSEC3 denial-of-existence records. When false, NSEC
	// records are generated instead.
	NSEC3Enabled bool

	// NSEC3Iterations is the number of additional NSEC3 hash iterations.
	NSEC3Iterations uint16

	// NSEC3SaltLength is the NSEC3 salt length in bytes. Zero means no salt.
	NSEC3SaltLength int
}

// DefaultSignerOptions returns default signer options.
func DefaultSignerOptions() SignerOptions {
	return SignerOptions{
		Inception:       -1 * time.Hour,
		Expiration:      30 * 24 * time.Hour,
		ResignThreshold: 7 * 24 * time.Hour,
		NSEC3Enabled:    true,
		NSEC3Iterations: 1,
		NSEC3SaltLength: 8,
	}
}

// ZoneSigner signs DNS zones with DNSSEC.
type ZoneSigner struct {
	keyManager *KeyManager
	options    SignerOptions
	clock      func() time.Time // For testability
}

// NewZoneSigner creates a new zone signer.
func NewZoneSigner(keyManager *KeyManager, opts SignerOptions) *ZoneSigner {
	if opts == (SignerOptions{}) {
		opts = DefaultSignerOptions()
	}
	if opts.Expiration <= 0 {
		opts.Expiration = DefaultSignerOptions().Expiration
	}
	if opts.ResignThreshold < 0 {
		opts.ResignThreshold = 0
	}

	return &ZoneSigner{
		keyManager: keyManager,
		options:    opts,
		clock:      time.Now,
	}
}

// SignZone signs a zone and returns the signed zone with DNSSEC records.
// It returns the signed RRs (including DNSKEY and RRSIG records) and updated zone metadata.
func (s *ZoneSigner) SignZone(zone *model.Zone) (*model.Zone, []dns.RR, error) {
	return s.SignZoneContext(context.Background(), zone)
}

// SignZoneContext signs a zone and honors ctx while loading DNSSEC keys.
func (s *ZoneSigner) SignZoneContext(ctx context.Context, zone *model.Zone) (*model.Zone, []dns.RR, error) {
	if zone == nil {
		return nil, nil, fmt.Errorf("zone is nil")
	}

	// Normalize zone name
	normalizedZoneName, err := NormalizeZoneFQDN(zone.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid zone name: %w", err)
	}

	// Ensure keys exist for this zone
	ksk, zsk, err := s.keyManager.EnsureZoneKeysContext(ctx, normalizedZoneName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get zone keys: %w", err)
	}

	return s.signZoneWithKeys(zone, normalizedZoneName, ksk, zsk)
}

// SignZoneWithKeys signs a zone with a caller-provided key snapshot.
func (s *ZoneSigner) SignZoneWithKeys(zone *model.Zone, ksk, zsk *KeyPair) (*model.Zone, []dns.RR, error) {
	if zone == nil {
		return nil, nil, fmt.Errorf("zone is nil")
	}
	if ksk == nil || zsk == nil {
		return nil, nil, fmt.Errorf("dnssec keys are required")
	}

	normalizedZoneName, err := NormalizeZoneFQDN(zone.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid zone name: %w", err)
	}

	return s.signZoneWithKeys(zone, normalizedZoneName, ksk, zsk)
}

func (s *ZoneSigner) signZoneWithKeys(zone *model.Zone, normalizedZoneName string, ksk, zsk *KeyPair) (*model.Zone, []dns.RR, error) {
	// Convert zone to RRs
	rrs, err := s.modelToRRs(zone, normalizedZoneName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert zone to RRs: %w", err)
	}

	// Add DNSKEY records
	dnskeys := s.createDNSKEYRecords(normalizedZoneName, ksk, zsk)
	rrs = append(rrs, dnskeys...)

	// Group RRsets by (owner, type)
	rrsets, err := groupRRsets(rrs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to group RRsets: %w", err)
	}

	// Sign each RRset
	signedRRs := make([]dns.RR, 0, len(rrs)*2)
	for _, rrset := range rrsets {
		// Skip only RRSIG records (to avoid double-signing)
		if rrset[0].Header().Rrtype == dns.TypeRRSIG {
			continue
		}

		signedRRs = append(signedRRs, rrset...)

		var signingKey *KeyPair
		if rrset[0].Header().Rrtype == dns.TypeDNSKEY {
			// DNSKEY RRset is signed with KSK
			signingKey = ksk
		} else {
			// All other RRsets are signed with ZSK
			signingKey = zsk
		}

		rrsig, err := s.signRRset(rrset, signingKey, normalizedZoneName)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign RRset %s/%s: %w",
				rrset[0].Header().Name, dns.TypeToString[rrset[0].Header().Rrtype], err)
		}
		signedRRs = append(signedRRs, rrsig)
	}

	var nsec3Params *NSEC3Params
	if s.options.NSEC3Enabled {
		params := NewNSEC3Params(zone.SOA.Minimum, s.options.NSEC3Iterations, s.options.NSEC3SaltLength)
		nsec3Records, err := GenerateNSEC3Chain(normalizedZoneName, signedRRs, params)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate NSEC3 chain: %w", err)
		}
		nsec3Params = &params

		// Sign NSEC3 and NSEC3PARAM records with ZSK.
		for _, nsec3RR := range nsec3Records {
			signedRRs = append(signedRRs, nsec3RR)

			rrsig, err := s.signRRset([]dns.RR{nsec3RR}, zsk, normalizedZoneName)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to sign NSEC3 record %s: %w", nsec3RR.Header().Name, err)
			}
			signedRRs = append(signedRRs, rrsig)
		}
	} else {
		nsecRecords, err := GenerateNSECChain(normalizedZoneName, signedRRs, zone.SOA.Minimum)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate NSEC chain: %w", err)
		}

		for _, nsecRR := range nsecRecords {
			signedRRs = append(signedRRs, nsecRR)

			rrsig, err := s.signRRset([]dns.RR{nsecRR}, zsk, normalizedZoneName)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to sign NSEC record %s: %w", nsecRR.Header().Name, err)
			}
			signedRRs = append(signedRRs, rrsig)
		}
	}

	// Sort signed RRs for deterministic output
	sortRRs(signedRRs)

	// Convert back to model.Zone
	signedZone, err := s.rrsToModel(zone, signedRRs, ksk, zsk, normalizedZoneName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert signed RRs to zone: %w", err)
	}

	if nsec3Params != nil {
		signedZone.DNSSEC.NSEC3Enabled = true
		signedZone.DNSSEC.NSEC3Iterations = nsec3Params.Iterations
		signedZone.DNSSEC.NSEC3Salt = nsec3Params.Salt
	}

	return signedZone, signedRRs, nil
}

// modelToRRs converts a model.Zone to []dns.RR.
func (s *ZoneSigner) modelToRRs(zone *model.Zone, normalizedZoneName string) ([]dns.RR, error) {
	rrs := make([]dns.RR, 0, len(zone.Records)+1)

	// Add SOA record
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   normalizedZoneName,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    zone.SOA.Minimum,
		},
		Ns:      model.NormalizeDomainTargetName(zone.SOA.MName, normalizedZoneName),
		Mbox:    model.NormalizeDomainTargetName(zone.SOA.RName, normalizedZoneName),
		Serial:  zone.SOA.Serial,
		Refresh: zone.SOA.Refresh,
		Retry:   zone.SOA.Retry,
		Expire:  zone.SOA.Expire,
		Minttl:  zone.SOA.Minimum,
	}
	rrs = append(rrs, soa)

	// Add other records
	for _, record := range zone.Records {
		rr, err := s.recordToRR(normalizedZoneName, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record %s: %w", record.Name, err)
		}
		rrs = append(rrs, rr)
	}

	return rrs, nil
}

// recordToRR converts a model.Record to dns.RR.
func (s *ZoneSigner) recordToRR(origin string, record *model.Record) (dns.RR, error) {
	name := model.NormalizeRecordOwnerName(record.Name, origin)

	// Create RR header
	hdr := dns.RR_Header{
		Name:  name,
		Class: dns.ClassINET,
		Ttl:   record.TTL,
	}

	// Create specific RR type with input validation
	switch record.Type {
	case model.RecordTypeA:
		hdr.Rrtype = dns.TypeA
		ip := net.ParseIP(record.Value)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %s", record.Value)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("not an IPv4 address: %s", record.Value)
		}
		return &dns.A{Hdr: hdr, A: ipv4}, nil

	case model.RecordTypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		ip := net.ParseIP(record.Value)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", record.Value)
		}
		// Ensure it's actually IPv6 (not IPv4)
		if ip.To4() != nil {
			return nil, fmt.Errorf("not an IPv6 address (IPv4 detected): %s", record.Value)
		}
		return &dns.AAAA{Hdr: hdr, AAAA: ip}, nil

	case model.RecordTypeNS:
		hdr.Rrtype = dns.TypeNS
		return &dns.NS{Hdr: hdr, Ns: model.NormalizeDomainTargetName(record.Value, origin)}, nil

	case model.RecordTypeCNAME:
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: model.NormalizeDomainTargetName(record.Value, origin)}, nil

	case model.RecordTypeMX:
		hdr.Rrtype = dns.TypeMX
		parts := strings.Fields(record.Value)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid MX value: %s", record.Value)
		}
		var prio uint16
		n, err := fmt.Sscanf(parts[0], "%d", &prio)
		if err != nil || n != 1 {
			return nil, fmt.Errorf("invalid MX priority: %s", parts[0])
		}
		return &dns.MX{Hdr: hdr, Preference: prio, Mx: model.NormalizeDomainTargetName(parts[1], origin)}, nil

	case model.RecordTypeTXT:
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: model.SplitTXTValue(record.Value)}, nil

	case model.RecordTypePTR:
		hdr.Rrtype = dns.TypePTR
		return &dns.PTR{Hdr: hdr, Ptr: model.NormalizeDomainTargetName(record.Value, origin)}, nil

	case model.RecordTypeSRV:
		hdr.Rrtype = dns.TypeSRV
		// Format: priority weight port target
		var priority, weight, port uint16
		var target string
		n, err := fmt.Sscanf(record.Value, "%d %d %d %s", &priority, &weight, &port, &target)
		if err != nil || n != 4 {
			return nil, fmt.Errorf("invalid SRV value: %s", record.Value)
		}
		return &dns.SRV{Hdr: hdr, Priority: priority, Weight: weight, Port: port, Target: model.NormalizeDomainTargetName(target, origin)}, nil

	case model.RecordTypeCAA:
		hdr.Rrtype = dns.TypeCAA
		parts := strings.Fields(record.Value)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid CAA value: %s", record.Value)
		}
		flag, err := strconv.Atoi(parts[0])
		if err != nil || flag < 0 || flag > 255 {
			return nil, fmt.Errorf("invalid CAA flag: %s", parts[0])
		}
		tag := parts[1]
		value := strings.Join(parts[2:], " ")
		value = strings.Trim(value, "\"")
		return &dns.CAA{Hdr: hdr, Flag: uint8(flag), Tag: tag, Value: value}, nil

	default:
		return nil, fmt.Errorf("unsupported record type: %s", record.Type)
	}
}

// createDNSKEYRecords creates DNSKEY RRs from zone keys.
func (s *ZoneSigner) createDNSKEYRecords(zoneName string, ksk, zsk *KeyPair) []dns.RR {
	return []dns.RR{
		&ksk.DNSKEY,
		&zsk.DNSKEY,
	}
}

// signRRset signs an RRset and returns the RRSIG record.
func (s *ZoneSigner) signRRset(rrset []dns.RR, key *KeyPair, zoneName string) (dns.RR, error) {
	if len(rrset) == 0 {
		return nil, fmt.Errorf("empty RRset")
	}

	// Validate RRset consistency (name, type, class must match)
	if !dns.IsRRset(rrset) {
		return nil, fmt.Errorf("invalid RRset: records have inconsistent name, type, or class")
	}

	now := s.clock()
	inception := uint32(now.Add(s.options.Inception).Unix())
	expiration := uint32(now.Add(s.options.Expiration).Unix())

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   rrset[0].Header().Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    rrset[0].Header().Ttl,
		},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.DNSKEY.Algorithm,
		Labels:      rrsigLabelCount(rrset[0].Header().Name),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      key.DNSKEY.KeyTag(),
		SignerName:  zoneName,
	}

	// Sign the RRset
	// Convert crypto.PrivateKey to crypto.Signer
	signer, ok := key.Private.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	err := rrsig.Sign(signer, rrset)
	if err != nil {
		return nil, fmt.Errorf("failed to sign RRset: %w", err)
	}

	return rrsig, nil
}

func rrsigLabelCount(owner string) uint8 {
	labels := dns.CountLabel(owner)
	if strings.HasPrefix(owner, "*.") && labels > 0 {
		labels--
	}
	return uint8(labels)
}

// rrsToModel converts signed RRs back to model.Zone.
func (s *ZoneSigner) rrsToModel(originalZone *model.Zone, signedRRs []dns.RR, ksk, zsk *KeyPair, normalizedZoneName string) (*model.Zone, error) {
	// Enable DNSSEC
	now := s.clock()

	// Create a copy of the original zone with normalized name
	signedZone := &model.Zone{
		Name:      normalizedZoneName,
		Version:   originalZone.Version,
		SOA:       originalZone.SOA,
		Records:   make([]model.Record, 0, len(signedRRs)),
		CreatedAt: originalZone.CreatedAt,
		UpdatedAt: now,
	}
	expiration, ok := earliestRRSIGExpiration(signedRRs)
	if !ok {
		return nil, fmt.Errorf("signed RRs contain no RRSIG records")
	}
	signedZone.DNSSEC = &model.DNSSECConfig{
		Enabled:             true,
		Algorithm:           ksk.DNSKEY.Algorithm,
		KSKKeyTag:           ksk.DNSKEY.KeyTag(),
		ZSKKeyTag:           zsk.DNSKEY.KeyTag(),
		SignatureExpiration: &expiration,
	}

	// Convert signed RRs to model.Records
	// For now, we only include the original records + DNSSEC records
	// The RRSIG records will be included in the zone file output
	signedZone.Records = originalZone.Records

	return signedZone, nil
}

func earliestRRSIGExpiration(rrs []dns.RR) (time.Time, bool) {
	var earliest uint32
	for _, rr := range rrs {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if earliest == 0 || rrsig.Expiration < earliest {
			earliest = rrsig.Expiration
		}
	}
	if earliest == 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(earliest), 0).UTC(), true
}

// groupRRsets groups RRs by (owner name, type) and validates TTL and class consistency.
func groupRRsets(rrs []dns.RR) ([][]dns.RR, error) {
	rrsetMap := make(map[string][]dns.RR)

	for _, rr := range rrs {
		key := fmt.Sprintf("%s/%d", rr.Header().Name, rr.Header().Rrtype)
		rrsetMap[key] = append(rrsetMap[key], rr)
	}

	rrsets := make([][]dns.RR, 0, len(rrsetMap))
	for key, rrset := range rrsetMap {
		// Validate consistent TTL and class within RRset
		if len(rrset) > 1 {
			ttl := rrset[0].Header().Ttl
			class := rrset[0].Header().Class
			for _, rr := range rrset[1:] {
				if rr.Header().Ttl != ttl {
					return nil, fmt.Errorf("TTL mismatch in RRset %s: %d vs %d (data corruption detected)",
						key, ttl, rr.Header().Ttl)
				}
				if rr.Header().Class != class {
					return nil, fmt.Errorf("class mismatch in RRset %s: %d vs %d (data corruption detected)",
						key, class, rr.Header().Class)
				}
			}
		}
		rrsets = append(rrsets, rrset)
	}

	return rrsets, nil
}

// sortRRs sorts RRs for deterministic output using sort.Slice.
// Sorts by: name (ascending), type (ascending), then by string representation.
func sortRRs(rrs []dns.RR) {
	sort.Slice(rrs, func(i, j int) bool {
		hi, hj := rrs[i].Header(), rrs[j].Header()

		// Compare by name first
		if hi.Name != hj.Name {
			return hi.Name < hj.Name
		}

		// Then by type
		if hi.Rrtype != hj.Rrtype {
			return hi.Rrtype < hj.Rrtype
		}

		// Finally by string representation for stability
		return rrs[i].String() < rrs[j].String()
	})
}

// GenerateSignedZoneFile generates a BIND format signed zone file.
func (s *ZoneSigner) GenerateSignedZoneFile(signedZone *model.Zone, signedRRs []dns.RR) (string, error) {
	var buf strings.Builder

	// Write zone header
	buf.WriteString(fmt.Sprintf("; Zone: %s\n", signedZone.Name))
	buf.WriteString("; Signed by arca-dns\n")
	buf.WriteString(fmt.Sprintf("; Version: %s\n", signedZone.Version))
	if signedZone.DNSSEC != nil && signedZone.DNSSEC.SignatureExpiration != nil {
		buf.WriteString(fmt.Sprintf("; Signatures valid until: %s\n", signedZone.DNSSEC.SignatureExpiration.Format(time.RFC3339)))
	}
	buf.WriteString("\n")

	// Write $ORIGIN
	buf.WriteString(fmt.Sprintf("$ORIGIN %s\n\n", signedZone.Name))

	// Write all signed RRs
	for _, rr := range signedRRs {
		buf.WriteString(rr.String())
		buf.WriteString("\n")
	}

	return buf.String(), nil
}
