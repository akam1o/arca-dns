package parser

import (
	"fmt"
	"sort"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
)

// NormalizeOptions configures zone normalization behavior
type NormalizeOptions struct {
	// Canonicalize converts all domain names to lowercase and ensures FQDN format
	Canonicalize bool
	// Deduplicate removes identical records
	Deduplicate bool
	// SortRecords sorts records for deterministic output
	SortRecords bool
}

// NormalizeMetadata reports non-fatal changes applied during normalization.
type NormalizeMetadata struct {
	DuplicateRecords int
}

// DefaultNormalizeOptions returns sensible defaults for zone normalization
func DefaultNormalizeOptions() NormalizeOptions {
	return NormalizeOptions{
		Canonicalize: true,
		Deduplicate:  true,
		SortRecords:  true,
	}
}

// NormalizeParsedZone converts a ParsedZone to a normalized model.Zone
func NormalizeParsedZone(parsed *ParsedZone, opts NormalizeOptions) (*model.Zone, error) {
	zone, _, err := NormalizeParsedZoneWithMetadata(parsed, opts)
	return zone, err
}

// NormalizeParsedZoneWithMetadata converts a ParsedZone to a normalized
// model.Zone and reports non-fatal normalization changes.
func NormalizeParsedZoneWithMetadata(parsed *ParsedZone, opts NormalizeOptions) (*model.Zone, NormalizeMetadata, error) {
	var metadata NormalizeMetadata
	if parsed == nil {
		return nil, metadata, fmt.Errorf("parsed zone is nil")
	}

	// Canonicalize origin
	origin := parsed.Origin
	if opts.Canonicalize {
		origin = canonicalizeDomain(origin)
	}

	zone := &model.Zone{
		Name:    origin,
		Records: make([]model.Record, 0, len(parsed.Records)),
	}

	// Track SOA record (required)
	var soaRecord *model.SOARecord
	hasSOA := false

	// Convert RRs to model.Record
	for _, rr := range parsed.Records {
		if rr == nil {
			continue
		}

		// Apply default TTL if record has TTL=0
		ttl := rr.Header().Ttl
		if ttl == 0 {
			ttl = parsed.DefaultTTL
		}

		name := rr.Header().Name
		if opts.Canonicalize {
			name = canonicalizeDomain(name)
		}

		switch v := rr.(type) {
		case *dns.SOA:
			if hasSOA {
				return nil, metadata, fmt.Errorf("multiple SOA records found")
			}
			hasSOA = true

			mname := v.Ns
			rname := v.Mbox
			if opts.Canonicalize {
				mname = canonicalizeDomain(mname)
				rname = canonicalizeDomain(rname)
			}

			soaRecord = &model.SOARecord{
				MName:   mname,
				RName:   rname,
				Serial:  v.Serial,
				Refresh: v.Refresh,
				Retry:   v.Retry,
				Expire:  v.Expire,
				Minimum: v.Minttl,
			}

		case *dns.NS:
			value := v.Ns
			if opts.Canonicalize {
				value = canonicalizeDomain(value)
			}
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "NS",
				TTL:   ttl,
				Value: value,
			})

		case *dns.A:
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "A",
				TTL:   ttl,
				Value: v.A.String(),
			})

		case *dns.AAAA:
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "AAAA",
				TTL:   ttl,
				Value: v.AAAA.String(),
			})

		case *dns.CNAME:
			value := v.Target
			if opts.Canonicalize {
				value = canonicalizeDomain(value)
			}
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "CNAME",
				TTL:   ttl,
				Value: value,
			})

		case *dns.MX:
			value := v.Mx
			if opts.Canonicalize {
				value = canonicalizeDomain(value)
			}
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "MX",
				TTL:   ttl,
				Value: fmt.Sprintf("%d %s", v.Preference, value),
			})

		case *dns.TXT:
			// Multiple TXT chunks represent one string split for DNS wire limits.
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "TXT",
				TTL:   ttl,
				Value: strings.Join(v.Txt, ""),
			})

		case *dns.PTR:
			value := v.Ptr
			if opts.Canonicalize {
				value = canonicalizeDomain(value)
			}
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "PTR",
				TTL:   ttl,
				Value: value,
			})

		case *dns.SRV:
			target := v.Target
			if opts.Canonicalize {
				target = canonicalizeDomain(target)
			}
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "SRV",
				TTL:   ttl,
				Value: fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, target),
			})

		case *dns.CAA:
			zone.Records = append(zone.Records, model.Record{
				Name:  name,
				Type:  "CAA",
				TTL:   ttl,
				Value: fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value),
			})

		default:
			// Reject unknown/unsupported record types explicitly
			// This prevents silent data loss during zone migration
			rrType := dns.TypeToString[rr.Header().Rrtype]
			if rrType == "" {
				rrType = fmt.Sprintf("TYPE%d", rr.Header().Rrtype)
			}
			return nil, metadata, fmt.Errorf("unsupported record type: %s (for record %s)", rrType, name)
		}
	}

	if !hasSOA {
		return nil, metadata, fmt.Errorf("no SOA record found")
	}

	zone.SOA = *soaRecord

	// Apply normalization options
	if opts.Deduplicate {
		zone.Records, metadata.DuplicateRecords = deduplicateRecordsWithCount(zone.Records)
	}

	if opts.SortRecords {
		sortRecords(zone.Records)
	}

	return zone, metadata, nil
}

// canonicalizeDomain converts a domain name to canonical form (lowercase, FQDN with trailing dot)
func canonicalizeDomain(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Ensure trailing dot
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	return name
}

// deduplicateRecords removes duplicate records based on all fields
func deduplicateRecords(records []model.Record) []model.Record {
	deduplicated, _ := deduplicateRecordsWithCount(records)
	return deduplicated
}

func deduplicateRecordsWithCount(records []model.Record) ([]model.Record, int) {
	seen := make(map[string]bool)
	result := make([]model.Record, 0, len(records))
	duplicates := 0

	for _, r := range records {
		// Create key from all fields except ID
		key := fmt.Sprintf("%s|%s|%d|%s", r.Name, r.Type, r.TTL, r.Value)
		if seen[key] {
			duplicates++
			continue
		}
		seen[key] = true
		result = append(result, r)
	}

	return result, duplicates
}

// sortRecords sorts records by name, type, then value for deterministic output
func sortRecords(records []model.Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		return records[i].Value < records[j].Value
	})
}
