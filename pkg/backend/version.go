package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
)

// ComputeZoneVersion generates a content-derived version identifier for a zone.
// Format: v{serial}-{hash8} where hash8 is first 8 chars of SHA256(normalized zone).
// Example: v2024122801-a3f5c2e9
//
// The version is deterministic: same zone content → same version.
// It excludes Zone.Version, CreatedAt, UpdatedAt, and SignatureExpiration from the hash computation.
//
// Returns an error if zone normalization fails.
func ComputeZoneVersion(zone *model.Zone) (string, error) {
	hash8, err := ComputeZoneHash8(zone)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("v%d-%s", zone.SOA.Serial, hash8), nil
}

// ComputeZoneHash returns the SHA256 hash (hex) of the normalized zone content.
func ComputeZoneHash(zone *model.Zone) (string, error) {
	normalized, err := NormalizeZoneForHashing(zone)
	if err != nil {
		return "", fmt.Errorf("failed to normalize zone for hashing: %w", err)
	}
	hash := sha256.Sum256(normalized)
	return hex.EncodeToString(hash[:]), nil
}

// ComputeZoneHash8 returns the first 8 hex chars of ComputeZoneHash (hash8).
func ComputeZoneHash8(zone *model.Zone) (string, error) {
	hashHex, err := ComputeZoneHash(zone)
	if err != nil {
		return "", err
	}
	if len(hashHex) < 8 {
		return "", fmt.Errorf("unexpected hash length: %d", len(hashHex))
	}
	return hashHex[:8], nil
}

// NormalizeZoneForHashing produces a deterministic byte representation of zone content.
// Normalization rules:
// 1. Lowercase all domain names (owner names + RDATA: NS, CNAME, MX, SRV, SOA.MName/RName)
// 2. Expand relative owner names to FQDN (using zone origin)
// 3. Add trailing dots to FQDNs
// 4. Sort records deterministically (name → type → ttl → value)
// 5. Exclude Zone.Version, CreatedAt, UpdatedAt, Record.ID, Record.Priority, SignatureExpiration from serialization
// 6. Use deterministic JSON serialization (sorted map keys, no whitespace)
//
// Returns an error if normalization fails.
func NormalizeZoneForHashing(zone *model.Zone) ([]byte, error) {
	zoneName := model.NormalizeZoneName(zone.Name)

	// normalizedRecord excludes ID and Priority (backend-specific and derived fields)
	type normalizedRecord struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		TTL   uint32 `json:"ttl"`
		Value string `json:"value"`
	}

	// Normalize DNSSEC config (exclude SignatureExpiration - operational state)
	var dnssecNormalized *model.DNSSECConfig
	if zone.DNSSEC != nil {
		dnssecNormalized = &model.DNSSECConfig{
			Enabled:         zone.DNSSEC.Enabled,
			Algorithm:       zone.DNSSEC.Algorithm,
			KSKKeyTag:       zone.DNSSEC.KSKKeyTag,
			ZSKKeyTag:       zone.DNSSEC.ZSKKeyTag,
			NSEC3Enabled:    zone.DNSSEC.NSEC3Enabled,
			NSEC3Iterations: zone.DNSSEC.NSEC3Iterations,
			NSEC3Salt:       zone.DNSSEC.NSEC3Salt,
			// SignatureExpiration excluded (operational state, not config)
		}
	}

	// Create a copy to avoid modifying the original
	normalized := struct {
		Name    string              `json:"name"`
		SOA     model.SOARecord     `json:"soa"`
		Records []normalizedRecord  `json:"records"`
		DNSSEC  *model.DNSSECConfig `json:"dnssec,omitempty"`
	}{
		Name: zoneName,
		SOA: model.SOARecord{
			MName:   model.NormalizeDomainName(zone.SOA.MName),
			RName:   model.NormalizeDomainName(zone.SOA.RName),
			Serial:  zone.SOA.Serial,
			Refresh: zone.SOA.Refresh,
			Retry:   zone.SOA.Retry,
			Expire:  zone.SOA.Expire,
			Minimum: zone.SOA.Minimum,
		},
		DNSSEC: dnssecNormalized,
	}

	// Normalize and sort records
	normalizedRecords := make([]normalizedRecord, len(zone.Records))
	for i, rec := range zone.Records {
		// Expand relative owner names to FQDN
		ownerName := expandOwnerName(rec.Name, zoneName)

		normalizedRecords[i] = normalizedRecord{
			Name:  ownerName,
			Type:  rec.Type,
			TTL:   rec.TTL,
			Value: normalizeRecordValue(rec.Type, rec.Value),
		}
	}

	// Sort records deterministically: name → type → ttl → value
	// TTL included to ensure stable sort even for duplicate (name, type, value)
	sort.Slice(normalizedRecords, func(i, j int) bool {
		if normalizedRecords[i].Name != normalizedRecords[j].Name {
			return normalizedRecords[i].Name < normalizedRecords[j].Name
		}
		if normalizedRecords[i].Type != normalizedRecords[j].Type {
			return normalizedRecords[i].Type < normalizedRecords[j].Type
		}
		if normalizedRecords[i].TTL != normalizedRecords[j].TTL {
			return normalizedRecords[i].TTL < normalizedRecords[j].TTL
		}
		return normalizedRecords[i].Value < normalizedRecords[j].Value
	})

	normalized.Records = normalizedRecords

	// Use deterministic JSON encoding (sorted keys, no whitespace)
	// json.Marshal produces sorted keys by default in Go
	data, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize zone: %w", err)
	}

	return data, nil
}

// expandOwnerName expands a relative owner name to FQDN using the zone origin.
// Rules:
// - "@" → zone origin
// - Name with trailing dot → FQDN, normalize and return
// - Name without trailing dot but contains the zone origin → FQDN, normalize and return
// - Name without trailing dot and doesn't contain zone origin → Relative, prepend to zone origin
func expandOwnerName(name, zoneOrigin string) string {
	return model.NormalizeRecordOwnerName(name, zoneOrigin)
}

// normalizeRecordValue normalizes RDATA values that contain domain names.
// For record types with domain names in RDATA, lowercase and add trailing dot.
// Also normalizes whitespace for MX/SRV records.
func normalizeRecordValue(recordType, value string) string {
	switch recordType {
	case model.RecordTypeNS, model.RecordTypeCNAME, model.RecordTypePTR:
		// These have a single domain name as value
		return model.NormalizeDomainName(value)

	case model.RecordTypeMX:
		// Format: "priority target" (e.g., "10 mail.example.com")
		// Use strings.Fields to normalize whitespace (handles "10   mail.example.com")
		parts := strings.Fields(value)
		if len(parts) == 2 {
			return parts[0] + " " + model.NormalizeDomainName(parts[1])
		}
		return value

	case model.RecordTypeSRV:
		// Format: "priority weight port target" (e.g., "10 60 5060 sipserver.example.com")
		// Use strings.Fields to normalize whitespace
		parts := strings.Fields(value)
		if len(parts) == 4 {
			return parts[0] + " " + parts[1] + " " + parts[2] + " " + model.NormalizeDomainName(parts[3])
		}
		return value

	default:
		// A, AAAA, TXT, CAA: no domain names in RDATA
		return value
	}
}
