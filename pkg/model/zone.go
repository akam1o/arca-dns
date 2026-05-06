package model

import "time"

// Zone represents a DNS zone with all its records and metadata.
type Zone struct {
	// Name is the fully qualified domain name of the zone (e.g., "example.com.")
	Name string `json:"name"`

	// Version is the unique version identifier for this zone state
	// Format: v{ULID} (e.g., "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
	Version string `json:"version"`

	// SOA contains the Start of Authority record
	SOA SOARecord `json:"soa"`

	// Records contains all resource records for this zone
	Records []Record `json:"records"`

	// DNSSEC configuration (nil if DNSSEC is disabled)
	DNSSEC *DNSSECConfig `json:"dnssec,omitempty"`

	// CreatedAt is when the zone was first created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the zone was last modified
	UpdatedAt time.Time `json:"updated_at"`
}

// SOARecord represents a Start of Authority record.
type SOARecord struct {
	// MName is the primary name server for the zone
	MName string `json:"mname"`

	// RName is the email address of the zone administrator (with @ replaced by .)
	RName string `json:"rname"`

	// Serial is the zone serial number (auto-incremented on updates)
	// Format: YYYYMMDDnn (date-based with counter)
	Serial uint32 `json:"serial"`

	// Refresh is the time interval before the zone should be refreshed (seconds)
	Refresh uint32 `json:"refresh"`

	// Retry is the time interval before a failed refresh should be retried (seconds)
	Retry uint32 `json:"retry"`

	// Expire is the time value that specifies the upper limit on the time interval
	// that can elapse before the zone is no longer authoritative (seconds)
	Expire uint32 `json:"expire"`

	// Minimum is the TTL for negative responses (seconds)
	Minimum uint32 `json:"minimum"`
}

// Record represents a DNS resource record.
type Record struct {
	// ID is the unique identifier for this record (backend-specific)
	ID string `json:"id,omitempty"`

	// Name is the record name (can be relative to zone origin)
	// Examples: "@", "www", "mail.sub"
	Name string `json:"name"`

	// Type is the DNS record type (A, AAAA, CNAME, MX, TXT, NS, PTR, etc.)
	Type string `json:"type"`

	// TTL is the time to live in seconds
	TTL uint32 `json:"ttl"`

	// Value is the record data (format depends on Type)
	// A: "192.0.2.1"
	// AAAA: "2001:db8::1"
	// CNAME: "target.example.com."
	// MX: "10 mail.example.com."
	// TXT: "v=spf1 include:_spf.example.com ~all"
	Value string `json:"value"`

	// Priority is used for MX and SRV records (extracted from Value for convenience)
	Priority *uint16 `json:"priority,omitempty"`
}

// DNSSECConfig contains DNSSEC configuration for a zone.
type DNSSECConfig struct {
	// Enabled indicates if DNSSEC is enabled for this zone
	Enabled bool `json:"enabled"`

	// Algorithm is the DNSSEC algorithm number
	// 13 = ECDSA-P256, 8 = RSA-SHA256
	Algorithm uint8 `json:"algorithm"`

	// KSKKeyTag is the key signing key tag
	KSKKeyTag uint16 `json:"ksk_key_tag,omitempty"`

	// ZSKKeyTag is the zone signing key tag
	ZSKKeyTag uint16 `json:"zsk_key_tag,omitempty"`

	// NSEC3Enabled indicates if NSEC3 is used instead of NSEC
	NSEC3Enabled bool `json:"nsec3_enabled"`

	// NSEC3Iterations is the number of hash iterations for NSEC3
	NSEC3Iterations uint16 `json:"nsec3_iterations,omitempty"`

	// NSEC3Salt is the salt for NSEC3 hashing (hex encoded)
	NSEC3Salt string `json:"nsec3_salt,omitempty"`

	// SignatureExpiration is when the current signatures expire
	SignatureExpiration *time.Time `json:"signature_expiration,omitempty"`
}

// ZoneVersion represents a specific version of a zone for rollback/history.
type ZoneVersion struct {
	// Version is the version identifier
	Version string `json:"version"`

	// Serial is the SOA serial at this version
	Serial uint32 `json:"serial"`

	// Timestamp is when this version was created
	Timestamp time.Time `json:"timestamp"`

	// Hash is the SHA256 hash of the zone content (hex)
	Hash string `json:"hash"`

	// Hash8 is the first 8 characters of Hash.
	Hash8 string `json:"hash8,omitempty"`

	// SignedArtifactPath is the path to the signed zone file artifact
	SignedArtifactPath string `json:"signed_artifact_path,omitempty"`
}

// ZoneMetadata contains additional metadata about a zone.
type ZoneMetadata struct {
	// Zone name
	Name string `json:"name"`

	// Current version
	Version string `json:"version"`

	// Number of records
	RecordCount int `json:"record_count"`

	// DNSSEC enabled
	DNSSECEnabled bool `json:"dnssec_enabled"`

	// Last update timestamp
	LastUpdated time.Time `json:"last_updated"`

	// Last sync timestamp (for agents)
	LastSynced *time.Time `json:"last_synced,omitempty"`
}

// RecordType constants for supported DNS record types.
const (
	RecordTypeA     = "A"
	RecordTypeAAAA  = "AAAA"
	RecordTypeCNAME = "CNAME"
	RecordTypeMX    = "MX"
	RecordTypeNS    = "NS"
	RecordTypeTXT   = "TXT"
	RecordTypePTR   = "PTR"
	RecordTypeSOA   = "SOA"
	RecordTypeSRV   = "SRV"
	RecordTypeCAA   = "CAA"
)

// SupportedRecordTypes is the list of DNS record types supported by arca-dns.
var SupportedRecordTypes = []string{
	RecordTypeA,
	RecordTypeAAAA,
	RecordTypeCNAME,
	RecordTypeMX,
	RecordTypeNS,
	RecordTypeTXT,
	RecordTypePTR,
	RecordTypeSRV,
	RecordTypeCAA,
}

// IsValidRecordType checks if the given record type is supported.
func IsValidRecordType(recordType string) bool {
	for _, t := range SupportedRecordTypes {
		if t == recordType {
			return true
		}
	}
	return false
}

// DefaultSOA returns default SOA values for a new zone.
// Serial is set to 0, which triggers auto-generation in YYYYMMDDnn format.
func DefaultSOA(mname, rname string) SOARecord {
	return SOARecord{
		MName:   mname,
		RName:   rname,
		Serial:  0, // Auto-generated in YYYYMMDDnn format by backend
		Refresh: 3600,
		Retry:   1800,
		Expire:  604800,
		Minimum: 86400,
	}
}
