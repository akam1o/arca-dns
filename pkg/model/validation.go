package model

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	// DNS name regex: alphanumeric, hyphens, dots, must end with dot for FQDN
	dnsNameRegex     = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.?$`)
	recordLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]*$`)
	controlOrSpaceRe = regexp.MustCompile(`[\x00-\x20\x7f]`)
)

const (
	// MaxTXTCharacterStringLength is the DNS wire limit for one TXT character-string.
	MaxTXTCharacterStringLength = 255
	// MaxTXTValueLength is the largest TXT payload that fits in one RR after chunk length bytes.
	MaxTXTValueLength = 65279
)

// ValidateZone validates a complete zone.
func ValidateZone(zone *Zone) error {
	if zone == nil {
		return fmt.Errorf("zone is nil")
	}

	// Validate zone name
	if err := ValidateZoneName(zone.Name); err != nil {
		return fmt.Errorf("invalid zone name: %w", err)
	}

	// Validate SOA
	if err := ValidateSOA(&zone.SOA); err != nil {
		return fmt.Errorf("invalid SOA: %w", err)
	}

	// Validate records
	for i, record := range zone.Records {
		if err := ValidateRecord(&record); err != nil {
			return fmt.Errorf("invalid record at index %d: %w", i, err)
		}
		if err := ValidateRecordNameInZone(record.Name, zone.Name); err != nil {
			return fmt.Errorf("invalid record at index %d: %w", i, err)
		}
	}

	if err := ValidateRecordSetConstraints(zone); err != nil {
		return err
	}

	return nil
}

// ValidateRecordSetConstraints validates rules that depend on multiple records.
func ValidateRecordSetConstraints(zone *Zone) error {
	if zone == nil {
		return fmt.Errorf("zone is nil")
	}

	zoneName := NormalizeZoneName(zone.Name)
	type ownerState struct {
		cnameIndex int
		types      map[string]int
		rrsetTTLs  map[string]uint32
		rrsetIndex map[string]int
	}

	owners := make(map[string]ownerState)
	seenRecords := make(map[string]int)
	for i, record := range zone.Records {
		owner := canonicalRecordOwnerName(record.Name, zoneName)
		duplicateKey := canonicalRecordDuplicateKey(record, owner)
		if firstIndex, ok := seenRecords[duplicateKey]; ok {
			return fmt.Errorf("invalid record at index %d: duplicate record matches index %d", i, firstIndex)
		}
		seenRecords[duplicateKey] = i

		state, exists := owners[owner]
		if !exists {
			state.cnameIndex = -1
			state.types = make(map[string]int)
			state.rrsetTTLs = make(map[string]uint32)
			state.rrsetIndex = make(map[string]int)
		}

		if record.Type == RecordTypeCNAME {
			if owner == zoneName {
				return fmt.Errorf("invalid record at index %d: CNAME is not allowed at zone apex %s", i, zoneName)
			}
			if state.cnameIndex >= 0 {
				return fmt.Errorf("invalid record at index %d: multiple CNAME records for owner %s", i, owner)
			}
			state.cnameIndex = i
		}

		if ttl, ok := state.rrsetTTLs[record.Type]; ok && ttl != record.TTL {
			return fmt.Errorf("invalid record at index %d: RRset %s/%s has inconsistent TTL: first record at index %d has TTL %d, got %d", i, owner, record.Type, state.rrsetIndex[record.Type], ttl, record.TTL)
		}
		if _, ok := state.rrsetTTLs[record.Type]; !ok {
			state.rrsetTTLs[record.Type] = record.TTL
			state.rrsetIndex[record.Type] = i
		}

		state.types[record.Type]++
		owners[owner] = state
	}

	for owner, state := range owners {
		if state.cnameIndex >= 0 && len(state.types) > 1 {
			return fmt.Errorf("invalid record at index %d: CNAME for owner %s cannot coexist with other record types", state.cnameIndex, owner)
		}
	}

	return nil
}

func canonicalRecordDuplicateKey(record Record, owner string) string {
	return strings.Join([]string{
		owner,
		record.Type,
		strconv.FormatUint(uint64(record.TTL), 10),
		canonicalRecordValue(record.Type, record.Value),
	}, "\x00")
}

func canonicalRecordValue(recordType, value string) string {
	switch recordType {
	case RecordTypeA, RecordTypeAAAA:
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	case RecordTypeCNAME, RecordTypeNS, RecordTypePTR:
		return NormalizeDomainName(value)
	case RecordTypeMX:
		parts := strings.Fields(value)
		if len(parts) == 2 {
			return parts[0] + " " + NormalizeDomainName(parts[1])
		}
	case RecordTypeSRV:
		parts := strings.Fields(value)
		if len(parts) == 4 {
			return strings.Join([]string{
				parts[0],
				parts[1],
				parts[2],
				NormalizeDomainName(parts[3]),
			}, " ")
		}
	}

	return value
}

func canonicalRecordOwnerName(recordName, zoneName string) string {
	return NormalizeRecordOwnerName(recordName, zoneName)
}

// ValidateSOA validates an SOA record.
func ValidateSOA(soa *SOARecord) error {
	if soa == nil {
		return fmt.Errorf("SOA is nil")
	}

	if err := ValidateDomainTarget(soa.MName); err != nil {
		return fmt.Errorf("invalid MName: %w", err)
	}

	if err := ValidateDomainTarget(soa.RName); err != nil {
		return fmt.Errorf("invalid RName: %w", err)
	}

	if soa.Refresh == 0 {
		return fmt.Errorf("refresh must be non-zero")
	}

	if soa.Retry == 0 {
		return fmt.Errorf("retry must be non-zero")
	}

	if soa.Expire == 0 {
		return fmt.Errorf("expire must be non-zero")
	}

	if soa.Minimum == 0 {
		return fmt.Errorf("minimum must be non-zero")
	}

	return nil
}

// ValidateRecord validates a DNS record.
func ValidateRecord(record *Record) error {
	if record == nil {
		return fmt.Errorf("record is nil")
	}

	// Validate name (can be relative)
	if err := ValidateRecordName(record.Name); err != nil {
		return fmt.Errorf("invalid record name: %w", err)
	}

	// Validate type
	if !IsValidRecordType(record.Type) {
		return ErrInvalidRecordType
	}

	// Validate TTL (reasonable bounds)
	if record.TTL == 0 {
		return fmt.Errorf("TTL must be non-zero")
	}
	if record.TTL > 2147483647 {
		return ErrInvalidTTL
	}

	// Validate value based on type
	if err := ValidateRecordValue(record.Type, record.Value); err != nil {
		return err
	}

	return nil
}

// ValidateRecordName validates a DNS record owner name. Record names may be
// relative to a zone, absolute FQDNs, "@", or wildcard owners.
func ValidateRecordName(name string) error {
	if name == "" {
		return fmt.Errorf("record name is empty")
	}
	if name == "@" {
		return nil
	}
	if name == "." {
		return fmt.Errorf("record name must not be root")
	}
	if len(name) > 253 {
		return fmt.Errorf("record name too long (max 253 characters)")
	}
	if controlOrSpaceRe.MatchString(name) {
		return fmt.Errorf("record name contains whitespace or control characters")
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("record name contains empty label")
	}

	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return fmt.Errorf("record name is empty")
	}

	labels := strings.Split(trimmed, ".")
	for i, label := range labels {
		if label == "" {
			return fmt.Errorf("record name contains empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label too long (max 63 characters): %s", label)
		}
		if label == "*" {
			if i != 0 {
				return fmt.Errorf("wildcard label must be leftmost")
			}
			continue
		}
		if strings.Contains(label, "*") {
			return fmt.Errorf("wildcard must occupy a full label")
		}
		if !recordLabelRegex.MatchString(label) {
			return fmt.Errorf("invalid record label: %s", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("record label must not start or end with hyphen: %s", label)
		}
	}

	return nil
}

// ValidateRecordNameInZone ensures absolute record owner names are within the
// zone. Relative names are accepted because they are interpreted under the zone.
func ValidateRecordNameInZone(recordName, zoneName string) error {
	if err := ValidateRecordName(recordName); err != nil {
		return err
	}
	if recordName == "@" || !strings.HasSuffix(recordName, ".") {
		return nil
	}

	owner := NormalizeZoneName(recordName)
	zone := NormalizeZoneName(zoneName)
	if owner == zone || strings.HasSuffix(owner, "."+zone) {
		return nil
	}

	return fmt.Errorf("record name %s is outside zone %s", recordName, zoneName)
}

// ValidateRecordValue validates a record value based on its type.
func ValidateRecordValue(recordType, value string) error {
	if recordType == RecordTypeTXT {
		return ValidateTXTValue(value)
	}
	if value == "" {
		return ErrInvalidRecordValue
	}

	switch recordType {
	case RecordTypeA:
		return ValidateIPv4(value)
	case RecordTypeAAAA:
		return ValidateIPv6(value)
	case RecordTypeCNAME, RecordTypeNS, RecordTypePTR:
		return ValidateDomainTarget(value)
	case RecordTypeMX:
		return ValidateMXValue(value)
	case RecordTypeSRV:
		return ValidateSRVValue(value)
	case RecordTypeCAA:
		return ValidateCAAValue(value)
	default:
		// Unknown type, basic validation
		return nil
	}
}

// ValidateDomainTarget validates a DNS RDATA domain target. Unlike record
// owner names, targets must not use "@" as an apex shorthand.
func ValidateDomainTarget(name string) error {
	if name == "@" {
		return fmt.Errorf("domain target must not be @")
	}
	return ValidateDomainName(name)
}

// ValidateZoneName validates a DNS zone name. Zones must use a real domain
// name, not owner-name shorthand.
func ValidateZoneName(name string) error {
	if name == "@" {
		return fmt.Errorf("zone name must not be @")
	}
	return ValidateDomainName(name)
}

// ValidateDomainName validates a DNS domain name.
func ValidateDomainName(name string) error {
	if name == "" {
		return fmt.Errorf("domain name is empty")
	}

	// Special cases
	if name == "@" || name == "." {
		return nil
	}

	// Check length (max 253 characters for FQDN)
	if len(name) > 253 {
		return fmt.Errorf("domain name too long (max 253 characters)")
	}

	// Check format
	if !dnsNameRegex.MatchString(name) {
		return fmt.Errorf("invalid domain name format: %s", name)
	}

	// Check label length (max 63 characters per label)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("label too long (max 63 characters): %s", label)
		}
	}

	return nil
}

// ValidateIPv4 validates an IPv4 address.
func ValidateIPv4(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check if it's IPv4
	if parsed.To4() == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}

	return nil
}

// ValidateIPv6 validates an IPv6 address.
func ValidateIPv6(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check if it's IPv6
	if parsed.To4() != nil {
		return fmt.Errorf("not an IPv6 address: %s", ip)
	}

	return nil
}

// ValidateMXValue validates an MX record value (priority + domain).
func ValidateMXValue(value string) error {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return fmt.Errorf("MX value must be 'priority domain': %s", value)
	}

	// Validate priority (0-65535)
	priority, err := strconv.Atoi(parts[0])
	if err != nil || priority < 0 || priority > 65535 {
		return fmt.Errorf("invalid MX priority: %s", parts[0])
	}

	// Validate domain
	return ValidateDomainTarget(parts[1])
}

// ValidateTXTValue validates a TXT record value.
func ValidateTXTValue(value string) error {
	// TXT records have flexible format; enforce the aggregate payload limit.
	if len(value) > MaxTXTValueLength {
		return fmt.Errorf("TXT value too long (max %d bytes)", MaxTXTValueLength)
	}
	return nil
}

// SplitTXTValue splits a TXT value into DNS character-strings.
func SplitTXTValue(value string) []string {
	if len(value) <= MaxTXTCharacterStringLength {
		return []string{value}
	}

	chunks := make([]string, 0, (len(value)+MaxTXTCharacterStringLength-1)/MaxTXTCharacterStringLength)
	for len(value) > MaxTXTCharacterStringLength {
		chunks = append(chunks, value[:MaxTXTCharacterStringLength])
		value = value[MaxTXTCharacterStringLength:]
	}
	chunks = append(chunks, value)
	return chunks
}

// ValidateSRVValue validates an SRV record value (priority weight port target).
func ValidateSRVValue(value string) error {
	parts := strings.Fields(value)
	if len(parts) != 4 {
		return fmt.Errorf("SRV value must be 'priority weight port target': %s", value)
	}

	// Validate priority (0-65535)
	priority, err := strconv.Atoi(parts[0])
	if err != nil || priority < 0 || priority > 65535 {
		return fmt.Errorf("invalid SRV priority: %s", parts[0])
	}

	// Validate weight (0-65535)
	weight, err := strconv.Atoi(parts[1])
	if err != nil || weight < 0 || weight > 65535 {
		return fmt.Errorf("invalid SRV weight: %s", parts[1])
	}

	// Validate port (0-65535)
	port, err := strconv.Atoi(parts[2])
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("invalid SRV port: %s", parts[2])
	}

	// Validate target
	return ValidateDomainTarget(parts[3])
}

// ValidateCAAValue validates a CAA record value (flags tag value).
func ValidateCAAValue(value string) error {
	parts := strings.Fields(value)
	if len(parts) < 3 {
		return fmt.Errorf("CAA value must be 'flags tag value': %s", value)
	}

	// Validate flags (0-255)
	flags, err := strconv.Atoi(parts[0])
	if err != nil || flags < 0 || flags > 255 {
		return fmt.Errorf("invalid CAA flags: %s", parts[0])
	}

	// Tag should be alphanumeric
	tag := parts[1]
	if !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(tag) {
		return fmt.Errorf("invalid CAA tag: %s", tag)
	}

	return nil
}
