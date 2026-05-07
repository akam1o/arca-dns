package model

import "strings"

// NormalizeZoneName normalizes a zone name for storage and comparison.
// Rules:
// - Lowercase
// - Add trailing dot if missing
// - Empty string returns empty string
//
// Example: "Example.COM" → "example.com."
func NormalizeZoneName(name string) string {
	if name == "" {
		return ""
	}
	normalized := strings.ToLower(name)
	if !strings.HasSuffix(normalized, ".") {
		normalized += "."
	}
	return normalized
}

// NormalizeDomainName normalizes a domain name (zone name or record owner name).
// Same rules as NormalizeZoneName.
// Special cases:
// - "@" returns "@" (zone apex marker, not normalized)
// - "*" prefix preserved (wildcard)
//
// Example: "WWW.Example.COM" → "www.example.com."
// Example: "@" → "@"
// Example: "*.example.com" → "*.example.com."
func NormalizeDomainName(name string) string {
	if name == "" || name == "@" {
		return name
	}

	// Handle wildcard prefix
	if strings.HasPrefix(name, "*.") {
		rest := name[2:]
		return "*." + NormalizeZoneName(rest)
	}

	return NormalizeZoneName(name)
}

// NormalizeRecordOwnerName expands a DNS record owner name under a zone origin.
// Owner names may be relative to the zone, absolute FQDNs, "@", or wildcards.
// A name without a trailing dot that already ends with the zone origin is
// treated as an FQDN without the final dot.
func NormalizeRecordOwnerName(name, zoneOrigin string) string {
	zoneName := NormalizeZoneName(zoneOrigin)
	if name == "@" {
		return zoneName
	}

	if strings.HasSuffix(name, ".") {
		return NormalizeZoneName(name)
	}

	trimmedZone := strings.TrimSuffix(zoneName, ".")
	nameLower := strings.ToLower(name)
	zoneLower := strings.ToLower(trimmedZone)
	if nameLower == zoneLower || strings.HasSuffix(nameLower, "."+zoneLower) {
		return NormalizeZoneName(name)
	}

	return NormalizeZoneName(name + "." + trimmedZone)
}
