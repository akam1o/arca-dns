package dnssec

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
)

// KeyRole represents the role of a DNSSEC key (KSK or ZSK).
type KeyRole string

const (
	// KeyRoleKSK is the Key Signing Key role.
	KeyRoleKSK KeyRole = "KSK"

	// KeyRoleZSK is the Zone Signing Key role.
	KeyRoleZSK KeyRole = "ZSK"
)

// KeyID uniquely identifies a DNSSEC key.
type KeyID struct {
	// Zone is the zone name (FQDN with trailing dot).
	Zone string

	// Algorithm is the DNSSEC algorithm number.
	Algorithm uint8

	// KeyTag is the key tag (computed from DNSKEY).
	KeyTag uint16
}

// KeyPair represents a DNSSEC key pair (public + private).
type KeyPair struct {
	// ID uniquely identifies this key.
	ID KeyID

	// Role is the key's role (KSK or ZSK).
	Role KeyRole

	// DNSKEY is the public key record.
	DNSKEY dns.DNSKEY

	// Private is the private key.
	Private crypto.PrivateKey
}

// NormalizeZoneFQDN normalizes a zone name to FQDN format (with trailing dot).
// Examples:
//   - "example.com" -> "example.com."
//   - "example.com." -> "example.com."
//   - "EXAMPLE.COM" -> "example.com."
func NormalizeZoneFQDN(zone string) (string, error) {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return "", fmt.Errorf("zone name cannot be empty")
	}

	// Convert to lowercase
	zone = strings.ToLower(zone)

	// Ensure trailing dot
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	// Validate as an arca-dns zone, not just as a syntactically absolute DNS
	// string. DNSSEC key names are used in filesystem paths, so reject owner
	// shorthand, root, path separators, and other non-zone input here.
	if err := model.ValidateZoneName(zone); err != nil {
		return "", fmt.Errorf("invalid DNS zone name %q: %w", zone, err)
	}

	return zone, nil
}

// ZoneNameForFile converts a zone FQDN to a filename-safe format (without trailing dot).
// Examples:
//   - "example.com." -> "example.com"
//   - "example.com" -> "example.com"
func ZoneNameForFile(zone string) (string, error) {
	// Normalize first
	zone, err := NormalizeZoneFQDN(zone)
	if err != nil {
		return "", err
	}

	// Remove trailing dot
	return strings.TrimSuffix(zone, "."), nil
}

// MakeKeyFilenames generates the filenames for a DNSSEC key pair.
// Format: Kexample.com.+013+12345.key / Kexample.com.+013+12345.private.enc
func MakeKeyFilenames(zone string, alg uint8, keyTag uint16) (pub string, privEnc string, err error) {
	zoneName, err := ZoneNameForFile(zone)
	if err != nil {
		return "", "", err
	}

	base := fmt.Sprintf("K%s.+%03d+%05d", zoneName, alg, keyTag)
	pub = base + ".key"
	privEnc = base + ".private.enc"

	return pub, privEnc, nil
}

// AlgorithmName returns the human-readable name for a DNSSEC algorithm.
func AlgorithmName(alg uint8) string {
	switch alg {
	case 8:
		return "RSASHA256"
	case 13:
		return "ECDSAP256SHA256"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", alg)
	}
}

// ValidateAlgorithm validates that the algorithm is supported.
func ValidateAlgorithm(alg uint8) error {
	switch alg {
	case 8, 13:
		return nil
	default:
		return fmt.Errorf("unsupported DNSSEC algorithm: %d (supported: 8=RSA-SHA256, 13=ECDSA-P256)", alg)
	}
}
