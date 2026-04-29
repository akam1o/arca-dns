package dnssec

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
)

// KeyManager manages DNSSEC keys (generation, storage, loading).
type KeyManager struct {
	keyDir    string
	masterKey []byte
	algorithm uint8
	kskBits   int
	zskBits   int
}

// KeyManagerOptions configures the key manager.
type KeyManagerOptions struct {
	// KeyDirectory is the directory where keys are stored.
	KeyDirectory string

	// MasterKey is the AES-256 master key for encrypting private keys.
	MasterKey []byte

	// Algorithm is the DNSSEC algorithm (8=RSA-SHA256, 13=ECDSA-P256).
	Algorithm uint8

	// KSKBits is the key size in bits for KSK (RSA only).
	KSKBits int

	// ZSKBits is the key size in bits for ZSK (RSA only).
	ZSKBits int
}

// NewKeyManager creates a new key manager.
func NewKeyManager(opts KeyManagerOptions) (*KeyManager, error) {
	if opts.KeyDirectory == "" {
		return nil, fmt.Errorf("key directory cannot be empty")
	}

	if len(opts.MasterKey) != MasterKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidMasterKey, MasterKeySize, len(opts.MasterKey))
	}

	if err := ValidateAlgorithm(opts.Algorithm); err != nil {
		return nil, err
	}

	// Set default key sizes
	if opts.Algorithm == 8 { // RSA
		if opts.KSKBits == 0 {
			opts.KSKBits = 2048
		}
		if opts.ZSKBits == 0 {
			opts.ZSKBits = 1024
		}
	} else if opts.Algorithm == 13 { // ECDSA-P256
		// For ECDSA, bit size should be 256 (P-256)
		opts.KSKBits = 256
		opts.ZSKBits = 256
	}

	return &KeyManager{
		keyDir:    opts.KeyDirectory,
		masterKey: opts.MasterKey,
		algorithm: opts.Algorithm,
		kskBits:   opts.KSKBits,
		zskBits:   opts.ZSKBits,
	}, nil
}

// GenerateKSK generates a new Key Signing Key for the zone.
func (km *KeyManager) GenerateKSK(zone string) (*KeyPair, error) {
	return km.generateKey(zone, KeyRoleKSK, km.kskBits, dns.SEP|dns.ZONE)
}

// GenerateZSK generates a new Zone Signing Key for the zone.
func (km *KeyManager) GenerateZSK(zone string) (*KeyPair, error) {
	return km.generateKey(zone, KeyRoleZSK, km.zskBits, dns.ZONE)
}

// generateKey generates a DNSSEC key pair.
func (km *KeyManager) generateKey(zone string, role KeyRole, bits int, flags uint16) (*KeyPair, error) {
	// Normalize zone
	zoneFQDN, err := NormalizeZoneFQDN(zone)
	if err != nil {
		return nil, err
	}

	// Create DNSKEY record
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zoneFQDN,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: km.algorithm,
	}

	// Generate key pair using DNSKEY.Generate()
	privateKey, err := dnskey.Generate(bits)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Calculate key tag
	keyTag := dnskey.KeyTag()

	// Create KeyPair
	keyPair := &KeyPair{
		ID: KeyID{
			Zone:      zoneFQDN,
			Algorithm: km.algorithm,
			KeyTag:    keyTag,
		},
		Role:    role,
		DNSKEY:  *dnskey,
		Private: privateKey,
	}

	// Save to disk
	if err := km.saveKey(keyPair); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}

	return keyPair, nil
}

// LoadKSK loads the KSK for the zone.
func (km *KeyManager) LoadKSK(zone string) (*KeyPair, error) {
	return km.loadKey(zone, KeyRoleKSK)
}

// LoadZSK loads the ZSK for the zone.
func (km *KeyManager) LoadZSK(zone string) (*KeyPair, error) {
	return km.loadKey(zone, KeyRoleZSK)
}

// loadKey loads a key from disk.
func (km *KeyManager) loadKey(zone string, role KeyRole) (*KeyPair, error) {
	// Normalize zone
	zoneFQDN, err := NormalizeZoneFQDN(zone)
	if err != nil {
		return nil, err
	}

	// Get zone directory
	zoneDir, err := km.getZoneDir(zoneFQDN)
	if err != nil {
		return nil, err
	}

	// Read active.json to get the active key tag
	activeFile := filepath.Join(zoneDir, "active.json")
	activeData, err := os.ReadFile(activeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("read active.json: %w", err)
	}

	// Parse active.json
	var active struct {
		Algorithm    uint8  `json:"algorithm"`
		ActiveKSKTag uint16 `json:"active_ksk_key_tag"`
		ActiveZSKTag uint16 `json:"active_zsk_key_tag"`
	}
	if err := json.Unmarshal(activeData, &active); err != nil {
		return nil, fmt.Errorf("parse active.json: %w", err)
	}

	// Get the appropriate key tag
	var keyTag uint16
	switch role {
	case KeyRoleKSK:
		keyTag = active.ActiveKSKTag
	case KeyRoleZSK:
		keyTag = active.ActiveZSKTag
	default:
		return nil, fmt.Errorf("invalid key role: %s", role)
	}

	// Load the key files
	pubFile, privFile, err := MakeKeyFilenames(zoneFQDN, km.algorithm, keyTag)
	if err != nil {
		return nil, err
	}

	pubPath := filepath.Join(zoneDir, pubFile)
	privPath := filepath.Join(zoneDir, privFile)

	// Read public key
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("read public key: %w", err)
	}

	// Parse DNSKEY record
	rr, err := dns.NewRR(string(pubData))
	if err != nil {
		return nil, fmt.Errorf("parse dnskey: %w", err)
	}

	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("not a dnskey record")
	}

	// Read and decrypt private key
	privEncData, err := os.ReadFile(privPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("read private key: %w", err)
	}

	privData, envelope, err := DecryptPrivateKey(km.masterKey, privEncData)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}

	// Parse private key based on algorithm
	var privateKey interface{}
	switch km.algorithm {
	case 8: // RSA
		key, err := x509.ParsePKCS1PrivateKey(privData)
		if err != nil {
			return nil, fmt.Errorf("parse rsa private key: %w", err)
		}
		privateKey = key

	case 13: // ECDSA
		key, err := x509.ParseECPrivateKey(privData)
		if err != nil {
			return nil, fmt.Errorf("parse ecdsa private key: %w", err)
		}
		privateKey = key

	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", km.algorithm)
	}

	// Create KeyPair
	keyPair := &KeyPair{
		ID: KeyID{
			Zone:      zoneFQDN,
			Algorithm: envelope.Algorithm,
			KeyTag:    envelope.KeyTag,
		},
		Role:    envelope.Role,
		DNSKEY:  *dnskey,
		Private: privateKey,
	}

	return keyPair, nil
}

// saveKey saves a key pair to disk.
func (km *KeyManager) saveKey(kp *KeyPair) error {
	// Get zone directory
	zoneDir, err := km.getZoneDir(kp.ID.Zone)
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(zoneDir, 0700); err != nil {
		return fmt.Errorf("create zone directory: %w", err)
	}

	// Generate filenames
	pubFile, privFile, err := MakeKeyFilenames(kp.ID.Zone, kp.ID.Algorithm, kp.ID.KeyTag)
	if err != nil {
		return err
	}

	pubPath := filepath.Join(zoneDir, pubFile)
	privPath := filepath.Join(zoneDir, privFile)

	// Prepare public key data (BIND format)
	pubData := kp.DNSKEY.String() + "\n"

	// Serialize private key
	var privData []byte
	switch km.algorithm {
	case 8: // RSA
		rsaKey, ok := kp.Private.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("invalid rsa private key type")
		}
		privData = x509.MarshalPKCS1PrivateKey(rsaKey)

	case 13: // ECDSA
		ecKey, ok := kp.Private.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("invalid ecdsa private key type")
		}
		var err error
		privData, err = x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return fmt.Errorf("marshal ecdsa private key: %w", err)
		}

	default:
		return fmt.Errorf("unsupported algorithm: %d", km.algorithm)
	}

	// Encrypt private key
	meta := EncryptedPrivateKey{
		Zone:      kp.ID.Zone,
		Algorithm: kp.ID.Algorithm,
		KeyTag:    kp.ID.KeyTag,
		Role:      kp.Role,
	}
	encData, err := EncryptPrivateKey(km.masterKey, privData, meta)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	// Atomic write for public key
	pubTmpPath := pubPath + ".tmp"
	if err := os.WriteFile(pubTmpPath, []byte(pubData), 0644); err != nil {
		return fmt.Errorf("write public key tmp: %w", err)
	}
	if err := os.Rename(pubTmpPath, pubPath); err != nil {
		os.Remove(pubTmpPath)
		return fmt.Errorf("rename public key: %w", err)
	}

	// Atomic write for private key
	privTmpPath := privPath + ".tmp"
	if err := os.WriteFile(privTmpPath, encData, 0600); err != nil {
		return fmt.Errorf("write private key tmp: %w", err)
	}
	if err := os.Rename(privTmpPath, privPath); err != nil {
		os.Remove(privTmpPath)
		return fmt.Errorf("rename private key: %w", err)
	}

	// Update active.json
	if err := km.updateActiveKeys(kp); err != nil {
		return fmt.Errorf("update active keys: %w", err)
	}

	return nil
}

// updateActiveKeys updates the active.json file.
func (km *KeyManager) updateActiveKeys(kp *KeyPair) error {
	zoneDir, err := km.getZoneDir(kp.ID.Zone)
	if err != nil {
		return err
	}

	activeFile := filepath.Join(zoneDir, "active.json")

	// Read existing active.json or create new
	var active struct {
		Algorithm    uint8  `json:"algorithm"`
		ActiveKSKTag uint16 `json:"active_ksk_key_tag"`
		ActiveZSKTag uint16 `json:"active_zsk_key_tag"`
	}

	// Read existing file if it exists
	if data, err := os.ReadFile(activeFile); err == nil {
		// Parse existing file, return error if corrupted
		if err := json.Unmarshal(data, &active); err != nil {
			return fmt.Errorf("parse existing active.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		// Return error if read failed for reasons other than file not existing
		return fmt.Errorf("read active.json: %w", err)
	}

	// Update the appropriate key tag
	active.Algorithm = km.algorithm
	switch kp.Role {
	case KeyRoleKSK:
		active.ActiveKSKTag = kp.ID.KeyTag
	case KeyRoleZSK:
		active.ActiveZSKTag = kp.ID.KeyTag
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(active, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal active.json: %w", err)
	}

	// Atomic write: write to .tmp, fsync, rename
	tmpFile := activeFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("write active.json.tmp: %w", err)
	}

	// Rename atomically
	if err := os.Rename(tmpFile, activeFile); err != nil {
		os.Remove(tmpFile) // Clean up on failure
		return fmt.Errorf("rename active.json: %w", err)
	}

	return nil
}

// getZoneDir returns the directory path for a zone's keys.
func (km *KeyManager) getZoneDir(zone string) (string, error) {
	zoneName, err := ZoneNameForFile(zone)
	if err != nil {
		return "", err
	}
	return filepath.Join(km.keyDir, zoneName), nil
}

// EnsureZoneKeys ensures that both KSK and ZSK exist for a zone.
// If they don't exist, they are generated. Returns the key pair.
func (km *KeyManager) EnsureZoneKeys(zone string) (ksk *KeyPair, zsk *KeyPair, err error) {
	// Try to load existing keys
	ksk, err = km.LoadKSK(zone)
	if err != nil && !errors.Is(err, model.ErrZoneNotFound) {
		return nil, nil, fmt.Errorf("load ksk: %w", err)
	}

	zsk, err = km.LoadZSK(zone)
	if err != nil && !errors.Is(err, model.ErrZoneNotFound) {
		return nil, nil, fmt.Errorf("load zsk: %w", err)
	}

	// Generate missing keys
	if ksk == nil {
		ksk, err = km.GenerateKSK(zone)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ksk: %w", err)
		}
	}

	if zsk == nil {
		zsk, err = km.GenerateZSK(zone)
		if err != nil {
			return nil, nil, fmt.Errorf("generate zsk: %w", err)
		}
	}

	return ksk, zsk, nil
}

// ExportDS exports the DS record for a zone's KSK.
func (km *KeyManager) ExportDS(zone string, digestType uint8) (*dns.DS, error) {
	// Load KSK
	ksk, err := km.LoadKSK(zone)
	if err != nil {
		return nil, fmt.Errorf("load ksk: %w", err)
	}

	// Generate DS record
	ds := ksk.DNSKEY.ToDS(digestType)
	if ds == nil {
		return nil, fmt.Errorf("failed to generate ds record")
	}

	return ds, nil
}
