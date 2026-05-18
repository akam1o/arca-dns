package dnssec

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/gofrs/flock"
	"github.com/miekg/dns"
)

// KeyManager manages DNSSEC keys (generation, storage, loading).
type KeyManager struct {
	keyDir    string
	masterKey []byte
	algorithm uint8
	kskBits   int
	zskBits   int
	zoneLocks sync.Map // map[string]chan struct{}
}

type activeKeys struct {
	Algorithm    uint8  `json:"algorithm"`
	ActiveKSKTag uint16 `json:"active_ksk_key_tag"`
	ActiveZSKTag uint16 `json:"active_zsk_key_tag"`
}

const (
	dnskeyKSKFlags = dns.SEP | dns.ZONE
	dnskeyZSKFlags = dns.ZONE
)

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
	return km.GenerateKSKContext(context.Background(), zone)
}

// GenerateKSKContext generates a new Key Signing Key for the zone.
func (km *KeyManager) GenerateKSKContext(ctx context.Context, zone string) (*KeyPair, error) {
	var key *KeyPair
	err := km.withZoneKeyLock(ctx, zone, true, func(zoneFQDN string) error {
		var err error
		key, err = km.generateKeyLocked(zoneFQDN, KeyRoleKSK, km.kskBits, dnskeyKSKFlags, true)
		return err
	})
	return key, err
}

// GenerateZSK generates a new Zone Signing Key for the zone.
func (km *KeyManager) GenerateZSK(zone string) (*KeyPair, error) {
	return km.GenerateZSKContext(context.Background(), zone)
}

// GenerateZSKContext generates a new Zone Signing Key for the zone.
func (km *KeyManager) GenerateZSKContext(ctx context.Context, zone string) (*KeyPair, error) {
	var key *KeyPair
	err := km.withZoneKeyLock(ctx, zone, true, func(zoneFQDN string) error {
		var err error
		key, err = km.generateKeyLocked(zoneFQDN, KeyRoleZSK, km.zskBits, dnskeyZSKFlags, true)
		return err
	})
	return key, err
}

// generateKeyLocked generates a DNSSEC key pair. Callers must hold the zone key lock.
func (km *KeyManager) generateKeyLocked(zone string, role KeyRole, bits int, flags uint16, activate bool) (*KeyPair, error) {
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

	if activate {
		if err := km.saveKey(keyPair); err != nil {
			return nil, fmt.Errorf("save key: %w", err)
		}
	} else if err := km.saveKeyFiles(keyPair); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}

	return keyPair, nil
}

// LoadKSK loads the KSK for the zone.
func (km *KeyManager) LoadKSK(zone string) (*KeyPair, error) {
	return km.LoadKSKContext(context.Background(), zone)
}

// LoadKSKContext loads the KSK for the zone.
func (km *KeyManager) LoadKSKContext(ctx context.Context, zone string) (*KeyPair, error) {
	return km.loadKeyWithLock(ctx, zone, KeyRoleKSK)
}

// LoadZSK loads the ZSK for the zone.
func (km *KeyManager) LoadZSK(zone string) (*KeyPair, error) {
	return km.LoadZSKContext(context.Background(), zone)
}

// LoadZSKContext loads the ZSK for the zone.
func (km *KeyManager) LoadZSKContext(ctx context.Context, zone string) (*KeyPair, error) {
	return km.loadKeyWithLock(ctx, zone, KeyRoleZSK)
}

func (km *KeyManager) loadKeyWithLock(ctx context.Context, zone string, role KeyRole) (*KeyPair, error) {
	var key *KeyPair
	err := km.withZoneKeyLock(ctx, zone, false, func(zoneFQDN string) error {
		var err error
		key, err = km.loadKey(zoneFQDN, role)
		return err
	})
	return key, err
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
	activeData, err := readRegularKeyFile(activeFile)
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
	pubData, err := readRegularKeyFile(pubPath)
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
	privEncData, err := readRegularKeyFile(privPath)
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
	if err := km.saveKeyFiles(kp); err != nil {
		return err
	}
	if err := km.updateActiveKeys(kp); err != nil {
		return fmt.Errorf("update active keys: %w", err)
	}
	return nil
}

// saveKeyFiles saves a key pair to disk without changing active.json.
func (km *KeyManager) saveKeyFiles(kp *KeyPair) error {
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

	if err := writeFileAtomic(pubPath, []byte(pubData), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	if err := writeFileAtomic(privPath, encData, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	return nil
}

// updateActiveKeys updates the active.json file.
func (km *KeyManager) updateActiveKeys(kp *KeyPair) error {
	active, err := km.readActiveKeys(kp.ID.Zone)
	if err != nil {
		return err
	}

	// Update the appropriate key tag
	active.Algorithm = km.algorithm
	switch kp.Role {
	case KeyRoleKSK:
		active.ActiveKSKTag = kp.ID.KeyTag
	case KeyRoleZSK:
		active.ActiveZSKTag = kp.ID.KeyTag
	default:
		return fmt.Errorf("invalid key role: %s", kp.Role)
	}

	return km.writeActiveKeys(kp.ID.Zone, active)
}

func (km *KeyManager) readActiveKeys(zone string) (activeKeys, error) {
	zoneDir, err := km.getZoneDir(zone)
	if err != nil {
		return activeKeys{}, err
	}

	activeFile := filepath.Join(zoneDir, "active.json")
	active := activeKeys{Algorithm: km.algorithm}

	if data, err := readRegularKeyFile(activeFile); err == nil {
		if err := json.Unmarshal(data, &active); err != nil {
			return activeKeys{}, fmt.Errorf("parse existing active.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return activeKeys{}, fmt.Errorf("read active.json: %w", err)
	}

	return active, nil
}

func (km *KeyManager) writeActiveKeys(zone string, active activeKeys) error {
	zoneDir, err := km.getZoneDir(zone)
	if err != nil {
		return err
	}

	activeFile := filepath.Join(zoneDir, "active.json")

	data, err := json.MarshalIndent(active, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal active.json: %w", err)
	}

	if err := writeFileAtomic(activeFile, data, 0644); err != nil {
		return fmt.Errorf("write active.json: %w", err)
	}

	return nil
}

func (km *KeyManager) withZoneKeyLock(ctx context.Context, zone string, createDir bool, fn func(zoneFQDN string) error) (err error) {
	zoneFQDN, err := NormalizeZoneFQDN(zone)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	zoneDir, err := km.getZoneDir(zoneFQDN)
	if err != nil {
		return err
	}

	releaseZone, err := km.acquireZoneMutex(ctx, zoneFQDN)
	if err != nil {
		return err
	}
	defer releaseZone()

	keyDirExisted := true
	if statErr := validateExistingKeyDirectory(km.keyDir); statErr != nil {
		if !os.IsNotExist(statErr) {
			return fmt.Errorf("stat key directory: %w", statErr)
		}
		if !createDir {
			return model.ErrZoneNotFound
		}
		keyDirExisted = false
	}
	if createDir {
		if err := os.MkdirAll(km.keyDir, 0700); err != nil {
			return fmt.Errorf("create key directory: %w", err)
		}
		if err := validateExistingKeyDirectory(km.keyDir); err != nil {
			return fmt.Errorf("stat key directory: %w", err)
		}
		if !keyDirExisted {
			if err := syncDir(filepath.Dir(km.keyDir)); err != nil {
				return fmt.Errorf("sync key directory parent: %w", err)
			}
		}
	}

	existed := true
	if statErr := validateExistingZoneKeyDir(zoneDir); statErr != nil {
		if !os.IsNotExist(statErr) {
			return fmt.Errorf("stat zone key directory: %w", statErr)
		}
		if !createDir {
			return model.ErrZoneNotFound
		}
		existed = false
	}
	if createDir {
		if err := os.MkdirAll(zoneDir, 0700); err != nil {
			return fmt.Errorf("create zone directory: %w", err)
		}
		if err := validateExistingZoneKeyDir(zoneDir); err != nil {
			return fmt.Errorf("stat zone key directory: %w", err)
		}
		if !existed {
			if err := syncDir(filepath.Dir(zoneDir)); err != nil {
				return fmt.Errorf("sync key directory parent: %w", err)
			}
		}
	}

	fileLock := flock.New(filepath.Join(zoneDir, ".lock"))
	locked, err := fileLock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock zone key directory: %w", err)
	}
	if !locked {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("lock zone key directory: %w", err)
		}
		return fmt.Errorf("lock zone key directory: lock not acquired")
	}
	defer func() {
		if unlockErr := fileLock.Unlock(); unlockErr != nil && err == nil {
			err = fmt.Errorf("unlock zone key directory: %w", unlockErr)
		}
	}()

	return fn(zoneFQDN)
}

func (km *KeyManager) acquireZoneMutex(ctx context.Context, zone string) (func(), error) {
	actual, _ := km.zoneLocks.LoadOrStore(zone, make(chan struct{}, 1))
	ch := actual.(chan struct{})
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// getZoneDir returns the directory path for a zone's keys.
func (km *KeyManager) getZoneDir(zone string) (string, error) {
	zoneName, err := ZoneNameForFile(zone)
	if err != nil {
		return "", err
	}
	return filepath.Join(km.keyDir, zoneName), nil
}

func validateExistingKeyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("key directory must not be a symlink: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("key path must be a directory: %s", path)
	}
	return nil
}

func validateExistingZoneKeyDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("zone key directory must not be a symlink: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("zone key path must be a directory: %s", path)
	}
	return nil
}

func readRegularKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("key file must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key file must be a regular file: %s", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("key file changed while opening: %s", path)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("key file must be a regular file: %s", path)
	}

	return io.ReadAll(file)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := writeAll(tmp, data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// EnsureZoneKeys ensures that both KSK and ZSK exist for a zone.
// If they don't exist, they are generated. Returns the key pair.
func (km *KeyManager) EnsureZoneKeys(zone string) (ksk *KeyPair, zsk *KeyPair, err error) {
	return km.EnsureZoneKeysContext(context.Background(), zone)
}

// EnsureZoneKeysContext ensures that both KSK and ZSK exist for a zone.
func (km *KeyManager) EnsureZoneKeysContext(ctx context.Context, zone string) (ksk *KeyPair, zsk *KeyPair, err error) {
	err = km.withZoneKeyLock(ctx, zone, true, func(zoneFQDN string) error {
		var err error
		ksk, zsk, err = km.ensureZoneKeysLocked(zoneFQDN)
		return err
	})
	return ksk, zsk, err
}

func (km *KeyManager) ensureZoneKeysLocked(zoneFQDN string) (ksk *KeyPair, zsk *KeyPair, err error) {
	// Try to load existing keys
	ksk, err = km.loadKey(zoneFQDN, KeyRoleKSK)
	if err != nil && !errors.Is(err, model.ErrZoneNotFound) {
		return nil, nil, fmt.Errorf("load ksk: %w", err)
	}

	zsk, err = km.loadKey(zoneFQDN, KeyRoleZSK)
	if err != nil && !errors.Is(err, model.ErrZoneNotFound) {
		return nil, nil, fmt.Errorf("load zsk: %w", err)
	}

	// Generate missing keys
	if ksk == nil {
		ksk, err = km.generateKeyLocked(zoneFQDN, KeyRoleKSK, km.kskBits, dnskeyKSKFlags, true)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ksk: %w", err)
		}
	}

	if zsk == nil {
		zsk, err = km.generateKeyLocked(zoneFQDN, KeyRoleZSK, km.zskBits, dnskeyZSKFlags, true)
		if err != nil {
			return nil, nil, fmt.Errorf("generate zsk: %w", err)
		}
	}

	return ksk, zsk, nil
}

// ExportDS exports the DS record for a zone's KSK.
func (km *KeyManager) ExportDS(zone string, digestType uint8) (*dns.DS, error) {
	return km.ExportDSContext(context.Background(), zone, digestType)
}

// ExportDSContext exports the DS record for a zone's KSK.
func (km *KeyManager) ExportDSContext(ctx context.Context, zone string, digestType uint8) (*dns.DS, error) {
	var ds *dns.DS
	err := km.withZoneKeyLock(ctx, zone, false, func(zoneFQDN string) error {
		ksk, err := km.loadKey(zoneFQDN, KeyRoleKSK)
		if err != nil {
			return fmt.Errorf("load ksk: %w", err)
		}

		ds = ksk.DNSKEY.ToDS(digestType)
		if ds == nil {
			return fmt.Errorf("failed to generate ds record")
		}
		return nil
	})
	return ds, err
}
