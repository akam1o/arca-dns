package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/parser"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// SigningService handles DNSSEC signing operations and signed zone storage.
type SigningService struct {
	store      backend.ZoneStore
	keyManager *dnssec.KeyManager
	logger     *zap.Logger
	zoneLocks  sync.Map // map[string]*sync.Mutex - per-zone locks for concurrent signing safety
}

// SignedZoneArtifact represents a signed zone with metadata.
type SignedZoneArtifact struct {
	ZoneName    string
	Version     string
	SignedZone  string // BIND format zone file with DNSSEC records
	UnsignedRRs []dns.RR
	SignedRRs   []dns.RR
	Metadata    SigningMetadata
}

// SigningMetadata tracks signing parameters and timing.
type SigningMetadata struct {
	KSKKeyTag  uint16
	ZSKKeyTag  uint16
	Algorithm  uint8
	Inception  uint32
	Expiration uint32
	NSEC3Params *NSEC3Metadata
}

// NSEC3Metadata tracks NSEC3 parameters used for signing.
type NSEC3Metadata struct {
	Enabled    bool
	HashAlg    uint8
	Flags      uint8
	Iterations uint16
	Salt       string
}

// NewSigningService creates a new signing service.
func NewSigningService(store backend.ZoneStore, keyManager *dnssec.KeyManager, logger *zap.Logger) *SigningService {
	return &SigningService{
		store:      store,
		keyManager: keyManager,
		logger:     logger,
	}
}

// SignZone signs a zone and returns the signed artifact.
// This is the single signing entrypoint used by both update hooks and the scheduler.
func (s *SigningService) SignZone(ctx context.Context, zone *model.Zone) (*SignedZoneArtifact, error) {
	// Ensure keys exist for the zone
	ksk, zsk, err := s.keyManager.EnsureZoneKeys(zone.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure zone keys: %w", err)
	}

	// Create signer with default options
	signer := dnssec.NewZoneSigner(s.keyManager, dnssec.DefaultSignerOptions())

	// Sign the zone
	signedZone, signedRRs, err := signer.SignZone(zone)
	if err != nil {
		return nil, fmt.Errorf("failed to sign zone: %w", err)
	}

	// Generate BIND format zone file with DNSSEC records (M4.5 fix: use RRs directly)
	signedZoneFile, err := parser.GenerateBINDZoneFileFromRRs(zone.Name, signedZone.Version, signedRRs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signed zone file: %w", err)
	}

	// Extract metadata
	metadata := SigningMetadata{
		KSKKeyTag:  ksk.ID.KeyTag,
		ZSKKeyTag:  zsk.ID.KeyTag,
		Algorithm:  ksk.ID.Algorithm,
		Inception:  0, // TODO: Extract from RRSIG
		Expiration: 0, // TODO: Extract from RRSIG
	}

	// Add NSEC3 metadata if enabled (M4.5 fix: null-safety check)
	if signedZone.DNSSEC != nil && signedZone.DNSSEC.NSEC3Enabled {
		metadata.NSEC3Params = &NSEC3Metadata{
			Enabled:    true,
			HashAlg:    dns.SHA1,
			Flags:      0,
			Iterations: signedZone.DNSSEC.NSEC3Iterations,
			Salt:       signedZone.DNSSEC.NSEC3Salt,
		}
	}

	artifact := &SignedZoneArtifact{
		ZoneName:    zone.Name,
		Version:     signedZone.Version,
		SignedZone:  signedZoneFile,
		UnsignedRRs: nil, // TODO: Store if needed for diffing
		SignedRRs:   signedRRs,
		Metadata:    metadata,
	}

	return artifact, nil
}

// SignAndStoreZone signs a zone and stores both unsigned and signed versions.
// This is called automatically after zone create/update operations.
// NOTE: This acquires per-zone lock to prevent concurrent signing.
func (s *SigningService) SignAndStoreZone(ctx context.Context, zone *model.Zone) error {
	// Acquire per-zone lock to prevent concurrent signing (M4.4 fix)
	lock := s.getZoneLock(zone.Name)
	lock.Lock()
	defer lock.Unlock()

	// Sign the zone
	artifact, err := s.SignZone(ctx, zone)
	if err != nil {
		s.logger.Error("Failed to sign zone",
			zap.String("zone", zone.Name),
			zap.Error(err))
		return err
	}

	// Store signed artifact (implementation depends on backend)
	// For now, we'll use the zone's DNSSEC metadata to mark it as signed
	// TODO: Implement proper signed artifact storage when backend supports it

	s.logger.Info("Zone signed successfully",
		zap.String("zone", zone.Name),
		zap.String("version", artifact.Version),
		zap.Uint16("ksk_keytag", artifact.Metadata.KSKKeyTag),
		zap.Uint16("zsk_keytag", artifact.Metadata.ZSKKeyTag))

	return nil
}

// GetSignedZone retrieves the signed version of a zone.
func (s *SigningService) GetSignedZone(ctx context.Context, zoneName string) (*SignedZoneArtifact, error) {
	// Get unsigned zone from backend
	zone, err := s.store.GetZone(ctx, zoneName)
	if err != nil {
		return nil, err
	}

	// Check if zone has been signed (M4.5 fix: null-safety check)
	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
		// Sign it now if not already signed
		return s.SignZone(ctx, zone)
	}

	// TODO: Retrieve cached signed artifact if backend supports it
	// For now, re-sign on every request (will be optimized with artifact storage)
	return s.SignZone(ctx, zone)
}

// GetDSRecords returns DS records for the given zone (for parent zone delegation).
func (s *SigningService) GetDSRecords(ctx context.Context, zoneName string) ([]string, error) {
	// Ensure keys exist
	ksk, _, err := s.keyManager.EnsureZoneKeys(zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone keys: %w", err)
	}

	// Export DS records for both SHA-256 and SHA-384
	var dsStrings []string
	for _, digestType := range []uint8{dns.SHA256, dns.SHA384} {
		ds, err := s.keyManager.ExportDS(zoneName, digestType)
		if err != nil {
			return nil, fmt.Errorf("failed to export DS record (digest type %d): %w", digestType, err)
		}
		dsStrings = append(dsStrings, ds.String())
	}

	s.logger.Info("DS records retrieved",
		zap.String("zone", zoneName),
		zap.Uint16("keytag", ksk.ID.KeyTag),
		zap.Int("ds_count", len(dsStrings)))

	return dsStrings, nil
}

// GetEarliestExpiration returns the earliest RRSIG expiration time for a zone.
// This is used by the scheduler to determine when to re-sign.
func (s *SigningService) GetEarliestExpiration(ctx context.Context, zoneName string) (uint32, error) {
	// Get the signed zone
	artifact, err := s.GetSignedZone(ctx, zoneName)
	if err != nil {
		return 0, fmt.Errorf("failed to get signed zone: %w", err)
	}

	// Find earliest expiration from RRSIGs
	var earliestExpiration uint32 = ^uint32(0) // max uint32
	for _, rr := range artifact.SignedRRs {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.Expiration < earliestExpiration {
				earliestExpiration = rrsig.Expiration
			}
		}
	}

	if earliestExpiration == ^uint32(0) {
		return 0, fmt.Errorf("no RRSIG records found in signed zone")
	}

	return earliestExpiration, nil
}

// ResignZone safely re-signs a zone with per-zone locking.
// This is the method used by the scheduler (M4.4) to avoid racing with update hooks.
func (s *SigningService) ResignZone(ctx context.Context, zoneName string) error {
	// Fetch latest zone from backend
	zone, err := s.store.GetZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("failed to get zone: %w", err)
	}

	// Skip if DNSSEC is not enabled
	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
		return fmt.Errorf("DNSSEC not enabled for zone %s", zoneName)
	}

	// Sign and store the zone (locking handled inside SignAndStoreZone)
	return s.SignAndStoreZone(ctx, zone)
}

// getZoneLock returns the mutex for a given zone name, creating it if needed.
func (s *SigningService) getZoneLock(zoneName string) *sync.Mutex {
	actual, _ := s.zoneLocks.LoadOrStore(zoneName, &sync.Mutex{})
	return actual.(*sync.Mutex)
}
