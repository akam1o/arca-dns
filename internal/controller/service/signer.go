package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ctrlmetrics "github.com/akam1o/arca-dns/internal/controller/metrics"
	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/parser"
	"github.com/akam1o/arca-dns/pkg/util"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// SigningService handles DNSSEC signing operations and signed zone storage.
type SigningService struct {
	store       backend.ZoneStore
	keyManager  *dnssec.KeyManager
	logger      *zap.Logger
	zoneLocks   sync.Map // map[string]*sync.Mutex - per-zone locks for concurrent signing safety
	artifactDir string
	metrics     *ctrlmetrics.ControllerMetrics
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
	KSKKeyTag   uint16
	ZSKKeyTag   uint16
	Algorithm   uint8
	Inception   uint32
	Expiration  uint32
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
func NewSigningService(store backend.ZoneStore, keyManager *dnssec.KeyManager, artifactDir string, metrics *ctrlmetrics.ControllerMetrics, logger *zap.Logger) *SigningService {
	return &SigningService{
		store:       store,
		keyManager:  keyManager,
		logger:      logger,
		artifactDir: artifactDir,
		metrics:     metrics,
	}
}

// SignZone signs a zone and returns the signed artifact.
// This is the single signing entrypoint used by both update hooks and the scheduler.
func (s *SigningService) SignZone(ctx context.Context, zone *model.Zone) (*SignedZoneArtifact, error) {
	start := time.Now()
	status := "success"
	defer func() {
		if s.metrics != nil {
			s.metrics.ObserveSigningDuration(status, time.Since(start).Seconds())
		}
	}()

	// Capture unsigned RR set for audit/troubleshooting purposes.
	unsignedRRs, err := s.unsignedRRsFromZone(zone)
	if err != nil {
		status = "error"
		return nil, fmt.Errorf("build unsigned RRs: %w", err)
	}

	// Ensure keys exist for the zone
	ksk, zsk, err := s.keyManager.EnsureZoneKeys(zone.Name)
	if err != nil {
		status = "error"
		return nil, fmt.Errorf("failed to ensure zone keys: %w", err)
	}

	// Create signer with default options
	signer := dnssec.NewZoneSigner(s.keyManager, dnssec.DefaultSignerOptions())

	// Sign the zone
	signedZone, signedRRs, err := signer.SignZone(zone)
	if err != nil {
		status = "error"
		return nil, fmt.Errorf("failed to sign zone: %w", err)
	}

	// Generate BIND format zone file with DNSSEC records (M4.5 fix: use RRs directly)
	signedZoneFile, err := parser.GenerateBINDZoneFileFromRRs(zone.Name, signedZone.Version, signedRRs)
	if err != nil {
		status = "error"
		return nil, fmt.Errorf("failed to generate signed zone file: %w", err)
	}

	// Extract metadata
	metadata := SigningMetadata{
		KSKKeyTag:  ksk.ID.KeyTag,
		ZSKKeyTag:  zsk.ID.KeyTag,
		Algorithm:  ksk.ID.Algorithm,
		Inception:  0,
		Expiration: 0,
	}

	// Extract inception/expiration from RRSIG records (best-effort).
	// For expiration, we prefer the earliest (minimum) expiration across RRsets.
	// For inception, we set the earliest inception (minimum) as a conservative start.
	var inception uint32
	var expiration uint32
	for _, rr := range signedRRs {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if inception == 0 || rrsig.Inception < inception {
			inception = rrsig.Inception
		}
		if expiration == 0 || rrsig.Expiration < expiration {
			expiration = rrsig.Expiration
		}
	}
	metadata.Inception = inception
	metadata.Expiration = expiration

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
		UnsignedRRs: unsignedRRs,
		SignedRRs:   signedRRs,
		Metadata:    metadata,
	}

	return artifact, nil
}

func (s *SigningService) unsignedRRsFromZone(zone *model.Zone) ([]dns.RR, error) {
	zoneFile, err := parser.GenerateBINDZoneFile(zone)
	if err != nil {
		return nil, err
	}

	parsed, err := parser.ParseBINDZone(strings.NewReader(zoneFile), zone.Name, parser.DefaultParseOptions())
	if err != nil {
		return nil, err
	}
	return parsed.Records, nil
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

	dnskeyAdded, rrsigAdded, nsec3Added, nsec3paramAdded := diffDNSSECTypes(artifact.UnsignedRRs, artifact.SignedRRs)

	// Store signed artifact (implementation depends on backend)
	if s.artifactDir != "" {
		if err := s.storeArtifact(zone.Name, artifact.Version, []byte(artifact.SignedZone)); err != nil {
			s.logger.Warn("Failed to store signed artifact (continuing without cache)",
				zap.String("zone", zone.Name),
				zap.String("version", artifact.Version),
				zap.Error(err))
		}
	}

	s.logger.Info("Zone signed successfully",
		zap.String("zone", zone.Name),
		zap.String("version", artifact.Version),
		zap.Uint16("ksk_keytag", artifact.Metadata.KSKKeyTag),
		zap.Uint16("zsk_keytag", artifact.Metadata.ZSKKeyTag),
		zap.Int("dnssec_added_dnskey", dnskeyAdded),
		zap.Int("dnssec_added_rrsig", rrsigAdded),
		zap.Int("dnssec_added_nsec3", nsec3Added),
		zap.Int("dnssec_added_nsec3param", nsec3paramAdded))

	return nil
}

func diffDNSSECTypes(unsignedRRs []dns.RR, signedRRs []dns.RR) (dnskeyAdded int, rrsigAdded int, nsec3Added int, nsec3paramAdded int) {
	uc := countRRTypes(unsignedRRs)
	sc := countRRTypes(signedRRs)

	dnskeyAdded = sc[dns.TypeDNSKEY] - uc[dns.TypeDNSKEY]
	rrsigAdded = sc[dns.TypeRRSIG] - uc[dns.TypeRRSIG]
	nsec3Added = sc[dns.TypeNSEC3] - uc[dns.TypeNSEC3]
	nsec3paramAdded = sc[dns.TypeNSEC3PARAM] - uc[dns.TypeNSEC3PARAM]

	if dnskeyAdded < 0 {
		dnskeyAdded = 0
	}
	if rrsigAdded < 0 {
		rrsigAdded = 0
	}
	if nsec3Added < 0 {
		nsec3Added = 0
	}
	if nsec3paramAdded < 0 {
		nsec3paramAdded = 0
	}

	return dnskeyAdded, rrsigAdded, nsec3Added, nsec3paramAdded
}

func countRRTypes(rrs []dns.RR) map[uint16]int {
	m := make(map[uint16]int)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		if h == nil {
			continue
		}
		m[h.Rrtype]++
	}
	return m
}

// GetSignedZone retrieves the signed version of a zone.
func (s *SigningService) GetSignedZone(ctx context.Context, zoneName string) (*SignedZoneArtifact, error) {
	// Get unsigned zone from backend
	zone, err := s.store.GetZone(ctx, zoneName)
	if err != nil {
		return nil, err
	}

	// Fast path: serve cached signed artifact if available.
	// Use the unsigned zone version as the cache key (must match the artifact version scheme).
	if s.artifactDir != "" && zone.Version != "" {
		if signed, err := s.loadArtifact(zone.Name, zone.Version); err == nil && signed != nil {
			return &SignedZoneArtifact{
				ZoneName:   zone.Name,
				Version:    zone.Version,
				SignedZone: string(signed),
			}, nil
		}
	}

	// Check if zone has been signed (M4.5 fix: null-safety check)
	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
		// Sign it now if not already signed
		artifact, err := s.SignZone(ctx, zone)
		if err != nil {
			return nil, err
		}
		if s.artifactDir != "" {
			if err := s.storeArtifact(zone.Name, artifact.Version, []byte(artifact.SignedZone)); err != nil {
				s.logger.Warn("Failed to store signed artifact (continuing without cache)",
					zap.String("zone", zone.Name),
					zap.String("version", artifact.Version),
					zap.Error(err))
			}
		}
		return artifact, nil
	}

	// Fallback: re-sign on demand.
	artifact, err := s.SignZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	if s.artifactDir != "" {
		if err := s.storeArtifact(zone.Name, artifact.Version, []byte(artifact.SignedZone)); err != nil {
			s.logger.Warn("Failed to store signed artifact (continuing without cache)",
				zap.String("zone", zone.Name),
				zap.String("version", artifact.Version),
				zap.Error(err))
		}
	}
	return artifact, nil
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

func (s *SigningService) artifactPath(zoneName, version string) string {
	zoneDir := filepath.Join(s.artifactDir, util.SafeZoneFilename(zoneName))
	return filepath.Join(zoneDir, fmt.Sprintf("%s.zone.signed", version))
}

func (s *SigningService) storeArtifact(zoneName, version string, contents []byte) error {
	if s.artifactDir == "" {
		return nil
	}

	path := s.artifactPath(zoneName, version)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir artifact dir: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, contents, 0o644); err != nil {
		return fmt.Errorf("write temp artifact: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename artifact: %w", err)
	}
	return nil
}

func (s *SigningService) loadArtifact(zoneName, version string) ([]byte, error) {
	if s.artifactDir == "" {
		return nil, fmt.Errorf("artifact cache disabled")
	}
	path := s.artifactPath(zoneName, version)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}
