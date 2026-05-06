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
	options     dnssec.SignerOptions
}

// SignedZoneArtifact represents a signed zone with metadata.
type SignedZoneArtifact struct {
	ZoneName    string
	Version     string
	Serial      uint32
	SignedZone  string // BIND format zone file with DNSSEC records
	UnsignedRRs []dns.RR
	SignedRRs   []dns.RR
	Metadata    SigningMetadata
	DNSSEC      *model.DNSSECConfig
}

// SignedZoneWrite is a prepared DNSSEC write with the zone signing lock held.
// Call Complete after the backend write succeeds, or Abort on every error path.
type SignedZoneWrite struct {
	service  *SigningService
	artifact *SignedZoneArtifact
	unlock   func()
	once     sync.Once
}

// Complete stores the signed artifact cache, logs the signing result, and
// releases the zone signing lock.
func (w *SignedZoneWrite) Complete() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		if w.unlock != nil {
			defer w.unlock()
		}
		w.service.completeSignedZoneWrite(w.artifact)
	})
}

// Abort releases the zone signing lock without storing the prepared artifact.
func (w *SignedZoneWrite) Abort() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		if w.unlock != nil {
			w.unlock()
		}
	})
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
func NewSigningService(store backend.ZoneStore, keyManager *dnssec.KeyManager, artifactDir string, metrics *ctrlmetrics.ControllerMetrics, logger *zap.Logger, options ...dnssec.SignerOptions) *SigningService {
	signerOptions := dnssec.DefaultSignerOptions()
	if len(options) > 0 {
		signerOptions = options[0]
	}

	return &SigningService{
		store:       store,
		keyManager:  keyManager,
		logger:      logger,
		artifactDir: artifactDir,
		metrics:     metrics,
		options:     signerOptions,
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

	signer := dnssec.NewZoneSigner(s.keyManager, s.options)

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
		Serial:      signedZone.SOA.Serial,
		SignedZone:  signedZoneFile,
		UnsignedRRs: unsignedRRs,
		SignedRRs:   signedRRs,
		Metadata:    metadata,
		DNSSEC:      cloneDNSSECConfig(signedZone.DNSSEC),
	}

	return artifact, nil
}

// PrepareSignedZoneWrite signs a zone before it is persisted, attaches the
// generated DNSSEC metadata to the zone, and keeps the per-zone signing lock
// held until the returned write is completed or aborted.
func (s *SigningService) PrepareSignedZoneWrite(ctx context.Context, zone *model.Zone) (*SignedZoneWrite, error) {
	lock := s.getZoneLock(model.NormalizeZoneName(zone.Name))
	lock.Lock()

	artifact, err := s.SignZone(ctx, zone)
	if err != nil {
		lock.Unlock()
		return nil, err
	}
	zone.DNSSEC = cloneDNSSECConfig(artifact.DNSSEC)
	return &SignedZoneWrite{
		service:  s,
		artifact: artifact,
		unlock:   lock.Unlock,
	}, nil
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

func signedArtifactFromCache(zone *model.Zone, signed []byte) (*SignedZoneArtifact, error) {
	signedZone := string(signed)
	parsed, err := parser.ParseBINDZone(strings.NewReader(signedZone), zone.Name, parser.DefaultParseOptions())
	if err != nil {
		return nil, fmt.Errorf("parse cached signed artifact: %w", err)
	}

	metadata := signingMetadataFromRRs(parsed.Records, zone.DNSSEC)
	if metadata.Expiration == 0 {
		return nil, fmt.Errorf("cached signed artifact has no RRSIG records")
	}

	return &SignedZoneArtifact{
		ZoneName:   zone.Name,
		Version:    zone.Version,
		Serial:     zone.SOA.Serial,
		SignedZone: signedZone,
		SignedRRs:  parsed.Records,
		Metadata:   metadata,
		DNSSEC:     cloneDNSSECConfig(zone.DNSSEC),
	}, nil
}

func (s *SigningService) cachedSignedZoneArtifact(zone *model.Zone) (*SignedZoneArtifact, bool) {
	artifact, err := s.loadCachedSignedZoneArtifact(zone)
	if err != nil {
		return nil, false
	}
	if !s.cachedArtifactFresh(artifact) {
		s.logger.Info("Cached signed artifact is stale (re-signing)",
			zap.String("zone", zone.Name),
			zap.String("version", zone.Version),
			zap.Uint32("expiration", artifact.Metadata.Expiration))
		return nil, false
	}

	return artifact, true
}

func (s *SigningService) loadCachedSignedZoneArtifact(zone *model.Zone) (*SignedZoneArtifact, error) {
	if s.artifactDir == "" {
		return nil, fmt.Errorf("artifact cache disabled")
	}
	if zone.Version == "" {
		return nil, fmt.Errorf("zone version is empty")
	}

	signed, err := s.loadArtifact(zone.Name, zone.Version)
	if err != nil {
		return nil, err
	}

	artifact, err := signedArtifactFromCache(zone, signed)
	if err != nil {
		s.logger.Warn("Failed to load cached signed artifact",
			zap.String("zone", zone.Name),
			zap.String("version", zone.Version),
			zap.Error(err))
		return nil, err
	}

	return artifact, nil
}

func (s *SigningService) cachedArtifactFresh(artifact *SignedZoneArtifact) bool {
	if artifact == nil || artifact.Metadata.Expiration == 0 {
		return false
	}

	threshold := s.options.ResignThreshold
	if threshold < 0 {
		threshold = 0
	}

	expiration := time.Unix(int64(artifact.Metadata.Expiration), 0)
	return expiration.After(time.Now().Add(threshold))
}

func signingMetadataFromRRs(rrs []dns.RR, dnssecConfig *model.DNSSECConfig) SigningMetadata {
	var metadata SigningMetadata

	for _, rr := range rrs {
		switch record := rr.(type) {
		case *dns.RRSIG:
			if metadata.Algorithm == 0 {
				metadata.Algorithm = record.Algorithm
			}
			if metadata.Inception == 0 || record.Inception < metadata.Inception {
				metadata.Inception = record.Inception
			}
			if metadata.Expiration == 0 || record.Expiration < metadata.Expiration {
				metadata.Expiration = record.Expiration
			}
		case *dns.DNSKEY:
			if metadata.Algorithm == 0 {
				metadata.Algorithm = record.Algorithm
			}
			switch record.Flags {
			case 257:
				if metadata.KSKKeyTag == 0 {
					metadata.KSKKeyTag = record.KeyTag()
				}
			case 256:
				if metadata.ZSKKeyTag == 0 {
					metadata.ZSKKeyTag = record.KeyTag()
				}
			}
		case *dns.NSEC3PARAM:
			metadata.NSEC3Params = &NSEC3Metadata{
				Enabled:    true,
				HashAlg:    record.Hash,
				Flags:      record.Flags,
				Iterations: record.Iterations,
				Salt:       record.Salt,
			}
		}
	}

	if metadata.NSEC3Params == nil && dnssecConfig != nil && dnssecConfig.NSEC3Enabled {
		metadata.NSEC3Params = &NSEC3Metadata{
			Enabled:    true,
			HashAlg:    dns.SHA1,
			Flags:      0,
			Iterations: dnssecConfig.NSEC3Iterations,
			Salt:       dnssecConfig.NSEC3Salt,
		}
	}

	return metadata
}

// SignAndStoreZone signs a zone and stores both unsigned and signed versions.
// This is called automatically after zone create/update operations.
// NOTE: This acquires per-zone lock to prevent concurrent signing.
func (s *SigningService) SignAndStoreZone(ctx context.Context, zone *model.Zone) error {
	// Acquire per-zone lock to prevent concurrent signing (M4.4 fix)
	lock := s.getZoneLock(model.NormalizeZoneName(zone.Name))
	lock.Lock()
	defer lock.Unlock()

	return s.signAndStoreZoneLocked(ctx, zone)
}

func (s *SigningService) signAndStoreZoneLocked(ctx context.Context, zone *model.Zone) error {
	// Sign the zone
	artifact, err := s.SignZone(ctx, zone)
	if err != nil {
		s.logger.Error("Failed to sign zone",
			zap.String("zone", zone.Name),
			zap.Error(err))
		return err
	}

	if err := s.persistDNSSECMetadata(ctx, zone.Name, artifact.DNSSEC); err != nil {
		s.logger.Error("Failed to persist DNSSEC metadata",
			zap.String("zone", zone.Name),
			zap.Error(err))
		return err
	}
	zone.DNSSEC = cloneDNSSECConfig(artifact.DNSSEC)

	s.completeSignedZoneWrite(artifact)

	return nil
}

// completeSignedZoneWrite stores the optional signed artifact cache and emits
// the signing audit log after the backend write has succeeded.
func (s *SigningService) completeSignedZoneWrite(artifact *SignedZoneArtifact) {
	if artifact == nil {
		return
	}

	dnskeyAdded, rrsigAdded, nsec3Added, nsec3paramAdded := diffDNSSECTypes(artifact.UnsignedRRs, artifact.SignedRRs)

	if s.artifactDir != "" {
		if err := s.storeArtifact(artifact.ZoneName, artifact.Version, []byte(artifact.SignedZone)); err != nil {
			s.logger.Warn("Failed to store signed artifact (continuing without cache)",
				zap.String("zone", artifact.ZoneName),
				zap.String("version", artifact.Version),
				zap.Error(err))
		}
	}

	s.logger.Info("Zone signed successfully",
		zap.String("zone", artifact.ZoneName),
		zap.String("version", artifact.Version),
		zap.Uint16("ksk_keytag", artifact.Metadata.KSKKeyTag),
		zap.Uint16("zsk_keytag", artifact.Metadata.ZSKKeyTag),
		zap.Int("dnssec_added_dnskey", dnskeyAdded),
		zap.Int("dnssec_added_rrsig", rrsigAdded),
		zap.Int("dnssec_added_nsec3", nsec3Added),
		zap.Int("dnssec_added_nsec3param", nsec3paramAdded))
}

func (s *SigningService) persistDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	if dnssec == nil || !dnssec.Enabled {
		return fmt.Errorf("signed DNSSEC metadata missing for zone %s", zoneName)
	}

	metadataStore, ok := s.store.(backend.DNSSECMetadataStore)
	if !ok {
		return fmt.Errorf("backend does not support DNSSEC metadata persistence")
	}

	return metadataStore.UpdateDNSSECMetadata(ctx, zoneName, cloneDNSSECConfig(dnssec))
}

func cloneDNSSECConfig(config *model.DNSSECConfig) *model.DNSSECConfig {
	if config == nil {
		return nil
	}

	cloned := *config
	if config.SignatureExpiration != nil {
		expiration := *config.SignatureExpiration
		cloned.SignatureExpiration = &expiration
	}
	return &cloned
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
	if artifact, ok := s.cachedSignedZoneArtifact(zone); ok {
		return artifact, nil
	}

	lock := s.getZoneLock(model.NormalizeZoneName(zone.Name))
	lock.Lock()
	defer lock.Unlock()

	// The zone may have changed while waiting for an API write or scheduler
	// re-sign to finish. Re-read and re-check the cache under the same lock.
	zone, err = s.store.GetZone(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	if artifact, ok := s.cachedSignedZoneArtifact(zone); ok {
		return artifact, nil
	}

	return s.getSignedZoneLocked(ctx, zone)
}

func (s *SigningService) getSignedZoneLocked(ctx context.Context, zone *model.Zone) (*SignedZoneArtifact, error) {
	// Check if zone has been signed (M4.5 fix: null-safety check)
	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
		// Sign it now if not already signed
		artifact, err := s.SignZone(ctx, zone)
		if err != nil {
			return nil, err
		}
		if err := s.persistDNSSECMetadata(ctx, zone.Name, artifact.DNSSEC); err != nil {
			return nil, err
		}
		zone.DNSSEC = cloneDNSSECConfig(artifact.DNSSEC)
		s.completeSignedZoneWrite(artifact)
		return artifact, nil
	}

	// Fallback: re-sign on demand.
	artifact, err := s.SignZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	if err := s.persistDNSSECMetadata(ctx, zone.Name, artifact.DNSSEC); err != nil {
		return nil, err
	}
	zone.DNSSEC = cloneDNSSECConfig(artifact.DNSSEC)
	s.completeSignedZoneWrite(artifact)
	return artifact, nil
}

// GetDSRecords returns DS records for the given zone (for parent zone delegation).
func (s *SigningService) GetDSRecords(ctx context.Context, zoneName string) ([]string, error) {
	lock := s.getZoneLock(model.NormalizeZoneName(zoneName))
	lock.Lock()
	defer lock.Unlock()

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
	zone, err := s.store.GetZone(ctx, zoneName)
	if err != nil {
		return 0, err
	}

	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
		return 0, fmt.Errorf("DNSSEC not enabled for zone %s", zoneName)
	}

	if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
		return uint32(zone.DNSSEC.SignatureExpiration.Unix()), nil
	}

	artifact, err := s.loadCachedSignedZoneArtifact(zone)
	if err == nil {
		return artifact.Metadata.Expiration, nil
	}

	return 0, fmt.Errorf("%w for zone %s: %v", dnssec.ErrSignatureExpirationUnavailable, zoneName, err)
}

// ResignZone safely re-signs a zone with per-zone locking.
// This is the method used by the scheduler (M4.4) to avoid racing with update hooks.
func (s *SigningService) ResignZone(ctx context.Context, zoneName string) error {
	lock := s.getZoneLock(model.NormalizeZoneName(zoneName))
	lock.Lock()
	defer lock.Unlock()

	// Fetch latest zone from backend
	zone, err := s.store.GetZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("failed to get zone: %w", err)
	}

	// Skip if DNSSEC is not enabled
	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
		return fmt.Errorf("DNSSEC not enabled for zone %s", zoneName)
	}

	return s.signAndStoreZoneLocked(ctx, zone)
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
