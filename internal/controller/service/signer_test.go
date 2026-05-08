package service

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/parser"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func setupSigningService(t *testing.T, options ...dnssec.SignerOptions) (*SigningService, func()) {
	t.Helper()

	// Create temporary directory for keys
	tmpDir, err := os.MkdirTemp("", "signing-service-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	// Initialize key manager with temporary directory
	masterKey, err := dnssec.GenerateMasterKey()
	if err != nil {
		cleanup()
		t.Fatalf("failed to generate master key: %v", err)
	}

	keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: filepath.Join(tmpDir, "keys"),
		MasterKey:    masterKey,
		Algorithm:    13, // ECDSA-P256
	})
	if err != nil {
		cleanup()
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Create in-memory backend
	store := backend.NewMemoryBackend()

	// Create logger
	logger := zap.NewNop()

	// Create signing service
	service := NewSigningService(store, keyManager, filepath.Join(tmpDir, "artifacts"), nil, logger, options...)

	return service, cleanup
}

func createTestZone() *model.Zone {
	return &model.Zone{
		Name:    "example.com.",
		Version: "v1-test",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024122801,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{
			{
				ID:    "1",
				Name:  "example.com.",
				Type:  "NS",
				TTL:   3600,
				Value: "ns1.example.com.",
			},
			{
				ID:    "2",
				Name:  "www.example.com.",
				Type:  "A",
				TTL:   3600,
				Value: "192.0.2.1",
			},
		},
		DNSSEC: &model.DNSSECConfig{
			Enabled: false,
		},
	}
}

func TestSigningService_PruneArtifactsKeepsNewestVersions(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	service.SetMaxArtifactsPerZone(2)
	zoneName := "example.com."
	baseTime := time.Unix(1700000000, 0)

	for i, version := range []string{"v1-old", "v2-middle", "v3-new"} {
		if err := service.storeArtifact(zoneName, version, []byte(version)); err != nil {
			t.Fatalf("storeArtifact(%s) failed: %v", version, err)
		}
		artifactPath := service.artifactPath(zoneName, version)
		modTime := baseTime.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(artifactPath, modTime, modTime); err != nil {
			t.Fatalf("chtimes(%s) failed: %v", version, err)
		}
	}

	zoneDir := filepath.Dir(service.artifactPath(zoneName, "v3-new"))
	if err := os.WriteFile(filepath.Join(zoneDir, "README"), []byte("keep"), 0644); err != nil {
		t.Fatalf("write non-artifact file failed: %v", err)
	}

	if err := service.pruneArtifacts(zoneName); err != nil {
		t.Fatalf("pruneArtifacts failed: %v", err)
	}

	entries, err := os.ReadDir(zoneDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	want := []string{"README", "v2-middle.zone.signed", "v3-new.zone.signed"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("artifact names = %v, want %v", names, want)
	}
}

func TestSigningService_SignZone(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	// Sign the zone
	artifact, err := service.SignZone(ctx, zone)
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	// Verify artifact fields
	if artifact.ZoneName != zone.Name {
		t.Errorf("ZoneName mismatch: got %s, want %s", artifact.ZoneName, zone.Name)
	}

	if artifact.SignedZone == "" {
		t.Error("SignedZone is empty")
	}

	if len(artifact.SignedRRs) == 0 {
		t.Error("SignedRRs is empty")
	}

	if len(artifact.UnsignedRRs) == 0 {
		t.Error("UnsignedRRs is empty")
	}

	// Verify metadata
	if artifact.Metadata.KSKKeyTag == 0 {
		t.Error("KSKKeyTag is zero")
	}
	if artifact.Metadata.ZSKKeyTag == 0 {
		t.Error("ZSKKeyTag is zero")
	}
	if artifact.Metadata.Algorithm == 0 {
		t.Error("Algorithm is zero")
	}

	// Verify DNSSEC records are present
	hasDNSKEY := false
	hasRRSIG := false
	hasNSEC3 := false
	hasNSEC3PARAM := false
	unsignedHasDNSSEC := false

	for _, rr := range artifact.SignedRRs {
		switch rr.(type) {
		case *dns.DNSKEY:
			hasDNSKEY = true
		case *dns.RRSIG:
			hasRRSIG = true
		case *dns.NSEC3:
			hasNSEC3 = true
		case *dns.NSEC3PARAM:
			hasNSEC3PARAM = true
		}
	}

	for _, rr := range artifact.UnsignedRRs {
		switch rr.(type) {
		case *dns.DNSKEY, *dns.RRSIG, *dns.NSEC3, *dns.NSEC3PARAM:
			unsignedHasDNSSEC = true
		}
	}

	if !hasDNSKEY {
		t.Error("No DNSKEY records found in signed zone")
	}
	if !hasRRSIG {
		t.Error("No RRSIG records found in signed zone")
	}
	if !hasNSEC3 {
		t.Error("No NSEC3 records found in signed zone")
	}
	if !hasNSEC3PARAM {
		t.Error("No NSEC3PARAM record found in signed zone")
	}
	if unsignedHasDNSSEC {
		t.Error("UnsignedRRs contains DNSSEC records unexpectedly")
	}

	// Verify NSEC3 metadata
	if artifact.Metadata.NSEC3Params == nil {
		t.Error("NSEC3Params is nil")
	} else {
		if !artifact.Metadata.NSEC3Params.Enabled {
			t.Error("NSEC3 not enabled in metadata")
		}
		if artifact.Metadata.NSEC3Params.HashAlg != dns.SHA1 {
			t.Errorf("NSEC3 HashAlg mismatch: got %d, want %d", artifact.Metadata.NSEC3Params.HashAlg, dns.SHA1)
		}
		if artifact.Metadata.NSEC3Params.Iterations != 1 {
			t.Errorf("NSEC3 Iterations mismatch: got %d, want 1", artifact.Metadata.NSEC3Params.Iterations)
		}
	}

	// Verify signed zone file contains DNSSEC records (M4.5 fix verification)
	if !strings.Contains(artifact.SignedZone, "DNSKEY") {
		t.Error("SignedZone file does not contain DNSKEY records")
	}
	if !strings.Contains(artifact.SignedZone, "RRSIG") {
		t.Error("SignedZone file does not contain RRSIG records")
	}
	if !strings.Contains(artifact.SignedZone, "NSEC3PARAM") {
		t.Error("SignedZone file does not contain NSEC3PARAM record")
	}
	if !strings.Contains(artifact.SignedZone, "NSEC3\t") {
		t.Error("SignedZone file does not contain NSEC3 records")
	}

	t.Logf("Signed zone successfully: %d signed RRs", len(artifact.SignedRRs))
	t.Logf("Signed zone file length: %d bytes", len(artifact.SignedZone))
}

func TestSigningService_UsesConfiguredSignerOptions(t *testing.T) {
	options := dnssec.DefaultSignerOptions()
	options.NSEC3Iterations = 9
	options.NSEC3SaltLength = 3

	service, cleanup := setupSigningService(t, options)
	defer cleanup()

	artifact, err := service.SignZone(context.Background(), createTestZone())
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	if artifact.Metadata.NSEC3Params == nil {
		t.Fatal("NSEC3Params is nil")
	}
	if artifact.Metadata.NSEC3Params.Iterations != 9 {
		t.Errorf("NSEC3 iterations mismatch: got %d, want 9", artifact.Metadata.NSEC3Params.Iterations)
	}
	if len(artifact.Metadata.NSEC3Params.Salt) != 6 {
		t.Errorf("NSEC3 salt hex length mismatch: got %d, want 6", len(artifact.Metadata.NSEC3Params.Salt))
	}
}

func TestSigningService_UsesNSECWhenNSEC3Disabled(t *testing.T) {
	options := dnssec.DefaultSignerOptions()
	options.NSEC3Enabled = false

	service, cleanup := setupSigningService(t, options)
	defer cleanup()

	artifact, err := service.SignZone(context.Background(), createTestZone())
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	if artifact.Metadata.NSEC3Params != nil {
		t.Fatalf("NSEC3Params should be nil when NSEC3 is disabled: %+v", artifact.Metadata.NSEC3Params)
	}

	hasNSEC := false
	for _, rr := range artifact.SignedRRs {
		switch rr.(type) {
		case *dns.NSEC:
			hasNSEC = true
		case *dns.NSEC3, *dns.NSEC3PARAM:
			t.Fatalf("found NSEC3 record when NSEC3 is disabled: %T", rr)
		}
	}
	if !hasNSEC {
		t.Fatal("no NSEC records found")
	}
}

func TestSigningService_PrepareSignedZoneWriteHoldsLockUntilAbort(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	write, err := service.PrepareSignedZoneWrite(context.Background(), zone)
	if err != nil {
		t.Fatalf("PrepareSignedZoneWrite failed: %v", err)
	}
	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled {
		t.Fatal("PrepareSignedZoneWrite did not attach DNSSEC metadata")
	}

	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		lock := service.getZoneLock(model.NormalizeZoneName(zone.Name))
		lock.Lock()
		defer lock.Unlock()
		close(acquired)
	}()

	<-started
	select {
	case <-acquired:
		t.Fatal("zone signing lock was released before the write completed")
	case <-time.After(50 * time.Millisecond):
	}

	write.Abort()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("zone signing lock was not released after abort")
	}
}

func TestSigningService_CommitHoldsLockUntilComplete(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	write, err := service.PrepareSignedZoneWrite(context.Background(), zone)
	if err != nil {
		t.Fatalf("PrepareSignedZoneWrite failed: %v", err)
	}
	if err := write.Store(); err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if err := write.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		lock := service.getZoneLock(model.NormalizeZoneName(zone.Name))
		lock.Lock()
		defer lock.Unlock()
		close(acquired)
	}()

	<-started
	select {
	case <-acquired:
		t.Fatal("zone signing lock was released before the write completed")
	case <-time.After(50 * time.Millisecond):
	}

	if err := write.Complete(); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("zone signing lock was not released after complete")
	}
}

func TestSigningService_GetSignedZoneWaitsForZoneLockBeforeSigning(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	// Pre-create keys so an unlocked on-demand signing path would finish quickly.
	if _, _, err := service.keyManager.EnsureZoneKeys(zone.Name); err != nil {
		t.Fatalf("failed to create test zone keys: %v", err)
	}

	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	lock := service.getZoneLock(model.NormalizeZoneName(zone.Name))
	lock.Lock()
	locked := true
	defer func() {
		if locked {
			lock.Unlock()
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := service.GetSignedZone(ctx, zone.Name)
		done <- err
	}()

	select {
	case err := <-done:
		lock.Unlock()
		locked = false
		if err != nil {
			t.Fatalf("GetSignedZone returned before lock release with error: %v", err)
		}
		t.Fatal("GetSignedZone completed before the zone signing lock was released")
	case <-time.After(50 * time.Millisecond):
	}

	lock.Unlock()
	locked = false

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("GetSignedZone failed after lock release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GetSignedZone did not complete after the zone signing lock was released")
	}

	persisted, err := service.store.GetZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("failed to get persisted zone: %v", err)
	}
	if persisted.DNSSEC == nil || !persisted.DNSSEC.Enabled {
		t.Fatal("GetSignedZone did not persist DNSSEC metadata")
	}
}

func TestSigningService_SignAndStoreZone(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	// Store unsigned zone first
	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	// Sign and store
	if err := service.SignAndStoreZone(ctx, zone); err != nil {
		t.Fatalf("SignAndStoreZone failed: %v", err)
	}

	// Verify zone was signed (DNSSEC metadata updated)
	persisted, err := service.store.GetZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("failed to get persisted zone: %v", err)
	}
	if persisted.DNSSEC == nil || !persisted.DNSSEC.Enabled {
		t.Fatal("DNSSEC metadata was not persisted as enabled")
	}
	if persisted.DNSSEC.Algorithm == 0 {
		t.Error("DNSSEC algorithm was not persisted")
	}
	if persisted.DNSSEC.KSKKeyTag == 0 {
		t.Error("KSK key tag was not persisted")
	}
	if persisted.DNSSEC.ZSKKeyTag == 0 {
		t.Error("ZSK key tag was not persisted")
	}
	if persisted.DNSSEC.SignatureExpiration == nil {
		t.Error("signature expiration was not persisted")
	}
	if persisted.Version != zone.Version {
		t.Errorf("zone version changed during DNSSEC metadata persistence: got %s, want %s", persisted.Version, zone.Version)
	}
	if persisted.SOA.Serial != zone.SOA.Serial {
		t.Errorf("SOA serial changed during DNSSEC metadata persistence: got %d, want %d", persisted.SOA.Serial, zone.SOA.Serial)
	}
}

func TestSigningService_SignAndStoreZoneReturnsArtifactStoreError(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()
	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	artifactPath := filepath.Join(t.TempDir(), "artifacts")
	if err := os.WriteFile(artifactPath, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("failed to create artifact path: %v", err)
	}
	service.artifactDir = artifactPath

	err := service.SignAndStoreZone(ctx, zone)
	if err == nil {
		t.Fatal("SignAndStoreZone succeeded despite artifact store failure")
	}
	if !strings.Contains(err.Error(), "store signed artifact") {
		t.Fatalf("SignAndStoreZone returned unexpected error: %v", err)
	}

	persisted, err := service.store.GetZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("failed to get persisted zone: %v", err)
	}
	if persisted.DNSSEC != nil && persisted.DNSSEC.Enabled {
		t.Fatal("DNSSEC metadata was persisted despite artifact store failure")
	}
}

func TestSigningService_GetSignedZone(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	// Store unsigned zone
	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	// Get signed zone (should sign on-demand)
	artifact, err := service.GetSignedZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetSignedZone failed: %v", err)
	}

	if artifact == nil {
		t.Fatal("artifact is nil")
	}

	if artifact.SignedZone == "" {
		t.Error("SignedZone is empty")
	}

	t.Logf("Retrieved signed zone: %s (version %s)", artifact.ZoneName, artifact.Version)
}

func TestSigningService_GetSignedZone_CacheHitRestoresSignedRRs(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	artifact, err := service.GetSignedZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetSignedZone failed: %v", err)
	}

	const cacheMarker = "; cache-hit-marker"
	if err := service.storeArtifact(zone.Name, artifact.Version, []byte(artifact.SignedZone+"\n"+cacheMarker+"\n")); err != nil {
		t.Fatalf("failed to store marked signed artifact: %v", err)
	}

	cachedArtifact, err := service.GetSignedZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetSignedZone cache hit failed: %v", err)
	}

	if !strings.Contains(cachedArtifact.SignedZone, cacheMarker) {
		t.Fatal("expected GetSignedZone to serve the cached signed artifact")
	}
	if len(cachedArtifact.SignedRRs) == 0 {
		t.Fatal("cached artifact did not restore SignedRRs")
	}

	hasRRSIG := false
	for _, rr := range cachedArtifact.SignedRRs {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}
	if !hasRRSIG {
		t.Fatal("cached artifact SignedRRs has no RRSIG records")
	}

	expiration, err := service.GetEarliestExpiration(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetEarliestExpiration failed on cached artifact: %v", err)
	}
	if expiration == 0 {
		t.Fatal("cached artifact returned zero expiration")
	}
}

func TestSigningService_GetSignedZone_StaleCacheIsResigned(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	artifact, err := service.SignZone(ctx, zone)
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}
	zone.DNSSEC = artifact.DNSSEC
	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	parsed, err := parser.ParseBINDZone(strings.NewReader(artifact.SignedZone), zone.Name, parser.DefaultParseOptions())
	if err != nil {
		t.Fatalf("failed to parse signed artifact: %v", err)
	}
	expiredAt := uint32(time.Now().Add(-time.Hour).Unix())
	for _, rr := range parsed.Records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sig.Expiration = expiredAt
		}
	}

	expiredZoneFile, err := parser.GenerateBINDZoneFileFromRRs(zone.Name, artifact.Version, parsed.Records)
	if err != nil {
		t.Fatalf("failed to generate expired signed artifact: %v", err)
	}

	const staleCacheMarker = "; stale-cache-marker"
	if err := service.storeArtifact(zone.Name, artifact.Version, []byte(expiredZoneFile+"\n"+staleCacheMarker+"\n")); err != nil {
		t.Fatalf("failed to store expired signed artifact: %v", err)
	}

	freshArtifact, err := service.GetSignedZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetSignedZone failed: %v", err)
	}

	if strings.Contains(freshArtifact.SignedZone, staleCacheMarker) {
		t.Fatal("expected stale cached signed artifact to be ignored")
	}
	if freshArtifact.Metadata.Expiration <= uint32(time.Now().Unix()) {
		t.Fatalf("re-signed artifact still expired: %d", freshArtifact.Metadata.Expiration)
	}

	persistedZone, err := service.store.GetZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("failed to get persisted zone: %v", err)
	}
	if persistedZone.DNSSEC == nil || persistedZone.DNSSEC.SignatureExpiration == nil {
		t.Fatal("re-signed zone did not persist DNSSEC signature expiration")
	}
	if got, want := persistedZone.DNSSEC.SignatureExpiration.Unix(), int64(freshArtifact.Metadata.Expiration); got != want {
		t.Fatalf("persisted signature expiration = %d, want %d", got, want)
	}
}

func TestSigningService_GetDSRecords(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zoneName := "example.com."
	ctx := context.Background()

	// Ensure keys exist by signing a zone first
	zone := createTestZone()
	_, err := service.SignZone(ctx, zone)
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	// Get DS records
	dsRecords, err := service.GetDSRecords(ctx, zoneName)
	if err != nil {
		t.Fatalf("GetDSRecords failed: %v", err)
	}

	if len(dsRecords) == 0 {
		t.Error("No DS records returned")
	}

	// Verify DS record format (should be BIND format)
	for i, ds := range dsRecords {
		if ds == "" {
			t.Errorf("DS record %d is empty", i)
		}
		t.Logf("DS record %d: %s", i, ds)
	}
}

func TestSigningService_GetDSRecordsWaitsForZoneLock(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	if _, _, err := service.keyManager.EnsureZoneKeys(zone.Name); err != nil {
		t.Fatalf("failed to create test zone keys: %v", err)
	}

	lock := service.getZoneLock(model.NormalizeZoneName(zone.Name))
	lock.Lock()
	locked := true
	defer func() {
		if locked {
			lock.Unlock()
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := service.GetDSRecords(ctx, zone.Name)
		done <- err
	}()

	select {
	case err := <-done:
		lock.Unlock()
		locked = false
		if err != nil {
			t.Fatalf("GetDSRecords returned before lock release with error: %v", err)
		}
		t.Fatal("GetDSRecords completed before the zone signing lock was released")
	case <-time.After(50 * time.Millisecond):
	}

	lock.Unlock()
	locked = false

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("GetDSRecords failed after lock release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GetDSRecords did not complete after the zone signing lock was released")
	}
}

func TestSigningService_GetEarliestExpiration(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	// Store and sign zone
	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	artifact, err := service.GetSignedZone(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetSignedZone failed: %v", err)
	}

	// Get earliest expiration
	expiration, err := service.GetEarliestExpiration(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetEarliestExpiration failed: %v", err)
	}

	if expiration == 0 {
		t.Error("Expiration is zero")
	}
	if expiration != artifact.Metadata.Expiration {
		t.Errorf("Expiration = %d, want %d", expiration, artifact.Metadata.Expiration)
	}

	// Expiration should be in the future (roughly 30 days from now)
	// RRSIG expiration is in UNIX timestamp format
	t.Logf("Earliest expiration: %d", expiration)
}

func TestSigningService_GetEarliestExpiration_UsesCachedArtifactWithoutResigning(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	artifact, err := service.SignZone(ctx, zone)
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}
	zone.DNSSEC = artifact.DNSSEC
	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	parsed, err := parser.ParseBINDZone(strings.NewReader(artifact.SignedZone), zone.Name, parser.DefaultParseOptions())
	if err != nil {
		t.Fatalf("failed to parse signed artifact: %v", err)
	}
	expiredAt := uint32(time.Now().Add(-time.Hour).Unix())
	for _, rr := range parsed.Records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sig.Expiration = expiredAt
		}
	}

	expiredZoneFile, err := parser.GenerateBINDZoneFileFromRRs(zone.Name, artifact.Version, parsed.Records)
	if err != nil {
		t.Fatalf("failed to generate expired signed artifact: %v", err)
	}

	const staleCacheMarker = "; expiration-cache-marker"
	if err := service.storeArtifact(zone.Name, artifact.Version, []byte(expiredZoneFile+"\n"+staleCacheMarker+"\n")); err != nil {
		t.Fatalf("failed to store expired signed artifact: %v", err)
	}

	metadataStore, ok := service.store.(backend.DNSSECMetadataStore)
	if !ok {
		t.Fatal("store does not support DNSSEC metadata persistence")
	}
	dnssecConfig := cloneDNSSECConfig(zone.DNSSEC)
	dnssecConfig.SignatureExpiration = nil
	if err := metadataStore.UpdateDNSSECMetadata(ctx, zone.Name, dnssecConfig); err != nil {
		t.Fatalf("failed to clear signature expiration metadata: %v", err)
	}

	expiration, err := service.GetEarliestExpiration(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetEarliestExpiration failed: %v", err)
	}
	if expiration != expiredAt {
		t.Fatalf("Expiration = %d, want cached artifact expiration %d", expiration, expiredAt)
	}

	cached, err := service.loadArtifact(zone.Name, artifact.Version)
	if err != nil {
		t.Fatalf("failed to load signed artifact cache: %v", err)
	}
	if !strings.Contains(string(cached), staleCacheMarker) {
		t.Fatal("expected GetEarliestExpiration to leave cached artifact unchanged")
	}
}

func TestSigningService_GetSignedZone_NotFound(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	ctx := context.Background()

	// Try to get signed zone for non-existent zone
	_, err := service.GetSignedZone(ctx, "nonexistent.com.")
	if err == nil {
		t.Error("Expected error for non-existent zone, got nil")
	}
	if err != model.ErrZoneNotFound {
		t.Errorf("Expected ErrZoneNotFound, got: %v", err)
	}
}
