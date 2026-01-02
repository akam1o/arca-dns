package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func setupSigningService(t *testing.T) (*SigningService, func()) {
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
	service := NewSigningService(store, keyManager, filepath.Join(tmpDir, "artifacts"), nil, logger)

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
	// Note: Current implementation doesn't persist signed artifact in backend
	// This test verifies the signing succeeds without errors
	t.Log("Zone signed and stored successfully")
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

func TestSigningService_GetEarliestExpiration(t *testing.T) {
	service, cleanup := setupSigningService(t)
	defer cleanup()

	zone := createTestZone()
	ctx := context.Background()

	// Store and sign zone
	if err := service.store.CreateZone(ctx, zone); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	// Get earliest expiration
	expiration, err := service.GetEarliestExpiration(ctx, zone.Name)
	if err != nil {
		t.Fatalf("GetEarliestExpiration failed: %v", err)
	}

	if expiration == 0 {
		t.Error("Expiration is zero")
	}

	// Expiration should be in the future (roughly 30 days from now)
	// RRSIG expiration is in UNIX timestamp format
	t.Logf("Earliest expiration: %d", expiration)
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
