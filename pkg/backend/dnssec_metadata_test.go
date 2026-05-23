package backend

import (
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

func TestDNSSECColumnValues(t *testing.T) {
	enabled, algorithm, kskKeyTag, zskKeyTag, nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration := dnssecColumnValues(nil)
	if enabled || algorithm != nil || kskKeyTag != nil || zskKeyTag != nil || nsec3Enabled || nsec3Iterations != nil || nsec3Salt != nil || signatureExpiration != nil {
		t.Fatalf("dnssecColumnValues(nil) returned non-empty values")
	}

	expiration := time.Unix(1_700_000_000, 0).UTC()
	config := &model.DNSSECConfig{
		Enabled:             true,
		Algorithm:           13,
		KSKKeyTag:           12345,
		ZSKKeyTag:           54321,
		NSEC3Enabled:        true,
		NSEC3Iterations:     7,
		NSEC3Salt:           "abcdef",
		SignatureExpiration: &expiration,
	}

	enabled, algorithm, kskKeyTag, zskKeyTag, nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration = dnssecColumnValues(config)
	if !enabled {
		t.Fatal("enabled = false, want true")
	}
	if algorithm != uint8(13) {
		t.Fatalf("algorithm = %#v, want 13", algorithm)
	}
	if kskKeyTag != uint16(12345) {
		t.Fatalf("kskKeyTag = %#v, want 12345", kskKeyTag)
	}
	if zskKeyTag != uint16(54321) {
		t.Fatalf("zskKeyTag = %#v, want 54321", zskKeyTag)
	}
	if !nsec3Enabled {
		t.Fatal("nsec3Enabled = false, want true")
	}
	if nsec3Iterations != uint16(7) {
		t.Fatalf("nsec3Iterations = %#v, want 7", nsec3Iterations)
	}
	if nsec3Salt != "abcdef" {
		t.Fatalf("nsec3Salt = %#v, want abcdef", nsec3Salt)
	}
	if signatureExpiration != &expiration {
		t.Fatalf("signatureExpiration = %#v, want expiration pointer", signatureExpiration)
	}
}

func TestSQLiteDNSSECMetadataUpdateArgs(t *testing.T) {
	expiration := time.Unix(1_700_000_000, 123).UTC()
	dnssec := &model.DNSSECConfig{
		Enabled:             true,
		Algorithm:           13,
		KSKKeyTag:           12345,
		ZSKKeyTag:           54321,
		NSEC3Enabled:        true,
		NSEC3Iterations:     7,
		NSEC3Salt:           "abcdef",
		SignatureExpiration: &expiration,
	}

	args := (&SQLiteBackend{}).dnssecMetadataUpdateArgs("example.com.", dnssec)

	if len(args) != 10 {
		t.Fatalf("len(args) = %d, want 10", len(args))
	}
	if args[0] != 1 {
		t.Fatalf("dnssec enabled arg = %#v, want 1", args[0])
	}
	if args[1] != uint8(13) {
		t.Fatalf("algorithm arg = %#v, want 13", args[1])
	}
	if args[2] != uint16(12345) {
		t.Fatalf("ksk key tag arg = %#v, want 12345", args[2])
	}
	if args[3] != uint16(54321) {
		t.Fatalf("zsk key tag arg = %#v, want 54321", args[3])
	}
	if args[4] != 1 {
		t.Fatalf("nsec3 enabled arg = %#v, want 1", args[4])
	}
	if args[5] != uint16(7) {
		t.Fatalf("nsec3 iterations arg = %#v, want 7", args[5])
	}
	if args[6] != "abcdef" {
		t.Fatalf("nsec3 salt arg = %#v, want abcdef", args[6])
	}
	if args[7] != expiration.Format(time.RFC3339Nano) {
		t.Fatalf("signature expiration arg = %#v, want formatted expiration", args[7])
	}
	if _, err := time.Parse(time.RFC3339Nano, args[8].(string)); err != nil {
		t.Fatalf("updated_at arg is not RFC3339Nano: %v", err)
	}
	if args[9] != "example.com." {
		t.Fatalf("zone name arg = %#v, want example.com.", args[9])
	}
}

func TestSQLiteZoneUpdateArgsIncludesDNSSECMetadata(t *testing.T) {
	expiration := time.Unix(1_700_000_000, 456).UTC()
	updatedAt := time.Unix(1_700_000_100, 789).UTC()
	zone := &model.Zone{
		Name:      "example.com.",
		Version:   "v1",
		SOA:       model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		UpdatedAt: updatedAt,
		DNSSEC: &model.DNSSECConfig{
			Enabled:             true,
			Algorithm:           13,
			KSKKeyTag:           12345,
			ZSKKeyTag:           54321,
			NSEC3Enabled:        true,
			NSEC3Iterations:     7,
			NSEC3Salt:           "abcdef",
			SignatureExpiration: &expiration,
		},
	}

	args := (&SQLiteBackend{}).zoneUpdateArgs(zone)

	if len(args) != 18 {
		t.Fatalf("len(args) = %d, want 18", len(args))
	}
	if args[0] != "v1" {
		t.Fatalf("version arg = %#v, want v1", args[0])
	}
	if args[8] != 1 {
		t.Fatalf("dnssec enabled arg = %#v, want 1", args[8])
	}
	if args[9] != uint8(13) {
		t.Fatalf("algorithm arg = %#v, want 13", args[9])
	}
	if args[10] != uint16(12345) {
		t.Fatalf("ksk key tag arg = %#v, want 12345", args[10])
	}
	if args[11] != uint16(54321) {
		t.Fatalf("zsk key tag arg = %#v, want 54321", args[11])
	}
	if args[12] != 1 {
		t.Fatalf("nsec3 enabled arg = %#v, want 1", args[12])
	}
	if args[13] != uint16(7) {
		t.Fatalf("nsec3 iterations arg = %#v, want 7", args[13])
	}
	if args[14] != "abcdef" {
		t.Fatalf("nsec3 salt arg = %#v, want abcdef", args[14])
	}
	if args[15] != expiration.Format(time.RFC3339Nano) {
		t.Fatalf("signature expiration arg = %#v, want formatted expiration", args[15])
	}
	if args[16] != updatedAt.Format(time.RFC3339Nano) {
		t.Fatalf("updated_at arg = %#v, want formatted updated time", args[16])
	}
	if args[17] != "example.com." {
		t.Fatalf("zone name arg = %#v, want example.com.", args[17])
	}
}
