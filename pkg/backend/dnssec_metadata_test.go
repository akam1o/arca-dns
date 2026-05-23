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
