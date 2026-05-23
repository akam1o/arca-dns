package backend

import (
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

func TestPrepareZoneForCreateNormalizesAndDefaultsCopy(t *testing.T) {
	priority := uint16(10)
	source := &model.Zone{
		Name: "Example.COM.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: testZoneRecords("example.com.",
			model.Record{Name: "mail", Type: model.RecordTypeMX, TTL: 300, Value: "10 mail.example.com.", Priority: &priority},
		),
	}

	before := time.Now()
	prepared, err := prepareZoneForCreate(source, model.NormalizeZoneName)
	after := time.Now()
	if err != nil {
		t.Fatalf("prepareZoneForCreate returned error: %v", err)
	}

	if prepared == source {
		t.Fatal("prepareZoneForCreate returned the source pointer")
	}
	if prepared.Name != "example.com." {
		t.Fatalf("prepared name = %q, want example.com.", prepared.Name)
	}
	if source.Name != "Example.COM." {
		t.Fatalf("source name was mutated: %q", source.Name)
	}
	if prepared.SOA.Serial == 0 {
		t.Fatal("prepared SOA serial was not generated")
	}
	if source.SOA.Serial != 0 {
		t.Fatalf("source SOA serial was mutated: %d", source.SOA.Serial)
	}
	if prepared.Version == "" {
		t.Fatal("prepared version is empty")
	}
	if source.Version != "" {
		t.Fatalf("source version was mutated: %q", source.Version)
	}
	if prepared.CreatedAt.Before(before) || prepared.CreatedAt.After(after) {
		t.Fatalf("prepared CreatedAt = %s, want between %s and %s", prepared.CreatedAt, before, after)
	}
	if prepared.UpdatedAt.Before(before) || prepared.UpdatedAt.After(after) {
		t.Fatalf("prepared UpdatedAt = %s, want between %s and %s", prepared.UpdatedAt, before, after)
	}
	if source.CreatedAt != (time.Time{}) || source.UpdatedAt != (time.Time{}) {
		t.Fatalf("source timestamps were mutated: created=%s updated=%s", source.CreatedAt, source.UpdatedAt)
	}
	if prepared.Records[1].Priority == source.Records[1].Priority {
		t.Fatal("record priority pointer was not deep-copied")
	}
}

func TestPrepareZoneForCreateReturnsValidationError(t *testing.T) {
	prepared, err := prepareZoneForCreate(nil, model.NormalizeZoneName)
	if err == nil {
		t.Fatal("expected nil zone validation error")
	}
	if prepared != nil {
		t.Fatalf("prepared zone = %#v, want nil", prepared)
	}
	if !strings.Contains(err.Error(), "zone is nil") {
		t.Fatalf("expected zone is nil error, got %v", err)
	}
}

func TestCopyZoneIntoDeepCopiesAndHandlesNil(t *testing.T) {
	copyZoneInto(nil, &model.Zone{Name: "ignored.example.com."})

	dst := &model.Zone{Name: "old.example.com."}
	copyZoneInto(dst, nil)
	if dst.Name != "old.example.com." {
		t.Fatalf("copyZoneInto mutated destination for nil source: %q", dst.Name)
	}

	priority := uint16(20)
	expiration := time.Unix(1_700_000_000, 0).UTC()
	src := &model.Zone{
		Name:    "copy.example.com.",
		Version: "v1",
		SOA:     model.DefaultSOA("ns1.copy.example.com.", "admin.copy.example.com."),
		Records: testZoneRecords("copy.example.com.",
			model.Record{Name: "mail", Type: model.RecordTypeMX, TTL: 300, Value: "20 mail.copy.example.com.", Priority: &priority},
		),
		DNSSEC: &model.DNSSECConfig{
			Enabled:             true,
			Algorithm:           13,
			SignatureExpiration: &expiration,
		},
	}

	copyZoneInto(dst, src)

	if dst.Name != src.Name || dst.Version != src.Version {
		t.Fatalf("destination basic fields = (%q, %q), want (%q, %q)", dst.Name, dst.Version, src.Name, src.Version)
	}
	if dst.Records[1].Priority == src.Records[1].Priority {
		t.Fatal("record priority pointer was not deep-copied")
	}
	if dst.DNSSEC == src.DNSSEC {
		t.Fatal("DNSSEC config pointer was not deep-copied")
	}
	if dst.DNSSEC.SignatureExpiration == src.DNSSEC.SignatureExpiration {
		t.Fatal("DNSSEC signature expiration pointer was not deep-copied")
	}
}
