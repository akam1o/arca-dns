package backend

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSQLiteBackend_Contract runs the full contract test suite against SQLiteBackend.
// This uses an in-memory SQLite database so it always runs (no external dependency).
func TestSQLiteBackend_Contract(t *testing.T) {
	store, err := NewSQLiteBackend(":memory:")
	if err != nil {
		t.Fatalf("Failed to create SQLite backend: %v", err)
	}
	defer store.Close()

	if err := store.InitSchema(); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}

	t.Run("ZoneStoreCRUD", func(t *testing.T) {
		RunZoneStoreCRUDSuite(t, store)
	})
}

func TestSQLiteDSNWithDefaultPragmas_AddsMissingPragmas(t *testing.T) {
	dsn := sqliteDSNWithDefaultPragmas("file:arca.db?_pragma=journal_mode(wal)")

	assert.Contains(t, dsn, "_pragma=journal_mode(wal)")
	assert.Contains(t, dsn, "_pragma=foreign_keys(1)")
	assert.Contains(t, dsn, "_pragma=busy_timeout(5000)")
	assert.Equal(t, 1, strings.Count(dsn, "journal_mode"))
}

func TestSQLiteBackend_PartialPragmaDSNEnablesCascadeDelete(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "arca.db") + "?_pragma=journal_mode(wal)"
	store, err := NewSQLiteBackend(dsn)
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.InitSchema())

	ctx := context.Background()
	zone := &model.Zone{
		Name: "cascade.example.com.",
		SOA:  model.DefaultSOA("ns1.cascade.example.com.", "admin.cascade.example.com."),
		Records: testZoneRecords("cascade.example.com.",
			model.Record{Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		),
	}
	require.NoError(t, store.CreateZone(ctx, zone))
	require.NoError(t, store.DeleteZone(ctx, zone.Name))

	var recordCount int
	require.NoError(t, store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM records").Scan(&recordCount))
	assert.Equal(t, 0, recordCount)
}

func TestSQLiteBackend_PreservesRecordIDOnUpdate(t *testing.T) {
	store, err := NewSQLiteBackend(":memory:")
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.InitSchema())

	ctx := context.Background()
	zone := &model.Zone{
		Name: "record-id.example.com.",
		SOA:  model.DefaultSOA("ns1.record-id.example.com.", "admin.record-id.example.com."),
		Records: testZoneRecords("record-id.example.com.",
			model.Record{Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		),
	}
	require.NoError(t, store.CreateZone(ctx, zone))

	created, err := store.GetZone(ctx, zone.Name)
	require.NoError(t, err)
	require.Len(t, created.Records, 2)
	originalID := created.Records[1].ID
	require.NotEmpty(t, originalID)

	created.Records[1].Value = "192.0.2.2"
	require.NoError(t, store.UpdateZone(ctx, created, created.Version))

	updated, err := store.GetZone(ctx, zone.Name)
	require.NoError(t, err)
	require.Len(t, updated.Records, 2)
	assert.Equal(t, originalID, updated.Records[1].ID)
	assert.Equal(t, "192.0.2.2", updated.Records[1].Value)
}

func TestSQLiteBackend_IgnoresClientRecordIDsOnCreate(t *testing.T) {
	store, err := NewSQLiteBackend(":memory:")
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.InitSchema())

	ctx := context.Background()
	first := &model.Zone{
		Name: "first-record-id.example.com.",
		SOA:  model.DefaultSOA("ns1.first-record-id.example.com.", "admin.first-record-id.example.com."),
		Records: testZoneRecords("first-record-id.example.com.",
			model.Record{ID: "1", Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		),
	}
	require.NoError(t, store.CreateZone(ctx, first))

	second := &model.Zone{
		Name: "second-record-id.example.com.",
		SOA:  model.DefaultSOA("ns1.second-record-id.example.com.", "admin.second-record-id.example.com."),
		Records: testZoneRecords("second-record-id.example.com.",
			model.Record{ID: "1", Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.2"},
		),
	}
	require.NoError(t, store.CreateZone(ctx, second))

	created, err := store.GetZone(ctx, second.Name)
	require.NoError(t, err)
	require.Len(t, created.Records, 2)
	assert.NotEqual(t, "1", created.Records[1].ID)
}

func TestSQLiteBackend_PreservesZeroRecordPriority(t *testing.T) {
	store, err := NewSQLiteBackend(":memory:")
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.InitSchema())

	ctx := context.Background()
	zone := &model.Zone{
		Name: "zero-priority.example.com.",
		SOA:  model.DefaultSOA("ns1.zero-priority.example.com.", "admin.zero-priority.example.com."),
		Records: testZoneRecords("zero-priority.example.com.",
			model.Record{Name: "@", Type: model.RecordTypeMX, TTL: 300, Value: "0 mail.zero-priority.example.com."},
		),
	}
	require.NoError(t, store.CreateZone(ctx, zone))

	created, err := store.GetZone(ctx, zone.Name)
	require.NoError(t, err)
	require.Len(t, created.Records, 2)
	var mxRecord *model.Record
	for i := range created.Records {
		if created.Records[i].Type == model.RecordTypeMX {
			mxRecord = &created.Records[i]
			break
		}
	}
	require.NotNil(t, mxRecord)
	require.NotNil(t, mxRecord.Priority)
	assert.Equal(t, uint16(0), *mxRecord.Priority)
}
