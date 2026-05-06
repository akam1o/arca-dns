package backend

import (
	"context"
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

func TestSQLiteBackend_PreservesRecordIDOnUpdate(t *testing.T) {
	store, err := NewSQLiteBackend(":memory:")
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.InitSchema())

	ctx := context.Background()
	zone := &model.Zone{
		Name: "record-id.example.com.",
		SOA:  model.DefaultSOA("ns1.record-id.example.com.", "admin.record-id.example.com."),
		Records: []model.Record{
			{Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(ctx, zone))

	created, err := store.GetZone(ctx, zone.Name)
	require.NoError(t, err)
	require.Len(t, created.Records, 1)
	originalID := created.Records[0].ID
	require.NotEmpty(t, originalID)

	created.Records[0].Value = "192.0.2.2"
	require.NoError(t, store.UpdateZone(ctx, created, created.Version))

	updated, err := store.GetZone(ctx, zone.Name)
	require.NoError(t, err)
	require.Len(t, updated.Records, 1)
	assert.Equal(t, originalID, updated.Records[0].ID)
	assert.Equal(t, "192.0.2.2", updated.Records[0].Value)
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
		Records: []model.Record{
			{ID: "1", Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(ctx, first))

	second := &model.Zone{
		Name: "second-record-id.example.com.",
		SOA:  model.DefaultSOA("ns1.second-record-id.example.com.", "admin.second-record-id.example.com."),
		Records: []model.Record{
			{ID: "1", Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.2"},
		},
	}
	require.NoError(t, store.CreateZone(ctx, second))

	created, err := store.GetZone(ctx, second.Name)
	require.NoError(t, err)
	require.Len(t, created.Records, 1)
	assert.NotEqual(t, "1", created.Records[0].ID)
}
