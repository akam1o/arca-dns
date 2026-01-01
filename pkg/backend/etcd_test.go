// +build integration

package backend

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// setupEtcdBackend creates a test etcd backend.
// Requires etcd to be running on localhost:2379
func setupEtcdBackend(t *testing.T) (*EtcdBackend, func()) {
	endpoints := []string{"localhost:2379"}

	// Allow override via environment variable for CI
	if etcdEndpoint := os.Getenv("ETCD_ENDPOINT"); etcdEndpoint != "" {
		endpoints = []string{etcdEndpoint}
	}

	// Use a unique prefix for each test to avoid conflicts
	prefix := fmt.Sprintf("/arca-dns-test-%d", time.Now().UnixNano())

	backend, err := NewEtcdBackend(
		endpoints,
		prefix,
		"",  // username
		"",  // password
		5*time.Second,  // dialTimeout
		10*time.Second, // requestTimeout
	)
	require.NoError(t, err, "Failed to create EtcdBackend")

	cleanup := func() {
		// Clean up test data
		ctx := context.Background()
		backend.client.Delete(ctx, prefix, clientv3.WithPrefix())
		backend.Close()
	}

	return backend, cleanup
}

func TestEtcdBackend_CreateZone(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{
			{
				Name:  "example.com.",
				Type:  "A",
				TTL:   300,
				Value: "192.0.2.1",
			},
		},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Verify zone was created
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name)
	assert.Equal(t, uint32(2024010101), retrieved.SOA.Serial)
	assert.Len(t, retrieved.Records, 1)
	assert.NotEmpty(t, retrieved.Version)
	assert.NotZero(t, retrieved.CreatedAt)
	assert.NotZero(t, retrieved.UpdatedAt)
}

func TestEtcdBackend_CreateZone_AlreadyExists(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	// Create zone first time
	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Try to create again - should fail
	err = backend.CreateZone(ctx, zone)
	assert.ErrorIs(t, err, model.ErrZoneAlreadyExists)
}

func TestEtcdBackend_GetZone_NotFound(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	_, err := backend.GetZone(ctx, "nonexistent.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestEtcdBackend_UpdateZone(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create initial zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get current version
	created, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	originalVersion := created.Version
	originalSerial := created.SOA.Serial
	originalCreatedAt := created.CreatedAt

	// Wait to ensure timestamp difference
	time.Sleep(100 * time.Millisecond)

	// Update zone
	zone.Records = []model.Record{
		{Name: "test.example.com.", Type: "A", TTL: 300, Value: "192.0.2.2"},
	}

	err = backend.UpdateZone(ctx, zone, originalVersion)
	require.NoError(t, err)

	// Verify update
	updated, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotEqual(t, originalVersion, updated.Version, "Version should change")
	assert.Greater(t, updated.SOA.Serial, originalSerial, "Serial should auto-increment")
	assert.Equal(t, originalCreatedAt, updated.CreatedAt, "CreatedAt should be preserved")
	assert.True(t, updated.UpdatedAt.After(originalCreatedAt), "UpdatedAt should be newer")
	assert.Len(t, updated.Records, 1)
}

func TestEtcdBackend_UpdateZone_Conflict(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get current zone
	current, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)

	// Update with wrong version - should fail
	zone.Records = []model.Record{
		{Name: "test.example.com.", Type: "A", TTL: 300, Value: "192.0.2.2"},
	}
	err = backend.UpdateZone(ctx, zone, "wrong-version")
	assert.ErrorIs(t, err, model.ErrConflict)

	// Update with correct version - should succeed
	err = backend.UpdateZone(ctx, zone, current.Version)
	assert.NoError(t, err)
}

func TestEtcdBackend_DeleteZone(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Delete zone
	err = backend.DeleteZone(ctx, "example.com.")
	require.NoError(t, err)

	// Verify zone is gone
	_, err = backend.GetZone(ctx, "example.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)

	// Delete again - should fail
	err = backend.DeleteZone(ctx, "example.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestEtcdBackend_ListZones(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create multiple zones
	zones := []string{"a.com.", "b.com.", "c.com."}
	for _, name := range zones {
		zone := &model.Zone{
			Name: name,
			SOA: model.SOARecord{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
			},
			Records: []model.Record{},
		}
		err := backend.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// List all zones
	listed, err := backend.ListZones(ctx, ListOptions{Offset: 0, Limit: 0})
	require.NoError(t, err)
	assert.Len(t, listed, 3)

	// Verify ordering (should be sorted by name)
	assert.Equal(t, "a.com.", listed[0].Name)
	assert.Equal(t, "b.com.", listed[1].Name)
	assert.Equal(t, "c.com.", listed[2].Name)

	// Test pagination - limit
	limited, err := backend.ListZones(ctx, ListOptions{Offset: 0, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, limited, 2)

	// Test pagination - offset
	offset, err := backend.ListZones(ctx, ListOptions{Offset: 1, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, offset, 2)
	assert.Equal(t, "b.com.", offset[0].Name)
}

func TestEtcdBackend_ListZones_Empty(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	zones, err := backend.ListZones(ctx, ListOptions{})
	require.NoError(t, err)
	assert.NotNil(t, zones, "Should return empty slice, not nil")
	assert.Len(t, zones, 0)
}

func TestEtcdBackend_GetRevision(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get version
	current, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	version1 := current.Version

	// Update zone
	zone.Records = []model.Record{
		{Name: "test.example.com.", Type: "A", TTL: 300, Value: "192.0.2.2"},
	}
	err = backend.UpdateZone(ctx, zone, version1)
	require.NoError(t, err)

	// Get new version
	updated, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	version2 := updated.Version

	// Retrieve old revision
	oldRevision, err := backend.GetRevision(ctx, "example.com.", version1)
	require.NoError(t, err)
	assert.Equal(t, version1, oldRevision.Version)
	assert.Len(t, oldRevision.Records, 0)

	// Retrieve new revision
	newRevision, err := backend.GetRevision(ctx, "example.com.", version2)
	require.NoError(t, err)
	assert.Equal(t, version2, newRevision.Version)
	assert.Len(t, newRevision.Records, 1)
}

func TestEtcdBackend_ListRevisions(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Make several updates
	for i := 0; i < 3; i++ {
		current, err := backend.GetZone(ctx, "example.com.")
		require.NoError(t, err)

		zone.Records = append(zone.Records, model.Record{
			Name:  fmt.Sprintf("host%d.example.com.", i),
			Type:  "A",
			TTL:   300,
			Value: fmt.Sprintf("192.0.2.%d", i+1),
		})

		err = backend.UpdateZone(ctx, zone, current.Version)
		require.NoError(t, err)

		time.Sleep(50 * time.Millisecond) // Ensure different timestamps
	}

	// List revisions
	revisions, err := backend.ListRevisions(ctx, "example.com.", ListOptions{})
	require.NoError(t, err)
	assert.Len(t, revisions, 4, "Should have 4 revisions (1 create + 3 updates)")

	// Verify reverse chronological order
	for i := 0; i < len(revisions)-1; i++ {
		assert.True(t, revisions[i].Timestamp.After(revisions[i+1].Timestamp) ||
			revisions[i].Timestamp.Equal(revisions[i+1].Timestamp),
			"Revisions should be in reverse chronological order")
	}
}

func TestEtcdBackend_GetCurrentVersion(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get current version
	version, err := backend.GetCurrentVersion(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotEmpty(t, version)

	// Verify it matches zone version
	current, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, current.Version, version)
}

func TestEtcdBackend_Watch(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start watching
	eventChan, err := backend.Watch(ctx, "")
	require.NoError(t, err)

	// Create zone in background
	go func() {
		time.Sleep(100 * time.Millisecond)
		zone := &model.Zone{
			Name: "example.com.",
			SOA: model.SOARecord{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
			},
			Records: []model.Record{},
		}
		backend.CreateZone(context.Background(), zone)
	}()

	// Wait for create event
	select {
	case event := <-eventChan:
		assert.Equal(t, EventTypeCreated, event.Type)
		assert.Equal(t, "example.com.", event.ZoneName)
		assert.NotEmpty(t, event.Version)
		assert.NotNil(t, event.Zone)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for create event")
	}
}

func TestEtcdBackend_ZoneNameNormalization(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone with uppercase name
	zone := &model.Zone{
		Name: "EXAMPLE.COM.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Retrieve with lowercase (should work - normalized)
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name, "Name should be normalized to lowercase")

	// Retrieve with uppercase (should still work)
	retrieved2, err := backend.GetZone(ctx, "EXAMPLE.COM.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved2.Name)
}

func TestEtcdBackend_ListZones_LimitZero(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create 5 zones
	for i := 0; i < 5; i++ {
		zone := &model.Zone{
			Name: fmt.Sprintf("zone%d.com.", i),
			SOA: model.SOARecord{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
			},
			Records: []model.Record{},
		}
		err := backend.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// List with Limit==0 (should return all)
	zones, err := backend.ListZones(ctx, ListOptions{Offset: 0, Limit: 0})
	require.NoError(t, err)
	assert.Len(t, zones, 5, "Limit==0 should return all zones")
}

func TestEtcdBackend_SerialAutoGeneration(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone with serial=0
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  0, // Should be auto-generated
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Retrieve and verify serial was generated
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotZero(t, retrieved.SOA.Serial, "Serial should be auto-generated")
	assert.Greater(t, retrieved.SOA.Serial, uint32(2024000000), "Serial should be in YYYYMMDDnn format")
}

func TestEtcdBackend_TimestampHandling(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Get created zone
	created, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.NotZero(t, created.CreatedAt, "CreatedAt should be set")
	assert.NotZero(t, created.UpdatedAt, "UpdatedAt should be set")
	originalCreatedAt := created.CreatedAt
	originalUpdatedAt := created.UpdatedAt

	// Wait to ensure timestamp difference
	time.Sleep(100 * time.Millisecond)

	// Update zone
	zone.Records = []model.Record{
		{Name: "test.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
	}
	err = backend.UpdateZone(ctx, zone, created.Version)
	require.NoError(t, err)

	// Verify timestamps
	updated, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, originalCreatedAt, updated.CreatedAt, "CreatedAt should be preserved")
	assert.NotEqual(t, originalUpdatedAt, updated.UpdatedAt, "UpdatedAt should change")
	assert.True(t, updated.UpdatedAt.After(originalUpdatedAt), "UpdatedAt should be newer")
}

func TestEtcdBackend_GetRevision_NotFound(t *testing.T) {
	backend, cleanup := setupEtcdBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Try to get non-existent version
	_, err = backend.GetRevision(ctx, "example.com.", "v2024010101-nonexist")
	assert.ErrorIs(t, err, model.ErrVersionNotFound, "Should return ErrVersionNotFound for missing version")
}
