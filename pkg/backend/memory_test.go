package backend

import (
	"context"
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryBackend_CreateZone(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	zone := &model.Zone{
		Name: "example.com.",
		SOA: model.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Verify zone was created
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name)
	assert.NotZero(t, retrieved.SOA.Serial)
	assert.NotEmpty(t, retrieved.Version)
	assert.NotZero(t, retrieved.CreatedAt)
	assert.NotZero(t, retrieved.UpdatedAt)
}

func TestMemoryBackend_CreateZone_AlreadyExists(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Try to create again
	err = backend.CreateZone(ctx, zone)
	assert.ErrorIs(t, err, model.ErrZoneAlreadyExists)
}

func TestMemoryBackend_GetZone_NotFound(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	_, err := backend.GetZone(ctx, "nonexistent.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestMemoryBackend_UpdateZone(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	// Create initial zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	originalVersion := retrieved.Version
	originalSerial := retrieved.SOA.Serial

	// Update zone
	retrieved.Records = append(retrieved.Records, model.Record{
		Name:  "www",
		Type:  "A",
		TTL:   300,
		Value: "192.0.2.2",
	})

	err = backend.UpdateZone(ctx, retrieved, originalVersion)
	require.NoError(t, err)

	// Verify update
	updated, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Len(t, updated.Records, 2)
	assert.NotEqual(t, originalVersion, updated.Version)
	assert.NotEqual(t, originalSerial, updated.SOA.Serial)
	assert.True(t, updated.SOA.Serial > originalSerial, "Serial should be incremented")
}

func TestMemoryBackend_UpdateZone_OptimisticLocking(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	version1 := retrieved.Version

	// Update once
	err = backend.UpdateZone(ctx, retrieved, version1)
	require.NoError(t, err)

	// Try to update with old version (should conflict)
	err = backend.UpdateZone(ctx, retrieved, version1)
	assert.ErrorIs(t, err, model.ErrConflict)
}

func TestMemoryBackend_DeleteZone(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	// Create zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Delete zone
	err = backend.DeleteZone(ctx, "example.com.")
	require.NoError(t, err)

	// Verify deletion
	_, err = backend.GetZone(ctx, "example.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestMemoryBackend_DeleteZone_NotFound(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	err := backend.DeleteZone(ctx, "nonexistent.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestMemoryBackend_ListZones(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	// Create multiple zones
	zones := []string{"example.com.", "test.com.", "demo.org."}
	for _, name := range zones {
		zone := &model.Zone{
			Name: name,
			SOA:  model.DefaultSOA("ns1."+name, "admin."+name),
		}
		err := backend.CreateZone(ctx, zone)
		require.NoError(t, err)
	}

	// List all zones
	list, err := backend.ListZones(ctx, ListOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 3)

	// List with limit
	list, err = backend.ListZones(ctx, ListOptions{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// List with offset
	list, err = backend.ListZones(ctx, ListOptions{Offset: 2})
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// List with offset and limit
	list, err = backend.ListZones(ctx, ListOptions{Offset: 1, Limit: 1})
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestMemoryBackend_ListZones_Empty(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	list, err := backend.ListZones(ctx, ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestMemoryBackend_CaseInsensitivity(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	zone := &model.Zone{
		Name: "Example.COM.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}

	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Retrieve with different case - should work and return normalized name
	retrieved, err := backend.GetZone(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name, "Zone name should be normalized to lowercase (contract)")

	// Retrieve with uppercase - should also work
	retrieved2, err := backend.GetZone(ctx, "EXAMPLE.COM.")
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved2.Name, "Zone name should be normalized to lowercase (contract)")

	// Delete with different case - should work
	err = backend.DeleteZone(ctx, "EXAMPLE.COM.")
	require.NoError(t, err)
}

func TestMemoryBackend_Concurrency(t *testing.T) {
	backend := NewMemoryBackend()
	ctx := context.Background()

	// Create initial zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}
	err := backend.CreateZone(ctx, zone)
	require.NoError(t, err)

	// Concurrent reads should work
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := backend.GetZone(ctx, "example.com.")
			assert.NoError(t, err)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMemoryBackend_Info(t *testing.T) {
	backend := NewMemoryBackend()
	info := backend.Info()

	assert.Equal(t, "memory", info.Type)
	assert.Contains(t, info.Capabilities, "ZoneStore")
	assert.Equal(t, "strong", info.Consistency)
}

func TestMemoryBackend_Close(t *testing.T) {
	backend := NewMemoryBackend()
	err := backend.Close()
	assert.NoError(t, err)
}

func TestGenerateSerial(t *testing.T) {
	tests := []struct {
		name           string
		currentSerial  uint32
		wantDateBased  bool
		wantIncrement  bool
	}{
		{
			name:          "first serial",
			currentSerial: 0,
			wantDateBased: true,
		},
		{
			name:          "increment same day",
			currentSerial: 2024122801,
			wantIncrement: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newSerial := generateSerial(tt.currentSerial)
			assert.NotZero(t, newSerial)

			if tt.wantIncrement && tt.currentSerial > 0 {
				// Serial should be incremented
				assert.True(t, newSerial > tt.currentSerial)
			}

			if tt.wantDateBased {
				// Serial should follow YYYYMMDDnn format
				assert.True(t, newSerial > 2024010100)
				assert.True(t, newSerial < 2100010100)
			}
		})
	}
}

func TestBackendRegistration(t *testing.T) {
	// Verify memory backend is registered
	backends := GetRegisteredBackends()
	assert.Contains(t, backends, "memory")

	// Create backend via factory
	store, err := NewBackend("memory", nil)
	require.NoError(t, err)
	assert.NotNil(t, store)

	// Verify it implements Backend interface
	backend, ok := store.(Backend)
	assert.True(t, ok)
	assert.NotNil(t, backend)
}
