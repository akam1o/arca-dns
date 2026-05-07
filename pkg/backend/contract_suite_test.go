// Contract test suites for ZoneStore implementations.
//
// These test suites verify that all backends implement the ZoneStore interface contracts correctly,
// including invariants like version changes, case-insensitivity, and optimistic locking.
package backend

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RunZoneStoreCRUDSuite tests the core CRUD operations that all ZoneStore implementations must support.
//
// Test Cases:
//   - CreateZone, CreateZone_AlreadyExists
//   - GetZone, GetZone_NotFound, GetZone_CaseInsensitive
//   - UpdateZone, UpdateZone_OptimisticLocking, UpdateZone_OptionalVersionCheck, UpdateZone_NotFound
//   - DeleteZone, DeleteZone_NotFound, DeleteZoneWithVersion_OptimisticLocking
//   - ListZones_Multiple, ListZones_Pagination
//
// Contract Invariants Tested:
//   - Version changes on every update (content-derived)
//   - Case-insensitive zone name queries
//   - Optimistic locking (UpdateZone with expectedVersion)
//   - Optional version check (empty expectedVersion skips check)
//   - Deterministic ListZones ordering
//   - CreatedAt preservation, UpdatedAt changes
//   - Serial auto-increment on update
//   - Pagination (limit/offset, no overlap)
func RunZoneStoreCRUDSuite(t *testing.T, store ZoneStore) {
	ctx := context.Background()

	// Helper to create a test zone
	createTestZone := func(name string) *model.Zone {
		return &model.Zone{
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
	}

	t.Run("CreateZone", func(t *testing.T) {
		zone := createTestZone("create.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		// Verify version was set
		assert.NotEmpty(t, zone.Version, "Version should be set after creation")

		// Verify timestamps were set
		assert.False(t, zone.CreatedAt.IsZero(), "CreatedAt should be set")
		assert.False(t, zone.UpdatedAt.IsZero(), "UpdatedAt should be set")
	})

	t.Run("CreateZone_AlreadyExists", func(t *testing.T) {
		zone := createTestZone("duplicate.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		// Try to create again
		zone2 := createTestZone("duplicate.example.com.")
		err = store.CreateZone(ctx, zone2)
		assert.ErrorIs(t, err, model.ErrZoneAlreadyExists)
	})

	t.Run("CreateZone_DuplicateRecords", func(t *testing.T) {
		zone := createTestZone("duplicate-records.example.com.")
		zone.Records = []model.Record{
			{Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		}

		err := store.CreateZone(ctx, zone)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate record")
	})

	t.Run("GetZone", func(t *testing.T) {
		zone := createTestZone("get.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		retrieved, err := store.GetZone(ctx, "get.example.com.")
		require.NoError(t, err)
		assert.Equal(t, "get.example.com.", retrieved.Name)
		assert.Equal(t, zone.Version, retrieved.Version)
	})

	t.Run("GetZone_NotFound", func(t *testing.T) {
		_, err := store.GetZone(ctx, "notfound.example.com.")
		assert.ErrorIs(t, err, model.ErrZoneNotFound)
	})

	t.Run("GetZone_CaseInsensitive", func(t *testing.T) {
		zone := createTestZone("CaseSensitive.Example.COM.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		// Retrieve with different casing
		testCases := []string{
			"casesensitive.example.com.",
			"CASESENSITIVE.EXAMPLE.COM.",
			"CaseSensitive.Example.COM.",
		}

		for _, name := range testCases {
			retrieved, err := store.GetZone(ctx, name)
			require.NoError(t, err, "Should retrieve zone regardless of case: %s", name)
			assert.Equal(t, "casesensitive.example.com.", retrieved.Name,
				"Zone name should be normalized to lowercase")
		}
	})

	t.Run("UpdateZone", func(t *testing.T) {
		zone := createTestZone("update.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		originalVersion := zone.Version
		originalSerial := zone.SOA.Serial
		originalCreatedAt := zone.CreatedAt
		originalUpdatedAt := zone.UpdatedAt

		// Wait to ensure timestamp difference
		time.Sleep(10 * time.Millisecond)

		// Update zone
		zone.Records = []model.Record{
			{Name: "test.update.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		}
		err = store.UpdateZone(ctx, zone, originalVersion)
		require.NoError(t, err)

		// Retrieve updated zone
		updated, err := store.GetZone(ctx, "update.example.com.")
		require.NoError(t, err)

		// Verify version changed
		assert.NotEqual(t, originalVersion, updated.Version,
			"Version must change on every update (contract invariant)")

		// Verify serial incremented
		assert.Greater(t, updated.SOA.Serial, originalSerial,
			"Serial should auto-increment on update")

		// Verify CreatedAt preserved (use time.Equal to ignore monotonic clock)
		assert.True(t, originalCreatedAt.Equal(updated.CreatedAt),
			"CreatedAt should be preserved (contract invariant)")

		// Verify UpdatedAt changed
		assert.True(t, updated.UpdatedAt.After(originalUpdatedAt),
			"UpdatedAt should be updated (contract invariant)")

		// Verify record was added
		assert.Len(t, updated.Records, 1)
	})

	t.Run("UpdateZone_IgnoresClientSerialRollback", func(t *testing.T) {
		zone := createTestZone("serial-rollback.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		originalVersion := zone.Version
		originalSerial := zone.SOA.Serial

		zone.SOA.Serial = 1
		zone.Records = []model.Record{
			{Name: "test.serial-rollback.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		}
		err = store.UpdateZone(ctx, zone, originalVersion)
		require.NoError(t, err)

		updated, err := store.GetZone(ctx, "serial-rollback.example.com.")
		require.NoError(t, err)
		assert.Greater(t, updated.SOA.Serial, originalSerial,
			"UpdateZone must advance from the stored serial, not a stale client serial")
	})

	t.Run("UpdateZone_PreservesPreparedSerial", func(t *testing.T) {
		zone := createTestZone("prepared-serial.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		originalVersion := zone.Version
		originalSerial := zone.SOA.Serial
		preparedSerial := originalSerial + 42

		zone.SOA.Serial = preparedSerial
		zone.Records = []model.Record{
			{Name: "test.prepared-serial.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		}
		err = store.UpdateZone(ctx, zone, originalVersion)
		require.NoError(t, err)

		updated, err := store.GetZone(ctx, "prepared-serial.example.com.")
		require.NoError(t, err)
		assert.Equal(t, preparedSerial, updated.SOA.Serial,
			"UpdateZone should preserve a precomputed serial that already advanced from the stored serial")
	})

	t.Run("UpdateZone_OptimisticLocking", func(t *testing.T) {
		zone := createTestZone("locking.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		currentVersion := zone.Version

		// Update with correct version should succeed
		zone.Records = []model.Record{
			{Name: "test1.locking.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		}
		err = store.UpdateZone(ctx, zone, currentVersion)
		require.NoError(t, err)

		// Update with old version should fail
		zone.Records = []model.Record{
			{Name: "test2.locking.example.com.", Type: "A", TTL: 300, Value: "192.0.2.2"},
		}
		err = store.UpdateZone(ctx, zone, currentVersion) // Using old version
		assert.ErrorIs(t, err, model.ErrConflict,
			"UpdateZone with stale expectedVersion must return ErrConflict (contract invariant)")
	})

	t.Run("UpdateZone_OptionalVersionCheck", func(t *testing.T) {
		zone := createTestZone("optional-version.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		// Update with empty expectedVersion should succeed (no version check)
		zone.Records = []model.Record{
			{Name: "test.optional-version.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		}
		err = store.UpdateZone(ctx, zone, "") // Empty string = no version check
		require.NoError(t, err, "UpdateZone with empty expectedVersion should skip version check (contract)")
	})

	t.Run("UpdateZone_PreservesPreparedVersionWithoutCAS", func(t *testing.T) {
		zone := createTestZone("prepared-version.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		originalVersion := zone.Version
		preparedVersion, err := model.NewZoneVersion()
		require.NoError(t, err)
		require.NotEqual(t, originalVersion, preparedVersion)

		zone.Version = preparedVersion
		zone.Records = []model.Record{
			{Name: "test.prepared-version.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		}
		err = store.UpdateZone(ctx, zone, "")
		require.NoError(t, err, "UpdateZone with empty expectedVersion should preserve caller-provided non-current version")

		updated, err := store.GetZone(ctx, "prepared-version.example.com.")
		require.NoError(t, err)
		assert.Equal(t, preparedVersion, updated.Version)
	})

	t.Run("DeleteZone", func(t *testing.T) {
		zone := createTestZone("delete.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		err = store.DeleteZone(ctx, "delete.example.com.")
		require.NoError(t, err)

		// Verify zone no longer exists
		_, err = store.GetZone(ctx, "delete.example.com.")
		assert.ErrorIs(t, err, model.ErrZoneNotFound)
	})

	t.Run("DeleteZone_NotFound", func(t *testing.T) {
		err := store.DeleteZone(ctx, "nonexistent.example.com.")
		assert.ErrorIs(t, err, model.ErrZoneNotFound)
	})

	t.Run("DeleteZoneWithVersion_OptimisticLocking", func(t *testing.T) {
		conditionalStore, ok := store.(ConditionalDeleteStore)
		if !ok {
			t.Skip("store does not implement ConditionalDeleteStore")
		}

		zone := createTestZone("conditional-delete.example.com.")
		err := store.CreateZone(ctx, zone)
		require.NoError(t, err)

		originalVersion := zone.Version
		zone.Records = []model.Record{
			{Name: "test.conditional-delete.example.com.", Type: "A", TTL: 300, Value: "192.0.2.1"},
		}
		err = store.UpdateZone(ctx, zone, originalVersion)
		require.NoError(t, err)

		err = conditionalStore.DeleteZoneWithVersion(ctx, "conditional-delete.example.com.", originalVersion)
		assert.ErrorIs(t, err, model.ErrConflict,
			"DeleteZoneWithVersion with stale expectedVersion must return ErrConflict")

		current, err := store.GetZone(ctx, "conditional-delete.example.com.")
		require.NoError(t, err)

		err = conditionalStore.DeleteZoneWithVersion(ctx, "conditional-delete.example.com.", current.Version)
		require.NoError(t, err)

		_, err = store.GetZone(ctx, "conditional-delete.example.com.")
		assert.ErrorIs(t, err, model.ErrZoneNotFound)
	})

	t.Run("UpdateZone_NotFound", func(t *testing.T) {
		zone := createTestZone("nonexistent-update.example.com.")
		err := store.UpdateZone(ctx, zone, "")
		assert.ErrorIs(t, err, model.ErrZoneNotFound,
			"UpdateZone should return ErrZoneNotFound for non-existent zone (contract)")
	})

	t.Run("ListZones_Multiple", func(t *testing.T) {
		// Create multiple zones
		zoneNames := []string{
			"list-alpha.example.com.",
			"list-beta.example.com.",
			"list-gamma.example.com.",
		}

		for _, name := range zoneNames {
			zone := createTestZone(name)
			err := store.CreateZone(ctx, zone)
			require.NoError(t, err)
		}

		// List all zones
		zones, err := store.ListZones(ctx, ListOptions{Limit: 0})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(zones), 3, "Should return at least the 3 created zones")

		// Verify deterministic ordering (run twice, should be same order)
		zones2, err := store.ListZones(ctx, ListOptions{Limit: 0})
		require.NoError(t, err)

		assert.Equal(t, len(zones), len(zones2), "ListZones should return same count")
		for i := range zones {
			assert.Equal(t, zones[i].Name, zones2[i].Name,
				"ListZones must have deterministic ordering (contract invariant)")
		}
	})

	t.Run("ListZones_Pagination", func(t *testing.T) {
		// Create test zones with unique prefix
		prefix := fmt.Sprintf("page-%d", time.Now().UnixNano())
		for i := 0; i < 5; i++ {
			zone := createTestZone(fmt.Sprintf("%s-%d.example.com.", prefix, i))
			err := store.CreateZone(ctx, zone)
			require.NoError(t, err)
		}

		// Get all zones to understand total count
		allZones, err := store.ListZones(ctx, ListOptions{Limit: 0})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(allZones), 5, "Should have at least 5 zones for pagination test")

		// Test pagination: get first 2 pages
		page1, err := store.ListZones(ctx, ListOptions{Limit: 2, Offset: 0})
		require.NoError(t, err)
		assert.LessOrEqual(t, len(page1), 2, "First page should have at most 2 zones")

		page2, err := store.ListZones(ctx, ListOptions{Limit: 2, Offset: 2})
		require.NoError(t, err)
		assert.LessOrEqual(t, len(page2), 2, "Second page should have at most 2 zones")

		// Verify no overlap using set intersection
		page1Names := make(map[string]bool)
		for _, z := range page1 {
			page1Names[z.Name] = true
		}

		// Verify page2 zones are not in page1
		for _, z := range page2 {
			assert.False(t, page1Names[z.Name],
				"Zone %s appears in both pages - pagination overlap detected (contract violation)", z.Name)
		}

		// Verify pagination consistency: same zone at offset 1 should appear as second item in page1
		// and first item when queried with offset 1
		if len(page1) >= 2 {
			singleZone, err := store.ListZones(ctx, ListOptions{Limit: 1, Offset: 1})
			require.NoError(t, err)
			if len(singleZone) > 0 {
				assert.Equal(t, page1[1].Name, singleZone[0].Name,
					"Zone at offset 1 should be same whether fetched in page or individually (pagination consistency)")
			}
		}
	})
}
