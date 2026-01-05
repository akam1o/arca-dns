package backend

import (
	"context"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestZone(name string) *model.Zone {
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

func recvZoneEvent(t *testing.T, ch <-chan ZoneEvent, timeout time.Duration) ZoneEvent {
	t.Helper()

	select {
	case ev, ok := <-ch:
		require.True(t, ok, "event channel closed unexpectedly")
		return ev
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for zone event")
		return ZoneEvent{}
	}
}

func requireNoZoneEvent(t *testing.T, ch <-chan ZoneEvent, timeout time.Duration) {
	t.Helper()

	select {
	case ev, ok := <-ch:
		if !ok {
			return
		}
		t.Fatalf("unexpected zone event: %#v", ev)
	case <-time.After(timeout):
		// ok
	}
}

// RunTransactionalStoreSuite tests TransactionalStore contract behavior.
//
// Contract Invariants Tested:
// - Read-your-writes inside a transaction
// - No dirty reads outside a transaction
// - Commit persists changes
// - Rollback discards changes
func RunTransactionalStoreSuite(t *testing.T, store ZoneStore) {
	txStore, ok := store.(TransactionalStore)
	if !ok {
		t.Skip("store does not implement TransactionalStore")
		return
	}

	ctx := context.Background()

	t.Run("CreateAndCommitPersists", func(t *testing.T) {
		tx, err := txStore.BeginTx(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }() // best-effort cleanup if commit fails

		zone := newTestZone("tx-commit.example.com.")
		require.NoError(t, tx.CreateZone(ctx, zone))

		// Read-your-writes inside the tx.
		_, err = tx.GetZone(ctx, "tx-commit.example.com.")
		require.NoError(t, err)

		// Outside should not see uncommitted changes.
		_, err = store.GetZone(ctx, "tx-commit.example.com.")
		require.ErrorIs(t, err, model.ErrZoneNotFound)

		require.NoError(t, tx.Commit(ctx))

		// After commit, outside should see it.
		got, err := store.GetZone(ctx, "tx-commit.example.com.")
		require.NoError(t, err)
		require.Equal(t, model.NormalizeZoneName("tx-commit.example.com."), got.Name)
		require.NotEmpty(t, got.Version)
	})

	t.Run("CreateAndRollbackDiscards", func(t *testing.T) {
		tx, err := txStore.BeginTx(ctx)
		require.NoError(t, err)

		zone := newTestZone("tx-rollback.example.com.")
		require.NoError(t, tx.CreateZone(ctx, zone))

		// Read-your-writes inside the tx.
		_, err = tx.GetZone(ctx, "tx-rollback.example.com.")
		require.NoError(t, err)

		require.NoError(t, tx.Rollback(ctx))

		// After rollback, outside should not see it.
		_, err = store.GetZone(ctx, "tx-rollback.example.com.")
		require.ErrorIs(t, err, model.ErrZoneNotFound)
	})

	t.Run("UpdateAndRollbackRestoresOriginal", func(t *testing.T) {
		zone := newTestZone("tx-update-rollback.example.com.")
		require.NoError(t, store.CreateZone(ctx, zone))

		original, err := store.GetZone(ctx, "tx-update-rollback.example.com.")
		require.NoError(t, err)

		tx, err := txStore.BeginTx(ctx)
		require.NoError(t, err)

		// Update inside tx (append a record).
		toUpdate, err := tx.GetZone(ctx, "tx-update-rollback.example.com.")
		require.NoError(t, err)
		toUpdate.Records = append(toUpdate.Records, model.Record{
			Name:  "www",
			Type:  "A",
			TTL:   300,
			Value: "192.0.2.10",
		})
		require.NoError(t, tx.UpdateZone(ctx, toUpdate, ""))

		// Outside should still see original content.
		outsideBefore, err := store.GetZone(ctx, "tx-update-rollback.example.com.")
		require.NoError(t, err)
		assert.Len(t, outsideBefore.Records, len(original.Records))

		require.NoError(t, tx.Rollback(ctx))

		// After rollback, original content remains.
		outsideAfter, err := store.GetZone(ctx, "tx-update-rollback.example.com.")
		require.NoError(t, err)
		assert.Len(t, outsideAfter.Records, len(original.Records))
		assert.Equal(t, original.Version, outsideAfter.Version)
	})
}

// RunRevisionStoreSuite tests RevisionStore contract behavior.
//
// Contract Invariants Tested:
// - Versions are immutable once created
// - GetRevision returns ErrVersionNotFound for missing versions
// - ListRevisions returns newest-first ordering
// - Pagination for revisions (limit/offset)
// - GetCurrentVersion matches the current zone's version
func RunRevisionStoreSuite(t *testing.T, store ZoneStore) {
	rs, ok := store.(RevisionStore)
	if !ok {
		t.Skip("store does not implement RevisionStore")
		return
	}

	ctx := context.Background()

	t.Run("RevisionsAreImmutableAndOrdered", func(t *testing.T) {
		zone := newTestZone("revisions.example.com.")
		require.NoError(t, store.CreateZone(ctx, zone))
		v1 := zone.Version

		// Ensure distinct versions/timestamps for backends that rely on time ordering.
		time.Sleep(2 * time.Millisecond)

		zone.Records = append(zone.Records, model.Record{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1"})
		require.NoError(t, store.UpdateZone(ctx, zone, ""))
		v2 := zone.Version
		require.NotEqual(t, v1, v2)

		time.Sleep(2 * time.Millisecond)

		zone.Records = append(zone.Records, model.Record{Name: "api", Type: "A", TTL: 300, Value: "192.0.2.2"})
		require.NoError(t, store.UpdateZone(ctx, zone, ""))
		v3 := zone.Version
		require.NotEqual(t, v2, v3)

		// List revisions: newest first.
		revs, err := rs.ListRevisions(ctx, "revisions.example.com.", ListOptions{Limit: 0})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(revs), 3)
		assert.Equal(t, v3, revs[0].Version)
		assert.Equal(t, v2, revs[1].Version)
		assert.Equal(t, v1, revs[2].Version)

		// Pagination sanity.
		page, err := rs.ListRevisions(ctx, "revisions.example.com.", ListOptions{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, page, 1)
		assert.Equal(t, v2, page[0].Version)

		// Immutability: older revision should not contain later records.
		z1, err := rs.GetRevision(ctx, "revisions.example.com.", v1)
		require.NoError(t, err)
		assert.Len(t, z1.Records, 0)

		z2, err := rs.GetRevision(ctx, "revisions.example.com.", v2)
		require.NoError(t, err)
		assert.Len(t, z2.Records, 1)

		z3, err := rs.GetRevision(ctx, "revisions.example.com.", v3)
		require.NoError(t, err)
		assert.Len(t, z3.Records, 2)

		current, err := rs.GetCurrentVersion(ctx, "revisions.example.com.")
		require.NoError(t, err)
		assert.Equal(t, v3, current)
	})

	t.Run("GetRevision_NotFound", func(t *testing.T) {
		_, err := rs.GetRevision(ctx, "revisions.example.com.", "vdoesnotexist")
		assert.ErrorIs(t, err, model.ErrVersionNotFound)
	})
}

// RunWatchableStoreSuite tests WatchableStore contract behavior.
//
// Contract Invariants Tested:
// - Watch does not emit historical events (starts from "now")
// - Events are emitted for create/update/delete
// - Zone-specific watch filters by zone
// - Channel closes on context cancellation
func RunWatchableStoreSuite(t *testing.T, store ZoneStore) {
	ws, ok := store.(WatchableStore)
	if !ok {
		t.Skip("store does not implement WatchableStore")
		return
	}

	ctx := context.Background()

	t.Run("NoHistoricalEvents", func(t *testing.T) {
		zone := newTestZone("watch-existing.example.com.")
		require.NoError(t, store.CreateZone(ctx, zone))

		wctx, cancel := context.WithCancel(ctx)
		defer cancel()

		ch, err := ws.Watch(wctx, "")
		require.NoError(t, err)

		// Should not receive an event for an already-existing zone.
		requireNoZoneEvent(t, ch, 150*time.Millisecond)
	})

	t.Run("CreateUpdateDeleteEvents", func(t *testing.T) {
		wctx, cancel := context.WithCancel(ctx)
		defer cancel()

		ch, err := ws.Watch(wctx, "")
		require.NoError(t, err)

		// Give the watcher a moment to start to reduce race in integration tests.
		time.Sleep(25 * time.Millisecond)

		zone := newTestZone("watch.example.com.")
		require.NoError(t, store.CreateZone(ctx, zone))
		created := recvZoneEvent(t, ch, 2*time.Second)
		assert.Equal(t, EventTypeCreated, created.Type)
		assert.Equal(t, model.NormalizeZoneName("watch.example.com."), created.ZoneName)
		assert.NotEmpty(t, created.Version)
		assert.NotNil(t, created.Zone)

		zone.Records = append(zone.Records, model.Record{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.3"})
		require.NoError(t, store.UpdateZone(ctx, zone, ""))
		updated := recvZoneEvent(t, ch, 2*time.Second)
		assert.Equal(t, EventTypeUpdated, updated.Type)
		assert.Equal(t, model.NormalizeZoneName("watch.example.com."), updated.ZoneName)
		assert.NotEmpty(t, updated.Version)
		assert.NotNil(t, updated.Zone)

		require.NoError(t, store.DeleteZone(ctx, "watch.example.com."))
		deleted := recvZoneEvent(t, ch, 2*time.Second)
		assert.Equal(t, EventTypeDeleted, deleted.Type)
		assert.Equal(t, model.NormalizeZoneName("watch.example.com."), deleted.ZoneName)
		assert.Empty(t, deleted.Version)
		assert.Nil(t, deleted.Zone)
	})

	t.Run("ZoneSpecificFilterAndCancel", func(t *testing.T) {
		wctx, cancel := context.WithCancel(ctx)
		ch, err := ws.Watch(wctx, "filtered.example.com.")
		require.NoError(t, err)

		time.Sleep(25 * time.Millisecond)

		// A different zone should not produce an event on the filtered watcher.
		other := newTestZone("other.example.com.")
		require.NoError(t, store.CreateZone(ctx, other))
		requireNoZoneEvent(t, ch, 200*time.Millisecond)

		// The watched zone should produce events.
		target := newTestZone("filtered.example.com.")
		require.NoError(t, store.CreateZone(ctx, target))
		ev := recvZoneEvent(t, ch, 2*time.Second)
		assert.Equal(t, EventTypeCreated, ev.Type)
		assert.Equal(t, model.NormalizeZoneName("filtered.example.com."), ev.ZoneName)

		// Cancellation closes the channel.
		cancel()
		select {
		case _, ok := <-ch:
			assert.False(t, ok, "channel should be closed after cancellation")
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for watch channel to close")
		}
	})
}
