package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type revisionMetadataStore struct {
	*backend.MemoryBackend
	currentVersion string
	revision       *model.Zone
	versions       []*model.ZoneVersion
}

type zoneStoreWithoutConditionalDelete struct {
	inner backend.ZoneStore
}

func (s *zoneStoreWithoutConditionalDelete) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	return s.inner.GetZone(ctx, name)
}

func (s *zoneStoreWithoutConditionalDelete) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	return s.inner.ListZones(ctx, opts)
}

func (s *zoneStoreWithoutConditionalDelete) CreateZone(ctx context.Context, zone *model.Zone) error {
	return s.inner.CreateZone(ctx, zone)
}

func (s *zoneStoreWithoutConditionalDelete) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	return s.inner.UpdateZone(ctx, zone, expectedVersion)
}

func (s *zoneStoreWithoutConditionalDelete) DeleteZone(ctx context.Context, name string) error {
	return s.inner.DeleteZone(ctx, name)
}

func (s *zoneStoreWithoutConditionalDelete) Close() error {
	return s.inner.Close()
}

func (s *revisionMetadataStore) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	if version != s.currentVersion {
		return nil, model.ErrVersionNotFound
	}
	return s.revision, nil
}

func (s *revisionMetadataStore) ListRevisions(ctx context.Context, zoneName string, opts backend.ListOptions) ([]*model.ZoneVersion, error) {
	return s.versions, nil
}

func (s *revisionMetadataStore) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	return s.currentVersion, nil
}

func TestWrapZoneStorePreservesRevisionStore(t *testing.T) {
	ctx := context.Background()
	inner := &revisionMetadataStore{
		MemoryBackend:  backend.NewMemoryBackend(),
		currentVersion: "v1",
		revision: &model.Zone{
			Name:    "example.com.",
			Version: "v1",
			SOA: model.SOARecord{
				MName:   "ns1.example.com.",
				RName:   "admin.example.com.",
				Refresh: 3600,
				Retry:   1800,
				Expire:  604800,
				Minimum: 86400,
			},
		},
		versions: []*model.ZoneVersion{
			{Version: "v1", Timestamp: time.Unix(1, 0)},
		},
	}

	wrapped := WrapZoneStore(inner, NewControllerMetrics())

	revisionStore, ok := wrapped.(backend.RevisionStore)
	require.True(t, ok)

	currentVersion, err := revisionStore.GetCurrentVersion(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, "v1", currentVersion)

	versions, err := revisionStore.ListRevisions(ctx, "example.com.", backend.ListOptions{})
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, "v1", versions[0].Version)

	revision, err := revisionStore.GetRevision(ctx, "example.com.", "v1")
	require.NoError(t, err)
	assert.Equal(t, "v1", revision.Version)

	_, ok = wrapped.(backend.DNSSECMetadataStore)
	assert.True(t, ok)

	_, ok = wrapped.(backend.ConditionalDeleteStore)
	assert.True(t, ok)
}

func TestWrapZoneStoreDoesNotInventRevisionStore(t *testing.T) {
	wrapped := WrapZoneStore(backend.NewMemoryBackend(), NewControllerMetrics())

	_, ok := wrapped.(backend.RevisionStore)
	assert.False(t, ok)

	_, ok = wrapped.(backend.DNSSECMetadataStore)
	assert.True(t, ok)

	_, ok = wrapped.(backend.ConditionalDeleteStore)
	assert.True(t, ok)
}

func TestWrapZoneStoreDoesNotInventConditionalDeleteStore(t *testing.T) {
	wrapped := WrapZoneStore(&zoneStoreWithoutConditionalDelete{inner: backend.NewMemoryBackend()}, NewControllerMetrics())

	_, ok := wrapped.(backend.ConditionalDeleteStore)
	assert.False(t, ok)
}

func TestWrapZoneStorePreservesConditionalDeleteStore(t *testing.T) {
	wrapped := WrapZoneStore(backend.NewMemoryBackend(), NewControllerMetrics())

	_, ok := wrapped.(backend.ConditionalDeleteStore)
	assert.True(t, ok)
}

func TestWrapZoneStorePreservesZoneCountStore(t *testing.T) {
	ctx := context.Background()
	inner := backend.NewMemoryBackend()
	wrapped := WrapZoneStore(inner, NewControllerMetrics())

	countStore, ok := wrapped.(backend.ZoneCountStore)
	require.True(t, ok)

	count, err := countStore.CountZones(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestWrapZoneStorePreservesBackendInfo(t *testing.T) {
	wrapped := WrapZoneStore(backend.NewMemoryBackend(), NewControllerMetrics())

	infoStore, ok := wrapped.(backend.Backend)
	require.True(t, ok)
	assert.Equal(t, "memory", infoStore.Info().Type)
}

func TestWrapZoneStorePreservesTransactionalStore(t *testing.T) {
	sqlite, err := backend.NewSQLiteBackend(":memory:")
	require.NoError(t, err)
	defer sqlite.Close()

	wrapped := WrapZoneStore(sqlite, NewControllerMetrics())

	_, ok := wrapped.(backend.TransactionalStore)
	assert.True(t, ok)

	infoStore, ok := wrapped.(backend.Backend)
	require.True(t, ok)
	assert.Equal(t, "sqlite", infoStore.Info().Type)
}

func TestWrapZoneStorePreservesWatchableStore(t *testing.T) {
	wrapped := WrapZoneStore(&backend.EtcdBackend{}, NewControllerMetrics())

	_, ok := wrapped.(backend.WatchableStore)
	assert.True(t, ok)

	infoStore, ok := wrapped.(backend.Backend)
	require.True(t, ok)
	assert.Equal(t, "etcd", infoStore.Info().Type)
}

func TestWrapZoneStoreDoesNotInventAdvancedCapabilities(t *testing.T) {
	wrapped := WrapZoneStore(&zoneStoreWithoutConditionalDelete{inner: backend.NewMemoryBackend()}, NewControllerMetrics())

	_, hasBackendInfo := wrapped.(backend.Backend)
	assert.False(t, hasBackendInfo)

	_, hasTransactional := wrapped.(backend.TransactionalStore)
	assert.False(t, hasTransactional)

	_, hasWatchable := wrapped.(backend.WatchableStore)
	assert.False(t, hasWatchable)
}
