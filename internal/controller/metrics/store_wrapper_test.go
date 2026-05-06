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
}

func TestWrapZoneStoreDoesNotInventRevisionStore(t *testing.T) {
	wrapped := WrapZoneStore(backend.NewMemoryBackend(), NewControllerMetrics())

	_, ok := wrapped.(backend.RevisionStore)
	assert.False(t, ok)

	_, ok = wrapped.(backend.DNSSECMetadataStore)
	assert.True(t, ok)
}
