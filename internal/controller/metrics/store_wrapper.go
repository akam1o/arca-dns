package metrics

import (
	"context"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
)

// InstrumentedZoneStore wraps a ZoneStore and records backend operation counts.
type InstrumentedZoneStore struct {
	inner   backend.ZoneStore
	metrics *ControllerMetrics
}

func WrapZoneStore(inner backend.ZoneStore, metrics *ControllerMetrics) backend.ZoneStore {
	if metrics == nil {
		return inner
	}

	base := &InstrumentedZoneStore{inner: inner, metrics: metrics}
	_, hasDNSSECMetadata := inner.(backend.DNSSECMetadataStore)
	_, hasRevisions := inner.(backend.RevisionStore)
	_, hasConditionalDelete := inner.(backend.ConditionalDeleteStore)

	switch {
	case hasDNSSECMetadata && hasRevisions && hasConditionalDelete:
		return &instrumentedMetadataRevisionConditionalDeleteStore{
			instrumentedMetadataRevisionStore: &instrumentedMetadataRevisionStore{InstrumentedZoneStore: base},
		}
	case hasDNSSECMetadata && hasRevisions:
		return &instrumentedMetadataRevisionStore{InstrumentedZoneStore: base}
	case hasDNSSECMetadata && hasConditionalDelete:
		return &instrumentedMetadataConditionalDeleteStore{
			instrumentedMetadataStore: &instrumentedMetadataStore{InstrumentedZoneStore: base},
		}
	case hasDNSSECMetadata:
		return &instrumentedMetadataStore{InstrumentedZoneStore: base}
	case hasRevisions && hasConditionalDelete:
		return &instrumentedRevisionConditionalDeleteStore{
			instrumentedRevisionStore: &instrumentedRevisionStore{InstrumentedZoneStore: base},
		}
	case hasRevisions:
		return &instrumentedRevisionStore{InstrumentedZoneStore: base}
	case hasConditionalDelete:
		return &instrumentedConditionalDeleteStore{InstrumentedZoneStore: base}
	default:
		return base
	}
}

func (s *InstrumentedZoneStore) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	zone, err := s.inner.GetZone(ctx, name)
	s.metrics.IncBackendOperation("get_zone", statusLabel(err))
	return zone, err
}

func (s *InstrumentedZoneStore) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	zones, err := s.inner.ListZones(ctx, opts)
	s.metrics.IncBackendOperation("list_zones", statusLabel(err))
	return zones, err
}

func (s *InstrumentedZoneStore) CreateZone(ctx context.Context, zone *model.Zone) error {
	err := s.inner.CreateZone(ctx, zone)
	s.metrics.IncBackendOperation("create_zone", statusLabel(err))
	return err
}

func (s *InstrumentedZoneStore) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	err := s.inner.UpdateZone(ctx, zone, expectedVersion)
	s.metrics.IncBackendOperation("update_zone", statusLabel(err))
	return err
}

func (s *InstrumentedZoneStore) DeleteZone(ctx context.Context, name string) error {
	err := s.inner.DeleteZone(ctx, name)
	s.metrics.IncBackendOperation("delete_zone", statusLabel(err))
	return err
}

func (s *InstrumentedZoneStore) Close() error {
	err := s.inner.Close()
	s.metrics.IncBackendOperation("close", statusLabel(err))
	return err
}

func recordConditionalDelete(ctx context.Context, store backend.ZoneStore, metrics *ControllerMetrics, name string, expectedVersion string) error {
	conditionalStore := store.(backend.ConditionalDeleteStore)
	err := conditionalStore.DeleteZoneWithVersion(ctx, name, expectedVersion)
	metrics.IncBackendOperation("delete_zone", statusLabel(err))
	return err
}

func statusLabel(err error) string {
	if err == nil {
		return "success"
	}
	return "error"
}

type instrumentedMetadataStore struct {
	*InstrumentedZoneStore
}

func (s *instrumentedMetadataStore) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	metadataStore := s.inner.(backend.DNSSECMetadataStore)
	err := metadataStore.UpdateDNSSECMetadata(ctx, zoneName, dnssec)
	s.metrics.IncBackendOperation("update_dnssec_metadata", statusLabel(err))
	return err
}

type instrumentedRevisionStore struct {
	*InstrumentedZoneStore
}

func (s *instrumentedRevisionStore) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	revisionStore := s.inner.(backend.RevisionStore)
	zone, err := revisionStore.GetRevision(ctx, zoneName, version)
	s.metrics.IncBackendOperation("get_revision", statusLabel(err))
	return zone, err
}

func (s *instrumentedRevisionStore) ListRevisions(ctx context.Context, zoneName string, opts backend.ListOptions) ([]*model.ZoneVersion, error) {
	revisionStore := s.inner.(backend.RevisionStore)
	versions, err := revisionStore.ListRevisions(ctx, zoneName, opts)
	s.metrics.IncBackendOperation("list_revisions", statusLabel(err))
	return versions, err
}

func (s *instrumentedRevisionStore) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	revisionStore := s.inner.(backend.RevisionStore)
	version, err := revisionStore.GetCurrentVersion(ctx, zoneName)
	s.metrics.IncBackendOperation("get_current_version", statusLabel(err))
	return version, err
}

type instrumentedMetadataRevisionStore struct {
	*InstrumentedZoneStore
}

func (s *instrumentedMetadataRevisionStore) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	metadataStore := s.inner.(backend.DNSSECMetadataStore)
	err := metadataStore.UpdateDNSSECMetadata(ctx, zoneName, dnssec)
	s.metrics.IncBackendOperation("update_dnssec_metadata", statusLabel(err))
	return err
}

func (s *instrumentedMetadataRevisionStore) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	revisionStore := s.inner.(backend.RevisionStore)
	zone, err := revisionStore.GetRevision(ctx, zoneName, version)
	s.metrics.IncBackendOperation("get_revision", statusLabel(err))
	return zone, err
}

func (s *instrumentedMetadataRevisionStore) ListRevisions(ctx context.Context, zoneName string, opts backend.ListOptions) ([]*model.ZoneVersion, error) {
	revisionStore := s.inner.(backend.RevisionStore)
	versions, err := revisionStore.ListRevisions(ctx, zoneName, opts)
	s.metrics.IncBackendOperation("list_revisions", statusLabel(err))
	return versions, err
}

func (s *instrumentedMetadataRevisionStore) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	revisionStore := s.inner.(backend.RevisionStore)
	version, err := revisionStore.GetCurrentVersion(ctx, zoneName)
	s.metrics.IncBackendOperation("get_current_version", statusLabel(err))
	return version, err
}

type instrumentedConditionalDeleteStore struct {
	*InstrumentedZoneStore
}

func (s *instrumentedConditionalDeleteStore) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	return recordConditionalDelete(ctx, s.inner, s.metrics, name, expectedVersion)
}

type instrumentedMetadataConditionalDeleteStore struct {
	*instrumentedMetadataStore
}

func (s *instrumentedMetadataConditionalDeleteStore) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	return recordConditionalDelete(ctx, s.inner, s.metrics, name, expectedVersion)
}

type instrumentedRevisionConditionalDeleteStore struct {
	*instrumentedRevisionStore
}

func (s *instrumentedRevisionConditionalDeleteStore) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	return recordConditionalDelete(ctx, s.inner, s.metrics, name, expectedVersion)
}

type instrumentedMetadataRevisionConditionalDeleteStore struct {
	*instrumentedMetadataRevisionStore
}

func (s *instrumentedMetadataRevisionConditionalDeleteStore) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	return recordConditionalDelete(ctx, s.inner, s.metrics, name, expectedVersion)
}
