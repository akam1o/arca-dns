package metrics

import (
	"context"
	"time"

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
	start := time.Now()
	zone, err := s.inner.GetZone(ctx, name)
	s.metrics.ObserveBackendOperation("get_zone", err, time.Since(start).Seconds())
	return zone, err
}

func (s *InstrumentedZoneStore) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	start := time.Now()
	zones, err := s.inner.ListZones(ctx, opts)
	s.metrics.ObserveBackendOperation("list_zones", err, time.Since(start).Seconds())
	return zones, err
}

func (s *InstrumentedZoneStore) ListZoneSummaries(ctx context.Context, opts backend.ListOptions) ([]*backend.ZoneSummary, error) {
	start := time.Now()
	summaries, err := backend.ListZoneSummaries(ctx, s.inner, opts)
	s.metrics.ObserveBackendOperation("list_zone_summaries", err, time.Since(start).Seconds())
	return summaries, err
}

func (s *InstrumentedZoneStore) HealthCheck(ctx context.Context) error {
	start := time.Now()
	err := backend.CheckHealth(ctx, s.inner)
	s.metrics.ObserveBackendOperation("health_check", err, time.Since(start).Seconds())
	return err
}

func (s *InstrumentedZoneStore) CreateZone(ctx context.Context, zone *model.Zone) error {
	start := time.Now()
	err := s.inner.CreateZone(ctx, zone)
	s.metrics.ObserveBackendOperation("create_zone", err, time.Since(start).Seconds())
	return err
}

func (s *InstrumentedZoneStore) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	start := time.Now()
	err := s.inner.UpdateZone(ctx, zone, expectedVersion)
	s.metrics.ObserveBackendOperation("update_zone", err, time.Since(start).Seconds())
	return err
}

func (s *InstrumentedZoneStore) DeleteZone(ctx context.Context, name string) error {
	start := time.Now()
	err := s.inner.DeleteZone(ctx, name)
	s.metrics.ObserveBackendOperation("delete_zone", err, time.Since(start).Seconds())
	return err
}

func (s *InstrumentedZoneStore) Close() error {
	start := time.Now()
	err := s.inner.Close()
	s.metrics.ObserveBackendOperation("close", err, time.Since(start).Seconds())
	return err
}

func recordConditionalDelete(ctx context.Context, store backend.ZoneStore, metrics *ControllerMetrics, name string, expectedVersion string) error {
	start := time.Now()
	conditionalStore := store.(backend.ConditionalDeleteStore)
	err := conditionalStore.DeleteZoneWithVersion(ctx, name, expectedVersion)
	metrics.ObserveBackendOperation("delete_zone", err, time.Since(start).Seconds())
	return err
}

type instrumentedMetadataStore struct {
	*InstrumentedZoneStore
}

func (s *instrumentedMetadataStore) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	start := time.Now()
	metadataStore := s.inner.(backend.DNSSECMetadataStore)
	err := metadataStore.UpdateDNSSECMetadata(ctx, zoneName, dnssec)
	s.metrics.ObserveBackendOperation("update_dnssec_metadata", err, time.Since(start).Seconds())
	return err
}

type instrumentedRevisionStore struct {
	*InstrumentedZoneStore
}

func (s *instrumentedRevisionStore) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	start := time.Now()
	revisionStore := s.inner.(backend.RevisionStore)
	zone, err := revisionStore.GetRevision(ctx, zoneName, version)
	s.metrics.ObserveBackendOperation("get_revision", err, time.Since(start).Seconds())
	return zone, err
}

func (s *instrumentedRevisionStore) ListRevisions(ctx context.Context, zoneName string, opts backend.ListOptions) ([]*model.ZoneVersion, error) {
	start := time.Now()
	revisionStore := s.inner.(backend.RevisionStore)
	versions, err := revisionStore.ListRevisions(ctx, zoneName, opts)
	s.metrics.ObserveBackendOperation("list_revisions", err, time.Since(start).Seconds())
	return versions, err
}

func (s *instrumentedRevisionStore) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	start := time.Now()
	revisionStore := s.inner.(backend.RevisionStore)
	version, err := revisionStore.GetCurrentVersion(ctx, zoneName)
	s.metrics.ObserveBackendOperation("get_current_version", err, time.Since(start).Seconds())
	return version, err
}

type instrumentedMetadataRevisionStore struct {
	*InstrumentedZoneStore
}

func (s *instrumentedMetadataRevisionStore) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	start := time.Now()
	metadataStore := s.inner.(backend.DNSSECMetadataStore)
	err := metadataStore.UpdateDNSSECMetadata(ctx, zoneName, dnssec)
	s.metrics.ObserveBackendOperation("update_dnssec_metadata", err, time.Since(start).Seconds())
	return err
}

func (s *instrumentedMetadataRevisionStore) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	start := time.Now()
	revisionStore := s.inner.(backend.RevisionStore)
	zone, err := revisionStore.GetRevision(ctx, zoneName, version)
	s.metrics.ObserveBackendOperation("get_revision", err, time.Since(start).Seconds())
	return zone, err
}

func (s *instrumentedMetadataRevisionStore) ListRevisions(ctx context.Context, zoneName string, opts backend.ListOptions) ([]*model.ZoneVersion, error) {
	start := time.Now()
	revisionStore := s.inner.(backend.RevisionStore)
	versions, err := revisionStore.ListRevisions(ctx, zoneName, opts)
	s.metrics.ObserveBackendOperation("list_revisions", err, time.Since(start).Seconds())
	return versions, err
}

func (s *instrumentedMetadataRevisionStore) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	start := time.Now()
	revisionStore := s.inner.(backend.RevisionStore)
	version, err := revisionStore.GetCurrentVersion(ctx, zoneName)
	s.metrics.ObserveBackendOperation("get_current_version", err, time.Since(start).Seconds())
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
