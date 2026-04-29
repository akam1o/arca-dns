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
	return &InstrumentedZoneStore{inner: inner, metrics: metrics}
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

func (s *InstrumentedZoneStore) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	metadataStore, ok := s.inner.(backend.DNSSECMetadataStore)
	if !ok {
		err := model.NewAPIError(model.ErrorCodeInternal, "backend does not support DNSSEC metadata updates")
		s.metrics.IncBackendOperation("update_dnssec_metadata", statusLabel(err))
		return err
	}

	err := metadataStore.UpdateDNSSECMetadata(ctx, zoneName, dnssec)
	s.metrics.IncBackendOperation("update_dnssec_metadata", statusLabel(err))
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

func statusLabel(err error) string {
	if err == nil {
		return "success"
	}
	return "error"
}
