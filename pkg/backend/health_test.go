package backend

import (
	"context"
	"errors"
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
)

type healthCheckStore struct {
	ZoneStore
	err error
}

func (s *healthCheckStore) HealthCheck(ctx context.Context) error {
	return s.err
}

type zoneCountStore struct {
	ZoneStore
	count int
	err   error
}

func (s *zoneCountStore) CountZones(ctx context.Context) (int, error) {
	return s.count, s.err
}

type listHealthStore struct {
	err error
}

func (s *listHealthStore) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	return nil, model.ErrZoneNotFound
}

func (s *listHealthStore) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	return nil, s.err
}

func (s *listHealthStore) CreateZone(ctx context.Context, zone *model.Zone) error {
	return nil
}

func (s *listHealthStore) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	return nil
}

func (s *listHealthStore) DeleteZone(ctx context.Context, name string) error {
	return nil
}

func (s *listHealthStore) Close() error {
	return nil
}

func TestCheckHealthUsesHealthStore(t *testing.T) {
	expected := errors.New("health failed")
	store := &healthCheckStore{
		ZoneStore: NewMemoryBackend(),
		err:       expected,
	}

	if err := CheckHealth(context.Background(), store); !errors.Is(err, expected) {
		t.Fatalf("CheckHealth() error = %v, want %v", err, expected)
	}
}

func TestCheckHealthFallsBackToListZoneSummaries(t *testing.T) {
	expected := errors.New("list failed")
	store := &listHealthStore{err: expected}

	if err := CheckHealth(context.Background(), store); !errors.Is(err, expected) {
		t.Fatalf("CheckHealth() error = %v, want %v", err, expected)
	}
}

func TestCountZonesUsesZoneCountStore(t *testing.T) {
	store := &zoneCountStore{
		ZoneStore: &listHealthStore{err: errors.New("fallback should not be used")},
		count:     42,
	}

	count, err := CountZones(context.Background(), store)
	if err != nil {
		t.Fatalf("CountZones() error = %v", err)
	}
	if count != 42 {
		t.Fatalf("CountZones() = %d, want 42", count)
	}
}

func TestCountZonesReturnsZoneCountStoreError(t *testing.T) {
	expected := errors.New("count failed")
	store := &zoneCountStore{
		ZoneStore: NewMemoryBackend(),
		err:       expected,
	}

	count, err := CountZones(context.Background(), store)
	if !errors.Is(err, expected) {
		t.Fatalf("CountZones() error = %v, want %v", err, expected)
	}
	if count != 0 {
		t.Fatalf("CountZones() = %d, want 0", count)
	}
}
