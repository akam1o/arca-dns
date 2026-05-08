package metrics

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestHistogramCloneIndependence(t *testing.T) {
	h := NewHistogram([]float64{0.1, 1})
	h.Observe(0.05)

	clone := h.Clone()
	h.Observe(0.5)

	if clone.count != 1 {
		t.Fatalf("clone count changed after original observe: got %d, want 1", clone.count)
	}
	if clone.counts[0] != 1 || clone.counts[1] != 0 {
		t.Fatalf("clone bucket counts changed after original observe: got %v", clone.counts)
	}
}

func TestControllerMetricsRenderConcurrentSigningObserve(t *testing.T) {
	metrics := NewControllerMetrics()
	metrics.ObserveSigningDuration("success", 0.01)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				metrics.ObserveSigningDuration("success", 0.01)
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		_ = metrics.Render(0)
	}

	close(done)
	wg.Wait()
}

type summaryOnlyStore struct {
	total          int
	listZonesCalls int
}

func (s *summaryOnlyStore) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	return nil, model.ErrZoneNotFound
}

func (s *summaryOnlyStore) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	s.listZonesCalls++
	return nil, fmt.Errorf("ListZones should not be used for CountZones")
}

func (s *summaryOnlyStore) ListZoneSummaries(ctx context.Context, opts backend.ListOptions) ([]*backend.ZoneSummary, error) {
	if opts.Offset >= s.total {
		return []*backend.ZoneSummary{}, nil
	}
	end := opts.Offset + opts.Limit
	if opts.Limit <= 0 || end > s.total {
		end = s.total
	}
	summaries := make([]*backend.ZoneSummary, 0, end-opts.Offset)
	for i := opts.Offset; i < end; i++ {
		summaries = append(summaries, &backend.ZoneSummary{
			Name:    fmt.Sprintf("zone-%d.example.", i),
			Version: fmt.Sprintf("v%d", i),
		})
	}
	return summaries, nil
}

func (s *summaryOnlyStore) CreateZone(ctx context.Context, zone *model.Zone) error {
	return nil
}

func (s *summaryOnlyStore) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	return nil
}

func (s *summaryOnlyStore) DeleteZone(ctx context.Context, name string) error {
	return nil
}

func (s *summaryOnlyStore) Close() error {
	return nil
}

func TestCountZonesUsesSummaries(t *testing.T) {
	store := &summaryOnlyStore{total: 2501}

	count, err := CountZones(context.Background(), store)
	require.NoError(t, err)
	require.Equal(t, 2501, count)
	require.Zero(t, store.listZonesCalls)
}
