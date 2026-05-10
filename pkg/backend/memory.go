package backend

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

// MemoryBackend is an in-memory implementation of ZoneStore.
// Deprecated: retained only for tests. Use SQLite with DSN ":memory:" for
// disposable runtime storage.
type MemoryBackend struct {
	mu     sync.RWMutex
	zones  map[string]*model.Zone
	nextID int
}

// NewMemoryBackend creates a new in-memory backend.
// Deprecated: retained only for tests. Use NewSQLiteBackend(":memory:") for
// disposable runtime storage.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		zones: make(map[string]*model.Zone),
	}
}

// HealthCheck verifies that the in-memory backend can serve requests.
func (m *MemoryBackend) HealthCheck(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// GetZone retrieves a zone by name.
func (m *MemoryBackend) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normalized := model.NormalizeZoneName(name)
	zone, exists := m.zones[normalized]
	if !exists {
		return nil, model.ErrZoneNotFound
	}

	// Return a copy to prevent external modification
	return copyZone(zone), nil
}

// ListZones returns all zones, optionally paginated.
func (m *MemoryBackend) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect all zones
	zones := make([]*model.Zone, 0, len(m.zones))
	for _, zone := range m.zones {
		zones = append(zones, copyZone(zone))
	}

	// Sort zones by name for deterministic ordering
	sort.Slice(zones, func(i, j int) bool {
		return strings.ToLower(zones[i].Name) < strings.ToLower(zones[j].Name)
	})

	// Apply offset
	if opts.Offset > 0 {
		if opts.Offset >= len(zones) {
			return []*model.Zone{}, nil
		}
		zones = zones[opts.Offset:]
	}

	// Apply limit
	if opts.Limit > 0 && opts.Limit < len(zones) {
		zones = zones[:opts.Limit]
	}

	return zones, nil
}

// ListZoneSummaries returns zone metadata without copying record contents.
func (m *MemoryBackend) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summaries := make([]*ZoneSummary, 0, len(m.zones))
	for _, zone := range m.zones {
		summaries = append(summaries, &ZoneSummary{
			Name:    zone.Name,
			Version: zone.Version,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return strings.ToLower(summaries[i].Name) < strings.ToLower(summaries[j].Name)
	})

	if opts.Offset > 0 {
		if opts.Offset >= len(summaries) {
			return []*ZoneSummary{}, nil
		}
		summaries = summaries[opts.Offset:]
	}

	if opts.Limit > 0 && opts.Limit < len(summaries) {
		summaries = summaries[:opts.Limit]
	}

	return summaries, nil
}

// CreateZone creates a new zone.
func (m *MemoryBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	writeZone, err := prepareZoneForCreate(zone, model.NormalizeZoneName)
	if err != nil {
		return err
	}
	normalized := writeZone.Name

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.zones[normalized]; exists {
		return model.ErrZoneAlreadyExists
	}

	// Assign IDs to records
	for i := range writeZone.Records {
		m.nextID++
		writeZone.Records[i].ID = strconv.Itoa(m.nextID)
	}

	m.zones[normalized] = copyZone(writeZone)
	copyZoneInto(zone, writeZone)
	return nil
}

// UpdateZone updates an existing zone.
func (m *MemoryBackend) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := model.NormalizeZoneName(zone.Name)
	existing, exists := m.zones[normalized]
	if !exists {
		return model.ErrZoneNotFound
	}

	// Check version for optimistic locking
	if expectedVersion != "" && existing.Version != expectedVersion {
		return model.ErrConflict
	}

	// Normalize zone name in the zone object itself
	zone.Name = normalized

	// Advance from the stored serial. A caller may provide a precomputed
	// greater serial when another component already used it for a prepared artifact.
	zone.SOA.Serial = updateSOASerial(existing.SOA.Serial, zone.SOA.Serial)

	// Update timestamp
	zone.UpdatedAt = time.Now()
	zone.CreatedAt = existing.CreatedAt // Preserve creation time

	// Ensure version changes on update (normally issued by controller).
	if zone.Version == "" || zone.Version == existing.Version {
		newVersion, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = newVersion
	}

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	// Assign IDs to new records
	for i := range zone.Records {
		if zone.Records[i].ID == "" {
			m.nextID++
			zone.Records[i].ID = strconv.Itoa(m.nextID)
		}
	}

	m.zones[normalized] = copyZone(zone)
	return nil
}

// UpdateDNSSECMetadata updates DNSSEC metadata without changing zone version or SOA serial.
func (m *MemoryBackend) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := model.NormalizeZoneName(zoneName)
	zone, exists := m.zones[normalized]
	if !exists {
		return model.ErrZoneNotFound
	}

	zone.DNSSEC = cloneDNSSECConfig(dnssec)
	zone.UpdatedAt = time.Now()
	return nil
}

// DeleteZone removes a zone and all its records.
func (m *MemoryBackend) DeleteZone(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := model.NormalizeZoneName(name)
	if _, exists := m.zones[normalized]; !exists {
		return model.ErrZoneNotFound
	}

	delete(m.zones, normalized)
	return nil
}

// DeleteZoneWithVersion removes a zone only when its current version matches.
func (m *MemoryBackend) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := model.NormalizeZoneName(name)
	zone, exists := m.zones[normalized]
	if !exists {
		return model.ErrZoneNotFound
	}
	if expectedVersion != "" && zone.Version != expectedVersion {
		return model.ErrConflict
	}

	delete(m.zones, normalized)
	return nil
}

// Close releases any resources held by the backend.
func (m *MemoryBackend) Close() error {
	// Nothing to close for in-memory backend
	return nil
}

// Info returns metadata about this backend.
func (m *MemoryBackend) Info() BackendInfo {
	return BackendInfo{
		Type: "memory",
		Capabilities: []string{
			CapabilityZoneStore,
			CapabilityZoneSummaryStore,
			CapabilityHealthStore,
			CapabilityDNSSECMetadataStore,
			CapabilityConditionalDeleteStore,
		},
		Consistency: "strong",
		Description: "In-memory storage (test-only, not registered as runtime backend)",
	}
}

// Helper functions

func copyZone(zone *model.Zone) *model.Zone {
	if zone == nil {
		return nil
	}

	copied := &model.Zone{
		Name:      zone.Name,
		Version:   zone.Version,
		SOA:       zone.SOA,
		Records:   make([]model.Record, len(zone.Records)),
		CreatedAt: zone.CreatedAt,
		UpdatedAt: zone.UpdatedAt,
	}

	copy(copied.Records, zone.Records)
	for i := range copied.Records {
		if zone.Records[i].Priority != nil {
			priority := *zone.Records[i].Priority
			copied.Records[i].Priority = &priority
		}
	}

	if zone.DNSSEC != nil {
		copied.DNSSEC = cloneDNSSECConfig(zone.DNSSEC)
	}

	return copied
}

// generateSerial generates a new serial number based on the current serial.
// Format: YYYYMMDDnn (date-based with counter)
func generateSerial(currentSerial uint32) uint32 {
	now := time.Now()
	today := uint32(now.Year()*10000 + int(now.Month())*100 + now.Day())
	todayFirst := today*100 + 1

	if currentSerial == 0 {
		// First serial for this zone
		return todayFirst
	}

	currentDate := currentSerial / 100
	currentCounter := currentSerial % 100

	if currentDate == today && currentCounter < 99 {
		// Same day, increment counter
		return currentSerial + 1
	}

	if currentDate < today && todayFirst > currentSerial {
		// New day, move to today's first serial while preserving monotonicity.
		return todayFirst
	}

	if currentSerial < math.MaxUint32 {
		// Future serials or exhausted date counters must still move forward.
		return currentSerial + 1
	}

	// No larger uint32 value exists. Avoid moving backwards.
	return currentSerial
}
