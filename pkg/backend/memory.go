package backend

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

// MemoryBackend is an in-memory implementation of ZoneStore.
// It is thread-safe and suitable for testing and development.
type MemoryBackend struct {
	mu     sync.RWMutex
	zones  map[string]*model.Zone
	nextID int
}

// NewMemoryBackend creates a new in-memory backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		zones: make(map[string]*model.Zone),
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

// CreateZone creates a new zone.
func (m *MemoryBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := model.NormalizeZoneName(zone.Name)
	if _, exists := m.zones[normalized]; exists {
		return model.ErrZoneAlreadyExists
	}

	// Normalize zone name in the zone object itself
	zone.Name = normalized

	// Set timestamps
	now := time.Now()
	zone.CreatedAt = now
	zone.UpdatedAt = now

	// Auto-generate serial if not set
	if zone.SOA.Serial == 0 {
		zone.SOA.Serial = generateSerial(0)
	}

	// Generate version if not set
	if zone.Version == "" {
		zone.Version = generateVersion(zone)
	}

	// Assign IDs to records
	for i := range zone.Records {
		m.nextID++
		zone.Records[i].ID = strconv.Itoa(m.nextID)
	}

	m.zones[normalized] = copyZone(zone)
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

	// Auto-increment serial
	zone.SOA.Serial = generateSerial(existing.SOA.Serial)

	// Update timestamp
	zone.UpdatedAt = time.Now()
	zone.CreatedAt = existing.CreatedAt // Preserve creation time

	// Generate new version
	zone.Version = generateVersion(zone)

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

// Close releases any resources held by the backend.
func (m *MemoryBackend) Close() error {
	// Nothing to close for in-memory backend
	return nil
}

// Info returns metadata about this backend.
func (m *MemoryBackend) Info() BackendInfo {
	return BackendInfo{
		Type:         "memory",
		Capabilities: []string{"ZoneStore"},
		Consistency:  "strong",
		Description:  "In-memory storage (non-persistent, for testing and development)",
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

	if zone.DNSSEC != nil {
		dnssec := *zone.DNSSEC
		copied.DNSSEC = &dnssec
	}

	return copied
}

// generateSerial generates a new serial number based on the current serial.
// Format: YYYYMMDDnn (date-based with counter)
func generateSerial(currentSerial uint32) uint32 {
	now := time.Now()
	today := uint32(now.Year()*10000 + int(now.Month())*100 + now.Day())

	if currentSerial == 0 {
		// First serial for this zone
		return today*100 + 1
	}

	currentDate := currentSerial / 100
	currentCounter := currentSerial % 100

	if currentDate == today && currentCounter < 99 {
		// Same day, increment counter
		return currentSerial + 1
	}

	// New day or counter maxed out, reset to today01
	return today*100 + 1
}

// generateVersion generates a version identifier using the canonical version computation.
// This ensures memory backend uses the same version semantics as other backends.
func generateVersion(zone *model.Zone) string {
	version, err := ComputeZoneVersion(zone)
	if err != nil {
		// Fallback to simple version if computation fails (should never happen)
		return fmt.Sprintf("v%d-error", zone.SOA.Serial)
	}
	return version
}

// memoryBackendFactory is the factory function for memory backend.
func memoryBackendFactory(config map[string]interface{}) (ZoneStore, error) {
	return NewMemoryBackend(), nil
}

func init() {
	// Register the memory backend
	RegisterBackend("memory", memoryBackendFactory)
}
