package backend

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/akam1o/arca-dns/pkg/model"
)

// ZoneStore is the core interface that all backends must implement.
// It provides basic CRUD operations for DNS zones.
//
// Semantic Contracts:
// - All operations are atomic at the zone level
// - Zone names are case-insensitive (stored lowercase)
// - GetZone returns ErrZoneNotFound if zone doesn't exist
// - CreateZone returns ErrZoneAlreadyExists if zone exists
// - UpdateZone returns ErrZoneNotFound if zone doesn't exist
// - DeleteZone returns ErrZoneNotFound if zone doesn't exist
// - ListZones returns empty slice if no zones exist (never nil)
type ZoneStore interface {
	// GetZone retrieves a zone by name.
	// Returns model.ErrZoneNotFound if the zone does not exist.
	GetZone(ctx context.Context, name string) (*model.Zone, error)

	// ListZones returns all zones, optionally paginated.
	// If limit is 0, all zones are returned.
	// If offset is provided, skips that many zones.
	ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error)

	// CreateZone creates a new zone.
	// Returns model.ErrZoneAlreadyExists if a zone with the same name exists.
	// The zone's CreatedAt and UpdatedAt timestamps are set automatically.
	// If zone.SOA.Serial is 0, it will be auto-generated.
	CreateZone(ctx context.Context, zone *model.Zone) error

	// UpdateZone updates an existing zone.
	// Returns model.ErrZoneNotFound if the zone does not exist.
	// Returns model.ErrConflict if expectedVersion is provided and doesn't match.
	// The zone's UpdatedAt timestamp is updated automatically.
	// The SOA serial is auto-incremented.
	UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error

	// DeleteZone removes a zone and all its records.
	// Returns model.ErrZoneNotFound if the zone does not exist.
	// This operation is irreversible (unless RevisionStore is also implemented).
	DeleteZone(ctx context.Context, name string) error

	// Close releases any resources held by the backend.
	Close() error
}

// ZoneSummary is the lightweight representation used by controllers and
// agents when record contents are not needed.
type ZoneSummary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ZoneSummaryStore is an optional capability for backends that can list zone
// metadata without loading full zone records.
type ZoneSummaryStore interface {
	ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error)
}

// HealthStore is an optional capability for backends that can perform a cheap
// readiness check without loading zone contents.
type HealthStore interface {
	HealthCheck(ctx context.Context) error
}

// ListZoneSummaries returns lightweight zone metadata, using an optimized
// backend projection when available and falling back to ListZones otherwise.
func ListZoneSummaries(ctx context.Context, store ZoneStore, opts ListOptions) ([]*ZoneSummary, error) {
	if summaryStore, ok := store.(ZoneSummaryStore); ok {
		return summaryStore.ListZoneSummaries(ctx, opts)
	}

	zones, err := store.ListZones(ctx, opts)
	if err != nil {
		return nil, err
	}

	summaries := make([]*ZoneSummary, 0, len(zones))
	for _, zone := range zones {
		summaries = append(summaries, &ZoneSummary{
			Name:    zone.Name,
			Version: zone.Version,
		})
	}
	return summaries, nil
}

// CheckHealth verifies that the backend is reachable. Backends with a cheap
// health probe should implement HealthStore; the fallback preserves existing
// behavior for custom stores.
func CheckHealth(ctx context.Context, store ZoneStore) error {
	if healthStore, ok := store.(HealthStore); ok {
		return healthStore.HealthCheck(ctx)
	}

	_, err := ListZoneSummaries(ctx, store, ListOptions{Limit: 1, Offset: 0})
	return err
}

// DNSSECMetadataStore is an optional capability for backends that can update
// DNSSEC operational metadata without changing zone content version or SOA
// serial. This is used after signing so schedulers can identify signed zones.
type DNSSECMetadataStore interface {
	UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error
}

// ConditionalDeleteStore is an optional capability for backends that can delete
// a zone only when its current version matches an expected version.
type ConditionalDeleteStore interface {
	DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error
}

// RevisionStore is an optional capability for backends that support
// versioning and history (e.g., Git, etcd).
//
// Semantic Contracts:
// - Versions are immutable once created
// - GetRevision returns ErrVersionNotFound if version doesn't exist
// - ListRevisions returns versions in reverse chronological order
type RevisionStore interface {
	// GetRevision retrieves a specific version of a zone.
	// Returns model.ErrVersionNotFound if the version does not exist.
	GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error)

	// ListRevisions returns all versions of a zone.
	// Versions are returned in reverse chronological order (newest first).
	ListRevisions(ctx context.Context, zoneName string, opts ListOptions) ([]*model.ZoneVersion, error)

	// GetCurrentVersion returns the current version identifier for a zone.
	GetCurrentVersion(ctx context.Context, zoneName string) (string, error)
}

// WatchableStore is an optional capability for backends that support
// real-time change notifications (e.g., etcd).
//
// Semantic Contracts:
// - Watch starts from the current state (no historical events)
// - Events are delivered in order
// - Channel is closed when context is cancelled or on error
// - Multiple watchers can coexist independently
type WatchableStore interface {
	// Watch returns a channel that receives zone change events.
	// The channel is closed when the context is cancelled or an error occurs.
	// If zoneName is empty, watches all zones; otherwise watches only the specified zone.
	Watch(ctx context.Context, zoneName string) (<-chan ZoneEvent, error)
}

// TransactionalStore is an optional capability for backends that support
// transactions (e.g., MySQL, PostgreSQL).
//
// Semantic Contracts:
// - Transactions provide ACID guarantees
// - Commit/Rollback must be called explicitly
// - Operations within a transaction see uncommitted changes
// - Nested transactions are not supported
type TransactionalStore interface {
	// BeginTx starts a new transaction.
	// The returned Tx must be committed or rolled back.
	BeginTx(ctx context.Context) (Tx, error)
}

// Tx represents a database transaction.
type Tx interface {
	ZoneStore

	// Commit commits the transaction.
	// After calling Commit, the Tx is no longer usable.
	Commit(ctx context.Context) error

	// Rollback aborts the transaction.
	// After calling Rollback, the Tx is no longer usable.
	Rollback(ctx context.Context) error
}

// ListOptions configures list operations (pagination, filtering).
type ListOptions struct {
	// Limit is the maximum number of items to return (0 = no limit).
	Limit int

	// Offset is the number of items to skip.
	Offset int

	// Filter is an optional filter expression (backend-specific).
	Filter string
}

// ZoneEvent represents a zone change event from a WatchableStore.
type ZoneEvent struct {
	// Type is the event type (created, updated, deleted).
	Type EventType

	// ZoneName is the name of the affected zone.
	ZoneName string

	// Version is the new version identifier (empty for delete events).
	Version string

	// Zone is the updated zone data (nil for delete events).
	Zone *model.Zone
}

// EventType represents the type of zone change event.
type EventType string

const (
	EventTypeCreated EventType = "created"
	EventTypeUpdated EventType = "updated"
	EventTypeDeleted EventType = "deleted"
)

// BackendInfo provides metadata about a backend implementation.
type BackendInfo struct {
	// Type is the backend type (sqlite, postgres, mysql, git, etcd).
	Type string

	// Capabilities lists the optional interfaces this backend implements.
	Capabilities []string

	// Consistency describes the consistency model (strong, eventual).
	Consistency string

	// Description is a human-readable description.
	Description string
}

// Backend is the complete interface that backends can optionally implement
// to provide metadata about their capabilities.
type Backend interface {
	ZoneStore

	// Info returns metadata about this backend.
	Info() BackendInfo
}

// Factory is a function that creates a backend from configuration.
type Factory func(config map[string]interface{}) (ZoneStore, error)

// Backend factory registry with thread-safety
var (
	backendFactories   = make(map[string]Factory)
	backendFactoriesMu sync.RWMutex
)

// RegisterBackend registers a backend factory for a given type.
// It panics if the backend type is already registered, empty, or if factory is nil.
// This is intentional to catch configuration errors during initialization.
func RegisterBackend(backendType string, factory Factory) {
	backendFactoriesMu.Lock()
	defer backendFactoriesMu.Unlock()

	if backendType == "" {
		panic("backend type cannot be empty")
	}

	if factory == nil {
		panic("factory function cannot be nil")
	}

	if _, exists := backendFactories[backendType]; exists {
		panic(fmt.Sprintf("backend type %q is already registered", backendType))
	}

	backendFactories[backendType] = factory
}

// NewBackend creates a backend instance from configuration.
func NewBackend(backendType string, config map[string]interface{}) (ZoneStore, error) {
	backendFactoriesMu.RLock()
	factory, ok := backendFactories[backendType]
	backendFactoriesMu.RUnlock()

	if !ok {
		return nil, model.NewAPIError(model.ErrorCodeInvalidInput, "unknown backend type: "+backendType)
	}
	return factory(config)
}

// GetRegisteredBackends returns a sorted list of registered backend types.
func GetRegisteredBackends() []string {
	backendFactoriesMu.RLock()
	defer backendFactoriesMu.RUnlock()

	types := make([]string, 0, len(backendFactories))
	for t := range backendFactories {
		types = append(types, t)
	}

	// Sort for deterministic output
	sort.Strings(types)
	return types
}
