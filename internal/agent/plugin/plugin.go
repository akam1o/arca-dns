// Package plugin defines interfaces for pluggable agent components.
//
// This allows swapping implementations of authoritative DNS servers (NSD, Knot DNS),
// resolvers (Unbound), and route controllers (BIRD, FRRouting) without changing
// the agent's core orchestration logic.
package plugin

import (
	"context"
	"fmt"
	"time"
)

// AuthoritativeServer is the interface for authoritative DNS server plugins.
// Implementations: NSD ("nsd"), Knot DNS ("knot").
type AuthoritativeServer interface {
	// EnsureZone ensures the server configuration includes the zone before reload.
	EnsureZone(ctx context.Context, zoneName string) error

	// ReloadZone reloads a specific zone from its zone file.
	ReloadZone(ctx context.Context, zoneName string) error

	// CheckZone validates a zone file before loading it.
	CheckZone(ctx context.Context, zoneName string, zoneFile string) error

	// DeleteZone removes the zone from the server configuration.
	DeleteZone(ctx context.Context, zoneName string) error

	// Reload reloads all zones.
	Reload(ctx context.Context) error

	// Status returns the server's current status.
	Status(ctx context.Context) (ServerStatus, error)

	// Type returns the plugin type name (e.g., "nsd", "knot").
	Type() string
}

// Resolver is the interface for recursive DNS resolver plugins.
// Implementations: Unbound ("unbound").
type Resolver interface {
	// Reload reloads the resolver configuration.
	Reload(ctx context.Context) error

	// CheckConfig validates the resolver configuration.
	CheckConfig(ctx context.Context) error

	// FlushZone flushes a specific zone from the resolver's cache.
	FlushZone(ctx context.Context, zoneName string) error

	// UpdateStubZone updates the stub-zone configuration for a zone
	// so the resolver forwards queries to the local authoritative server.
	UpdateStubZone(ctx context.Context, zoneName string) error

	// DeleteStubZone removes generated stub-zone configuration for a zone.
	DeleteStubZone(ctx context.Context, zoneName string) error

	// Status returns the resolver's current status.
	Status(ctx context.Context) (ServerStatus, error)

	// Type returns the plugin type name (e.g., "unbound").
	Type() string
}

// RouteController is the interface for BGP route control plugins.
// Implementations: BIRD ("bird"), FRRouting ("frr").
type RouteController interface {
	// AnnounceRoutes enables BGP route announcements.
	AnnounceRoutes(ctx context.Context) error

	// WithdrawRoutes disables BGP route announcements.
	WithdrawRoutes(ctx context.Context) error

	// IsAnnounced returns whether routes are currently announced.
	IsAnnounced() bool

	// Reconcile syncs the controller's internal state with the actual BGP daemon state.
	Reconcile(ctx context.Context) error

	// GetStatus returns the current BGP protocol status.
	GetStatus(ctx context.Context) (string, error)

	// LastChangeTime returns the time of the last route change.
	LastChangeTime() time.Time

	// Type returns the plugin type name (e.g., "bird", "frr").
	Type() string
}

// ServerStatus represents the status of a DNS server or service.
type ServerStatus struct {
	// Running indicates whether the server process is running.
	Running bool

	// StatusText is a human-readable status string.
	StatusText string
}

// NoopAuthoritativeServer is a no-op implementation used when the authoritative server is disabled.
type NoopAuthoritativeServer struct{}

func (n *NoopAuthoritativeServer) EnsureZone(_ context.Context, _ string) error   { return nil }
func (n *NoopAuthoritativeServer) ReloadZone(_ context.Context, _ string) error   { return nil }
func (n *NoopAuthoritativeServer) CheckZone(_ context.Context, _, _ string) error { return nil }
func (n *NoopAuthoritativeServer) DeleteZone(_ context.Context, _ string) error   { return nil }
func (n *NoopAuthoritativeServer) Reload(_ context.Context) error                 { return nil }
func (n *NoopAuthoritativeServer) Status(_ context.Context) (ServerStatus, error) {
	return ServerStatus{StatusText: "disabled"}, nil
}
func (n *NoopAuthoritativeServer) Type() string { return "noop" }

// NoopResolver is a no-op implementation used when the resolver is disabled.
type NoopResolver struct{}

func (n *NoopResolver) Reload(_ context.Context) error                   { return nil }
func (n *NoopResolver) CheckConfig(_ context.Context) error              { return nil }
func (n *NoopResolver) FlushZone(_ context.Context, _ string) error      { return nil }
func (n *NoopResolver) UpdateStubZone(_ context.Context, _ string) error { return nil }
func (n *NoopResolver) DeleteStubZone(_ context.Context, _ string) error { return nil }
func (n *NoopResolver) Status(_ context.Context) (ServerStatus, error) {
	return ServerStatus{StatusText: "disabled"}, nil
}
func (n *NoopResolver) Type() string { return "noop" }

// NewAuthoritativeServer creates an AuthoritativeServer by type name.
// Callers must register implementations via RegisterAuthoritativeServer.
func NewAuthoritativeServer(typeName string, constructor interface{}) (AuthoritativeServer, error) {
	return nil, fmt.Errorf("use RegisterAuthoritativeServer to register implementations")
}
