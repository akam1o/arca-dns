package unbound

import (
	"context"

	"github.com/akam1o/arca-dns/internal/agent/plugin"
)

// Adapter wraps the existing Unbound Controller to implement the plugin.Resolver interface.
type Adapter struct {
	ctrl *Controller
}

// NewAdapter creates a new Unbound plugin adapter.
func NewAdapter(ctrl *Controller) *Adapter {
	return &Adapter{ctrl: ctrl}
}

// Reload reloads Unbound configuration.
func (a *Adapter) Reload(ctx context.Context) error {
	return a.ctrl.Reload()
}

// CheckConfig validates Unbound configuration.
func (a *Adapter) CheckConfig(ctx context.Context) error {
	return a.ctrl.CheckConfig()
}

// FlushZone flushes a specific zone from Unbound's cache.
func (a *Adapter) FlushZone(ctx context.Context, zoneName string) error {
	return a.ctrl.FlushZone(zoneName)
}

// UpdateStubZone updates the stub-zone configuration for a zone.
func (a *Adapter) UpdateStubZone(ctx context.Context, zoneName string) error {
	return a.ctrl.UpdateStubZoneConfig(zoneName)
}

// DeleteStubZone removes generated stub-zone configuration for a zone.
func (a *Adapter) DeleteStubZone(ctx context.Context, zoneName string) error {
	return a.ctrl.DeleteStubZoneConfig(zoneName)
}

// Status returns the Unbound server status.
func (a *Adapter) Status(ctx context.Context) (plugin.ServerStatus, error) {
	statusText, err := a.ctrl.Status()
	if err != nil {
		return plugin.ServerStatus{}, err
	}
	return plugin.ServerStatus{
		Running:    a.ctrl.IsRunning(),
		StatusText: statusText,
	}, nil
}

// Type returns "unbound".
func (a *Adapter) Type() string {
	return "unbound"
}

// Verify interface compliance at compile time.
var _ plugin.Resolver = (*Adapter)(nil)
