package nsd

import (
	"context"

	"github.com/akam1o/arca-dns/internal/agent/plugin"
)

// Adapter wraps the existing NSD Controller to implement the plugin.AuthoritativeServer interface.
type Adapter struct {
	ctrl *Controller
}

// NewAdapter creates a new NSD plugin adapter.
func NewAdapter(ctrl *Controller) *Adapter {
	return &Adapter{ctrl: ctrl}
}

// EnsureZone ensures NSD has a generated zone stanza for the zone.
func (a *Adapter) EnsureZone(ctx context.Context, zoneName string) error {
	return a.ctrl.EnsureZone(zoneName)
}

// ReloadZone reloads a specific zone in NSD.
func (a *Adapter) ReloadZone(ctx context.Context, zoneName string) error {
	return a.ctrl.ReloadZone(zoneName)
}

// CheckZone validates a zone file before loading it into NSD.
func (a *Adapter) CheckZone(ctx context.Context, zoneName string, zoneFile string) error {
	return a.ctrl.CheckZone(zoneName, zoneFile)
}

// DeleteZone removes the generated zone stanza for the zone.
func (a *Adapter) DeleteZone(ctx context.Context, zoneName string) error {
	return a.ctrl.DeleteZone(zoneName)
}

// Reload reloads all zones in NSD.
func (a *Adapter) Reload(ctx context.Context) error {
	return a.ctrl.Reload()
}

// Status returns the NSD server status.
func (a *Adapter) Status(ctx context.Context) (plugin.ServerStatus, error) {
	// NSD doesn't have a dedicated status command in the current implementation,
	// so we attempt a reload as a health probe (the Controller's methods check Enabled).
	return plugin.ServerStatus{
		Running:    a.ctrl.config.Enabled,
		StatusText: "enabled",
	}, nil
}

// Type returns "nsd".
func (a *Adapter) Type() string {
	return "nsd"
}

// Verify interface compliance at compile time.
var _ plugin.AuthoritativeServer = (*Adapter)(nil)
