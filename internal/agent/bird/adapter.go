package bird

import (
	"context"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/plugin"
)

// Adapter wraps the existing BIRD RouteManager to implement the plugin.RouteController interface.
type Adapter struct {
	rm *RouteManager
}

// NewAdapter creates a new BIRD plugin adapter wrapping the given RouteManager.
func NewAdapter(rm *RouteManager) *Adapter {
	return &Adapter{rm: rm}
}

// AnnounceRoutes enables BGP protocol to announce routes.
func (a *Adapter) AnnounceRoutes(ctx context.Context) error {
	return a.rm.AnnounceRoutes(ctx)
}

// WithdrawRoutes disables BGP protocol to withdraw routes.
func (a *Adapter) WithdrawRoutes(ctx context.Context) error {
	return a.rm.WithdrawRoutes(ctx)
}

// IsAnnounced returns whether routes are currently announced.
func (a *Adapter) IsAnnounced() bool {
	return a.rm.IsAnnounced()
}

// Reconcile syncs the adapter's internal state with BIRD's actual state.
func (a *Adapter) Reconcile(ctx context.Context) error {
	return a.rm.Reconcile(ctx)
}

// GetStatus returns the current BGP protocol status.
func (a *Adapter) GetStatus(ctx context.Context) (string, error) {
	return a.rm.GetStatus(ctx)
}

// LastChangeTime returns the time of the last route change.
func (a *Adapter) LastChangeTime() time.Time {
	return a.rm.LastChangeTime()
}

// Type returns "bird".
func (a *Adapter) Type() string {
	return "bird"
}

// Verify interface compliance at compile time.
var _ plugin.RouteController = (*Adapter)(nil)
