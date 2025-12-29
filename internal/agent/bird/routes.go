package bird

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RouteManager manages BGP route announcements.
type RouteManager struct {
	client       Client
	protocolName string
	mu           sync.Mutex
	announced    bool
	lastChange   time.Time
}

// NewRouteManager creates a new route manager.
// Note: Call Reconcile() after creation to sync with BIRD's actual state.
func NewRouteManager(client Client, protocolName string) *RouteManager {
	return &RouteManager{
		client:       client,
		protocolName: protocolName,
		announced:    false,
	}
}

// containsWord checks if a string contains a word (space-separated).
func containsWord(s, word string) bool {
	// Simple implementation: check if word appears as substring
	// surrounded by spaces or at start/end of string
	for i := 0; i < len(s); i++ {
		if i+len(word) > len(s) {
			break
		}
		if s[i:i+len(word)] == word {
			// Check boundaries
			beforeOK := i == 0 || s[i-1] == ' ' || s[i-1] == '\t'
			afterOK := i+len(word) == len(s) || s[i+len(word)] == ' ' || s[i+len(word)] == '\t'
			if beforeOK && afterOK {
				return true
			}
		}
	}
	return false
}

// Reconcile queries BIRD to sync the manager's state with reality.
// This should be called once during startup to avoid state drift.
func (rm *RouteManager) Reconcile(ctx context.Context) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	cmd := fmt.Sprintf("show protocols %s", rm.protocolName)
	resp, err := rm.client.Exec(ctx, cmd)
	if err != nil {
		return fmt.Errorf("reconcile: show protocols: %w", err)
	}

	if resp.IsError() {
		return fmt.Errorf("reconcile: BIRD error %d: %s", resp.Code, resp.RawText)
	}

	// Parse the protocol status from response
	// BIRD protocol status line format: "protocol_name proto table state since info"
	// We're looking for "up" state which means the protocol is enabled
	isUp := false
	for _, line := range resp.Lines {
		if len(line) > 0 {
			// Simple heuristic: if the status line contains "up", protocol is enabled
			// More robust parsing would be better, but this is sufficient for reconciliation
			if containsWord(line, "up") {
				isUp = true
				break
			}
		}
	}

	rm.announced = isUp
	return nil
}

// AnnounceRoutes enables the BGP protocol to announce routes.
// This is idempotent - calling multiple times has no additional effect.
func (rm *RouteManager) AnnounceRoutes(ctx context.Context) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.announced {
		// Already announced, no-op
		return nil
	}

	cmd := fmt.Sprintf("enable %s", rm.protocolName)
	resp, err := rm.client.Exec(ctx, cmd)
	if err != nil {
		return fmt.Errorf("enable protocol: %w", err)
	}

	if resp.IsError() {
		return fmt.Errorf("BIRD error %d: %s", resp.Code, resp.RawText)
	}

	rm.announced = true
	rm.lastChange = time.Now()
	return nil
}

// WithdrawRoutes disables the BGP protocol to withdraw routes.
// This is idempotent - calling multiple times has no additional effect.
func (rm *RouteManager) WithdrawRoutes(ctx context.Context) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.announced {
		// Already withdrawn, no-op
		return nil
	}

	cmd := fmt.Sprintf("disable %s", rm.protocolName)
	resp, err := rm.client.Exec(ctx, cmd)
	if err != nil {
		return fmt.Errorf("disable protocol: %w", err)
	}

	if resp.IsError() {
		return fmt.Errorf("BIRD error %d: %s", resp.Code, resp.RawText)
	}

	rm.announced = false
	rm.lastChange = time.Now()
	return nil
}

// IsAnnounced returns whether routes are currently announced.
func (rm *RouteManager) IsAnnounced() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.announced
}

// LastChangeTime returns the time of the last route change.
func (rm *RouteManager) LastChangeTime() time.Time {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.lastChange
}

// GetStatus queries BIRD for the current protocol status.
func (rm *RouteManager) GetStatus(ctx context.Context) (string, error) {
	cmd := fmt.Sprintf("show protocols %s", rm.protocolName)
	resp, err := rm.client.Exec(ctx, cmd)
	if err != nil {
		return "", fmt.Errorf("show protocols: %w", err)
	}

	if resp.IsError() {
		return "", fmt.Errorf("BIRD error %d: %s", resp.Code, resp.RawText)
	}

	return resp.RawText, nil
}
