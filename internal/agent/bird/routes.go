package bird

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// RouteManager manages BGP route announcements.
type RouteManager struct {
	client        Client
	protocolNames []string
	mu            sync.Mutex
	announced     bool
	lastChange    time.Time
}

// NewRouteManager creates a new route manager.
// Note: Call Reconcile() after creation to sync with BIRD's actual state.
func NewRouteManager(client Client, protocolNames []string) *RouteManager {
	return &RouteManager{
		client:        client,
		protocolNames: protocolNames,
		announced:     false,
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

func protocolEnabledFromShowProtocols(output string) bool {
	// Heuristic based on BIRD "show protocols <name>" output:
	// disabled protocols usually have "Disabled" in the info column.
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// If any line explicitly mentions Disabled, treat as disabled.
		if containsWord(line, "Disabled") || containsWord(line, "disabled") {
			return false
		}
	}
	// If we didn't see "Disabled", assume enabled (even if session is down).
	return true
}

// Reconcile queries BIRD to sync the manager's state with reality.
// This should be called once during startup to avoid state drift.
func (rm *RouteManager) Reconcile(ctx context.Context) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.protocolNames) == 0 {
		return fmt.Errorf("reconcile: no protocols configured")
	}

	allEnabled := true
	for _, name := range rm.protocolNames {
		cmd := fmt.Sprintf("show protocols %s", name)
		resp, err := rm.client.Exec(ctx, cmd)
		if err != nil {
			return fmt.Errorf("reconcile: show protocols %s: %w", name, err)
		}
		if resp.IsError() {
			return fmt.Errorf("reconcile: BIRD error %d: %s", resp.Code, resp.RawText)
		}
		if !protocolEnabledFromShowProtocols(resp.RawText) {
			allEnabled = false
		}
	}

	rm.announced = allEnabled
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

	for _, name := range rm.protocolNames {
		cmd := fmt.Sprintf("enable %s", name)
		resp, err := rm.client.Exec(ctx, cmd)
		if err != nil {
			return fmt.Errorf("enable protocol %s: %w", name, err)
		}
		if resp.IsError() {
			return fmt.Errorf("BIRD error enabling %s (%d): %s", name, resp.Code, resp.RawText)
		}
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

	for _, name := range rm.protocolNames {
		cmd := fmt.Sprintf("disable %s", name)
		resp, err := rm.client.Exec(ctx, cmd)
		if err != nil {
			return fmt.Errorf("disable protocol %s: %w", name, err)
		}
		if resp.IsError() {
			return fmt.Errorf("BIRD error disabling %s (%d): %s", name, resp.Code, resp.RawText)
		}
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
	var out []string
	for _, name := range rm.protocolNames {
		cmd := fmt.Sprintf("show protocols %s", name)
		resp, err := rm.client.Exec(ctx, cmd)
		if err != nil {
			return "", fmt.Errorf("show protocols %s: %w", name, err)
		}
		if resp.IsError() {
			return "", fmt.Errorf("BIRD error %s (%d): %s", name, resp.Code, resp.RawText)
		}
		out = append(out, resp.RawText)
	}
	return strings.Join(out, "\n"), nil
}
