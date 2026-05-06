package bird

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthState represents the health state of the DNS service.
type HealthState string

const (
	StateHealthy    HealthState = "Healthy"
	StateDegraded   HealthState = "Degraded"
	StateUnhealthy  HealthState = "Unhealthy"
	StateRecovering HealthState = "Recovering"
)

// HealthSignal represents a health check signal from the engine.
type HealthSignal struct {
	HardFail        bool
	LatencyDegraded bool
	Reason          string
	ObservedAt      time.Time
}

// StateMachineConfig configures the state machine.
type StateMachineConfig struct {
	FailureThreshold  int           // Consecutive failures before marking unhealthy
	RecoveryThreshold int           // Consecutive successes before marking healthy
	MinStateDuration  time.Duration // Minimum time between route changes (debounce)
}

// StateMachine manages health state transitions and route decisions.
type StateMachine struct {
	config           StateMachineConfig
	logger           *zap.Logger
	mu               sync.Mutex
	state            HealthState
	consecutiveFails int
	consecutiveOKs   int
	lastTransition   time.Time
	lastRouteChange  time.Time
}

// NewStateMachine creates a new state machine.
func NewStateMachine(config StateMachineConfig, logger *zap.Logger) *StateMachine {
	if logger == nil {
		panic("logger cannot be nil")
	}

	if err := ValidateStateMachineConfig(config); err != nil {
		panic(fmt.Sprintf("invalid state machine config: %v", err))
	}

	return &StateMachine{
		config:          config,
		logger:          logger,
		state:           StateHealthy,
		lastTransition:  time.Now(),
		lastRouteChange: time.Time{}, // Zero time means no route change yet
	}
}

// ProcessSignal processes a health signal and returns the required route action.
// Returns: shouldAnnounce bool, shouldWithdraw bool
func (sm *StateMachine) ProcessSignal(signal HealthSignal) (shouldAnnounce, shouldWithdraw bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	oldState := sm.state

	if signal.HardFail {
		sm.consecutiveFails++
		sm.consecutiveOKs = 0
		sm.handleHardFailure(signal)
	} else if signal.LatencyDegraded {
		sm.consecutiveFails = 0
		sm.consecutiveOKs = 0
		sm.handleLatencyDegradation(signal)
	} else {
		// Success
		sm.consecutiveFails = 0
		sm.consecutiveOKs++
		sm.handleSuccess(signal)
	}

	newState := sm.state

	// Log state transition
	if oldState != newState {
		sm.logger.Info("Health state transition",
			zap.String("from", string(oldState)),
			zap.String("to", string(newState)),
			zap.String("reason", signal.Reason))
		sm.lastTransition = time.Now()
	}

	if signal.HardFail && (sm.state == StateHealthy || sm.state == StateDegraded) {
		return false, false
	}

	// Determine route action with debounce
	shouldAnnounce, shouldWithdraw = sm.determineRouteAction()

	return shouldAnnounce, shouldWithdraw
}

// handleHardFailure handles a hard failure signal.
func (sm *StateMachine) handleHardFailure(signal HealthSignal) {
	switch sm.state {
	case StateHealthy, StateDegraded:
		if sm.consecutiveFails >= sm.config.FailureThreshold {
			sm.state = StateUnhealthy
		}
	case StateRecovering:
		// Back to unhealthy on any hard failure during recovery
		sm.state = StateUnhealthy
	case StateUnhealthy:
		// Stay unhealthy
	}
}

// handleLatencyDegradation handles latency-only degradation.
func (sm *StateMachine) handleLatencyDegradation(signal HealthSignal) {
	switch sm.state {
	case StateHealthy:
		sm.state = StateDegraded
		sm.logger.Warn("Latency degraded but service functional",
			zap.String("reason", signal.Reason))
	case StateDegraded:
		// Stay degraded
	case StateRecovering, StateUnhealthy:
		// Latency issues during recovery/unhealthy don't change state
	}
}

// handleSuccess handles a success signal.
func (sm *StateMachine) handleSuccess(signal HealthSignal) {
	switch sm.state {
	case StateDegraded:
		// Latency recovered, back to healthy
		sm.state = StateHealthy
	case StateUnhealthy:
		// First success after failure, move to recovering
		if sm.consecutiveOKs >= 1 {
			sm.state = StateRecovering
		}
	case StateRecovering:
		// Need consecutive successes to be healthy
		if sm.consecutiveOKs >= sm.config.RecoveryThreshold {
			sm.state = StateHealthy
		}
	case StateHealthy:
		// Stay healthy
	}
}

// determineRouteAction determines if routes should be announced or withdrawn.
// Respects MinStateDuration for debouncing.
func (sm *StateMachine) determineRouteAction() (shouldAnnounce, shouldWithdraw bool) {
	// Check debounce
	if !sm.lastRouteChange.IsZero() {
		timeSinceChange := time.Since(sm.lastRouteChange)
		if timeSinceChange < sm.config.MinStateDuration {
			// Too soon to change routes again
			return false, false
		}
	}

	switch sm.state {
	case StateHealthy, StateDegraded:
		// Announce routes
		return true, false
	case StateUnhealthy, StateRecovering:
		// Withdraw routes
		return false, true
	default:
		return false, false
	}
}

// MarkRouteChanged updates the last route change timestamp.
// Call this after successfully announcing or withdrawing routes.
func (sm *StateMachine) MarkRouteChanged() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.lastRouteChange = time.Now()
}

// GetState returns the current state.
func (sm *StateMachine) GetState() HealthState {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state
}

// GetStats returns statistics about the state machine.
func (sm *StateMachine) GetStats() map[string]interface{} {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	return map[string]interface{}{
		"state":             string(sm.state),
		"consecutive_fails": sm.consecutiveFails,
		"consecutive_oks":   sm.consecutiveOKs,
		"last_transition":   sm.lastTransition,
		"last_route_change": sm.lastRouteChange,
		"time_since_change": time.Since(sm.lastRouteChange),
	}
}

// String implements fmt.Stringer for HealthState.
func (hs HealthState) String() string {
	return string(hs)
}

// Validate validates the state machine configuration.
func (c StateMachineConfig) Validate() error {
	if c.FailureThreshold < 1 {
		return fmt.Errorf("failure_threshold must be >= 1, got %d", c.FailureThreshold)
	}
	if c.RecoveryThreshold < 1 {
		return fmt.Errorf("recovery_threshold must be >= 1, got %d", c.RecoveryThreshold)
	}
	if c.MinStateDuration < 0 {
		return fmt.Errorf("min_state_duration must be >= 0, got %v", c.MinStateDuration)
	}
	return nil
}

// ValidateStateMachineConfig validates the state machine configuration.
func ValidateStateMachineConfig(c StateMachineConfig) error {
	return c.Validate()
}
