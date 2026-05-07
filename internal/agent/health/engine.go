package health

import (
	"context"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/bird"
	"go.uber.org/zap"
)

// Engine processes health check results and generates signals for the state machine.
type Engine struct {
	checker           *Checker
	failureThreshold  int
	recoveryThreshold int
	logger            *zap.Logger
	consecutiveFails  int
	consecutiveOKs    int
	lastSignalType    string // Track last signal type to detect changes
}

// EngineConfig configures the health engine.
type EngineConfig struct {
	FailureThreshold  int
	RecoveryThreshold int
}

// NewEngine creates a new health engine.
func NewEngine(checker *Checker, config EngineConfig, logger *zap.Logger) *Engine {
	return &Engine{
		checker:           checker,
		failureThreshold:  config.FailureThreshold,
		recoveryThreshold: config.RecoveryThreshold,
		logger:            logger,
	}
}

// Run runs the health engine, processing health check results.
// It sends signals to the signalChan when health status changes.
func (e *Engine) Run(ctx context.Context, signalChan chan<- bird.HealthSignal) error {
	statusChan := make(chan HealthStatus, 1)

	// Start the checker
	go func() { _ = e.checker.Run(ctx, statusChan) }()

	return e.RunWithStatus(ctx, statusChan, signalChan)
}

// RunWithStatus processes health check results from an existing checker loop.
func (e *Engine) RunWithStatus(ctx context.Context, statusChan <-chan HealthStatus, signalChan chan<- bird.HealthSignal) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case status, ok := <-statusChan:
			if !ok {
				return nil // Channel closed
			}
			signal, shouldSend := e.processHealthStatus(status)
			if shouldSend {
				select {
				case signalChan <- signal:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
}

// processHealthStatus analyzes a health check result and generates a signal.
// Returns (signal, shouldSend).
// With threshold=1 (recommended), shouldSend is true for every status change.
// State machine handles multi-failure/recovery thresholds.
func (e *Engine) processHealthStatus(status HealthStatus) (bird.HealthSignal, bool) {
	now := time.Now()

	// Analyze the health check results
	hasHardFailure := false
	hasLatencyIssue := false
	var failureReason string

	for name, check := range status.Checks {
		if !check.Success {
			// Determine if this is a hard failure or just latency
			if name == CheckTypeLatency {
				hasLatencyIssue = true
			} else {
				// query/full_path failures are hard failures (routing decisions are based on DNS behavior)
				hasHardFailure = true
				if check.Error != nil {
					failureReason = check.Error.Error()
				} else {
					failureReason = "Unknown error"
				}
				break
			}
		}
	}

	if !status.Healthy && !hasHardFailure && !hasLatencyIssue {
		hasHardFailure = true
		failureReason = "Health status is unhealthy"
	}

	// Build signal
	signal := bird.HealthSignal{
		ObservedAt: now,
	}

	var currentType string
	shouldSend := false

	if hasHardFailure {
		e.consecutiveFails++
		e.consecutiveOKs = 0
		currentType = "hard_fail"

		// Send signal when threshold is reached (allows state machine to count)
		if e.consecutiveFails >= e.failureThreshold {
			signal.HardFail = true
			signal.Reason = failureReason
			shouldSend = true

			// Log only on first threshold reach
			if e.lastSignalType != currentType {
				e.lastSignalType = currentType
				e.logger.Warn("Hard failure threshold reached",
					zap.Int("consecutive_fails", e.consecutiveFails),
					zap.Int("threshold", e.failureThreshold),
					zap.String("reason", failureReason))
			}
		}
	} else if hasLatencyIssue && !hasHardFailure {
		e.consecutiveFails = 0
		e.consecutiveOKs = 0
		currentType = "latency_degraded"

		// Send latency signal every time (state machine will handle it)
		signal.LatencyDegraded = true
		signal.Reason = "Latency threshold exceeded"
		shouldSend = true

		// Log only on state change
		if e.lastSignalType != currentType {
			e.lastSignalType = currentType
			e.logger.Debug("Latency degradation detected")
		}
	} else {
		// All checks passed
		e.consecutiveFails = 0
		e.consecutiveOKs++
		currentType = "healthy"

		// Send recovery signal when threshold is reached (allows state machine to count)
		if e.consecutiveOKs >= e.recoveryThreshold {
			signal.Reason = "All health checks passed"
			shouldSend = true

			// Log only on first threshold reach
			if e.lastSignalType != currentType {
				e.lastSignalType = currentType
				e.logger.Info("Recovery threshold reached",
					zap.Int("consecutive_oks", e.consecutiveOKs),
					zap.Int("threshold", e.recoveryThreshold))
			}
		}
	}

	return signal, shouldSend
}
