package bird

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// ControlLoop manages the BGP control loop, connecting health checks to route management.
type ControlLoop struct {
	stateMachine *StateMachine
	routeManager *RouteManager
	logger       *zap.Logger
}

// NewControlLoop creates a new control loop.
func NewControlLoop(
	stateMachine *StateMachine,
	routeManager *RouteManager,
	logger *zap.Logger,
) *ControlLoop {
	return &ControlLoop{
		stateMachine: stateMachine,
		routeManager: routeManager,
		logger:       logger,
	}
}

// Run runs the control loop, processing health signals and managing routes.
// The signalChan should receive HealthSignal from the health engine.
func (cl *ControlLoop) Run(ctx context.Context, signalChan <-chan HealthSignal) error {
	cl.logger.Info("BGP control loop starting")

	// Initial state logging
	cl.logger.Info("Initial state",
		zap.String("state", string(cl.stateMachine.GetState())),
		zap.Bool("routes_announced", cl.routeManager.IsAnnounced()))

	for {
		select {
		case <-ctx.Done():
			cl.logger.Info("BGP control loop stopping")
			// Graceful shutdown: withdraw routes before exit
			if cl.routeManager.IsAnnounced() {
				cl.logger.Info("Withdrawing routes for graceful shutdown")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := cl.routeManager.WithdrawRoutes(shutdownCtx); err != nil {
					cl.logger.Error("Failed to withdraw routes on shutdown", zap.Error(err))
				} else {
					cl.logger.Info("Routes withdrawn successfully")
				}
				cancel()
			}
			return ctx.Err()

		case signal, ok := <-signalChan:
			if !ok {
				cl.logger.Info("Signal channel closed, stopping control loop")
				return nil
			}
			cl.processSignal(ctx, signal)
		}
	}
}

// processSignal processes a health signal and takes appropriate route action.
func (cl *ControlLoop) processSignal(ctx context.Context, signal HealthSignal) {
	// Process signal through state machine
	shouldAnnounce, shouldWithdraw := cl.stateMachine.ProcessSignal(signal)

	// Execute route action if needed
	if shouldAnnounce {
		if err := cl.routeManager.AnnounceRoutes(ctx); err != nil {
			cl.logger.Error("Failed to announce routes",
				zap.Error(err),
				zap.String("state", string(cl.stateMachine.GetState())))
		} else {
			cl.logger.Info("Routes announced",
				zap.String("state", string(cl.stateMachine.GetState())),
				zap.String("reason", signal.Reason))
			cl.stateMachine.MarkRouteChanged()
		}
	}

	if shouldWithdraw {
		if err := cl.routeManager.WithdrawRoutes(ctx); err != nil {
			cl.logger.Error("Failed to withdraw routes",
				zap.Error(err),
				zap.String("state", string(cl.stateMachine.GetState())))
		} else {
			cl.logger.Info("Routes withdrawn",
				zap.String("state", string(cl.stateMachine.GetState())),
				zap.String("reason", signal.Reason))
			cl.stateMachine.MarkRouteChanged()
		}
	}

	// Log current status
	if shouldAnnounce || shouldWithdraw {
		stats := cl.stateMachine.GetStats()
		cl.logger.Debug("State machine stats", zap.Any("stats", stats))
	}
}
