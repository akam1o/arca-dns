package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/bird"
	"github.com/akam1o/arca-dns/internal/agent/health"
	"github.com/akam1o/arca-dns/internal/agent/nsd"
	zonesync "github.com/akam1o/arca-dns/internal/agent/sync"
	"github.com/akam1o/arca-dns/internal/agent/unbound"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	configFile string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "arca-dns-agent",
		Short: "arca-dns Agent - Data plane agent for BGP Anycast DNS",
		Long: `arca-dns-agent is the data plane component that syncs zones from the controller,
manages NSD/Unbound, controls BGP routes via BIRD, and provides observability.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	daemonCmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the agent daemon",
		Long:  "Run the agent daemon to sync zones and manage DNS services",
		RunE:  runDaemon,
	}

	daemonCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file (optional, uses defaults if not provided)")

	rootCmd.AddCommand(daemonCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Sync()

	logger.Info("arca-dns-agent starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("date", date))

	// Load configuration
	var cfg *config.AgentConfig
	if configFile != "" {
		loadedCfg, loadErr := config.LoadAgentConfig(configFile)
		if loadErr != nil {
			return fmt.Errorf("failed to load config: %w", loadErr)
		}
		cfg = loadedCfg
		logger.Info("Configuration loaded from file", zap.String("config_file", configFile))
	} else {
		cfg = config.DefaultAgentConfig()
		logger.Info("Using default configuration")
	}

	// Create controller client
	client, err := zonesync.NewClient(cfg.Controller)
	if err != nil {
		return fmt.Errorf("failed to create controller client: %w", err)
	}
	defer client.Close()

	logger.Info("Controller client initialized", zap.String("url", cfg.Controller.URL))

	// Create file manager
	fileMgr := zonesync.NewFileManager(cfg.NSD.ZoneDirectory, cfg.Sync.BackupVersions, logger)
	if err := fileMgr.EnsureDirectory(); err != nil {
		return fmt.Errorf("failed to ensure zone directory: %w", err)
	}

	// Create syncer
	syncer := zonesync.NewSyncer(client, fileMgr, cfg.Sync, logger)

	// Create NSD controller
	var nsdCtrl *nsd.Controller
	if cfg.NSD.Enabled {
		nsdCtrl = nsd.NewController(cfg.NSD, logger)
		logger.Info("NSD controller initialized")
	}

	// Create Unbound controller
	var unboundCtrl *unbound.Controller
	if cfg.Unbound.Enabled {
		unboundCtrl = unbound.NewController(cfg.Unbound, logger)
		logger.Info("Unbound controller initialized")
	}

	// Create health checker
	nsdSocket := cfg.NSD.ConfigPath // Placeholder for actual socket path
	checker := health.NewChecker(cfg.Health, nsdSocket, cfg.Unbound.ControlPath, logger)
	logger.Info("Health checker initialized")

	// Create BIRD BGP control components (M5)
	var birdClient bird.Client
	var routeManager *bird.RouteManager
	var stateMachine *bird.StateMachine
	var healthEngine *health.Engine
	var controlLoop *bird.ControlLoop

	if cfg.BIRD.Enabled {
		// Create BIRD client
		var clientErr error
		birdClient, clientErr = bird.NewClient(bird.ClientConfig{
			SocketPath: cfg.BIRD.SocketPath,
			Timeout:    cfg.BIRD.CommandTimeout,
		})
		if clientErr != nil {
			logger.Warn("Failed to create BIRD client, BIRD control disabled",
				zap.Error(clientErr))
			cfg.BIRD.Enabled = false
		} else {
			logger.Info("BIRD client initialized", zap.String("socket", cfg.BIRD.SocketPath))
		}
	}

	if cfg.BIRD.Enabled {

		// Create route manager and reconcile state
		routeManager = bird.NewRouteManager(birdClient, cfg.BIRD.ProtocolName)
		reconcileCtx, reconcileCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := routeManager.Reconcile(reconcileCtx); err != nil {
			reconcileCancel()
			logger.Warn("Failed to reconcile BIRD state, assuming routes not announced",
				zap.Error(err))
		} else {
			reconcileCancel()
			logger.Info("BIRD route manager reconciled",
				zap.Bool("announced", routeManager.IsAnnounced()))
		}

		// Create state machine with validation
		// Note: State machine does the thresholding, so engine just passes through
		smConfig := bird.StateMachineConfig{
			FailureThreshold:  3,  // 3 consecutive failures before withdrawing routes
			RecoveryThreshold: 3,  // 3 consecutive successes before announcing routes
			MinStateDuration:  30 * time.Second, // 30s debounce to prevent flapping
		}
		stateMachine = bird.NewStateMachine(smConfig, logger)
		logger.Info("BIRD state machine initialized",
			zap.Int("failure_threshold", 3),
			zap.Int("recovery_threshold", 3),
			zap.Duration("min_state_duration", 30*time.Second))

		// Create health engine
		// Engine uses threshold=1 to pass through all state changes to state machine
		engineConfig := health.EngineConfig{
			FailureThreshold:  1,
			RecoveryThreshold: 1,
		}
		healthEngine = health.NewEngine(checker, engineConfig, logger)
		logger.Info("Health engine initialized")

		// Create control loop
		controlLoop = bird.NewControlLoop(stateMachine, routeManager, logger)
		logger.Info("BGP control loop initialized")
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Create wait group for goroutines
	var wg sync.WaitGroup

	// Start zone sync loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Starting zone sync loop")
		if err := syncer.Run(ctx); err != nil && err != context.Canceled {
			logger.Error("Zone sync loop failed", zap.Error(err))
		}
		logger.Info("Zone sync loop stopped")
	}()

	// Start health check loop
	healthStatusChan := make(chan health.HealthStatus, 10)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Starting health check loop")
		if err := checker.Run(ctx, healthStatusChan); err != nil && err != context.Canceled {
			logger.Error("Health check loop failed", zap.Error(err))
		}
		logger.Info("Health check loop stopped")
	}()

	// Start BIRD BGP control loop (M5)
	if cfg.BIRD.Enabled && healthEngine != nil && controlLoop != nil {
		healthSignalChan := make(chan bird.HealthSignal, 10)

		// Start health engine
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(healthSignalChan) // Close signal channel on exit
			logger.Info("Starting health engine")
			if err := healthEngine.Run(ctx, healthSignalChan); err != nil && err != context.Canceled {
				logger.Error("Health engine failed", zap.Error(err))
			}
			logger.Info("Health engine stopped")
		}()

		// Start BGP control loop
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("Starting BGP control loop")
			if err := controlLoop.Run(ctx, healthSignalChan); err != nil && err != context.Canceled {
				logger.Error("BGP control loop failed", zap.Error(err))
			}
			logger.Info("BGP control loop stopped")
		}()
	}

	// Monitor health status and trigger reloads
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Starting health status monitor")
		for {
			select {
			case <-ctx.Done():
				return
			case status, ok := <-healthStatusChan:
				if !ok {
					return // Channel closed
				}
				logger.Debug("Health status update",
					zap.Bool("healthy", status.Healthy),
					zap.Int("checks", len(status.Checks)))

				// Log failed checks
				for checkType, result := range status.Checks {
					if !result.Success {
						logger.Warn("Health check failed",
							zap.String("type", string(checkType)),
							zap.Error(result.Error))
					}
				}
			}
		}
	}()

	// Start HTTP status server
	wg.Add(1)
	statusServer := startStatusServer(cfg, syncer, checker, logger)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := statusServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("Status server shutdown failed", zap.Error(err))
		}
		logger.Info("Status server stopped")
	}()

	logger.Info("Agent started successfully",
		zap.String("sync_interval", cfg.Sync.SyncInterval.String()),
		zap.String("health_check_interval", cfg.Health.CheckInterval.String()),
		zap.String("zone_directory", cfg.NSD.ZoneDirectory))

	// Wait for signals
	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGHUP:
				logger.Info("Received SIGHUP, reloading configuration")
				// TODO: Implement configuration reload
				if nsdCtrl != nil {
					logger.Info("Reloading NSD")
					if err := nsdCtrl.Reload(); err != nil {
						logger.Error("NSD reload failed", zap.Error(err))
					}
				}
				if unboundCtrl != nil {
					logger.Info("Reloading Unbound")
					if err := unboundCtrl.Reload(); err != nil {
						logger.Error("Unbound reload failed", zap.Error(err))
					}
				}

			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("Received shutdown signal, gracefully shutting down",
					zap.String("signal", sig.String()))
				cancel()
				wg.Wait()
				logger.Info("Agent shutdown complete")
				return nil
			}
		}
	}
}

// startStatusServer starts an HTTP server for status and metrics.
func startStatusServer(cfg *config.AgentConfig, syncer *zonesync.Syncer, checker *health.Checker, logger *zap.Logger) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Status endpoint
	router.GET("/status", func(c *gin.Context) {
		zoneStates := syncer.GetAllZoneStates()
		healthStatus := checker.CheckHealth(c.Request.Context())

		c.JSON(http.StatusOK, gin.H{
			"status":          "running",
			"version":         version,
			"zone_count":      len(zoneStates),
			"zones":           zoneStates,
			"last_sync":       syncer.GetLastSuccessTime(),
			"is_stale":        syncer.IsStale(),
			"health":          healthStatus.Healthy,
			"health_checks":   len(healthStatus.Checks),
			"last_health_check": healthStatus.LastCheck,
		})
	})

	// Health endpoint (simple liveness)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	// Ready endpoint (readiness check)
	router.GET("/ready", func(c *gin.Context) {
		// Check if we've done at least one successful sync
		if syncer.GetLastSuccessTime().IsZero() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"reason": "no successful sync yet",
			})
			return
		}

		// Check if sync is stale
		if syncer.IsStale() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"reason": "sync is stale",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
		})
	})

	// Metrics endpoint (placeholder for Prometheus metrics)
	router.GET("/metrics", func(c *gin.Context) {
		// TODO: Implement Prometheus metrics in M6
		c.String(http.StatusOK, "# Metrics not yet implemented\n")
	})

	server := &http.Server{
		Addr:    cfg.Metrics.Listen,
		Handler: router,
	}

	go func() {
		logger.Info("Starting status server", zap.String("listen", cfg.Metrics.Listen))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Status server failed", zap.Error(err))
		}
	}()

	return server
}
