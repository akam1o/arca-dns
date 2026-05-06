package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/bird"
	"github.com/akam1o/arca-dns/internal/agent/dnstap"
	"github.com/akam1o/arca-dns/internal/agent/health"
	"github.com/akam1o/arca-dns/internal/agent/nsd"
	"github.com/akam1o/arca-dns/internal/agent/plugin"
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

var execFn = syscall.Exec

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
	defer func() { _ = logger.Sync() }()

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
		loadedCfg, loadErr := config.LoadAgentConfig("")
		if loadErr != nil {
			return fmt.Errorf("failed to load default config: %w", loadErr)
		}
		cfg = loadedCfg
		logger.Info("Using default configuration with environment overrides")
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

	// Create authoritative DNS server plugin
	var authServer plugin.AuthoritativeServer
	if cfg.NSD.Enabled {
		nsdCtrl := nsd.NewController(cfg.NSD, logger)
		authServer = nsd.NewAdapter(nsdCtrl)
		logger.Info("Authoritative server initialized", zap.String("type", authServer.Type()))
	} else {
		authServer = &plugin.NoopAuthoritativeServer{}
	}

	// Create resolver plugin
	var resolver plugin.Resolver
	if cfg.Unbound.Enabled {
		unboundCtrl := unbound.NewController(cfg.Unbound, logger)
		resolver = unbound.NewAdapter(unboundCtrl)
		logger.Info("Resolver initialized", zap.String("type", resolver.Type()))
	} else {
		resolver = &plugin.NoopResolver{}
	}

	syncer.SetValidateZoneFile(func(ctx context.Context, zoneName string, zonePath string) error {
		return authServer.CheckZone(ctx, zoneName, zonePath)
	})

	// Wire zone-apply hook: reload services after zone file write.
	syncer.SetOnZoneApplied(func(ctx context.Context, zoneName string) error {
		if err := authServer.EnsureZone(ctx, zoneName); err != nil {
			return err
		}
		// Reload authoritative server zone immediately so updates become visible to DNS.
		if err := authServer.ReloadZone(ctx, zoneName); err != nil {
			return err
		}
		if err := resolver.UpdateStubZone(ctx, zoneName); err != nil {
			return err
		}
		if err := resolver.CheckConfig(ctx); err != nil {
			return err
		}
		// Reload resolver to pick up any configuration changes.
		if err := resolver.Reload(ctx); err != nil {
			return err
		}
		return nil
	})

	// Wire zone-delete hook: reload services after the zone file is removed.
	syncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		if err := authServer.DeleteZone(ctx, zoneName); err != nil {
			return err
		}
		if err := resolver.DeleteStubZone(ctx, zoneName); err != nil {
			return err
		}
		if err := resolver.CheckConfig(ctx); err != nil {
			return err
		}
		if err := resolver.Reload(ctx); err != nil {
			return err
		}
		return nil
	})

	// Create health checker (DNS behavior is the source of truth).
	checker := health.NewCheckerWithOptions(cfg.Health, health.CheckerOptions{
		CheckAuthoritative: cfg.NSD.Enabled,
		CheckResolver:      cfg.Unbound.Enabled,
	}, logger)
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

		// Optionally generate BIRD config snippet and run "configure" once at startup.
		if cfg.BIRD.ConfigureOnStart.Enabled {
			configText, protocolNames, err := bird.RenderAnycastConfig(cfg.BIRD)
			if err != nil {
				logger.Warn("Failed to render BIRD anycast config, skipping configure",
					zap.Error(err))
			} else {
				if err := os.MkdirAll(filepath.Dir(cfg.BIRD.ConfigureOnStart.Path), 0o755); err != nil {
					logger.Warn("Failed to create BIRD config directory, skipping configure",
						zap.String("path", cfg.BIRD.ConfigureOnStart.Path),
						zap.Error(err))
				} else if err := os.WriteFile(cfg.BIRD.ConfigureOnStart.Path, []byte(configText), 0o644); err != nil {
					logger.Warn("Failed to write BIRD config snippet, skipping configure",
						zap.String("path", cfg.BIRD.ConfigureOnStart.Path),
						zap.Error(err))
				} else {
					// If protocol_names not set, use the generated list so enable/disable controls all neighbors.
					if len(cfg.BIRD.ProtocolNames) == 0 && len(protocolNames) > 0 {
						cfg.BIRD.ProtocolNames = protocolNames
					}
					cfgCtx, cfgCancel := context.WithTimeout(context.Background(), cfg.BIRD.CommandTimeout)
					if resp, err := birdClient.Exec(cfgCtx, "configure"); err != nil {
						logger.Warn("BIRD configure failed",
							zap.Error(err))
					} else if resp.IsError() {
						logger.Warn("BIRD configure returned error",
							zap.Int("code", resp.Code),
							zap.String("response", resp.RawText))
					} else {
						logger.Info("BIRD configured from generated snippet",
							zap.String("path", cfg.BIRD.ConfigureOnStart.Path))
					}
					cfgCancel()
				}
			}
		}

		// Create route manager and reconcile state
		var protocolNames []string
		if len(cfg.BIRD.Protocols) > 0 {
			for _, p := range cfg.BIRD.Protocols {
				protocolNames = append(protocolNames, p.Name)
			}
		} else {
			protocolNames = cfg.BIRD.ProtocolNames
			if len(protocolNames) == 0 && cfg.BIRD.ProtocolName != "" {
				protocolNames = []string{cfg.BIRD.ProtocolName}
			}
		}
		routeManager = bird.NewRouteManager(birdClient, protocolNames)
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
			FailureThreshold:  cfg.BIRD.StateMachine.FailureThreshold,
			RecoveryThreshold: cfg.BIRD.StateMachine.RecoveryThreshold,
			MinStateDuration:  cfg.BIRD.StateMachine.MinStateDuration,
		}
		stateMachine = bird.NewStateMachine(smConfig, logger)
		logger.Info("BIRD state machine initialized",
			zap.Int("failure_threshold", smConfig.FailureThreshold),
			zap.Int("recovery_threshold", smConfig.RecoveryThreshold),
			zap.Duration("min_state_duration", smConfig.MinStateDuration))

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

	// Create DNSTap processor (M6)
	var dnstapProcessor *dnstap.Processor
	if cfg.DNSTap.Enabled {
		processorConfig := dnstap.ProcessorConfig{
			ReceiverConfig: dnstap.ReceiverConfig{
				SocketPath: cfg.DNSTap.SocketPath,
				BufferSize: cfg.DNSTap.BufferSize,
			},
			LoggerConfig: dnstap.LoggerConfig{
				LogFile:    cfg.DNSTap.LogFile,
				MaxSize:    cfg.DNSTap.LogRotation.MaxSize,
				MaxBackups: cfg.DNSTap.LogRotation.MaxBackups,
				MaxAge:     cfg.DNSTap.LogRotation.MaxAge,
				Compress:   cfg.DNSTap.LogRotation.Compress,
				QueueSize:  1000, // Default queue size
			},
			SamplerConfig: dnstap.SamplerConfig{
				SampleRate:      1.0 / float64(cfg.DNSTap.SampleRate), // Convert 1/N to float
				AlwaysLogErrors: cfg.DNSTap.AlwaysLogErrors,
			},
			PrometheusEnabled: cfg.Metrics.Enabled,
		}
		dnstapProcessor = dnstap.NewProcessor(processorConfig, logger)
		logger.Info("DNSTap processor initialized",
			zap.String("socket", cfg.DNSTap.SocketPath),
			zap.String("log_file", cfg.DNSTap.LogFile),
			zap.Int("sample_rate", cfg.DNSTap.SampleRate))
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

	// Start DNSTap processor (M6)
	if cfg.DNSTap.Enabled && dnstapProcessor != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("Starting DNSTap processor")
			if err := dnstapProcessor.Run(ctx); err != nil && err != context.Canceled {
				logger.Error("DNSTap processor failed", zap.Error(err))
			}
			logger.Info("DNSTap processor stopped")
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
	var routeCtrl plugin.RouteController
	if routeManager != nil {
		routeCtrl = bird.NewAdapter(routeManager)
	}
	if cfg.Metrics.Enabled {
		wg.Add(1)
		statusServer := startStatusServer(cfg, syncer, checker, routeCtrl, dnstapProcessor, logger)
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
	} else {
		logger.Info("Status server disabled")
	}

	logger.Info("Agent started successfully",
		zap.String("sync_interval", cfg.Sync.SyncInterval.String()),
		zap.String("health_check_interval", cfg.Health.CheckInterval.String()),
		zap.String("zone_directory", cfg.NSD.ZoneDirectory))

	// Wait for signals
	for sig := range sigChan {
		switch sig {
		case syscall.SIGHUP:
			logger.Info("Received SIGHUP, reloading configuration via re-exec")

			// Gracefully stop background loops, then re-exec the current binary with the same args.
			cancel()
			wg.Wait()
			client.Close()
			_ = logger.Sync()

			if err := reexecSelf(); err != nil {
				return fmt.Errorf("re-exec failed: %w", err)
			}
			// If re-exec succeeds, this process image is replaced and code below is not executed.
			return nil

		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info("Received shutdown signal, gracefully shutting down",
				zap.String("signal", sig.String()))
			cancel()
			wg.Wait()
			logger.Info("Agent shutdown complete")
			return nil
		}
	}

	return nil
}

func reexecSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	exe, err = exec.LookPath(exe)
	if err != nil {
		return fmt.Errorf("lookpath executable: %w", err)
	}
	argv := append([]string{exe}, os.Args[1:]...)
	return execFn(exe, argv, os.Environ())
}

// startStatusServer starts an HTTP server for status and metrics.
func startStatusServer(cfg *config.AgentConfig, syncer *zonesync.Syncer, checker *health.Checker, routeCtrl plugin.RouteController, dnstapProcessor *dnstap.Processor, logger *zap.Logger) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Status endpoint
	router.GET("/status", func(c *gin.Context) {
		zoneStates := syncer.GetAllZoneStates()
		healthStatus := checker.CheckHealth(c.Request.Context())

		c.JSON(http.StatusOK, gin.H{
			"status":            "running",
			"version":           version,
			"zone_count":        len(zoneStates),
			"zones":             zoneStates,
			"last_sync":         syncer.GetLastSuccessTime(),
			"is_stale":          syncer.IsStale(),
			"health":            healthStatus.Healthy,
			"health_checks":     len(healthStatus.Checks),
			"last_health_check": healthStatus.LastCheck,
			"bgp_announced": func() bool {
				if routeCtrl == nil {
					return false
				}
				return routeCtrl.IsAnnounced()
			}(),
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

	// Metrics endpoint (Prometheus format)
	router.GET(metricPath(cfg.Metrics.Path), func(c *gin.Context) {
		var sb strings.Builder

		sb.WriteString("# arca-dns agent metrics\n")
		sb.WriteString("# HELP arca_dns_agent_sync_has_success Whether the agent has ever completed a successful sync (1/0).\n")
		sb.WriteString("# TYPE arca_dns_agent_sync_has_success gauge\n")
		sb.WriteString(fmt.Sprintf("arca_dns_agent_sync_has_success %d\n", boolToInt(!syncer.GetLastSuccessTime().IsZero())))

		sb.WriteString("\n# HELP arca_dns_agent_sync_stale Whether sync is currently considered stale (1/0).\n")
		sb.WriteString("# TYPE arca_dns_agent_sync_stale gauge\n")
		sb.WriteString(fmt.Sprintf("arca_dns_agent_sync_stale %d\n", boolToInt(syncer.IsStale())))

		lastSuccess := syncer.GetLastSuccessTime()
		sb.WriteString("\n# HELP arca_dns_agent_sync_last_success_timestamp_seconds Unix timestamp of the last successful sync (0 if none).\n")
		sb.WriteString("# TYPE arca_dns_agent_sync_last_success_timestamp_seconds gauge\n")
		if lastSuccess.IsZero() {
			sb.WriteString("arca_dns_agent_sync_last_success_timestamp_seconds 0\n")
		} else {
			sb.WriteString(fmt.Sprintf("arca_dns_agent_sync_last_success_timestamp_seconds %d\n", lastSuccess.Unix()))
		}

		healthStatus := checker.CheckHealth(c.Request.Context())
		sb.WriteString("\n# HELP arca_dns_agent_health_status Overall health status (1=healthy, 0=unhealthy).\n")
		sb.WriteString("# TYPE arca_dns_agent_health_status gauge\n")
		sb.WriteString(fmt.Sprintf("arca_dns_agent_health_status %d\n", boolToInt(healthStatus.Healthy)))

		sb.WriteString("\n# HELP arca_dns_agent_health_check_status Per-check health status (1=success, 0=failure).\n")
		sb.WriteString("# TYPE arca_dns_agent_health_check_status gauge\n")
		checkTypes := make([]string, 0, len(healthStatus.Checks))
		for checkType := range healthStatus.Checks {
			checkTypes = append(checkTypes, string(checkType))
		}
		sort.Strings(checkTypes)
		for _, checkType := range checkTypes {
			result := healthStatus.Checks[health.CheckType(checkType)]
			sb.WriteString(fmt.Sprintf("arca_dns_agent_health_check_status{type=%q} %d\n", checkType, boolToInt(result.Success)))
		}

		if routeCtrl != nil {
			sb.WriteString("\n# HELP arca_dns_agent_bgp_enabled Whether BGP control is enabled (1/0).\n")
			sb.WriteString("# TYPE arca_dns_agent_bgp_enabled gauge\n")
			sb.WriteString("arca_dns_agent_bgp_enabled 1\n")

			sb.WriteString("\n# HELP arca_dns_agent_bgp_routes_announced Whether routes are currently announced (1/0).\n")
			sb.WriteString("# TYPE arca_dns_agent_bgp_routes_announced gauge\n")
			sb.WriteString(fmt.Sprintf("arca_dns_agent_bgp_routes_announced %d\n", boolToInt(routeCtrl.IsAnnounced())))

			if ts := routeCtrl.LastChangeTime(); !ts.IsZero() {
				sb.WriteString("\n# HELP arca_dns_agent_bgp_last_change_timestamp_seconds Unix timestamp of the last successful route state change.\n")
				sb.WriteString("# TYPE arca_dns_agent_bgp_last_change_timestamp_seconds gauge\n")
				sb.WriteString(fmt.Sprintf("arca_dns_agent_bgp_last_change_timestamp_seconds %d\n", ts.Unix()))
			}
		} else {
			sb.WriteString("\n# HELP arca_dns_agent_bgp_enabled Whether BGP control is enabled (1/0).\n")
			sb.WriteString("# TYPE arca_dns_agent_bgp_enabled gauge\n")
			sb.WriteString("arca_dns_agent_bgp_enabled 0\n")

			sb.WriteString("\n# HELP arca_dns_agent_bgp_routes_announced Whether routes are currently announced (1/0).\n")
			sb.WriteString("# TYPE arca_dns_agent_bgp_routes_announced gauge\n")
			sb.WriteString("arca_dns_agent_bgp_routes_announced 0\n")
		}

		// Append DNSTap Prometheus metrics if processor is available
		if dnstapProcessor != nil {
			metricsText, err := dnstapProcessor.GetPrometheusMetrics()
			if err != nil {
				logger.Error("Failed to get DNSTap Prometheus metrics", zap.Error(err))
				c.String(http.StatusInternalServerError, "# Error retrieving metrics\n")
				return
			}
			if metricsText != "" {
				sb.WriteString("\n")
				sb.WriteString(metricsText)
			}
		}

		c.Header("Content-Type", "text/plain; version=0.0.4")
		c.String(http.StatusOK, sb.String())
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

func metricPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/metrics"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
