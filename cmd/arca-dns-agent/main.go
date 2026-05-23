package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
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
	applogging "github.com/akam1o/arca-dns/internal/logging"
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

const (
	bgpControlStatusActive   = "active"
	bgpControlStatusDisabled = "disabled"
	bgpControlStatusUnknown  = "unknown"
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
		Long: `Run the agent daemon to sync zones and manage DNS services.

Provide a configuration file, or provide all required settings via environment
variables. For example, signature verification requires
sync.controller_signature_key or ARCA_DNS_SYNC_CONTROLLER_SIGNATURE_KEY.`,
		RunE: runDaemon,
	}

	daemonCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file")

	rootCmd.AddCommand(daemonCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Initialize a bootstrap logger until configuration is loaded.
	bootstrapLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Load configuration
	var cfg *config.AgentConfig
	if configFile != "" {
		loadedCfg, loadErr := config.LoadAgentConfig(configFile)
		if loadErr != nil {
			return fmt.Errorf("failed to load config: %w", loadErr)
		}
		cfg = loadedCfg
	} else {
		loadedCfg, loadErr := config.LoadAgentConfig("")
		if loadErr != nil {
			return fmt.Errorf("failed to load config from defaults and environment: %w", loadErr)
		}
		cfg = loadedCfg
	}

	logger, err := applogging.NewLogger(cfg.Logging)
	if err != nil {
		bootstrapLogger.Error("Failed to initialize configured logger", zap.Error(err))
		return fmt.Errorf("failed to initialize configured logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()
	_ = bootstrapLogger.Sync()

	logger.Info("arca-dns-agent starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("date", date))
	if configFile != "" {
		logger.Info("Configuration loaded from file", zap.String("config_file", configFile))
	} else {
		logger.Info("Using default configuration with environment overrides")
	}
	warnPlaintextAPIKeyTransport(cfg.Controller, logger)

	// Create controller client
	client, err := zonesync.NewClient(cfg.Controller)
	if err != nil {
		return fmt.Errorf("failed to create controller client: %w", err)
	}
	defer client.Close()

	logger.Info("Controller client initialized", zap.String("url", cfg.Controller.URL))

	// Create file manager
	fileMgr := zonesync.NewFileManagerWithMinFreeBytes(cfg.NSD.ZoneDirectory, cfg.Sync.BackupVersions, cfg.Sync.MinFreeBytes, logger)
	if err := fileMgr.EnsureDirectory(); err != nil {
		return fmt.Errorf("failed to ensure zone directory: %w", err)
	}

	// Create syncer
	syncer := zonesync.NewSyncer(client, fileMgr, cfg.Sync, logger)

	// Create authoritative DNS server plugin
	var authServer plugin.AuthoritativeServer
	switch cfg.Authoritative {
	case "nsd":
		if cfg.NSD.Enabled {
			nsdCtrl := nsd.NewController(cfg.NSD, logger)
			authServer = nsd.NewAdapter(nsdCtrl)
			logger.Info("Authoritative server initialized", zap.String("type", authServer.Type()))
		} else {
			authServer = &plugin.NoopAuthoritativeServer{}
		}
	default:
		return fmt.Errorf("unsupported authoritative server: %s", cfg.Authoritative)
	}

	// Create resolver plugin
	var resolver plugin.Resolver
	if cfg.Unbound.Enabled {
		unboundCtrl := unbound.NewController(cfg.Unbound, logger)
		if err := unboundCtrl.EnsureEDNSBufferSize(); err != nil {
			return fmt.Errorf("failed to validate unbound EDNS buffer size: %w", err)
		}
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
		return applyZoneServiceReferences(ctx, zoneName, authServer, resolver)
	})
	syncer.SetOnZoneApplyRollback(func(ctx context.Context, zoneName string, hadPrevious bool) error {
		return rollbackAppliedZoneServiceReferences(ctx, zoneName, hadPrevious, authServer, resolver, logger)
	})

	// Wire zone-delete hook: remove service references before deleting the zone file.
	syncer.SetOnZoneDeleted(func(ctx context.Context, zoneName string) error {
		return deleteZoneServiceReferences(ctx, zoneName, authServer, resolver, logger)
	})
	syncer.SetOnZoneDeleteRollback(func(ctx context.Context, zoneName string) error {
		return restoreZoneServiceReferences(ctx, zoneName, authServer, resolver, true, true)
	})

	// Create health checker (DNS behavior is the source of truth).
	checker := health.NewCheckerWithOptions(cfg.Health, health.CheckerOptions{
		CheckAuthoritative: cfg.NSD.Enabled,
		CheckResolver:      cfg.Unbound.Enabled,
	}, logger)
	checker.AddCheck(func(ctx context.Context) health.CheckResult {
		now := time.Now()
		if failedZones := syncer.FailedZoneCount(); failedZones > 0 {
			return health.CheckResult{
				Type:      health.CheckTypeSync,
				Success:   false,
				Error:     fmt.Errorf("%d zone sync failures", failedZones),
				Timestamp: now,
			}
		}
		if syncer.GetLastSuccessTime().IsZero() {
			return health.CheckResult{
				Type:      health.CheckTypeSync,
				Success:   false,
				Error:     fmt.Errorf("no successful sync yet"),
				Timestamp: now,
			}
		}
		if syncer.IsStale() {
			return health.CheckResult{
				Type:      health.CheckTypeSync,
				Success:   false,
				Error:     fmt.Errorf("sync is stale"),
				Timestamp: now,
			}
		}
		return health.CheckResult{
			Type:      health.CheckTypeSync,
			Success:   true,
			Timestamp: now,
		}
	})
	logger.Info("Health checker initialized")

	// Create BIRD BGP control components (M5)
	var birdClient bird.Client
	var routeManager *bird.RouteManager
	var stateMachine *bird.StateMachine
	var healthEngine *health.Engine
	var controlLoop *bird.ControlLoop
	birdConfigStatus := newBIRDConfigRuntimeStatus(cfg.BIRD)

	if cfg.BIRD.Enabled {
		// Create BIRD client
		var clientErr error
		birdClient, clientErr = bird.NewClient(bird.ClientConfig{
			SocketPath: cfg.BIRD.SocketPath,
			Timeout:    cfg.BIRD.CommandTimeout,
		})
		if clientErr != nil {
			return fmt.Errorf("BIRD control enabled but failed to create BIRD client: %w", clientErr)
		} else {
			logger.Info("BIRD client initialized", zap.String("socket", cfg.BIRD.SocketPath))
		}
	}

	if cfg.BIRD.Enabled {

		// Optionally generate BIRD config snippet and run "configure" once at startup.
		if cfg.BIRD.ConfigureOnStart.Enabled {
			applyResult := applyBIRDConfigOnStart(cfg.BIRD, birdClient, logger)
			birdConfigStatus = applyResult.Status
			// If protocol_names not set, use the generated list so enable/disable controls all neighbors.
			// When config application fails, this intentionally targets the last known generated runtime config.
			if len(cfg.BIRD.ProtocolNames) == 0 && len(applyResult.ProtocolNames) > 0 {
				cfg.BIRD.ProtocolNames = applyResult.ProtocolNames
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
		routeManager, err = bird.NewRouteManager(birdClient, protocolNames)
		if err != nil {
			if birdConfigStatus.usingExisting() {
				logger.Warn("BIRD route manager initialization failed while using existing BIRD runtime config; continuing DNS service without BGP control",
					zap.Error(err))
				routeManager = nil
			} else {
				return fmt.Errorf("failed to create BIRD route manager: %w", err)
			}
		}
		if routeManager != nil {
			reconcileCtx, reconcileCancel := context.WithTimeout(context.Background(), 10*time.Second)
			reconcileErr := routeManager.Reconcile(reconcileCtx)
			reconcileCancel()
			if reconcileErr != nil {
				if birdConfigStatus.usingExisting() {
					logger.Warn("BIRD route manager reconcile failed while using existing BIRD runtime config; continuing DNS service without BGP control",
						zap.Error(reconcileErr))
					routeManager = nil
				} else {
					withdrawTimeout := cfg.BIRD.CommandTimeout
					if withdrawTimeout <= 0 {
						withdrawTimeout = 10 * time.Second
					}
					withdrawCtx, withdrawCancel := context.WithTimeout(context.Background(), withdrawTimeout)
					withdrawErr := routeManager.ForceWithdrawRoutes(withdrawCtx)
					withdrawCancel()
					if withdrawErr != nil {
						return fmt.Errorf("failed to reconcile BIRD state and force route withdraw: reconcile: %v; withdraw: %w", reconcileErr, withdrawErr)
					}
					return fmt.Errorf("failed to reconcile BIRD state; forced route withdraw: %w", reconcileErr)
				}
			} else {
				logger.Info("BIRD route manager reconciled",
					zap.Bool("announced", routeManager.IsAnnounced()))
			}
		}

		if routeManager != nil {
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
	}

	// Create DNSTap processor (M6)
	var dnstapProcessor *dnstap.Processor
	if cfg.DNSTap.Enabled {
		socketMode, err := cfg.DNSTap.SocketFileMode()
		if err != nil {
			return fmt.Errorf("invalid dnstap socket mode: %w", err)
		}

		processorConfig := dnstap.ProcessorConfig{
			ReceiverConfig: dnstap.ReceiverConfig{
				SocketPath:  cfg.DNSTap.SocketPath,
				SocketMode:  socketMode,
				SocketOwner: cfg.DNSTap.SocketOwner,
				SocketGroup: cfg.DNSTap.SocketGroup,
				BufferSize:  cfg.DNSTap.BufferSize,
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
		dnstapProcessor, err = dnstap.NewProcessor(processorConfig, logger)
		if err != nil {
			return fmt.Errorf("initialize dnstap processor: %w", err)
		}
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
	defer signal.Stop(sigChan)

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

	// Start one health check loop and fan out results to consumers.
	healthCheckChan := make(chan health.HealthStatus, 10)
	healthStatusChan := make(chan health.HealthStatus, 10)
	var healthEngineStatusChan chan health.HealthStatus
	if cfg.BIRD.Enabled && healthEngine != nil && controlLoop != nil {
		healthEngineStatusChan = make(chan health.HealthStatus, 10)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(healthCheckChan)
		logger.Info("Starting health check loop")
		if err := checker.Run(ctx, healthCheckChan); err != nil && err != context.Canceled {
			logger.Error("Health check loop failed", zap.Error(err))
		}
		logger.Info("Health check loop stopped")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(healthStatusChan)
		if healthEngineStatusChan != nil {
			defer close(healthEngineStatusChan)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case status, ok := <-healthCheckChan:
				if !ok {
					return
				}
				if !sendHealthStatus(ctx, healthStatusChan, status) {
					return
				}
				if healthEngineStatusChan != nil {
					if !sendHealthStatus(ctx, healthEngineStatusChan, status) {
						return
					}
				}
			}
		}
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
			if err := healthEngine.RunWithStatus(ctx, healthEngineStatusChan, healthSignalChan); err != nil && err != context.Canceled {
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
	statusServer, err := startStatusServer(cfg, syncer, checker, routeCtrl, dnstapProcessor, birdConfigStatus, logger)
	if err != nil {
		cancel()
		wg.Wait()
		return fmt.Errorf("start status server: %w", err)
	}
	wg.Add(1)
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

func warnPlaintextAPIKeyTransport(cfg config.ControllerClientConfig, logger *zap.Logger) {
	if strings.TrimSpace(cfg.APIKey) == "" || logger == nil {
		return
	}

	parsed, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || !strings.EqualFold(parsed.Scheme, "http") {
		return
	}

	logger.Warn("Controller API key will be sent over plaintext HTTP",
		zap.String("url", cfg.URL),
		zap.String("recommendation", "use HTTPS/TLS termination or an intentionally trusted transport"))
}

func applyZoneServiceReferences(ctx context.Context, zoneName string, authServer plugin.AuthoritativeServer, resolver plugin.Resolver) error {
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
	if err := resolver.FlushZone(ctx, zoneName); err != nil {
		return err
	}
	return nil
}

func rollbackAppliedZoneServiceReferences(ctx context.Context, zoneName string, hadPrevious bool, authServer plugin.AuthoritativeServer, resolver plugin.Resolver, logger *zap.Logger) error {
	if hadPrevious {
		return restoreZoneServiceReferences(ctx, zoneName, authServer, resolver, true, true)
	}
	return deleteZoneServiceReferences(ctx, zoneName, authServer, resolver, logger)
}

func deleteZoneServiceReferences(ctx context.Context, zoneName string, authServer plugin.AuthoritativeServer, resolver plugin.Resolver, logger *zap.Logger) error {
	authDeleted := false
	resolverDeleted := false

	if err := authServer.DeleteZone(ctx, zoneName); err != nil {
		return rollbackZoneServiceDeletion(ctx, zoneName, authServer, resolver, true, resolverDeleted, logger,
			fmt.Errorf("delete authoritative zone: %w", err))
	}
	authDeleted = true

	if err := resolver.DeleteStubZone(ctx, zoneName); err != nil {
		return rollbackZoneServiceDeletion(ctx, zoneName, authServer, resolver, authDeleted, resolverDeleted, logger,
			fmt.Errorf("delete resolver stub zone: %w", err))
	}
	resolverDeleted = true

	if err := resolver.CheckConfig(ctx); err != nil {
		return rollbackZoneServiceDeletion(ctx, zoneName, authServer, resolver, authDeleted, resolverDeleted, logger,
			fmt.Errorf("check resolver config after zone deletion: %w", err))
	}

	if err := resolver.Reload(ctx); err != nil {
		return rollbackZoneServiceDeletion(ctx, zoneName, authServer, resolver, authDeleted, resolverDeleted, logger,
			fmt.Errorf("reload resolver after zone deletion: %w", err))
	}

	if err := resolver.FlushZone(ctx, zoneName); err != nil {
		return rollbackZoneServiceDeletion(ctx, zoneName, authServer, resolver, authDeleted, resolverDeleted, logger,
			fmt.Errorf("flush resolver cache after zone deletion: %w", err))
	}

	return nil
}

func rollbackZoneServiceDeletion(ctx context.Context, zoneName string, authServer plugin.AuthoritativeServer, resolver plugin.Resolver, restoreAuth bool, restoreResolver bool, logger *zap.Logger, cause error) error {
	if err := restoreZoneServiceReferences(ctx, zoneName, authServer, resolver, restoreAuth, restoreResolver); err != nil {
		if logger != nil {
			logger.Error("Failed to roll back zone service deletion",
				zap.String("zone", zoneName),
				zap.Error(err))
		}
		return errors.Join(cause, fmt.Errorf("rollback zone service deletion: %w", err))
	}
	if logger != nil {
		logger.Info("Rolled back zone service deletion",
			zap.String("zone", zoneName))
	}
	return cause
}

func restoreZoneServiceReferences(ctx context.Context, zoneName string, authServer plugin.AuthoritativeServer, resolver plugin.Resolver, restoreAuth bool, restoreResolver bool) error {
	var errs []error

	if restoreAuth {
		if err := authServer.EnsureZone(ctx, zoneName); err != nil {
			errs = append(errs, fmt.Errorf("restore authoritative zone: %w", err))
		} else if err := authServer.ReloadZone(ctx, zoneName); err != nil {
			errs = append(errs, fmt.Errorf("reload restored authoritative zone: %w", err))
		}
	}

	if restoreResolver {
		if err := resolver.UpdateStubZone(ctx, zoneName); err != nil {
			errs = append(errs, fmt.Errorf("restore resolver stub zone: %w", err))
		} else {
			if err := resolver.CheckConfig(ctx); err != nil {
				errs = append(errs, fmt.Errorf("check restored resolver config: %w", err))
			}
			if err := resolver.Reload(ctx); err != nil {
				errs = append(errs, fmt.Errorf("reload restored resolver config: %w", err))
			} else if err := resolver.FlushZone(ctx, zoneName); err != nil {
				errs = append(errs, fmt.Errorf("flush restored resolver cache: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}

func sendHealthStatus(ctx context.Context, statusChan chan<- health.HealthStatus, status health.HealthStatus) bool {
	select {
	case statusChan <- status:
		return true
	case <-ctx.Done():
		return false
	}
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
func startStatusServer(cfg *config.AgentConfig, syncer *zonesync.Syncer, checker *health.Checker, routeCtrl plugin.RouteController, dnstapProcessor *dnstap.Processor, birdConfigStatus birdConfigRuntimeStatus, logger *zap.Logger) (*http.Server, error) {
	server := newStatusServer(cfg, syncer, checker, routeCtrl, dnstapProcessor, birdConfigStatus, logger)

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", server.Addr, err)
	}

	go func() {
		logger.Info("Starting status server", zap.String("listen", listener.Addr().String()))
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Error("Status server failed", zap.Error(err))
		}
	}()

	return server, nil
}

func newStatusServer(cfg *config.AgentConfig, syncer *zonesync.Syncer, checker *health.Checker, routeCtrl plugin.RouteController, dnstapProcessor *dnstap.Processor, birdConfigStatus birdConfigRuntimeStatus, logger *zap.Logger) *http.Server {
	router := newStatusRouter(cfg, syncer, checker, routeCtrl, dnstapProcessor, birdConfigStatus, logger)

	return &http.Server{
		Addr:              cfg.Metrics.Listen,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func newStatusRouter(cfg *config.AgentConfig, syncer *zonesync.Syncer, checker *health.Checker, routeCtrl plugin.RouteController, dnstapProcessor *dnstap.Processor, birdConfigStatus birdConfigRuntimeStatus, logger *zap.Logger) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	statusAuth := statusAuthMiddleware(cfg.Metrics.AuthToken)
	birdConfigStatus = birdConfigStatus.normalized()
	bgpStatus := bgpControlStatus(cfg, routeCtrl, birdConfigStatus)

	// Status endpoint
	router.GET("/status", statusAuth, func(c *gin.Context) {
		zoneStates := syncer.GetAllZoneStates()
		healthStatus := checker.CheckHealth(c.Request.Context())

		c.JSON(http.StatusOK, gin.H{
			"status":            "running",
			"version":           version,
			"zone_count":        len(zoneStates),
			"failed_zones":      syncer.FailedZoneCount(),
			"last_sync":         syncer.GetLastSuccessTime(),
			"is_stale":          syncer.IsStale(),
			"health":            healthStatus.Healthy,
			"health_checks":     len(healthStatus.Checks),
			"last_health_check": healthStatus.LastCheck,
			"bird_config": gin.H{
				"enabled":      birdConfigStatus.Enabled,
				"status":       birdConfigStatus.Status,
				"path":         birdConfigStatus.Path,
				"error":        birdConfigStatus.Error,
				"last_attempt": birdConfigStatus.LastAttempt,
				"last_success": birdConfigStatus.LastSuccess,
			},
			"bgp_control_status": bgpStatus,
			"bgp_announced": func() any {
				if routeCtrl != nil {
					return routeCtrl.IsAnnounced()
				}
				if bgpStatus == bgpControlStatusUnknown {
					return nil
				}
				return false
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

		if failedZones := syncer.FailedZoneCount(); failedZones > 0 {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":       "not ready",
				"reason":       "zone sync failures",
				"failed_zones": failedZones,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
		})
	})

	if !cfg.Metrics.Enabled {
		logger.Info("Metrics endpoint disabled")
		return router
	}

	// Metrics endpoint (Prometheus format)
	router.GET(metricPath(cfg.Metrics.Path), statusAuth, func(c *gin.Context) {
		var sb strings.Builder

		sb.WriteString("# arca-dns agent metrics\n")
		sb.WriteString("# HELP arca_dns_agent_sync_has_success Whether the agent has ever completed a successful sync (1/0).\n")
		sb.WriteString("# TYPE arca_dns_agent_sync_has_success gauge\n")
		sb.WriteString(fmt.Sprintf("arca_dns_agent_sync_has_success %d\n", boolToInt(!syncer.GetLastSuccessTime().IsZero())))

		sb.WriteString("\n# HELP arca_dns_agent_sync_stale Whether sync is currently considered stale (1/0).\n")
		sb.WriteString("# TYPE arca_dns_agent_sync_stale gauge\n")
		sb.WriteString(fmt.Sprintf("arca_dns_agent_sync_stale %d\n", boolToInt(syncer.IsStale())))

		sb.WriteString("\n# HELP arca_dns_agent_sync_failed_zones Number of zones with outstanding sync failures.\n")
		sb.WriteString("# TYPE arca_dns_agent_sync_failed_zones gauge\n")
		sb.WriteString(fmt.Sprintf("arca_dns_agent_sync_failed_zones %d\n", syncer.FailedZoneCount()))

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

		sb.WriteString("\n# HELP arca_dns_agent_bgp_control_status BGP control status (1 for the current status, 0 otherwise).\n")
		sb.WriteString("# TYPE arca_dns_agent_bgp_control_status gauge\n")
		for _, status := range []string{bgpControlStatusActive, bgpControlStatusDisabled, bgpControlStatusUnknown} {
			sb.WriteString(fmt.Sprintf("arca_dns_agent_bgp_control_status{status=%q} %d\n", status, boolToInt(bgpStatus == status)))
		}

		if routeCtrl != nil {
			sb.WriteString("\n# HELP arca_dns_agent_bgp_enabled Whether BGP control is enabled (1/0).\n")
			sb.WriteString("# TYPE arca_dns_agent_bgp_enabled gauge\n")
			sb.WriteString("arca_dns_agent_bgp_enabled 1\n")

			sb.WriteString("\n# HELP arca_dns_agent_bgp_routes_announced Whether routes are currently announced (1=announced, 0=withdrawn, -1=unknown).\n")
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

			sb.WriteString("\n# HELP arca_dns_agent_bgp_routes_announced Whether routes are currently announced (1=announced, 0=withdrawn, -1=unknown).\n")
			sb.WriteString("# TYPE arca_dns_agent_bgp_routes_announced gauge\n")
			if bgpStatus == bgpControlStatusUnknown {
				sb.WriteString("arca_dns_agent_bgp_routes_announced -1\n")
			} else {
				sb.WriteString("arca_dns_agent_bgp_routes_announced 0\n")
			}
		}

		sb.WriteString("\n# HELP arca_dns_agent_bird_config_status BIRD generated config status (1 for the current status, 0 otherwise).\n")
		sb.WriteString("# TYPE arca_dns_agent_bird_config_status gauge\n")
		for _, status := range []string{birdConfigStatusDisabled, birdConfigStatusApplied, birdConfigStatusUsingExisting} {
			sb.WriteString(fmt.Sprintf("arca_dns_agent_bird_config_status{status=%q} %d\n", status, boolToInt(birdConfigStatus.Status == status)))
		}

		sb.WriteString("\n# HELP arca_dns_agent_bird_config_last_attempt_timestamp_seconds Unix timestamp of the last generated BIRD config apply attempt (0 if none).\n")
		sb.WriteString("# TYPE arca_dns_agent_bird_config_last_attempt_timestamp_seconds gauge\n")
		if birdConfigStatus.LastAttempt.IsZero() {
			sb.WriteString("arca_dns_agent_bird_config_last_attempt_timestamp_seconds 0\n")
		} else {
			sb.WriteString(fmt.Sprintf("arca_dns_agent_bird_config_last_attempt_timestamp_seconds %d\n", birdConfigStatus.LastAttempt.Unix()))
		}

		sb.WriteString("\n# HELP arca_dns_agent_bird_config_last_success_timestamp_seconds Unix timestamp of the last successful generated BIRD config apply (0 if none).\n")
		sb.WriteString("# TYPE arca_dns_agent_bird_config_last_success_timestamp_seconds gauge\n")
		if birdConfigStatus.LastSuccess.IsZero() {
			sb.WriteString("arca_dns_agent_bird_config_last_success_timestamp_seconds 0\n")
		} else {
			sb.WriteString(fmt.Sprintf("arca_dns_agent_bird_config_last_success_timestamp_seconds %d\n", birdConfigStatus.LastSuccess.Unix()))
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

	return router
}

func statusAuthMiddleware(token string) gin.HandlerFunc {
	token = strings.TrimSpace(token)
	if token == "" {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		if statusAuthTokenMatches(c.GetHeader("Authorization"), token) {
			c.Next()
			return
		}

		c.Header("WWW-Authenticate", `Bearer realm="arca-dns-agent-status"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func statusAuthTokenMatches(authHeader string, expected string) bool {
	const bearerPrefix = "bearer "
	value := strings.TrimSpace(authHeader)
	if len(value) < len(bearerPrefix) || !strings.EqualFold(value[:len(bearerPrefix)], bearerPrefix) {
		return false
	}
	provided := strings.TrimSpace(value[len(bearerPrefix):])
	if provided == "" {
		return false
	}
	providedHash := sha256.Sum256([]byte(provided))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) == 1
}

func bgpControlStatus(cfg *config.AgentConfig, routeCtrl plugin.RouteController, birdConfigStatus birdConfigRuntimeStatus) string {
	if routeCtrl != nil {
		return bgpControlStatusActive
	}
	if cfg.BIRD.Enabled && birdConfigStatus.usingExisting() {
		return bgpControlStatusUnknown
	}
	return bgpControlStatusDisabled
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
