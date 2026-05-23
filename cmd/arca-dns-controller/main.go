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

	"github.com/akam1o/arca-dns/cmd/arca-dns-controller/cmd"
	"github.com/akam1o/arca-dns/internal/controller/api"
	ctrlmetrics "github.com/akam1o/arca-dns/internal/controller/metrics"
	"github.com/akam1o/arca-dns/internal/controller/service"
	applogging "github.com/akam1o/arca-dns/internal/logging"
	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	listenAddr              string
	observabilityListenAddr string
	configFile              string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "arca-dns-controller",
		Short: "arca-dns Controller - Control plane for BGP Anycast DNS",
		Long: `arca-dns-controller is the control plane component that manages DNS zones,
performs DNSSEC signing, and distributes zone artifacts to agents.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the controller API server",
		Long:  "Start the controller API server to handle zone management requests",
		RunE:  runServe,
	}

	serveCmd.Flags().StringVar(&listenAddr, "listen", ":8080", "HTTP API server listen address")
	serveCmd.Flags().StringVar(&observabilityListenAddr, "observability-listen", ":9053", "HTTP observability server listen address")
	serveCmd.Flags().StringVar(&configFile, "config", "", "Path to configuration file")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(cmd.NewDNSSECCmd())
	rootCmd.AddCommand(cmd.NewMigrateCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	// Initialize a bootstrap logger until configuration is loaded.
	bootstrapLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Load configuration (defaults < YAML file < environment variables)
	cfg, err := config.LoadControllerConfig(configFile)
	if err != nil {
		_ = bootstrapLogger.Sync()
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	applyServeFlagOverrides(cmd, cfg)
	if err := config.ValidateControllerConfig(cfg); err != nil {
		_ = bootstrapLogger.Sync()
		return fmt.Errorf("invalid configuration after applying command-line flags: %w", err)
	}

	logger, err := applogging.NewLogger(cfg.Logging)
	if err != nil {
		_ = bootstrapLogger.Sync()
		return fmt.Errorf("failed to initialize configured logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()
	_ = bootstrapLogger.Sync()

	logger.Info("arca-dns-controller starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("listen", cfg.API.Listen),
		zap.String("observability_listen", cfg.Observability.Listen))

	// Initialize backend from configuration
	store, err := newStoreFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize backend: %w", err)
	}
	storeOpen := true
	defer func() {
		if storeOpen {
			if err := store.Close(); err != nil {
				logger.Error("Failed to close backend", zap.Error(err))
			}
		}
	}()
	logger.Info("Backend initialized", zap.String("type", cfg.Backend.Type))

	// Metrics (Prometheus text format).
	metrics := ctrlmetrics.NewControllerMetrics()
	store = ctrlmetrics.WrapZoneStore(store, metrics)
	if err := validateControllerStoreCapabilities(store); err != nil {
		return err
	}

	// Initialize DNSSEC signing service if enabled
	var signingService *service.SigningService
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.DNSSEC.Enabled {
		logger.Info("Initializing DNSSEC signing service")
		keyDirectory := cfg.DNSSECKeyDirectory()

		// Load or generate master key
		masterKey, src, err := dnssec.LoadMasterKey(dnssec.MasterKeyOptions{
			KeyDirectory:      keyDirectory,
			AllowAutoGenerate: cfg.DNSSEC.MasterKeyAutoGenerate,
		})
		if err != nil {
			return fmt.Errorf("failed to load master key: %w", err)
		}
		logger.Info("Master key loaded", zap.String("source", string(src)))

		// Initialize key manager
		keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
			KeyDirectory: keyDirectory,
			MasterKey:    masterKey,
			Algorithm:    cfg.DNSSEC.Algorithm,
			KSKBits:      cfg.DNSSEC.KSKKeySize,
			ZSKBits:      cfg.DNSSEC.ZSKKeySize,
		})
		if err != nil {
			return fmt.Errorf("failed to create key manager: %w", err)
		}

		signingService = service.NewSigningService(
			store,
			keyManager,
			cfg.Storage.ArtifactDirectory,
			metrics,
			logger,
			signerOptionsFromConfig(cfg.DNSSEC),
		)
		signingService.SetMaxArtifactsPerZone(cfg.Storage.MaxVersionsPerZone)
		logger.Info("DNSSEC signing service initialized")

		// Initialize scheduler if enabled
		if cfg.DNSSEC.SchedulerEnabled {
			// Validate scheduler configuration
			if cfg.DNSSEC.SchedulerCheckInterval <= 0 {
				return fmt.Errorf("invalid scheduler check interval: %s", cfg.DNSSEC.SchedulerCheckInterval)
			}

			logger.Info("Initializing DNSSEC signature freshness scheduler")

			schedulerConfig := dnssec.SchedulerConfig{
				CheckInterval:     cfg.DNSSEC.SchedulerCheckInterval,
				ResignThreshold:   cfg.DNSSEC.ResignThreshold,
				InitialJitter:     5 * time.Minute,
				FailureBackoffMin: 5 * time.Minute,
				FailureBackoffMax: 6 * time.Hour,
			}

			ticker := dnssec.NewRealTicker(schedulerConfig.CheckInterval)
			scheduler := dnssec.NewScheduler(
				schedulerConfig,
				store,          // ZoneLister
				signingService, // Signer
				&dnssec.RealClock{},
				ticker,
				metrics,
				logger,
			)

			// Start scheduler in background with proper lifecycle management
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer ticker.Stop()
				if err := scheduler.Start(ctx); err != nil && err != context.Canceled {
					logger.Error("Scheduler stopped with error", zap.Error(err))
				}
			}()
			logger.Info("Scheduler started",
				zap.Duration("check_interval", schedulerConfig.CheckInterval),
				zap.Duration("resign_threshold", schedulerConfig.ResignThreshold))
		}
	}

	// Initialize API handler
	handler := api.NewHandler(store, signingService, metrics, api.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}, logger)
	handler.SetArtifactSignatureKey(cfg.API.ArtifactSignatureKey)

	// Setup routers
	apiRouter := api.SetupRouter(handler, &cfg.API, logger)
	observabilityRouter := api.SetupObservabilityRouterWithConfig(handler, &cfg.API, &cfg.Observability, logger)

	// Create HTTP servers
	apiSrv := newControllerHTTPServer(cfg.API.Listen, apiRouter)
	observabilitySrv := newControllerHTTPServer(cfg.Observability.Listen, observabilityRouter)

	// Start servers in goroutines
	serverErrCh := make(chan controllerHTTPServerError, 2)
	startControllerHTTPServer(logger, "api", apiSrv, serverErrCh)
	startControllerHTTPServer(logger, "observability", observabilitySrv, serverErrCh)

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	var serverErr error
	select {
	case sig := <-quit:
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
	case err := <-serverErrCh:
		serverErr = err
		logger.Error("HTTP server stopped with error", zap.String("server", err.name), zap.Error(err.err))
	}

	logger.Info("Shutting down servers...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// First, stop accepting new requests
	if err := apiSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("API server forced to shutdown", zap.Error(err))
	}
	if err := observabilitySrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Observability server forced to shutdown", zap.Error(err))
	}

	// Cancel context to stop scheduler
	cancel()

	// Wait for background tasks with timeout (max 30 seconds for scheduler to finish)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Background tasks stopped gracefully")
	case <-time.After(30 * time.Second):
		logger.Warn("Background tasks did not stop within timeout, proceeding with shutdown")
	}

	// Close backend after all goroutines have stopped
	if err := store.Close(); err != nil {
		logger.Error("Failed to close backend", zap.Error(err))
	}
	storeOpen = false

	logger.Info("Servers stopped")
	if serverErr != nil {
		return serverErr
	}
	return nil
}

type controllerHTTPServerError struct {
	name string
	err  error
}

func (e controllerHTTPServerError) Error() string {
	return fmt.Sprintf("%s server failed: %v", e.name, e.err)
}

func (e controllerHTTPServerError) Unwrap() error {
	return e.err
}

func startControllerHTTPServer(logger *zap.Logger, name string, srv *http.Server, errCh chan<- controllerHTTPServerError) {
	go func() {
		logger.Info("HTTP server listening", zap.String("server", name), zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- controllerHTTPServerError{name: name, err: err}
		}
	}()
}

func validateControllerStoreCapabilities(store backend.ZoneStore) error {
	if store == nil {
		return fmt.Errorf("backend store is nil")
	}
	if _, ok := store.(backend.ConditionalDeleteStore); !ok {
		return fmt.Errorf("backend missing required capability: %s", backend.CapabilityConditionalDeleteStore)
	}
	return nil
}

func applyServeFlagOverrides(cmd *cobra.Command, cfg *config.ControllerConfig) {
	if cmd.Flags().Changed("listen") {
		cfg.API.Listen = listenAddr
	}
	if cmd.Flags().Changed("observability-listen") {
		cfg.Observability.Listen = observabilityListenAddr
	}
}

func newStoreFromConfig(cfg *config.ControllerConfig) (backend.ZoneStore, error) {
	configMap := make(map[string]interface{})

	switch cfg.Backend.Type {
	case "sqlite":
		if cfg.Backend.SQLite.DSN != "" {
			configMap["dsn"] = cfg.Backend.SQLite.DSN
		}
		return backend.NewBackend("sqlite", configMap)

	case "postgres":
		if cfg.Backend.Postgres.DSN == "" {
			return nil, fmt.Errorf("postgres backend requires backend.postgres.dsn")
		}
		configMap["dsn"] = cfg.Backend.Postgres.DSN
		if cfg.Backend.Postgres.MaxOpenConns > 0 {
			configMap["max_open_conns"] = cfg.Backend.Postgres.MaxOpenConns
		}
		if cfg.Backend.Postgres.MaxIdleConns > 0 {
			configMap["max_idle_conns"] = cfg.Backend.Postgres.MaxIdleConns
		}
		if cfg.Backend.Postgres.ConnMaxLifetime > 0 {
			configMap["conn_max_lifetime"] = cfg.Backend.Postgres.ConnMaxLifetime
		}
		return backend.NewBackend("postgres", configMap)

	case "mysql":
		if cfg.Backend.MySQL.DSN == "" {
			return nil, fmt.Errorf("mysql backend requires backend.mysql.dsn")
		}
		configMap["dsn"] = cfg.Backend.MySQL.DSN
		if cfg.Backend.MySQL.MaxOpenConns > 0 {
			configMap["max_open_conns"] = cfg.Backend.MySQL.MaxOpenConns
		}
		if cfg.Backend.MySQL.MaxIdleConns > 0 {
			configMap["max_idle_conns"] = cfg.Backend.MySQL.MaxIdleConns
		}
		if cfg.Backend.MySQL.ConnMaxLifetime > 0 {
			configMap["conn_max_lifetime"] = cfg.Backend.MySQL.ConnMaxLifetime
		}
		return backend.NewBackend("mysql", configMap)

	case "git":
		if cfg.Backend.Git.RepositoryPath == "" {
			return nil, fmt.Errorf("git backend requires backend.git.repository_path")
		}
		configMap["repository_path"] = cfg.Backend.Git.RepositoryPath
		if cfg.Backend.Git.Branch != "" {
			configMap["branch"] = cfg.Backend.Git.Branch
		}
		if cfg.Backend.Git.Author != "" {
			configMap["author"] = cfg.Backend.Git.Author
		}
		if cfg.Backend.Git.Email != "" {
			configMap["email"] = cfg.Backend.Git.Email
		}
		if cfg.Backend.Git.RemoteURL != "" {
			configMap["remote_url"] = cfg.Backend.Git.RemoteURL
		}
		configMap["auto_push"] = cfg.Backend.Git.AutoPush
		if cfg.Backend.Git.AutoPull != nil {
			configMap["auto_pull"] = *cfg.Backend.Git.AutoPull
		}
		if cfg.Backend.Git.PullInterval > 0 {
			configMap["pull_interval"] = cfg.Backend.Git.PullInterval
		}
		return backend.NewBackend("git", configMap)

	case "etcd":
		if len(cfg.Backend.Etcd.Endpoints) == 0 {
			return nil, fmt.Errorf("etcd backend requires backend.etcd.endpoints")
		}
		configMap["endpoints"] = cfg.Backend.Etcd.Endpoints
		if cfg.Backend.Etcd.Prefix != "" {
			configMap["prefix"] = cfg.Backend.Etcd.Prefix
		}
		if cfg.Backend.Etcd.Username != "" {
			configMap["username"] = cfg.Backend.Etcd.Username
		}
		if cfg.Backend.Etcd.Password != "" {
			configMap["password"] = cfg.Backend.Etcd.Password
		}
		if cfg.Backend.Etcd.DialTimeout > 0 {
			configMap["dial_timeout"] = cfg.Backend.Etcd.DialTimeout
		}
		if cfg.Backend.Etcd.RequestTimeout > 0 {
			configMap["request_timeout"] = cfg.Backend.Etcd.RequestTimeout
		}
		return backend.NewBackend("etcd", configMap)

	default:
		return nil, fmt.Errorf("unsupported backend type: %s", cfg.Backend.Type)
	}
}

func signerOptionsFromConfig(cfg config.DNSSECConfig) dnssec.SignerOptions {
	options := dnssec.DefaultSignerOptions()
	options.Inception = -cfg.SignatureInception
	options.Expiration = cfg.SignatureValidity
	options.ResignThreshold = cfg.ResignThreshold
	options.NSEC3Enabled = cfg.NSEC3
	options.NSEC3Iterations = cfg.NSEC3Iterations
	options.NSEC3SaltLength = cfg.NSEC3SaltLength
	return options
}

func newControllerHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
