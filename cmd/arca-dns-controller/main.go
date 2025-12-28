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
	"github.com/akam1o/arca-dns/internal/controller/service"
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
	listenAddr string
	configFile string
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
		Run:   runServe,
	}

	serveCmd.Flags().StringVar(&listenAddr, "listen", ":8080", "HTTP server listen address")
	serveCmd.Flags().StringVar(&configFile, "config", "", "Path to configuration file")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(cmd.NewDNSSECCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("arca-dns-controller starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("listen", listenAddr))

	// Load configuration (use defaults if no config file)
	cfg := config.DefaultControllerConfig()
	if configFile != "" {
		// TODO: Implement config file loading
		logger.Info("Config file loading not yet implemented, using defaults")
	}

	// Override listen address from flag if provided
	if listenAddr != "" {
		cfg.API.Listen = listenAddr
	}

	// Initialize backend (in-memory for now)
	store := backend.NewMemoryBackend()
	logger.Info("Backend initialized", zap.String("type", "memory"))

	// Initialize DNSSEC signing service if enabled
	var signingService *service.SigningService
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.DNSSEC.Enabled {
		logger.Info("Initializing DNSSEC signing service")

		// Load or generate master key
		masterKey, src, err := dnssec.LoadMasterKey(dnssec.MasterKeyOptions{
			KeyDirectory:      cfg.DNSSEC.KeyDirectory,
			AllowAutoGenerate: cfg.DNSSEC.MasterKeyAutoGenerate,
		})
		if err != nil {
			logger.Fatal("Failed to load master key", zap.Error(err))
		}
		logger.Info("Master key loaded", zap.String("source", string(src)))

		// Initialize key manager
		keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
			KeyDirectory: cfg.DNSSEC.KeyDirectory,
			MasterKey:    masterKey,
			Algorithm:    cfg.DNSSEC.Algorithm,
			KSKBits:      cfg.DNSSEC.KSKKeySize,
			ZSKBits:      cfg.DNSSEC.ZSKKeySize,
		})
		if err != nil {
			logger.Fatal("Failed to create key manager", zap.Error(err))
		}

		// Create signing service (Note: SignerOptions are set per-zone in SigningService)
		signingService = service.NewSigningService(store, keyManager, logger)
		logger.Info("DNSSEC signing service initialized")

		// Initialize scheduler if enabled
		if cfg.DNSSEC.SchedulerEnabled {
			// Validate scheduler configuration
			if cfg.DNSSEC.SchedulerCheckInterval <= 0 {
				logger.Fatal("Invalid scheduler check interval",
					zap.Duration("interval", cfg.DNSSEC.SchedulerCheckInterval))
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
				store,           // ZoneLister
				signingService,  // Signer
				&dnssec.RealClock{},
				ticker,
				nil, // metrics (TODO: implement)
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
	handler := api.NewHandler(store, signingService, logger)

	// Setup router
	router := api.SetupRouter(handler, logger)

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.API.Listen,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("HTTP server listening", zap.String("addr", cfg.API.Listen))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// First, stop accepting new requests
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
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

	logger.Info("Server stopped")
}
