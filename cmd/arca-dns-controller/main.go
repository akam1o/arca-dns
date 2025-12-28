package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akam1o/arca-dns/cmd/arca-dns-controller/cmd"
	"github.com/akam1o/arca-dns/internal/controller/api"
	"github.com/akam1o/arca-dns/pkg/backend"
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

	// Initialize backend (in-memory for M1)
	store := backend.NewMemoryBackend()
	logger.Info("Backend initialized", zap.String("type", "memory"))

	// Initialize API handler
	handler := api.NewHandler(store, logger)

	// Setup router
	router := api.SetupRouter(handler, logger)

	// Create HTTP server
	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("HTTP server listening", zap.String("addr", listenAddr))
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	// Close backend
	if err := store.Close(); err != nil {
		logger.Error("Failed to close backend", zap.Error(err))
	}

	logger.Info("Server stopped")
}
