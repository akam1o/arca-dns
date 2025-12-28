package nsd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
	"go.uber.org/zap"
)

// Controller manages NSD operations via nsd-control.
type Controller struct {
	config config.NSDConfig
	logger *zap.Logger
}

// NewController creates a new NSD controller.
func NewController(cfg config.NSDConfig, logger *zap.Logger) *Controller {
	return &Controller{
		config: cfg,
		logger: logger,
	}
}

// ReloadZone reloads a specific zone in NSD.
// This triggers NSD to re-read the zone file from disk.
func (c *Controller) ReloadZone(zoneName string) error {
	if !c.config.Enabled {
		c.logger.Debug("NSD is disabled, skipping reload")
		return nil
	}

	c.logger.Info("Reloading zone in NSD",
		zap.String("zone", zoneName))

	ctx, cancel := context.WithTimeout(context.Background(), c.config.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.config.ControlPath, "reload", zoneName)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsd-control reload failed: %w, stderr: %s", err, stderr.String())
	}

	c.logger.Info("Zone reloaded successfully in NSD",
		zap.String("zone", zoneName),
		zap.String("output", stdout.String()))

	return nil
}

// NotifyZone sends a NOTIFY to slaves for a specific zone.
func (c *Controller) NotifyZone(zoneName string) error {
	if !c.config.Enabled {
		c.logger.Debug("NSD is disabled, skipping notify")
		return nil
	}

	c.logger.Info("Sending NOTIFY for zone",
		zap.String("zone", zoneName))

	ctx, cancel := context.WithTimeout(context.Background(), c.config.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.config.ControlPath, "notify", zoneName)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsd-control notify failed: %w, stderr: %s", err, stderr.String())
	}

	c.logger.Info("NOTIFY sent successfully",
		zap.String("zone", zoneName),
		zap.String("output", stdout.String()))

	return nil
}

// Reload reloads all zones in NSD.
func (c *Controller) Reload() error {
	if !c.config.Enabled {
		c.logger.Debug("NSD is disabled, skipping reload")
		return nil
	}

	c.logger.Info("Reloading all zones in NSD")

	ctx, cancel := context.WithTimeout(context.Background(), c.config.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.config.ControlPath, "reload")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsd-control reload failed: %w, stderr: %s", err, stderr.String())
	}

	c.logger.Info("All zones reloaded successfully in NSD",
		zap.String("output", stdout.String()))

	return nil
}

// CheckZone validates a zone file before loading it into NSD.
// Returns true if the zone file is valid, false otherwise.
func (c *Controller) CheckZone(zoneName string, zoneFile string) error {
	if !c.config.Enabled {
		c.logger.Debug("NSD is disabled, skipping zone check")
		return nil
	}

	c.logger.Debug("Validating zone file",
		zap.String("zone", zoneName),
		zap.String("file", zoneFile))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.config.CheckzonePath, zoneName, zoneFile)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zone validation failed: %w, output: %s, stderr: %s",
			err, stdout.String(), stderr.String())
	}

	c.logger.Debug("Zone file is valid",
		zap.String("zone", zoneName),
		zap.String("output", stdout.String()))

	return nil
}

// Status retrieves NSD status.
func (c *Controller) Status() (string, error) {
	if !c.config.Enabled {
		return "disabled", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.config.ControlPath, "status")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("nsd-control status failed: %w, stderr: %s", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// IsRunning checks if NSD is running and responsive.
func (c *Controller) IsRunning() bool {
	if !c.config.Enabled {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.config.ControlPath, "status")

	if err := cmd.Run(); err != nil {
		c.logger.Debug("NSD is not running or not responsive",
			zap.Error(err))
		return false
	}

	return true
}
