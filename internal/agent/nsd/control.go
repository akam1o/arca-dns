package nsd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/commandpath"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/util"
	"go.uber.org/zap"
)

// Controller manages NSD operations via nsd-control.
type Controller struct {
	config config.NSDConfig
	logger *zap.Logger
}

const maxManagedZoneConfigFileSize = 4 * 1024 * 1024

// NewController creates a new NSD controller.
func NewController(cfg config.NSDConfig, logger *zap.Logger) *Controller {
	return &Controller{
		config: cfg,
		logger: logger,
	}
}

func (c *Controller) validatedControlPath() (string, error) {
	if err := commandpath.Validate("nsd.control_path", c.config.ControlPath); err != nil {
		return "", err
	}
	return c.config.ControlPath, nil
}

func (c *Controller) validatedCheckzonePath() (string, error) {
	if err := commandpath.Validate("nsd.checkzone_path", c.config.CheckzonePath); err != nil {
		return "", err
	}
	return c.config.CheckzonePath, nil
}

// EnsureZone ensures a managed NSD zone stanza exists, then reconfigures NSD if needed.
func (c *Controller) EnsureZone(zoneName string) error {
	if !c.config.Enabled {
		c.logger.Debug("NSD is disabled, skipping zone config update")
		return nil
	}

	normalized, err := normalizeZoneName(zoneName)
	if err != nil {
		return err
	}
	changed, err := c.updateManagedZoneConfig(func(zones map[string]struct{}) {
		zones[normalized] = struct{}{}
	})
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	c.logger.Info("Managed NSD zone config updated",
		zap.String("zone", normalized),
		zap.String("config", c.zoneConfigPath()))
	return c.Reconfig()
}

// DeleteZone removes a managed NSD zone stanza, then reconfigures NSD if needed.
func (c *Controller) DeleteZone(zoneName string) error {
	if !c.config.Enabled {
		c.logger.Debug("NSD is disabled, skipping zone config deletion")
		return nil
	}

	normalized, err := normalizeZoneName(zoneName)
	if err != nil {
		return err
	}
	changed, err := c.updateManagedZoneConfig(func(zones map[string]struct{}) {
		delete(zones, normalized)
	})
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	c.logger.Info("Managed NSD zone config removed",
		zap.String("zone", normalized),
		zap.String("config", c.zoneConfigPath()))
	return c.Reconfig()
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

	normalized, err := normalizeZoneName(zoneName)
	if err != nil {
		return err
	}
	controlPath, err := c.validatedControlPath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.config.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, controlPath, "reload", normalized)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsd-control reload failed: %w, stderr: %s", err, stderr.String())
	}

	c.logger.Info("Zone reloaded successfully in NSD",
		zap.String("zone", normalized),
		zap.String("output", stdout.String()))

	return nil
}

// Reconfig tells NSD to reload its configuration.
func (c *Controller) Reconfig() error {
	if !c.config.Enabled {
		c.logger.Debug("NSD is disabled, skipping reconfig")
		return nil
	}

	c.logger.Info("Reconfiguring NSD")

	controlPath, err := c.validatedControlPath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.config.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, controlPath, "reconfig")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsd-control reconfig failed: %w, stderr: %s", err, stderr.String())
	}

	c.logger.Info("NSD reconfigured successfully",
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

	normalized, err := normalizeZoneName(zoneName)
	if err != nil {
		return err
	}
	controlPath, err := c.validatedControlPath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.config.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, controlPath, "notify", normalized)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsd-control notify failed: %w, stderr: %s", err, stderr.String())
	}

	c.logger.Info("NOTIFY sent successfully",
		zap.String("zone", normalized),
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

	controlPath, err := c.validatedControlPath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.config.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, controlPath, "reload")

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

	normalized, err := normalizeZoneName(zoneName)
	if err != nil {
		return err
	}
	checkzonePath, err := c.validatedCheckzonePath()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, checkzonePath, normalized, zoneFile)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zone validation failed: %w, output: %s, stderr: %s",
			err, stdout.String(), stderr.String())
	}

	c.logger.Debug("Zone file is valid",
		zap.String("zone", normalized),
		zap.String("output", stdout.String()))

	return nil
}

// Status retrieves NSD status.
func (c *Controller) Status() (string, error) {
	if !c.config.Enabled {
		return "disabled", nil
	}

	controlPath, err := c.validatedControlPath()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, controlPath, "status")

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

	controlPath, err := c.validatedControlPath()
	if err != nil {
		c.logger.Debug("Invalid NSD control path", zap.Error(err))
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, controlPath, "status")

	if err := cmd.Run(); err != nil {
		c.logger.Debug("NSD is not running or not responsive",
			zap.Error(err))
		return false
	}

	return true
}

func (c *Controller) updateManagedZoneConfig(mutator func(map[string]struct{})) (bool, error) {
	path := c.zoneConfigPath()
	if err := config.ValidateNSDRenderedConfigPath("nsd.zone_config_path", path); err != nil {
		return false, err
	}
	if err := config.ValidateNSDRenderedConfigPath("nsd.zone_directory", c.config.ZoneDirectory); err != nil {
		return false, err
	}

	existing, zones, err := readManagedZoneConfig(path)
	if err != nil {
		return false, err
	}

	mutator(zones)
	after := renderManagedZoneConfig(path, c.config.ZoneDirectory, zones)
	if existing == after {
		return false, nil
	}

	if err := writeFileAtomic(path, []byte(after), 0644); err != nil {
		return false, fmt.Errorf("write NSD managed zone config: %w", err)
	}
	return true, nil
}

func (c *Controller) zoneConfigPath() string {
	if c.config.ZoneConfigPath != "" {
		return c.config.ZoneConfigPath
	}
	return filepath.Join(filepath.Dir(c.config.ConfigPath), "arca-dns-zones.conf")
}

func readManagedZoneConfig(path string) (string, map[string]struct{}, error) {
	zones := make(map[string]struct{})

	if err := validateConfigDirectoryIfExistsForPath(path); err != nil {
		return "", nil, err
	}

	data, err := readRegularManagedZoneConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", zones, nil
		}
		return "", nil, fmt.Errorf("read NSD managed zone config: %w", err)
	}

	existing := string(data)
	for _, line := range strings.Split(existing, "\n") {
		line = strings.TrimSpace(line)
		zoneName, ok := strings.CutPrefix(line, "# arca-dns-zone:")
		if !ok {
			continue
		}
		zoneName = strings.TrimSpace(zoneName)
		if zoneName == "" {
			continue
		}
		normalized, err := normalizeZoneName(zoneName)
		if err != nil {
			return "", nil, fmt.Errorf("invalid NSD managed zone marker: %w", err)
		}
		zones[normalized] = struct{}{}
	}

	return existing, zones, nil
}

func readRegularManagedZoneConfigFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("NSD managed zone config must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("NSD managed zone config must be a regular file: %s", path)
	}
	if info.Size() > maxManagedZoneConfigFileSize {
		return nil, fmt.Errorf("NSD managed zone config exceeds maximum size of %d bytes: %s", maxManagedZoneConfigFileSize, path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("NSD managed zone config changed while opening: %s", path)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("NSD managed zone config must be a regular file: %s", path)
	}
	if openedInfo.Size() > maxManagedZoneConfigFileSize {
		return nil, fmt.Errorf("NSD managed zone config exceeds maximum size of %d bytes: %s", maxManagedZoneConfigFileSize, path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxManagedZoneConfigFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManagedZoneConfigFileSize {
		return nil, fmt.Errorf("NSD managed zone config exceeds maximum size of %d bytes: %s", maxManagedZoneConfigFileSize, path)
	}
	return data, nil
}

func normalizeZoneName(zoneName string) (string, error) {
	normalized := model.NormalizeZoneName(zoneName)
	if err := model.ValidateZoneName(normalized); err != nil {
		return "", fmt.Errorf("invalid zone name %q: %w", zoneName, err)
	}
	return normalized, nil
}

func renderManagedZoneConfig(configPath, zoneDir string, zones map[string]struct{}) string {
	zoneNames := make([]string, 0, len(zones))
	for zoneName := range zones {
		zoneNames = append(zoneNames, model.NormalizeZoneName(zoneName))
	}
	sort.Strings(zoneNames)

	var b strings.Builder
	b.WriteString("# Generated by arca-dns-agent. DO NOT EDIT.\n")
	b.WriteString("# Include this file from nsd.conf, for example:\n")
	b.WriteString(fmt.Sprintf("# include: \"%s\"\n\n", configPath))

	for _, zoneName := range zoneNames {
		zoneFile := filepath.Join(zoneDir, util.SafeZoneFilename(zoneName)+".zone")
		b.WriteString(fmt.Sprintf("# arca-dns-zone: %s\n", zoneName))
		b.WriteString("zone:\n")
		b.WriteString(fmt.Sprintf("    name: \"%s\"\n", zoneName))
		b.WriteString(fmt.Sprintf("    zonefile: \"%s\"\n\n", zoneFile))
	}

	return b.String()
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dirPath := filepath.Dir(path)
	if err := ensureConfigDirectoryForPath(path); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dirPath, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if n, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	} else if n != len(data) {
		_ = tmp.Close()
		return io.ErrShortWrite
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanupTmp = false
	if err := syncDir(dirPath); err != nil {
		return err
	}
	return nil
}

func ensureConfigDirectoryForPath(path string) error {
	dirPath := filepath.Dir(path)
	existed := true
	if err := validateExistingConfigDirectory(dirPath); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat config directory: %w", err)
		}
		existed = false
	}

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := validateExistingConfigDirectory(dirPath); err != nil {
		return fmt.Errorf("stat config directory: %w", err)
	}
	if !existed {
		if err := syncDir(filepath.Dir(dirPath)); err != nil {
			return fmt.Errorf("fsync config directory parent: %w", err)
		}
	}

	return nil
}

func validateConfigDirectoryIfExistsForPath(path string) error {
	dirPath := filepath.Dir(path)
	if err := validateExistingConfigDirectory(dirPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat config directory: %w", err)
	}
	return nil
}

func validateExistingConfigDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config directory must not be a symlink: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("config path must be a directory: %s", path)
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		if errors.Is(syncErr, syscall.EINVAL) || errors.Is(syncErr, syscall.ENOTSUP) {
			syncErr = nil
		}
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}
