package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/bird"
	"github.com/akam1o/arca-dns/pkg/config"
	"go.uber.org/zap"
)

const (
	birdConfigStatusDisabled      = "disabled"
	birdConfigStatusApplied       = "applied"
	birdConfigStatusUsingExisting = "using_existing"
)

type birdConfigRuntimeStatus struct {
	Enabled     bool
	Status      string
	Path        string
	Error       string
	LastAttempt time.Time
	LastSuccess time.Time
}

type birdConfigApplyResult struct {
	Status        birdConfigRuntimeStatus
	ProtocolNames []string
}

func newBIRDConfigRuntimeStatus(cfg config.BIRDConfig) birdConfigRuntimeStatus {
	status := birdConfigRuntimeStatus{
		Enabled: cfg.Enabled && cfg.ConfigureOnStart.Enabled,
		Status:  birdConfigStatusDisabled,
		Path:    cfg.ConfigureOnStart.Path,
	}
	if status.Enabled {
		status.Status = birdConfigStatusUsingExisting
	}
	return status
}

func (s birdConfigRuntimeStatus) normalized() birdConfigRuntimeStatus {
	if s.Status == "" {
		s.Status = birdConfigStatusDisabled
	}
	return s
}

func (s birdConfigRuntimeStatus) usingExisting() bool {
	return s.normalized().Status == birdConfigStatusUsingExisting
}

func applyBIRDConfigOnStart(cfg config.BIRDConfig, client bird.Client, logger *zap.Logger) birdConfigApplyResult {
	result := birdConfigApplyResult{
		Status: newBIRDConfigRuntimeStatus(cfg),
	}
	if !cfg.ConfigureOnStart.Enabled {
		return result
	}

	result.Status.LastAttempt = time.Now()
	configText, protocolNames, err := bird.RenderAnycastConfig(cfg)
	if err != nil {
		result.Status.Error = err.Error()
		logger.Warn("Failed to render BIRD anycast config; continuing with existing BIRD runtime config",
			zap.Error(err))
		return result
	}
	result.ProtocolNames = protocolNames

	path := cfg.ConfigureOnStart.Path
	if err := ensureConfigDirectoryForPath(path); err != nil {
		result.Status.Error = err.Error()
		logger.Warn("Failed to create BIRD config directory; continuing with existing BIRD runtime config",
			zap.String("path", path),
			zap.Error(err))
		return result
	}

	previousConfig, hadPreviousConfig, err := readPreviousBIRDConfig(path)
	if err != nil {
		result.Status.Error = err.Error()
		logger.Warn("Failed to read existing BIRD config snippet; continuing with existing BIRD runtime config",
			zap.String("path", path),
			zap.Error(err))
		return result
	}

	if err := writeFileAtomic(path, []byte(configText), 0o644); err != nil {
		result.Status.Error = err.Error()
		logger.Warn("Failed to write BIRD config snippet; continuing with existing BIRD runtime config",
			zap.String("path", path),
			zap.Error(err))
		return result
	}

	if err := configureBIRD(client, cfg.CommandTimeout); err != nil {
		restoreErr := restoreBIRDConfig(path, previousConfig, hadPreviousConfig)
		if restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous BIRD config: %w", restoreErr))
		} else if hadPreviousConfig {
			if restoreConfigureErr := configureBIRD(client, cfg.CommandTimeout); restoreConfigureErr != nil {
				err = errors.Join(err, fmt.Errorf("restore BIRD runtime config: %w", restoreConfigureErr))
			}
		}
		result.Status.Error = err.Error()
		logger.Warn("BIRD configure failed; rolled back generated snippet and continuing with existing BIRD runtime config",
			zap.String("path", path),
			zap.Error(err))
		return result
	}

	result.Status.Status = birdConfigStatusApplied
	result.Status.Error = ""
	result.Status.LastSuccess = time.Now()
	logger.Info("BIRD configured from generated snippet",
		zap.String("path", path))
	return result
}

func readPreviousBIRDConfig(path string) ([]byte, bool, error) {
	if err := validateConfigDirectoryIfExistsForPath(path); err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return data, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, err
}

func restoreBIRDConfig(path string, previousConfig []byte, hadPreviousConfig bool) error {
	if err := validateConfigDirectoryIfExistsForPath(path); err != nil {
		return err
	}
	if hadPreviousConfig {
		return writeFileAtomic(path, previousConfig, 0o644)
	}
	if err := os.Remove(path); err == nil {
		if err := syncDir(filepath.Dir(path)); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := ensureConfigDirectoryForPath(path); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()

	if n, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	} else if n != len(data) {
		_ = tmp.Close()
		return io.ErrShortWrite
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	removeTemp = false
	if err := syncDir(dir); err != nil {
		return err
	}
	return nil
}

func ensureConfigDirectoryForPath(path string) error {
	dir := filepath.Dir(path)
	existed := true
	if err := validateExistingConfigDirectory(dir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat config directory: %w", err)
		}
		existed = false
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := validateExistingConfigDirectory(dir); err != nil {
		return fmt.Errorf("stat config directory: %w", err)
	}
	if !existed {
		if err := syncDir(filepath.Dir(dir)); err != nil {
			return fmt.Errorf("sync config directory parent: %w", err)
		}
	}

	return nil
}

func validateConfigDirectoryIfExistsForPath(path string) error {
	dir := filepath.Dir(path)
	if err := validateExistingConfigDirectory(dir); err != nil {
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
	return closeErr
}

func configureBIRD(client bird.Client, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, err := client.Exec(ctx, "configure")
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("empty BIRD configure response")
	}
	if resp.IsError() {
		return fmt.Errorf("BIRD configure error %d: %s", resp.Code, resp.RawText)
	}
	return nil
}
