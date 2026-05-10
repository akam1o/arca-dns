package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
	if hadPreviousConfig {
		return writeFileAtomic(path, previousConfig, 0o644)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
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

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
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
	return nil
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
