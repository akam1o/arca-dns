package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/akam1o/arca-dns/pkg/config"
	"go.uber.org/zap"
)

// NewLogger builds a zap logger from arca-dns logging configuration.
func NewLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	zapCfg := zap.NewProductionConfig()

	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	zapCfg.Level = level

	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = "json"
	}
	switch format {
	case "json", "console":
		zapCfg.Encoding = format
	default:
		return nil, fmt.Errorf("invalid logging.format: %s (must be json or console)", cfg.Format)
	}

	output := strings.TrimSpace(cfg.Output)
	if output == "" {
		output = "stdout"
	}
	if err := ensureOutputPath(output); err != nil {
		return nil, err
	}
	zapCfg.OutputPaths = []string{output}
	zapCfg.ErrorOutputPaths = []string{"stderr"}
	zapCfg.DisableCaller = !cfg.EnableCaller
	zapCfg.DisableStacktrace = !cfg.EnableStacktrace

	return zapCfg.Build()
}

func parseLevel(level string) (zap.AtomicLevel, error) {
	atomic := zap.NewAtomicLevel()
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		atomic.SetLevel(zap.DebugLevel)
	case "info", "":
		atomic.SetLevel(zap.InfoLevel)
	case "warn":
		atomic.SetLevel(zap.WarnLevel)
	case "error":
		atomic.SetLevel(zap.ErrorLevel)
	default:
		return atomic, fmt.Errorf("invalid logging.level: %s (must be one of: debug, info, warn, error)", level)
	}
	return atomic, nil
}

func ensureOutputPath(output string) error {
	switch output {
	case "stdout", "stderr":
		return nil
	}

	dir := filepath.Dir(output)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create logging output directory: %w", err)
	}
	return nil
}
