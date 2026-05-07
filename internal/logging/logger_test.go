package logging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoggerHonorsLevelFormatAndOutput(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "arca-dns.log")

	logger, err := NewLogger(config.LoggingConfig{
		Level:            "debug",
		Format:           "json",
		Output:           logPath,
		EnableCaller:     false,
		EnableStacktrace: false,
	})
	require.NoError(t, err)

	logger.Debug("debug-visible")
	require.NoError(t, logger.Sync())

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "debug-visible")
	assert.Contains(t, string(data), `"level":"debug"`)
}

func TestNewLoggerRejectsInvalidFormat(t *testing.T) {
	_, err := NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "xml",
		Output: "stdout",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logging.format")
}
