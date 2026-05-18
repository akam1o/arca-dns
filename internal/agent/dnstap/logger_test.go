package dnstap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestNewLoggerRejectsSymlinkedLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	realPath := filepath.Join(tmpDir, "real.log")
	linkPath := filepath.Join(tmpDir, "dnstap.log")
	require.NoError(t, os.WriteFile(realPath, []byte("unchanged"), 0644))
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	_, err := NewLogger(LoggerConfig{LogFile: linkPath}, NewSampler(SamplerConfig{}), zaptest.NewLogger(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dnstap log file")
	assert.Contains(t, err.Error(), "symlink")

	data, readErr := os.ReadFile(realPath)
	require.NoError(t, readErr)
	assert.Equal(t, "unchanged", string(data))
}

func TestNewLoggerRejectsSymlinkedLogDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "target")
	logDir := filepath.Join(tmpDir, "logs")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	if err := os.Symlink(targetDir, logDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	_, err := NewLogger(LoggerConfig{LogFile: filepath.Join(logDir, "dnstap.log")}, NewSampler(SamplerConfig{}), zaptest.NewLogger(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dnstap log directory")
	assert.Contains(t, err.Error(), "symlink")

	_, statErr := os.Stat(filepath.Join(targetDir, "dnstap.log"))
	assert.True(t, os.IsNotExist(statErr), "DNSTap logger should not write through symlinked log directory")
}
