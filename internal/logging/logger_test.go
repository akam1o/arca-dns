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

func TestNewLoggerRejectsUnsafeOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "relative",
			output: "arca-dns.log",
			want:   "absolute path",
		},
		{
			name:   "surrounding whitespace",
			output: " " + filepath.Join(tmpDir, "arca-dns.log") + " ",
			want:   "surrounding whitespace",
		},
		{
			name:   "newline",
			output: filepath.Join(tmpDir, "arca-dns.log") + "\nextra",
			want:   "control characters",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewLogger(config.LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: tc.output,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestNewLoggerRejectsSymlinkedOutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	realPath := filepath.Join(tmpDir, "real.log")
	linkPath := filepath.Join(tmpDir, "arca-dns.log")
	require.NoError(t, os.WriteFile(realPath, []byte("unchanged"), 0644))
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	_, err := NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: linkPath,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logging output file")
	assert.Contains(t, err.Error(), "symlink")

	data, readErr := os.ReadFile(realPath)
	require.NoError(t, readErr)
	assert.Equal(t, "unchanged", string(data))
}

func TestNewLoggerRejectsSymlinkedOutputDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "target")
	outputDir := filepath.Join(tmpDir, "logs")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	if err := os.Symlink(targetDir, outputDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	_, err := NewLogger(config.LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: filepath.Join(outputDir, "arca-dns.log"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logging output directory")
	assert.Contains(t, err.Error(), "symlink")

	_, statErr := os.Stat(filepath.Join(targetDir, "arca-dns.log"))
	assert.True(t, os.IsNotExist(statErr), "logger should not write through symlinked output directory")
}
