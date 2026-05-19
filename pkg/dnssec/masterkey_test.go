package dnssec

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMasterKeyB64_Valid(t *testing.T) {
	// Generate a valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(validKey)

	key, err := ParseMasterKeyB64(encoded)
	require.NoError(t, err)
	assert.Equal(t, validKey, key)
	assert.Len(t, key, 32)
}

func TestParseMasterKeyB64_InvalidBase64(t *testing.T) {
	key, err := ParseMasterKeyB64("not-valid-base64!!!")
	assert.ErrorIs(t, err, ErrInvalidMasterKey)
	assert.Nil(t, key)
}

func TestParseMasterKeyB64_WrongLength(t *testing.T) {
	// 16 bytes instead of 32
	shortKey := make([]byte, 16)
	encoded := base64.StdEncoding.EncodeToString(shortKey)

	key, err := ParseMasterKeyB64(encoded)
	assert.ErrorIs(t, err, ErrInvalidMasterKey)
	assert.Nil(t, key)
}

func TestParseMasterKey_HexValid(t *testing.T) {
	// 32 bytes => 64 hex chars
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(255 - i)
	}
	hexStr := hex.EncodeToString(keyBytes)

	parsed, err := ParseMasterKey(hexStr)
	require.NoError(t, err)
	assert.Equal(t, keyBytes, parsed)
}

func TestGenerateMasterKey(t *testing.T) {
	key1, err := GenerateMasterKey()
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	key2, err := GenerateMasterKey()
	require.NoError(t, err)
	assert.Len(t, key2, 32)

	// Keys should be different (random)
	assert.NotEqual(t, key1, key2)
}

func TestSaveMasterKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "_masterkey")

	// Generate and save key
	key, err := GenerateMasterKey()
	require.NoError(t, err)

	err = SaveMasterKey(keyPath, key)
	require.NoError(t, err)

	// Verify file exists with correct permissions
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Read and verify content
	content, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(string(content))
	require.NoError(t, err)
	assert.Equal(t, key, decoded)
}

func TestSaveMasterKey_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "subdir", "keys", "_masterkey")

	key, err := GenerateMasterKey()
	require.NoError(t, err)

	err = SaveMasterKey(keyPath, key)
	require.NoError(t, err)

	// Verify directory was created
	assert.DirExists(t, filepath.Dir(keyPath))
}

func TestSaveMasterKey_RejectsUnsafePath(t *testing.T) {
	tmpDir := t.TempDir()
	key, err := GenerateMasterKey()
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "relative",
			path: "_masterkey",
			want: "absolute path",
		},
		{
			name: "surrounding whitespace",
			path: " " + filepath.Join(tmpDir, "_masterkey") + " ",
			want: "surrounding whitespace",
		},
		{
			name: "newline",
			path: filepath.Join(tmpDir, "_masterkey") + "\nextra",
			want: "control characters",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := SaveMasterKey(tc.path, key)
			require.Error(t, err)
			require.Contains(t, err.Error(), "master key file")
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestSaveMasterKey_RejectsSymlinkedDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "keys")
	targetDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.Mkdir(targetDir, 0700))
	if err := os.Symlink(targetDir, keyDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	key, err := GenerateMasterKey()
	require.NoError(t, err)

	err = SaveMasterKey(filepath.Join(keyDir, "_masterkey"), key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key directory")
	assert.Contains(t, err.Error(), "symlink")
	assert.NoFileExists(t, filepath.Join(targetDir, "_masterkey"))
}

func TestSaveMasterKey_DoesNotFollowPredictableTempSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "_masterkey")
	sentinelPath := filepath.Join(tmpDir, "sentinel")
	sentinel := []byte("keep")
	require.NoError(t, os.WriteFile(sentinelPath, sentinel, 0600))
	require.NoError(t, os.Symlink(sentinelPath, keyPath+".tmp"))

	key, err := GenerateMasterKey()
	require.NoError(t, err)

	err = SaveMasterKey(keyPath, key)
	require.NoError(t, err)

	contents, err := os.ReadFile(sentinelPath)
	require.NoError(t, err)
	assert.Equal(t, sentinel, contents)

	linkInfo, err := os.Lstat(keyPath + ".tmp")
	require.NoError(t, err)
	assert.NotZero(t, linkInfo.Mode()&os.ModeSymlink)
}

func TestLoadMasterKey_FromEnv(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a key and set environment variable
	key, err := GenerateMasterKey()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(key)

	os.Setenv(MasterKeyEnvVar, encoded)
	defer os.Unsetenv(MasterKeyEnvVar)

	opts := MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: false,
	}

	loadedKey, src, err := LoadMasterKey(opts)
	require.NoError(t, err)
	assert.Equal(t, MasterKeySourceEnv, src)
	assert.Equal(t, key, loadedKey)
}

func TestLoadMasterKey_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "_masterkey")

	// Generate and save key to file
	key, err := GenerateMasterKey()
	require.NoError(t, err)
	err = SaveMasterKey(keyPath, key)
	require.NoError(t, err)

	opts := MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: false,
	}

	loadedKey, src, err := LoadMasterKey(opts)
	require.NoError(t, err)
	assert.Equal(t, MasterKeySourceFile, src)
	assert.Equal(t, key, loadedKey)
}

func TestLoadMasterKey_RejectsSymlinkedFile(t *testing.T) {
	t.Setenv(MasterKeyEnvVar, "")
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "_masterkey")
	realKeyPath := filepath.Join(tmpDir, "_masterkey.real")

	key, err := GenerateMasterKey()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(key)
	require.NoError(t, os.WriteFile(realKeyPath, []byte(encoded), 0600))
	if err := os.Symlink(realKeyPath, keyPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	loadedKey, src, err := LoadMasterKey(MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: false,
	})

	require.Error(t, err)
	assert.Nil(t, loadedKey)
	assert.Empty(t, src)
	assert.Contains(t, err.Error(), "read master key file")
	assert.Contains(t, err.Error(), "symlink")
}

func TestLoadMasterKey_RejectsWorldReadableFile(t *testing.T) {
	t.Setenv(MasterKeyEnvVar, "")
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "_masterkey")

	key, err := GenerateMasterKey()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(key)
	require.NoError(t, os.WriteFile(keyPath, []byte(encoded), 0600))
	require.NoError(t, os.Chmod(keyPath, 0644))

	loadedKey, src, err := LoadMasterKey(MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: false,
	})

	require.Error(t, err)
	assert.Nil(t, loadedKey)
	assert.Empty(t, src)
	assert.Contains(t, err.Error(), "read master key file")
	assert.Contains(t, err.Error(), "permissions")
	assert.Contains(t, err.Error(), "other access")
}

func TestLoadMasterKey_AllowsGroupReadableFile(t *testing.T) {
	t.Setenv(MasterKeyEnvVar, "")
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "_masterkey")

	key, err := GenerateMasterKey()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(key)
	require.NoError(t, os.WriteFile(keyPath, []byte(encoded), 0600))
	require.NoError(t, os.Chmod(keyPath, 0640))

	loadedKey, src, err := LoadMasterKey(MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: false,
	})

	require.NoError(t, err)
	assert.Equal(t, MasterKeySourceFile, src)
	assert.Equal(t, key, loadedKey)
}

func TestLoadMasterKey_RejectsSymlinkedDirectory(t *testing.T) {
	t.Setenv(MasterKeyEnvVar, "")
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "keys")
	targetDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.Mkdir(targetDir, 0700))
	if err := os.Symlink(targetDir, keyDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	key, err := GenerateMasterKey()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(key)
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "_masterkey"), []byte(encoded), 0600))

	loadedKey, src, err := LoadMasterKey(MasterKeyOptions{
		KeyDirectory:      keyDir,
		AllowAutoGenerate: false,
	})

	require.Error(t, err)
	assert.Nil(t, loadedKey)
	assert.Empty(t, src)
	assert.Contains(t, err.Error(), "master key directory")
	assert.Contains(t, err.Error(), "symlink")
}

func TestLoadMasterKey_RejectsUnsafeKeyDirectory(t *testing.T) {
	t.Setenv(MasterKeyEnvVar, "")
	tmpDir := t.TempDir()

	tests := []struct {
		name         string
		keyDirectory string
		want         string
	}{
		{
			name:         "relative",
			keyDirectory: "keys",
			want:         "absolute path",
		},
		{
			name:         "surrounding whitespace",
			keyDirectory: " " + tmpDir + " ",
			want:         "surrounding whitespace",
		},
		{
			name:         "newline",
			keyDirectory: tmpDir + "\nextra",
			want:         "control characters",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, src, err := LoadMasterKey(MasterKeyOptions{
				KeyDirectory:      tc.keyDirectory,
				AllowAutoGenerate: false,
			})
			require.Error(t, err)
			require.Nil(t, key)
			require.Empty(t, src)
			require.Contains(t, err.Error(), "master key directory")
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoadMasterKey_RejectsUnsafeFileName(t *testing.T) {
	t.Setenv(MasterKeyEnvVar, "")
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		fileName string
		want     string
	}{
		{
			name:     "parent traversal",
			fileName: "../_masterkey",
			want:     "not a path",
		},
		{
			name:     "absolute",
			fileName: filepath.Join(tmpDir, "_masterkey"),
			want:     "not a path",
		},
		{
			name:     "surrounding whitespace",
			fileName: " _masterkey ",
			want:     "surrounding whitespace",
		},
		{
			name:     "newline",
			fileName: "_masterkey\nextra",
			want:     "control characters",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, src, err := LoadMasterKey(MasterKeyOptions{
				KeyDirectory:      tmpDir,
				FileName:          tc.fileName,
				AllowAutoGenerate: false,
			})
			require.Error(t, err)
			require.Nil(t, key)
			require.Empty(t, src)
			require.Contains(t, err.Error(), "master key filename")
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoadMasterKey_AutoGenerate(t *testing.T) {
	tmpDir := t.TempDir()

	opts := MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: true,
	}

	// First load should generate
	key1, src1, err := LoadMasterKey(opts)
	require.NoError(t, err)
	assert.Equal(t, MasterKeySourceGenerated, src1)
	assert.Len(t, key1, 32)

	// Second load should read from file
	key2, src2, err := LoadMasterKey(opts)
	require.NoError(t, err)
	assert.Equal(t, MasterKeySourceFile, src2)
	assert.Equal(t, key1, key2)
}

func TestLoadMasterKey_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	opts := MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: false,
	}

	key, src, err := LoadMasterKey(opts)
	assert.ErrorIs(t, err, ErrMasterKeyNotFound)
	assert.Empty(t, src)
	assert.Nil(t, key)
}

func TestLoadMasterKey_EnvPriorityOverFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "_masterkey")

	// Create file key
	fileKey, err := GenerateMasterKey()
	require.NoError(t, err)
	err = SaveMasterKey(keyPath, fileKey)
	require.NoError(t, err)

	// Set different env key
	envKey, err := GenerateMasterKey()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(envKey)
	os.Setenv(MasterKeyEnvVar, encoded)
	defer os.Unsetenv(MasterKeyEnvVar)

	opts := MasterKeyOptions{
		KeyDirectory:      tmpDir,
		AllowAutoGenerate: false,
	}

	loadedKey, src, err := LoadMasterKey(opts)
	require.NoError(t, err)
	assert.Equal(t, MasterKeySourceEnv, src)
	assert.Equal(t, envKey, loadedKey)
	assert.NotEqual(t, fileKey, loadedKey)
}

func TestMasterKeyPath(t *testing.T) {
	tests := []struct {
		name     string
		keyDir   string
		fileName string
		expected string
	}{
		{
			name:     "default filename",
			keyDir:   "/var/lib/keys",
			fileName: "",
			expected: "/var/lib/keys/_masterkey",
		},
		{
			name:     "custom filename",
			keyDir:   "/tmp/keys",
			fileName: "custom.key",
			expected: "/tmp/keys/custom.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := MasterKeyPath(tt.keyDir, tt.fileName)
			assert.Equal(t, tt.expected, path)
		})
	}
}
