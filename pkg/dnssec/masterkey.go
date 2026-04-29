package dnssec

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MasterKeyEnvVar is the environment variable for the master key.
	MasterKeyEnvVar = "ARCA_DNS_DNSSEC_MASTER_KEY_B64"

	// MasterKeySize is the required size for AES-256 (32 bytes).
	MasterKeySize = 32

	// MasterKeyFileName is the default filename for the master key.
	MasterKeyFileName = "_masterkey"

	// LegacyMasterKeyFilePath is an additional file location supported for GA operations docs.
	// If present, it is used after KeyDirectory/_masterkey.
	LegacyMasterKeyFilePath = "/etc/arca-dns/master.key"
)

var (
	// ErrMasterKeyNotFound is returned when no master key is found.
	ErrMasterKeyNotFound = errors.New("master key not found")

	// ErrInvalidMasterKey is returned when the master key is invalid.
	ErrInvalidMasterKey = errors.New("invalid master key")
)

// MasterKeySource indicates where the master key was loaded from.
type MasterKeySource string

const (
	// MasterKeySourceEnv indicates the key was loaded from environment variable.
	MasterKeySourceEnv MasterKeySource = "env"

	// MasterKeySourceFile indicates the key was loaded from file.
	MasterKeySourceFile MasterKeySource = "file"

	// MasterKeySourceGenerated indicates the key was generated.
	MasterKeySourceGenerated MasterKeySource = "generated"
)

// MasterKeyOptions configures master key loading.
type MasterKeyOptions struct {
	// KeyDirectory is the directory where the master key file is stored.
	KeyDirectory string

	// AllowAutoGenerate allows automatic generation of master key (dev only).
	AllowAutoGenerate bool

	// FileName is the master key filename (default: _masterkey).
	FileName string
}

// LoadMasterKey loads the master key from environment variable, file, or generates it.
// Priority: ARCA_DNS_DNSSEC_MASTER_KEY_B64 > KeyDirectory/_masterkey > /etc/arca-dns/master.key > auto-generate (if allowed).
func LoadMasterKey(opts MasterKeyOptions) (key []byte, src MasterKeySource, err error) {
	// Priority 1: Environment variable
	if envKey := os.Getenv(MasterKeyEnvVar); envKey != "" {
		key, err := ParseMasterKeyB64(envKey)
		if err != nil {
			return nil, "", fmt.Errorf("load master key from env: %w", err)
		}
		return key, MasterKeySourceEnv, nil
	}

	// Priority 2: File
	fileName := opts.FileName
	if fileName == "" {
		fileName = MasterKeyFileName
	}
	keyPath := MasterKeyPath(opts.KeyDirectory, fileName)

	if _, err := os.Stat(keyPath); err == nil {
		// File exists, read it
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, "", fmt.Errorf("read master key file: %w", err)
		}

		key, err := ParseMasterKey(string(data))
		if err != nil {
			return nil, "", fmt.Errorf("parse master key from file: %w", err)
		}
		return key, MasterKeySourceFile, nil
	}

	// Priority 3: Legacy file path (for operational parity)
	if _, err := os.Stat(LegacyMasterKeyFilePath); err == nil {
		data, err := os.ReadFile(LegacyMasterKeyFilePath)
		if err != nil {
			return nil, "", fmt.Errorf("read legacy master key file: %w", err)
		}
		key, err := ParseMasterKey(string(data))
		if err != nil {
			return nil, "", fmt.Errorf("parse master key from legacy file: %w", err)
		}
		return key, MasterKeySourceFile, nil
	}

	// Priority 4: Auto-generate (dev only)
	if opts.AllowAutoGenerate {
		key, err := GenerateMasterKey()
		if err != nil {
			return nil, "", fmt.Errorf("generate master key: %w", err)
		}

		// Save to file
		if err := SaveMasterKey(keyPath, key); err != nil {
			return nil, "", fmt.Errorf("save generated master key: %w", err)
		}

		return key, MasterKeySourceGenerated, nil
	}

	// No key found
	return nil, "", ErrMasterKeyNotFound
}

// ParseMasterKeyB64 parses a base64-encoded master key.
func ParseMasterKeyB64(s string) ([]byte, error) {
	// Trim whitespace
	s = strings.TrimSpace(s)

	// Decode base64
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64", ErrInvalidMasterKey)
	}

	// Validate size
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidMasterKey, MasterKeySize, len(key))
	}

	return key, nil
}

// ParseMasterKey parses a master key from either base64(32 bytes) or hex(32 bytes).
func ParseMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("%w: empty key", ErrInvalidMasterKey)
	}
	if key, err := ParseMasterKeyB64(s); err == nil {
		return key, nil
	}
	return ParseMasterKeyHex(s)
}

// ParseMasterKeyHex parses a hex-encoded master key (64 hex chars => 32 bytes).
func ParseMasterKeyHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex", ErrInvalidMasterKey)
	}
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidMasterKey, MasterKeySize, len(key))
	}
	return key, nil
}

// GenerateMasterKey generates a new random master key.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	return key, nil
}

// SaveMasterKey saves a master key to file with restricted permissions.
func SaveMasterKey(path string, key []byte) error {
	if len(key) != MasterKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidMasterKey, MasterKeySize, len(key))
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(key)

	// Write atomically (tmp + rename)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("write master key file: %w", err)
	}

	// Rename atomically
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // Clean up on failure
		return fmt.Errorf("rename master key file: %w", err)
	}

	return nil
}

// MasterKeyPath returns the full path to the master key file.
func MasterKeyPath(keyDir string, fileName string) string {
	if fileName == "" {
		fileName = MasterKeyFileName
	}
	return filepath.Join(keyDir, fileName)
}
