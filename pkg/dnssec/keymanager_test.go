package dnssec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyManager(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	opts := KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13, // ECDSA-P256
	}

	km, err := NewKeyManager(opts)
	require.NoError(t, err)
	assert.NotNil(t, km)
	assert.Equal(t, tmpDir, km.keyDir)
	assert.Equal(t, uint8(13), km.algorithm)
}

func TestNewKeyManager_EmptyDirectory(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	opts := KeyManagerOptions{
		KeyDirectory: "",
		MasterKey:    masterKey,
		Algorithm:    13,
	}

	km, err := NewKeyManager(opts)
	assert.Error(t, err)
	assert.Nil(t, km)
	assert.Contains(t, err.Error(), "key directory cannot be empty")
}

func TestNewKeyManager_InvalidMasterKey(t *testing.T) {
	tmpDir := t.TempDir()

	opts := KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    []byte("too-short"),
		Algorithm:    13,
	}

	km, err := NewKeyManager(opts)
	assert.ErrorIs(t, err, ErrInvalidMasterKey)
	assert.Nil(t, km)
}

func TestNewKeyManager_InvalidAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	opts := KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    99, // Invalid
	}

	km, err := NewKeyManager(opts)
	assert.Error(t, err)
	assert.Nil(t, km)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestGenerateKSK_ECDSA(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	ksk, err := km.GenerateKSK("example.com")
	require.NoError(t, err)
	assert.NotNil(t, ksk)
	assert.Equal(t, "example.com.", ksk.ID.Zone)
	assert.Equal(t, uint8(13), ksk.ID.Algorithm)
	assert.Equal(t, KeyRoleKSK, ksk.Role)
	assert.NotZero(t, ksk.ID.KeyTag)

	// Verify key files exist
	zoneDir := filepath.Join(tmpDir, "example.com")
	pubFile, privFile, err := MakeKeyFilenames("example.com", 13, ksk.ID.KeyTag)
	require.NoError(t, err)

	assert.FileExists(t, filepath.Join(zoneDir, pubFile))
	assert.FileExists(t, filepath.Join(zoneDir, privFile))
	assert.FileExists(t, filepath.Join(zoneDir, "active.json"))
}

func TestGenerateZoneKeysRejectsUnsafeZoneName(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "keys")
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: keyDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	_, _, err = km.GenerateZoneKeys("../escape", false)
	require.Error(t, err)
	assert.NoDirExists(t, filepath.Join(tmpDir, "escape"))
}

func TestGenerateZSK_ECDSA(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	zsk, err := km.GenerateZSK("example.com")
	require.NoError(t, err)
	assert.NotNil(t, zsk)
	assert.Equal(t, "example.com.", zsk.ID.Zone)
	assert.Equal(t, uint8(13), zsk.ID.Algorithm)
	assert.Equal(t, KeyRoleZSK, zsk.Role)
	assert.NotZero(t, zsk.ID.KeyTag)
}

func TestGenerateKSK_RSA(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    8,
		KSKBits:      1024, // Smaller for faster tests
		ZSKBits:      1024,
	})
	require.NoError(t, err)

	ksk, err := km.GenerateKSK("example.com")
	require.NoError(t, err)
	assert.NotNil(t, ksk)
	assert.Equal(t, uint8(8), ksk.ID.Algorithm)
	assert.Equal(t, KeyRoleKSK, ksk.Role)
}

func TestLoadKSK(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Generate KSK
	ksk1, err := km.GenerateKSK("example.com")
	require.NoError(t, err)

	// Load KSK
	ksk2, err := km.LoadKSK("example.com")
	require.NoError(t, err)
	assert.Equal(t, ksk1.ID.KeyTag, ksk2.ID.KeyTag)
	assert.Equal(t, ksk1.ID.Algorithm, ksk2.ID.Algorithm)
	assert.Equal(t, ksk1.Role, ksk2.Role)
}

func TestLoadZSK(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Generate ZSK
	zsk1, err := km.GenerateZSK("example.com")
	require.NoError(t, err)

	// Load ZSK
	zsk2, err := km.LoadZSK("example.com")
	require.NoError(t, err)
	assert.Equal(t, zsk1.ID.KeyTag, zsk2.ID.KeyTag)
	assert.Equal(t, zsk1.ID.Algorithm, zsk2.ID.Algorithm)
	assert.Equal(t, zsk1.Role, zsk2.Role)
}

func TestLoadKey_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Try to load non-existent key
	ksk, err := km.LoadKSK("nonexistent.com")
	assert.Error(t, err)
	assert.Nil(t, ksk)
}

func TestLoadKey_WrongMasterKey(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey1, err := GenerateMasterKey()
	require.NoError(t, err)

	km1, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey1,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Generate KSK with first master key
	_, err = km1.GenerateKSK("example.com")
	require.NoError(t, err)

	// Try to load with different master key
	masterKey2, err := GenerateMasterKey()
	require.NoError(t, err)

	km2, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey2,
		Algorithm:    13,
	})
	require.NoError(t, err)

	ksk, err := km2.LoadKSK("example.com")
	assert.ErrorIs(t, err, ErrDecryptFailed)
	assert.Nil(t, ksk)
}

func TestEnsureZoneKeys_Generate(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Ensure keys (should generate)
	ksk, zsk, err := km.EnsureZoneKeys("example.com")
	require.NoError(t, err)
	assert.NotNil(t, ksk)
	assert.NotNil(t, zsk)
	assert.Equal(t, KeyRoleKSK, ksk.Role)
	assert.Equal(t, KeyRoleZSK, zsk.Role)

	// Verify files exist
	zoneDir := filepath.Join(tmpDir, "example.com")
	assert.DirExists(t, zoneDir)
}

func TestEnsureZoneKeys_Load(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// First ensure (generate)
	ksk1, zsk1, err := km.EnsureZoneKeys("example.com")
	require.NoError(t, err)

	// Second ensure (load)
	ksk2, zsk2, err := km.EnsureZoneKeys("example.com")
	require.NoError(t, err)

	// Should return same keys
	assert.Equal(t, ksk1.ID.KeyTag, ksk2.ID.KeyTag)
	assert.Equal(t, zsk1.ID.KeyTag, zsk2.ID.KeyTag)
}

func TestLoadKSK_DoesNotCreateMissingZoneDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	ksk, err := km.LoadKSK("missing.example")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
	assert.Nil(t, ksk)
	assert.NoDirExists(t, filepath.Join(tmpDir, "missing.example"))
}

func TestEnsureZoneKeys_Concurrent(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	const goroutines = 8
	kskTags := make([]uint16, goroutines)
	zskTags := make([]uint16, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			ksk, zsk, err := km.EnsureZoneKeys("example.com")
			if err != nil {
				errs[i] = err
				return
			}
			kskTags[i] = ksk.ID.KeyTag
			zskTags[i] = zsk.ID.KeyTag
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, kskTags[0], kskTags[i])
		assert.Equal(t, zskTags[0], zskTags[i])
	}
}

func TestEnsureZoneKeysContext_CancelledWhileWaitingForZoneLock(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	zoneFQDN, err := NormalizeZoneFQDN("example.com")
	require.NoError(t, err)
	release, err := km.acquireZoneMutex(context.Background(), zoneFQDN)
	require.NoError(t, err)
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	ksk, zsk, err := km.EnsureZoneKeysContext(ctx, "example.com")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, ksk)
	assert.Nil(t, zsk)
}

func TestGenerateZoneKeys_RotateFailureKeepsExistingActiveKeys(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	goodKM, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    8,
		KSKBits:      1024,
		ZSKBits:      1024,
	})
	require.NoError(t, err)

	ksk, zsk, err := goodKM.GenerateZoneKeys("example.com", false)
	require.NoError(t, err)
	before := readTestActiveKeys(t, tmpDir, "example.com.")
	require.Equal(t, ksk.ID.KeyTag, before.ActiveKSKTag)
	require.Equal(t, zsk.ID.KeyTag, before.ActiveZSKTag)

	badKM, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    8,
		KSKBits:      1024,
		ZSKBits:      -1,
	})
	require.NoError(t, err)

	_, _, err = badKM.GenerateZoneKeys("example.com", true)
	require.Error(t, err)

	after := readTestActiveKeys(t, tmpDir, "example.com.")
	assert.Equal(t, before, after)

	loadedKSK, err := goodKM.LoadKSK("example.com")
	require.NoError(t, err)
	assert.Equal(t, ksk.ID.KeyTag, loadedKSK.ID.KeyTag)

	loadedZSK, err := goodKM.LoadZSK("example.com")
	require.NoError(t, err)
	assert.Equal(t, zsk.ID.KeyTag, loadedZSK.ID.KeyTag)
}

func TestExportDS(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Generate KSK
	ksk, err := km.GenerateKSK("example.com")
	require.NoError(t, err)

	// Export DS record (SHA-256)
	ds, err := km.ExportDS("example.com", 2)
	require.NoError(t, err)
	assert.NotNil(t, ds)
	assert.Equal(t, "example.com.", ds.Hdr.Name)
	assert.Equal(t, ksk.ID.KeyTag, ds.KeyTag)
	assert.Equal(t, uint8(13), ds.Algorithm)
	assert.Equal(t, uint8(2), ds.DigestType) // SHA-256
	assert.NotEmpty(t, ds.Digest)
}

func TestKeyPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Generate keys
	ksk1, err := km.GenerateKSK("example.com")
	require.NoError(t, err)
	zsk1, err := km.GenerateZSK("example.com")
	require.NoError(t, err)

	// Verify active.json
	activeFile := filepath.Join(tmpDir, "example.com", "active.json")
	assert.FileExists(t, activeFile)

	// Read active.json
	data, err := os.ReadFile(activeFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "active_ksk_key_tag")
	assert.Contains(t, string(data), "active_zsk_key_tag")

	// Create new KeyManager instance
	km2, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Load keys
	ksk2, err := km2.LoadKSK("example.com")
	require.NoError(t, err)
	zsk2, err := km2.LoadZSK("example.com")
	require.NoError(t, err)

	// Verify persistence
	assert.Equal(t, ksk1.ID.KeyTag, ksk2.ID.KeyTag)
	assert.Equal(t, zsk1.ID.KeyTag, zsk2.ID.KeyTag)
}

func TestEncryptedPrivateKey_Metadata(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	// Generate KSK
	ksk, err := km.GenerateKSK("example.com")
	require.NoError(t, err)

	// Read encrypted private key file
	_, privFile, err := MakeKeyFilenames("example.com", 13, ksk.ID.KeyTag)
	require.NoError(t, err)

	encFile := filepath.Join(tmpDir, "example.com", privFile)
	encData, err := os.ReadFile(encFile)
	require.NoError(t, err)

	// Verify it's valid JSON and contains metadata
	assert.Contains(t, string(encData), "version")
	assert.Contains(t, string(encData), "cipher")
	assert.Contains(t, string(encData), "zone")
	assert.Contains(t, string(encData), "algorithm")
	assert.Contains(t, string(encData), "key_tag")
	assert.Contains(t, string(encData), "role")
}

func TestKeyManager_RemoveZoneKeys(t *testing.T) {
	tmpDir := t.TempDir()
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	km, err := NewKeyManager(KeyManagerOptions{
		KeyDirectory: tmpDir,
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	_, _, err = km.GenerateZoneKeys("example.com.", false)
	require.NoError(t, err)

	zoneName, err := ZoneNameForFile("example.com.")
	require.NoError(t, err)
	zoneDir := filepath.Join(tmpDir, zoneName)
	require.DirExists(t, zoneDir)

	require.NoError(t, km.RemoveZoneKeys("example.com."))
	_, err = os.Stat(zoneDir)
	require.True(t, os.IsNotExist(err), "expected zone key directory to be removed, got %v", err)

	require.NoError(t, km.RemoveZoneKeys("example.com."))
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestWriteAllRejectsShortWrite(t *testing.T) {
	err := writeAll(shortWriter{}, []byte("dnssec-key-material"))
	require.Error(t, err)
	require.True(t, errors.Is(err, io.ErrShortWrite), "expected ErrShortWrite, got %v", err)
}

func readTestActiveKeys(t *testing.T, keyDir, zone string) activeKeys {
	t.Helper()

	zoneName, err := ZoneNameForFile(zone)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(keyDir, zoneName, "active.json"))
	require.NoError(t, err)

	var active activeKeys
	require.NoError(t, json.Unmarshal(data, &active))
	return active
}
