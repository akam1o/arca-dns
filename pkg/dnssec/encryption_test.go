package dnssec

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptPrivateKey(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	plaintext := []byte("test private key data")
	meta := EncryptedPrivateKey{
		Zone:      "example.com.",
		Algorithm: 13,
		KeyTag:    12345,
		Role:      KeyRoleKSK,
	}

	// Encrypt
	encrypted, err := EncryptPrivateKey(masterKey, plaintext, meta)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Decrypt
	decrypted, envelope, err := DecryptPrivateKey(masterKey, encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.Equal(t, meta.Zone, envelope.Zone)
	assert.Equal(t, meta.Algorithm, envelope.Algorithm)
	assert.Equal(t, meta.KeyTag, envelope.KeyTag)
	assert.Equal(t, meta.Role, envelope.Role)
}

func TestDecryptPrivateKey_WrongMasterKey(t *testing.T) {
	masterKey1, err := GenerateMasterKey()
	require.NoError(t, err)

	masterKey2, err := GenerateMasterKey()
	require.NoError(t, err)

	plaintext := []byte("test data")
	meta := EncryptedPrivateKey{
		Zone:      "example.com.",
		Algorithm: 13,
		KeyTag:    12345,
		Role:      KeyRoleKSK,
	}

	// Encrypt with masterKey1
	encrypted, err := EncryptPrivateKey(masterKey1, plaintext, meta)
	require.NoError(t, err)

	// Try to decrypt with masterKey2
	decrypted, _, err := DecryptPrivateKey(masterKey2, encrypted)
	assert.ErrorIs(t, err, ErrDecryptFailed)
	assert.Nil(t, decrypted)
}

func TestDecryptPrivateKey_InvalidNonceLength(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	// Create envelope with invalid nonce length
	invalidNonce := make([]byte, 5) // Wrong size (should be 12 for GCM)
	envelope := EncryptedPrivateKey{
		Version:       1,
		Cipher:        "aes-256-gcm",
		NonceB64:      base64.StdEncoding.EncodeToString(invalidNonce),
		CiphertextB64: base64.StdEncoding.EncodeToString([]byte("dummy")),
		Zone:          "example.com.",
		Algorithm:     13,
		KeyTag:        12345,
		Role:          KeyRoleKSK,
	}

	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	// Should fail with nonce length error, not panic
	decrypted, _, err := DecryptPrivateKey(masterKey, data)
	assert.ErrorIs(t, err, ErrDecryptFailed)
	assert.Contains(t, err.Error(), "invalid nonce length")
	assert.Nil(t, decrypted)
}

func TestDecryptPrivateKey_TamperedMetadata(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	plaintext := []byte("test data")
	meta := EncryptedPrivateKey{
		Zone:      "example.com.",
		Algorithm: 13,
		KeyTag:    12345,
		Role:      KeyRoleKSK,
	}

	// Encrypt
	encrypted, err := EncryptPrivateKey(masterKey, plaintext, meta)
	require.NoError(t, err)

	// Parse envelope
	var envelope EncryptedPrivateKey
	err = json.Unmarshal(encrypted, &envelope)
	require.NoError(t, err)

	// Tamper with metadata
	envelope.Zone = "attacker.com."
	envelope.KeyTag = 65535

	// Re-marshal
	tampered, err := json.Marshal(envelope)
	require.NoError(t, err)

	// Should fail due to AAD mismatch
	decrypted, _, err := DecryptPrivateKey(masterKey, tampered)
	assert.ErrorIs(t, err, ErrDecryptFailed)
	assert.Nil(t, decrypted)
}

func TestDecryptPrivateKey_UnsupportedVersion(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	envelope := EncryptedPrivateKey{
		Version: 99, // Unsupported version
		Cipher:  "aes-256-gcm",
	}

	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	decrypted, _, err := DecryptPrivateKey(masterKey, data)
	assert.ErrorIs(t, err, ErrDecryptFailed)
	assert.Contains(t, err.Error(), "unsupported version")
	assert.Nil(t, decrypted)
}

func TestDecryptPrivateKey_UnsupportedCipher(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	envelope := EncryptedPrivateKey{
		Version: 1,
		Cipher:  "aes-128-cbc", // Unsupported cipher
	}

	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	decrypted, _, err := DecryptPrivateKey(masterKey, data)
	assert.ErrorIs(t, err, ErrUnsupportedCipher)
	assert.Nil(t, decrypted)
}

func TestDecryptPrivateKey_InvalidJSON(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	invalidJSON := []byte("{invalid json")

	decrypted, _, err := DecryptPrivateKey(masterKey, invalidJSON)
	assert.ErrorIs(t, err, ErrDecryptFailed)
	assert.Contains(t, err.Error(), "invalid json")
	assert.Nil(t, decrypted)
}

func TestDecryptPrivateKey_InvalidBase64Nonce(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	envelope := EncryptedPrivateKey{
		Version:       1,
		Cipher:        "aes-256-gcm",
		NonceB64:      "not-valid-base64!!!",
		CiphertextB64: base64.StdEncoding.EncodeToString([]byte("dummy")),
		Zone:          "example.com.",
		Algorithm:     13,
		KeyTag:        12345,
		Role:          KeyRoleKSK,
	}

	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	decrypted, _, err := DecryptPrivateKey(masterKey, data)
	assert.ErrorIs(t, err, ErrDecryptFailed)
	assert.Contains(t, err.Error(), "invalid nonce")
	assert.Nil(t, decrypted)
}

func TestEncryptPrivateKey_InvalidMasterKeySize(t *testing.T) {
	invalidKey := []byte("too-short")
	plaintext := []byte("test data")
	meta := EncryptedPrivateKey{
		Zone:      "example.com.",
		Algorithm: 13,
		KeyTag:    12345,
		Role:      KeyRoleKSK,
	}

	encrypted, err := EncryptPrivateKey(invalidKey, plaintext, meta)
	assert.ErrorIs(t, err, ErrInvalidMasterKey)
	assert.Nil(t, encrypted)
}

func TestBuildAAD(t *testing.T) {
	meta := EncryptedPrivateKey{
		Zone:      "example.com.",
		Algorithm: 13,
		KeyTag:    12345,
		Role:      KeyRoleKSK,
	}

	aad := buildAAD(meta)
	assert.NotEmpty(t, aad)
	assert.Contains(t, string(aad), "example.com.")
	assert.Contains(t, string(aad), "13")
	assert.Contains(t, string(aad), "12345")
	assert.Contains(t, string(aad), "KSK")
}
