package dnssec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrDecryptFailed is returned when decryption fails.
	ErrDecryptFailed = errors.New("decryption failed")

	// ErrUnsupportedCipher is returned when an unsupported cipher is encountered.
	ErrUnsupportedCipher = errors.New("unsupported cipher")
)

// EncryptedPrivateKey represents an encrypted private key with metadata.
type EncryptedPrivateKey struct {
	// Version is the encryption format version.
	Version int `json:"version"`

	// Cipher is the cipher algorithm (e.g., "aes-256-gcm").
	Cipher string `json:"cipher"`

	// NonceB64 is the base64-encoded nonce/IV.
	NonceB64 string `json:"nonce"`

	// CiphertextB64 is the base64-encoded ciphertext.
	CiphertextB64 string `json:"ciphertext"`

	// Zone is the zone name (metadata).
	Zone string `json:"zone"`

	// Algorithm is the DNSSEC algorithm (metadata).
	Algorithm uint8 `json:"algorithm"`

	// KeyTag is the key tag (metadata).
	KeyTag uint16 `json:"key_tag"`

	// Role is the key role (KSK or ZSK).
	Role KeyRole `json:"role"`
}

// EncryptPrivateKey encrypts a private key using AES-256-GCM with authenticated metadata.
func EncryptPrivateKey(masterKey []byte, plaintext []byte, meta EncryptedPrivateKey) ([]byte, error) {
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("%w: invalid master key size", ErrInvalidMasterKey)
	}

	// Create AES cipher
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Build AAD (Additional Authenticated Data) from metadata
	// This ensures metadata cannot be tampered with
	aad := buildAAD(meta)

	// Encrypt with AAD
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Build envelope
	envelope := meta
	envelope.Version = 1
	envelope.Cipher = "aes-256-gcm"
	envelope.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
	envelope.CiphertextB64 = base64.StdEncoding.EncodeToString(ciphertext)

	// Marshal to JSON
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	return data, nil
}

// buildAAD builds Additional Authenticated Data from metadata.
// This ensures the metadata cannot be tampered with without detection.
func buildAAD(meta EncryptedPrivateKey) []byte {
	aadData := fmt.Sprintf("zone=%s,algorithm=%d,keytag=%d,role=%s",
		meta.Zone, meta.Algorithm, meta.KeyTag, meta.Role)
	return []byte(aadData)
}

// DecryptPrivateKey decrypts a private key using AES-256-GCM.
func DecryptPrivateKey(masterKey []byte, encryptedData []byte) ([]byte, EncryptedPrivateKey, error) {
	if len(masterKey) != MasterKeySize {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: invalid master key size", ErrInvalidMasterKey)
	}

	// Parse envelope
	var envelope EncryptedPrivateKey
	if err := json.Unmarshal(encryptedData, &envelope); err != nil {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: invalid json", ErrDecryptFailed)
	}

	// Validate version
	if envelope.Version != 1 {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: unsupported version %d", ErrDecryptFailed, envelope.Version)
	}

	// Validate cipher
	if envelope.Cipher != "aes-256-gcm" {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: %s", ErrUnsupportedCipher, envelope.Cipher)
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(envelope.NonceB64)
	if err != nil {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: invalid nonce", ErrDecryptFailed)
	}

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.CiphertextB64)
	if err != nil {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: invalid ciphertext", ErrDecryptFailed)
	}

	// Create AES cipher
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: create cipher", ErrDecryptFailed)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: create gcm", ErrDecryptFailed)
	}

	// Validate nonce length (prevent panic in gcm.Open)
	if len(nonce) != gcm.NonceSize() {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: invalid nonce length %d, expected %d",
			ErrDecryptFailed, len(nonce), gcm.NonceSize())
	}

	// Build AAD from metadata for verification
	aad := buildAAD(envelope)

	// Decrypt with AAD verification
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, EncryptedPrivateKey{}, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	return plaintext, envelope, nil
}
