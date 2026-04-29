package dnssec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeZoneFQDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "without trailing dot",
			input:    "example.com",
			expected: "example.com.",
			wantErr:  false,
		},
		{
			name:     "with trailing dot",
			input:    "example.com.",
			expected: "example.com.",
			wantErr:  false,
		},
		{
			name:     "uppercase",
			input:    "EXAMPLE.COM",
			expected: "example.com.",
			wantErr:  false,
		},
		{
			name:     "mixed case",
			input:    "Example.COM",
			expected: "example.com.",
			wantErr:  false,
		},
		{
			name:     "subdomain",
			input:    "sub.example.com",
			expected: "sub.example.com.",
			wantErr:  false,
		},
		{
			name:     "root zone",
			input:    ".",
			expected: ".",
			wantErr:  false,
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeZoneFQDN(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestZoneNameForFile(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "with trailing dot",
			input:    "example.com.",
			expected: "example.com",
			wantErr:  false,
		},
		{
			name:     "without trailing dot",
			input:    "example.com",
			expected: "example.com",
			wantErr:  false,
		},
		{
			name:     "uppercase",
			input:    "EXAMPLE.COM",
			expected: "example.com",
			wantErr:  false,
		},
		{
			name:     "subdomain",
			input:    "sub.example.com",
			expected: "sub.example.com",
			wantErr:  false,
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ZoneNameForFile(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestMakeKeyFilenames(t *testing.T) {
	tests := []struct {
		name        string
		zone        string
		alg         uint8
		keyTag      uint16
		expectedPub string
		expectedEnc string
		wantErr     bool
	}{
		{
			name:        "example.com with ECDSA",
			zone:        "example.com",
			alg:         13,
			keyTag:      12345,
			expectedPub: "Kexample.com.+013+12345.key",
			expectedEnc: "Kexample.com.+013+12345.private.enc",
			wantErr:     false,
		},
		{
			name:        "with trailing dot",
			zone:        "example.com.",
			alg:         13,
			keyTag:      54321,
			expectedPub: "Kexample.com.+013+54321.key",
			expectedEnc: "Kexample.com.+013+54321.private.enc",
			wantErr:     false,
		},
		{
			name:        "RSA algorithm",
			zone:        "test.org",
			alg:         8,
			keyTag:      65535,
			expectedPub: "Ktest.org.+008+65535.key",
			expectedEnc: "Ktest.org.+008+65535.private.enc",
			wantErr:     false,
		},
		{
			name:        "subdomain",
			zone:        "sub.example.com",
			alg:         13,
			keyTag:      1,
			expectedPub: "Ksub.example.com.+013+00001.key",
			expectedEnc: "Ksub.example.com.+013+00001.private.enc",
			wantErr:     false,
		},
		{
			name:        "empty zone",
			zone:        "",
			alg:         13,
			keyTag:      12345,
			expectedPub: "",
			expectedEnc: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, enc, err := MakeKeyFilenames(tt.zone, tt.alg, tt.keyTag)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedPub, pub)
				assert.Equal(t, tt.expectedEnc, enc)
			}
		})
	}
}

func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		alg      uint8
		expected string
	}{
		{alg: 8, expected: "RSASHA256"},
		{alg: 13, expected: "ECDSAP256SHA256"},
		{alg: 99, expected: "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := AlgorithmName(tt.alg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		alg     uint8
		wantErr bool
	}{
		{
			name:    "RSA-SHA256",
			alg:     8,
			wantErr: false,
		},
		{
			name:    "ECDSA-P256",
			alg:     13,
			wantErr: false,
		},
		{
			name:    "unsupported",
			alg:     99,
			wantErr: true,
		},
		{
			name:    "zero",
			alg:     0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAlgorithm(tt.alg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
