package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateGenerateKeysFlags(t *testing.T) {
	tests := []struct {
		name        string
		rotate      bool
		activateNow bool
		wantErr     string
	}{
		{
			name: "initial generation",
		},
		{
			name:        "confirmed rotation",
			rotate:      true,
			activateNow: true,
		},
		{
			name:    "rotation requires explicit activation confirmation",
			rotate:  true,
			wantErr: "--activate-now",
		},
		{
			name:        "activation confirmation requires rotation",
			activateNow: true,
			wantErr:     "requires --rotate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGenerateKeysFlags(tt.rotate, tt.activateNow)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
