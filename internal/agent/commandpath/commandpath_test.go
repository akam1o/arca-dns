package commandpath

import (
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	validPath, err := filepath.Abs("nsd-control")
	if err != nil {
		t.Fatalf("filepath.Abs() error = %v", err)
	}

	tests := []struct {
		name        string
		path        string
		wantErrText string
	}{
		{
			name: "absolute path",
			path: validPath,
		},
		{
			name:        "empty",
			path:        "",
			wantErrText: "invalid nsd.control_path: empty",
		},
		{
			name:        "surrounding whitespace",
			path:        validPath + " ",
			wantErrText: "invalid nsd.control_path: must not contain surrounding whitespace",
		},
		{
			name:        "control character",
			path:        validPath + "\x7f",
			wantErrText: "invalid nsd.control_path: contains control characters",
		},
		{
			name:        "relative path",
			path:        "nsd-control",
			wantErrText: "invalid nsd.control_path: must be an absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate("nsd.control_path", tt.path)
			if tt.wantErrText == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", tt.wantErrText)
			}
			if err.Error() != tt.wantErrText {
				t.Fatalf("Validate() error = %q, want %q", err.Error(), tt.wantErrText)
			}
		})
	}
}
