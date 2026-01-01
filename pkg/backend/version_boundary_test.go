package backend

import (
	"testing"
)

// TestExpandOwnerName_LabelBoundary tests that label boundaries are correctly checked
func TestExpandOwnerName_LabelBoundary(t *testing.T) {
	tests := []struct {
		name       string
		ownerName  string
		zoneOrigin string
		want       string
	}{
		{
			name:       "false positive prevented: notexample.com",
			ownerName:  "www.notexample.com",
			zoneOrigin: "example.com.",
			want:       "www.notexample.com.example.com.", // Should be treated as relative
		},
		{
			name:       "true positive: www.example.com",
			ownerName:  "www.example.com",
			zoneOrigin: "example.com.",
			want:       "www.example.com.", // Should be treated as FQDN
		},
		{
			name:       "apex match",
			ownerName:  "example.com",
			zoneOrigin: "example.com.",
			want:       "example.com.", // Should be treated as apex FQDN
		},
		{
			name:       "false positive: subexample.com",
			ownerName:  "test.subexample.com",
			zoneOrigin: "example.com.",
			want:       "test.subexample.com.example.com.", // Should be treated as relative
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandOwnerName(tt.ownerName, tt.zoneOrigin)
			if got != tt.want {
				t.Errorf("expandOwnerName(%q, %q) = %q, want %q", tt.ownerName, tt.zoneOrigin, got, tt.want)
			}
		})
	}
}
