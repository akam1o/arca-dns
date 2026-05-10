package sync

import "testing"

func TestZoneSerialBefore(t *testing.T) {
	tests := []struct {
		name      string
		candidate uint32
		current   uint32
		want      bool
	}{
		{
			name:      "older without wrap",
			candidate: 2024010101,
			current:   2024010201,
			want:      true,
		},
		{
			name:      "same",
			candidate: 2024010101,
			current:   2024010101,
			want:      false,
		},
		{
			name:      "newer without wrap",
			candidate: 2024010201,
			current:   2024010101,
			want:      false,
		},
		{
			name:      "newer after wrap",
			candidate: 3,
			current:   ^uint32(0) - 1,
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := zoneSerialBefore(tc.candidate, tc.current); got != tc.want {
				t.Fatalf("zoneSerialBefore(%d, %d) = %t, want %t", tc.candidate, tc.current, got, tc.want)
			}
		})
	}
}
