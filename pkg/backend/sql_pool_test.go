package backend

import (
	"testing"
	"time"
)

func TestIntFromConfigCoversSupportedNumericTypes(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  int
		ok    bool
	}{
		{name: "int", value: int(3), want: 3, ok: true},
		{name: "int8", value: int8(-2), want: -2, ok: true},
		{name: "int16", value: int16(4), want: 4, ok: true},
		{name: "int32", value: int32(5), want: 5, ok: true},
		{name: "int64", value: int64(6), want: 6, ok: true},
		{name: "uint", value: uint(7), want: 7, ok: true},
		{name: "uint8", value: uint8(8), want: 8, ok: true},
		{name: "uint16", value: uint16(9), want: 9, ok: true},
		{name: "uint32", value: uint32(10), want: 10, ok: true},
		{name: "uint64", value: uint64(11), want: 11, ok: true},
		{name: "integral float32", value: float32(12), want: 12, ok: true},
		{name: "integral float64", value: float64(13), want: 13, ok: true},
		{name: "fractional float32", value: float32(1.5), ok: false},
		{name: "fractional float64", value: float64(2.5), ok: false},
		{name: "string", value: "14", ok: false},
		{name: "nil", value: nil, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := intFromConfig(tt.value)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("value = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDurationFromConfig(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  time.Duration
		ok    bool
	}{
		{name: "duration", value: 3 * time.Minute, want: 3 * time.Minute, ok: true},
		{name: "duration string", value: "45s", want: 45 * time.Second, ok: true},
		{name: "empty string", value: "", ok: false},
		{name: "invalid string", value: "not-a-duration", ok: false},
		{name: "numeric", value: int64(10), ok: false},
		{name: "nil", value: nil, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := durationFromConfig(tt.value)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("duration = %s, want %s", got, tt.want)
			}
		})
	}
}
