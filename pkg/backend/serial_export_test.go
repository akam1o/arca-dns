package backend

import (
	"math"
	"testing"
)

func TestNextSOASerial(t *testing.T) {
	if serial := NextSOASerial(0); serial == 0 {
		t.Fatal("NextSOASerial(0) = 0, want generated serial")
	}

	if serial := NextSOASerial(math.MaxUint32); serial != math.MaxUint32 {
		t.Fatalf("NextSOASerial(MaxUint32) = %d, want %d", serial, uint32(math.MaxUint32))
	}
}
