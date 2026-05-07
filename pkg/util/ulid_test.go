package util

import (
	"testing"
	"time"
)

func TestNewULIDMonotonicAcrossClockRollback(t *testing.T) {
	resetULIDState()
	t.Cleanup(resetULIDState)

	first, err := NewULID(time.UnixMilli(2_000))
	if err != nil {
		t.Fatalf("NewULID first: %v", err)
	}

	second, err := NewULID(time.UnixMilli(1_000))
	if err != nil {
		t.Fatalf("NewULID second: %v", err)
	}

	if second <= first {
		t.Fatalf("ULID did not remain monotonic across clock rollback: first=%s second=%s", first, second)
	}
}

func resetULIDState() {
	ulidMu.Lock()
	defer ulidMu.Unlock()

	ulidLastMS = 0
	ulidLastRnd = [10]byte{}
}
