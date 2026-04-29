package util

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// Crockford's Base32 alphabet (no I, L, O, U).
const crockfordBase32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	ulidMu      sync.Mutex
	ulidLastMS  uint64
	ulidLastRnd [10]byte
)

// NewULID returns a monotonic ULID string (26 chars) using crypto/rand for entropy.
// It is safe for concurrent use.
func NewULID(now time.Time) (string, error) {
	ms := uint64(now.UnixMilli())

	ulidMu.Lock()
	defer ulidMu.Unlock()

	var rnd [10]byte
	if ms > ulidLastMS {
		if _, err := rand.Read(rnd[:]); err != nil {
			return "", fmt.Errorf("read random: %w", err)
		}
		ulidLastMS = ms
		ulidLastRnd = rnd
	} else {
		rnd = ulidLastRnd
		if err := increment80(&rnd); err != nil {
			return "", err
		}
		ulidLastRnd = rnd
	}

	return encodeULID(ms, rnd), nil
}

func increment80(v *[10]byte) error {
	for i := 9; i >= 0; i-- {
		v[i]++
		if v[i] != 0 {
			return nil
		}
	}
	return fmt.Errorf("ulid: randomness overflow")
}

func encodeULID(ms uint64, rnd [10]byte) string {
	var data [16]byte

	// 48-bit timestamp (ms), big-endian.
	data[0] = byte(ms >> 40)
	data[1] = byte(ms >> 32)
	data[2] = byte(ms >> 24)
	data[3] = byte(ms >> 16)
	data[4] = byte(ms >> 8)
	data[5] = byte(ms)

	copy(data[6:], rnd[:])

	out := make([]byte, 0, 26)

	var buf uint32
	var nbits uint8

	// ULID encodes 128 bits into 26 base32 chars (130 bits), with 2 leading zero bits.
	nbits = 2
	buf = 0

	for _, b := range data {
		buf = (buf << 8) | uint32(b)
		nbits += 8
		for nbits >= 5 {
			shift := nbits - 5
			idx := (buf >> shift) & 0x1F
			out = append(out, crockfordBase32[idx])
			if shift == 0 {
				buf = 0
			} else {
				buf &= (1 << shift) - 1
			}
			nbits -= 5
			if len(out) == 26 {
				return string(out)
			}
		}
	}

	return string(out)
}
