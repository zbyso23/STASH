// Package checked provides overflow-checked unsigned arithmetic for
// media-derived values (SPEC §16.1). Every function reports overflow
// instead of wrapping.
package checked

import (
	"errors"
	"math"
	"math/bits"
)

// ErrOverflow is returned when an operation would wrap around.
var ErrOverflow = errors.New("stash: arithmetic overflow")

// Add64 returns a+b or ErrOverflow.
func Add64(a, b uint64) (uint64, error) {
	s, c := bits.Add64(a, b, 0)
	if c != 0 {
		return 0, ErrOverflow
	}
	return s, nil
}

// Sub64 returns a-b or ErrOverflow when b > a.
func Sub64(a, b uint64) (uint64, error) {
	d, borrow := bits.Sub64(a, b, 0)
	if borrow != 0 {
		return 0, ErrOverflow
	}
	return d, nil
}

// Mul64 returns a*b or ErrOverflow.
func Mul64(a, b uint64) (uint64, error) {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return 0, ErrOverflow
	}
	return lo, nil
}

// Sum64 adds all values, failing on the first overflow.
func Sum64(vs ...uint64) (uint64, error) {
	var t uint64
	for _, v := range vs {
		var err error
		if t, err = Add64(t, v); err != nil {
			return 0, err
		}
	}
	return t, nil
}

// ToInt converts to int (used for slice sizes) or fails when it does not fit.
func ToInt(v uint64) (int, error) {
	if v > math.MaxInt {
		return 0, ErrOverflow
	}
	return int(v), nil
}

// RangeEnd returns off+length and verifies the range ends at or before limit.
func RangeEnd(off, length, limit uint64) (uint64, error) {
	end, err := Add64(off, length)
	if err != nil {
		return 0, err
	}
	if end > limit {
		return 0, ErrOverflow
	}
	return end, nil
}
