package checked

import (
	"errors"
	"math"
	"testing"
)

func TestAdd64Boundaries(t *testing.T) {
	cases := []struct {
		a, b, want uint64
		ok         bool
	}{
		{0, 0, 0, true},
		{math.MaxUint64, 0, math.MaxUint64, true},
		{math.MaxUint64 - 1, 1, math.MaxUint64, true},
		{math.MaxUint64, 1, 0, false},
		{math.MaxUint64, math.MaxUint64, 0, false},
		{math.MaxUint32, math.MaxUint32, 2 * math.MaxUint32, true},
	}
	for _, c := range cases {
		got, err := Add64(c.a, c.b)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("Add64(%d,%d)=%d,%v want %d", c.a, c.b, got, err, c.want)
		}
		if !c.ok && !errors.Is(err, ErrOverflow) {
			t.Errorf("Add64(%d,%d) want overflow, got %d,%v", c.a, c.b, got, err)
		}
	}
}

func TestMul64Boundaries(t *testing.T) {
	cases := []struct {
		a, b, want uint64
		ok         bool
	}{
		{0, math.MaxUint64, 0, true},
		{1, math.MaxUint64, math.MaxUint64, true},
		{math.MaxUint32 + 1, math.MaxUint32, (math.MaxUint32 + 1) * math.MaxUint32, true},
		{math.MaxUint32 + 1, math.MaxUint32 + 1, 0, false},
		{math.MaxUint64, 2, 0, false},
		{0x00100000, 4096, 1 << 32, true},
	}
	for _, c := range cases {
		got, err := Mul64(c.a, c.b)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("Mul64(%d,%d)=%d,%v want %d", c.a, c.b, got, err, c.want)
		}
		if !c.ok && !errors.Is(err, ErrOverflow) {
			t.Errorf("Mul64(%d,%d) want overflow", c.a, c.b)
		}
	}
}

func TestSubSumRange(t *testing.T) {
	if _, err := Sub64(0, 1); !errors.Is(err, ErrOverflow) {
		t.Error("Sub64(0,1) must overflow")
	}
	if v, err := Sub64(5, 5); err != nil || v != 0 {
		t.Error("Sub64(5,5)")
	}
	if _, err := Sum64(math.MaxUint64, 0, 1); !errors.Is(err, ErrOverflow) {
		t.Error("Sum64 overflow")
	}
	if v, err := Sum64(1, 2, 3); err != nil || v != 6 {
		t.Error("Sum64")
	}
	if _, err := RangeEnd(10, 5, 14); !errors.Is(err, ErrOverflow) {
		t.Error("RangeEnd beyond limit")
	}
	if v, err := RangeEnd(10, 5, 15); err != nil || v != 15 {
		t.Error("RangeEnd at limit")
	}
	if _, err := RangeEnd(math.MaxUint64, 1, math.MaxUint64); !errors.Is(err, ErrOverflow) {
		t.Error("RangeEnd wrap")
	}
	if _, err := ToInt(math.MaxUint64); !errors.Is(err, ErrOverflow) {
		t.Error("ToInt")
	}
}
