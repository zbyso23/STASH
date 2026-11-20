// Package membudget shares one memory ceiling between the components that
// hold archive-scale working state (external sorts, page caches, merge
// buffers). A component reserves its working set up front and releases it
// when done, so the sum of reservations never exceeds the limit no matter
// how many run concurrently (SPEC §10.3, §16.1).
//
// A Budget accounts only for the large, size-controlled buffers that
// components declare. Small per-call allocations are not tracked; the
// ceiling is a bound on archive-dependent memory, not on the whole process.
package membudget

import (
	"context"
	"errors"
	"sync"
)

// DefaultLimit is the default ceiling for archive-scale working state.
const DefaultLimit = 1 << 30

// ErrTooLarge reports a reservation larger than the whole limit: it could
// never be granted, so it fails instead of waiting forever.
var ErrTooLarge = errors.New("membudget: reservation exceeds the memory limit")

// Budget is a counting semaphore over bytes. The zero value is unusable;
// use New. A nil *Budget grants everything (no ceiling), which keeps
// call sites simple in tests and tools.
type Budget struct {
	mu    sync.Mutex
	limit int64
	used  int64
	peak  int64
	wait  chan struct{} // closed and replaced on every release
}

// New returns a budget of limit bytes (DefaultLimit when limit <= 0).
func New(limit int64) *Budget {
	if limit <= 0 {
		limit = DefaultLimit
	}
	return &Budget{limit: limit, wait: make(chan struct{})}
}

// Limit returns the ceiling (0 for a nil budget).
func (b *Budget) Limit() int64 {
	if b == nil {
		return 0
	}
	return b.limit
}

// Used returns the bytes currently reserved.
func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Peak returns the highest reservation total seen.
func (b *Budget) Peak() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}

// Reservation is a granted share of a budget.
type Reservation struct {
	b    *Budget
	n    int64
	once sync.Once
}

// Size returns the reserved bytes.
func (r *Reservation) Size() int64 { return r.n }

// Release returns the bytes to the budget. It is idempotent.
func (r *Reservation) Release() {
	if r == nil || r.b == nil {
		return
	}
	r.once.Do(func() {
		b := r.b
		b.mu.Lock()
		b.used -= r.n
		close(b.wait)
		b.wait = make(chan struct{})
		b.mu.Unlock()
	})
}

// Reserve blocks until n bytes are available or ctx ends.
func (b *Budget) Reserve(ctx context.Context, n int64) (*Reservation, error) {
	if n < 0 {
		n = 0
	}
	if b == nil {
		return &Reservation{n: n}, nil
	}
	if n > b.limit {
		return nil, ErrTooLarge
	}
	for {
		b.mu.Lock()
		if b.used+n <= b.limit {
			b.grant(n)
			b.mu.Unlock()
			return &Reservation{b: b, n: n}, nil
		}
		w := b.wait
		b.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// TryReserve reserves up to want bytes but at least min, without waiting:
// it grants as much of want as is free, or fails (nil) when less than min
// is free. Components that can work with a smaller buffer use it to
// degrade instead of block.
func (b *Budget) TryReserve(min, want int64) *Reservation {
	if want < min {
		want = min
	}
	if b == nil {
		return &Reservation{n: want}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	free := b.limit - b.used
	if free < min {
		return nil
	}
	n := want
	if n > free {
		n = free
	}
	b.grant(n)
	return &Reservation{b: b, n: n}
}

func (b *Budget) grant(n int64) {
	b.used += n
	if b.used > b.peak {
		b.peak = b.used
	}
}
