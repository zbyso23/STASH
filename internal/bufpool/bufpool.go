// Package bufpool recycles frame-sized byte buffers.
//
// Frames are 4 KiB multiples up to MAX_FRAME_SIZE (16 MiB). Buffers are kept
// in power-of-two size classes from 4 KiB to 16 MiB, each with a bounded
// free list, and the pool as a whole never retains more than a configured
// number of bytes. A request larger than the largest class is served by a
// plain allocation and never retained.
//
// Callers MUST size requests only from validated values (a frame prefix that
// passed wire.DecodeFramePrefix, or a computed layout), never from raw input,
// so that corrupt data cannot pin large buffers (SPEC §16.1).
package bufpool

import (
	"math/bits"
	"sync"
	"sync/atomic"
)

const (
	minShift   = 12 // 4 KiB
	maxShift   = 24 // 16 MiB
	numClasses = maxShift - minShift + 1
)

// DefaultMaxRetained bounds memory a Pool keeps between uses.
const DefaultMaxRetained = 256 << 20

// Pool is safe for concurrent use. The zero value is not usable; use New.
type Pool struct {
	maxRetained int64
	retained    atomic.Int64
	classes     [numClasses]class

	// statistics (for tests and benchmarks)
	Hits, Misses, Drops atomic.Int64
}

type class struct {
	mu   sync.Mutex
	free [][]byte
}

// New returns a pool that retains at most maxRetained bytes (0 means
// DefaultMaxRetained).
func New(maxRetained int64) *Pool {
	if maxRetained <= 0 {
		maxRetained = DefaultMaxRetained
	}
	return &Pool{maxRetained: maxRetained}
}

// Default is a process-wide pool.
var Default = New(0)

func classOf(n int) int {
	if n <= 1<<minShift {
		return 0
	}
	return bits.Len(uint(n-1)) - minShift
}

// Get returns a buffer of length n. Its content is unspecified: callers
// overwrite every byte they use (frame encoders zero padding explicitly).
func (p *Pool) Get(n int) []byte {
	if n < 0 {
		panic("bufpool: negative size")
	}
	c := classOf(n)
	if c >= numClasses {
		p.Misses.Add(1)
		return make([]byte, n)
	}
	cl := &p.classes[c]
	cl.mu.Lock()
	if k := len(cl.free); k > 0 {
		b := cl.free[k-1]
		cl.free[k-1] = nil
		cl.free = cl.free[:k-1]
		cl.mu.Unlock()
		p.retained.Add(-int64(cap(b)))
		p.Hits.Add(1)
		return b[:n]
	}
	cl.mu.Unlock()
	p.Misses.Add(1)
	return make([]byte, n, 1<<(c+minShift))
}

// Put returns a buffer obtained from Get. Buffers of foreign capacity, and
// buffers that would push the pool over its retention limit, are dropped.
// The caller MUST NOT use b afterwards.
func (p *Pool) Put(b []byte) {
	c := cap(b)
	if c < 1<<minShift || c&(c-1) != 0 || c > 1<<maxShift {
		return
	}
	if p.retained.Add(int64(c)) > p.maxRetained {
		p.retained.Add(-int64(c))
		p.Drops.Add(1)
		return
	}
	cl := &p.classes[bits.Len(uint(c))-1-minShift]
	cl.mu.Lock()
	cl.free = append(cl.free, b[:0])
	cl.mu.Unlock()
}

// Retained reports the bytes currently held by the pool.
func (p *Pool) Retained() int64 { return p.retained.Load() }
