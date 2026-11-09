package archive

import (
	"sync/atomic"

	"stash/internal/wire"
)

// Compressed extents (§6.6.1): a DATA extent's logical length is bounded
// by MAX_FRAME_SIZE, not by the frame's physical payload capacity. With a
// compressing codec the extent sources yield windows of several extents,
// and each window is split into extents of up to min(MAX_FRAME_SIZE,
// MaxExtent) logical bytes whose compressed form fits a frame: as many logical bytes
// per frame as compress into it. The writer never needs more than one
// extra compression per window: the split estimates each extent's length
// from the compression ratio of the previous one.

// compressedExtents reports whether extents may exceed the frame's
// uncompressed capacity.
func (w *Writer) compressedExtents() bool {
	return w.h.CodecID != wire.CodecStore && !w.opt.UncompressedExtents
}

// extentLimit is the largest logical extent: MAX_FRAME_SIZE (§6.6.1)
// within MaxExtent.
func (w *Writer) extentLimit() int {
	n := min(int(w.h.MaxFrameSize()), w.opt.MaxExtent)
	return max(n/wire.BaseQuantum*wire.BaseQuantum, wire.BaseQuantum)
}

// window is the logical size of one extent-source window: several extents,
// so that only the last extent of a window may be short.
func (w *Writer) window() int {
	l := w.extentLimit()
	return max(l, min(windowBytes, 16*l)/l*l)
}

// windowBytes bounds a window (memory per worker of a streaming Put).
const windowBytes = 4 << 20

// encExtent is one extent of a window, compressed.
type encExtent struct {
	off     int // in the object
	n       int // logical length
	codec   wire.CodecID
	stored  []byte
	release func() // releases stored and the extent's share of the window
}

// splitWindow splits the window at object offset off into extents whose
// stored payload fits a frame of path p (§6.6.1). windowRelease (may be
// nil) is called once every extent has been released. An empty window
// yields one empty extent.
func (w *Writer) splitWindow(p string, off int, window []byte, windowRelease func()) []encExtent {
	capacity := w.frameCapacity(p)
	limit := w.extentLimit()
	var out []encExtent
	var refs atomic.Int32
	refs.Store(1) // held until the split is done
	drop := func() {
		if refs.Add(-1) == 0 && windowRelease != nil {
			windowRelease()
		}
	}
	add := func(at, n int, c wire.CodecID, stored []byte, rel func()) {
		refs.Add(1)
		out = append(out, encExtent{off: off + at, n: n, codec: c, stored: stored, release: func() {
			if rel != nil {
				rel()
			}
			drop()
		}})
	}
	ratio := 0.0 // logical/stored of the previous extent; 0 unknown
	pos := 0
	for pos < len(window) || len(out) == 0 {
		rest := len(window) - pos
		n := min(rest, limit)
		if ratio > 0 { // capacity always fits: STORE is the fallback
			n = min(n, max(capacity, quantumFloor(float64(capacity)*ratio*0.97)))
		}
		for try := 0; ; try++ {
			if n <= capacity || try == 3 {
				n = min(n, capacity, rest)
			}
			c, stored, rel := w.encode(window[pos : pos+n])
			if len(stored) <= capacity {
				if len(stored) > 0 {
					ratio = float64(n) / float64(len(stored))
				}
				add(pos, n, c, stored, rel)
				pos += n
				break
			}
			if rel != nil {
				rel()
			}
			// too large: shrink by the observed ratio, with a margin
			next := quantumFloor(float64(n) * float64(capacity) / float64(len(stored)) * 0.97)
			n = max(min(next, n-wire.BaseQuantum), capacity)
		}
		if rest == 0 {
			break
		}
	}
	drop()
	return out
}

func quantumFloor(x float64) int {
	n := int(x) / wire.BaseQuantum * wire.BaseQuantum
	return max(n, wire.BaseQuantum)
}

func (e pending) free() {
	if e.enc != nil {
		e.enc.release()
	} else if e.release != nil {
		e.release()
	}
}

// pendingSource turns an extent source into a sequence of extents in
// object order. With compressed extents the windows are split by up to
// workers goroutines ahead of the consumer. stop releases everything not
// consumed; it must be called once the consumer is done.
func (w *Writer) pendingSource(p string, src extentSource, workers int, failed func() bool) (next func() (pending, error), stop func()) {
	if !w.compressedExtents() {
		off, done := 0, false
		next = func() (pending, error) {
			if done {
				return pending{}, errDone
			}
			payload, rel, err := src(off)
			if err != nil {
				return pending{}, err
			}
			e := pending{off: off, payload: payload, release: rel}
			off += len(payload)
			done = len(payload) == 0 // the single extent of an empty object
			return e, nil
		}
		return next, func() {}
	}
	type split struct {
		exts []encExtent
		err  error
	}
	futs := make(chan chan split, workers)
	var stopped atomic.Bool
	go func() {
		defer close(futs)
		off := 0
		for !stopped.Load() && !failed() {
			payload, rel, err := src(off)
			if err == errDone {
				return
			}
			f := make(chan split, 1)
			futs <- f
			if err != nil {
				f <- split{err: err}
				return
			}
			go func(off int) { f <- split{exts: w.splitWindow(p, off, payload, rel)} }(off)
			off += len(payload)
			if len(payload) == 0 {
				return
			}
		}
	}()
	var queue []encExtent
	next = func() (pending, error) {
		for len(queue) == 0 {
			f, ok := <-futs
			if !ok {
				return pending{}, errDone
			}
			r := <-f
			if r.err != nil {
				return pending{}, r.err
			}
			queue = r.exts
		}
		e := queue[0]
		queue = queue[1:]
		return pending{off: e.off, enc: &e}, nil
	}
	stop = func() {
		stopped.Store(true)
		for _, e := range queue {
			e.release()
		}
		queue = nil
		for f := range futs {
			for _, e := range (<-f).exts {
				e.release()
			}
		}
	}
	return next, stop
}
