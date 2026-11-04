package blob

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Committed describes what the manifest graph (all LF-terminated records,
// anchored or not) references, for the torn-tail decision of §10.4.2. The
// manifest layer supplies it. The zero value means "nothing is referenced",
// which is correct only for a blob that no manifest record can name.
type Committed struct {
	// HighestOffset is the largest frame offset in this blob referenced by
	// a loc, or -1 (or 0) if none. A referenced offset at or beyond E means
	// committed data lies in the damaged region, whether or not the frame
	// there still validates.
	HighestOffset int64
	// GroupReferenced reports whether a loc anywhere references a frame
	// carrying groupID (non-zero). nil means no group is referenced.
	GroupReferenced func(groupID uint32) bool
}

// protects reports why the tail starting at E may not be truncated.
func (c *Committed) protects(E int64, tail []TailFrame) error {
	if c.HighestOffset >= E && c.HighestOffset > 0 {
		return fmt.Errorf("%w: committed frame at %d lies at or beyond damaged region at %d", ErrSealed, c.HighestOffset, E)
	}
	if c.GroupReferenced == nil {
		return nil
	}
	for _, t := range tail {
		if g := t.Trailer.GroupID; g != 0 && c.GroupReferenced(g) {
			return fmt.Errorf("%w: frame at %d belongs to committed parity group %d", ErrSealed, t.Offset, g)
		}
	}
	return nil
}

// OpenResult reports what OpenWriter found and did.
type OpenResult struct {
	Scan ScanResult
	// Tail lists valid frames found at frame-grid offsets >= Scan.End.
	Tail []TailFrame
	// Truncated is the number of torn bytes removed.
	Truncated int64
}

// Writer appends frames to one blob. Methods are safe for concurrent use:
// only the allocation of the next offset is serialized (§12.2); building
// frames (hashing) and writing them run in parallel.
type Writer struct {
	f    vfs.File
	h    *wire.ArchiveHeader
	pool *bufpool.Pool

	mu       sync.Mutex
	cond     sync.Cond          // signals completion of an in-flight write
	inflight map[int64]struct{} // offsets allocated but not yet written
	end      int64              // next frame offset
	poisoned error
}

// OpenWriter opens a blob for appending. It scans the blob, applies the
// torn-tail rules of §10.4.2 and returns a writer positioned at E:
//
//   - a loc references an offset >= E, or a valid frame there carries a
//     referenced group_id: the blob is SEALED; ErrSealed is returned
//     together with the OpenResult and no writer;
//   - otherwise (no valid frame there, or only uncommitted ones): truncate
//     to E and sync.
//
// A blob whose header is incomplete and that holds nothing beyond it (a
// crash inside Create) is re-initialized.
func OpenWriter(fsys vfs.FS, name string, h *wire.ArchiveHeader, pool *bufpool.Pool, committed Committed) (*Writer, OpenResult, error) {
	var res OpenResult
	if pool == nil {
		pool = bufpool.Default
	}
	f, err := fsys.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return nil, res, err
	}
	fail := func(err error) (*Writer, OpenResult, error) {
		f.Close()
		return nil, res, err
	}
	size, err := f.Size()
	if err != nil {
		return fail(err)
	}
	if err := checkHeader(f, h); err != nil {
		if !wire.IsFormatError(err) || size > wire.FrameAreaStart {
			return fail(err)
		}
		if err := reinitHeader(f, h); err != nil {
			return fail(err)
		}
		size = wire.FrameAreaStart
	}
	if res.Scan, err = scan(f, h, pool, size, nil); err != nil {
		return fail(err)
	}
	E := res.Scan.End
	if E < size {
		if res.Tail, err = probeTail(f, h, pool, E, size); err != nil {
			return fail(err)
		}
		if err := committed.protects(E, res.Tail); err != nil {
			return fail(err)
		}
		if err := f.Truncate(E); err != nil {
			return fail(err)
		}
		if err := f.Sync(); err != nil {
			return fail(err)
		}
		res.Truncated = size - E
	}
	w := &Writer{f: f, h: h, pool: pool, end: E, inflight: map[int64]struct{}{}}
	w.cond.L = &w.mu
	return w, res, nil
}

func reinitHeader(f vfs.File, h *wire.ArchiveHeader) error {
	hb, err := h.AppendBinary(nil)
	if err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(hb, 0); err != nil {
		return err
	}
	return f.Sync()
}

// End returns the offset where the next frame will be placed.
func (w *Writer) End() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.end
}

// Append builds the frame described by s into a pooled buffer and writes
// it at the next free offset. The frame is NOT durable until Sync returns
// nil (§10.4). It returns the frame's offset and size.
func (w *Writer) Append(s *frame.Spec) (off int64, size int64, err error) {
	buf := w.pool.Get(estimateFrameSize(w.h, s))
	b, err := frame.AppendFrame(buf[:0], w.h, s)
	if err != nil {
		w.pool.Put(buf)
		return 0, 0, err
	}
	defer w.pool.Put(b) // b may have grown past the estimate
	return w.write(b)
}

// estimateFrameSize returns an upper bound of the encoded frame size,
// capped at MAX_FRAME_SIZE, so small frames take small pooled buffers.
func estimateFrameSize(h *wire.ArchiveHeader, s *frame.Spec) int {
	maxSize := int(h.MaxFrameSize())
	if h.Mode == wire.ModeFixed || s.FrameQuanta != 0 {
		return maxSize
	}
	n := len(s.Payload) + wire.FrameOverhead + 8 + wire.MinParityPadding
	for i := range s.Entries {
		n += len(s.Entries[i].Path) + 2 + 24
		if n > maxSize {
			return maxSize
		}
	}
	n = (n + wire.BaseQuantum - 1) / wire.BaseQuantum * wire.BaseQuantum
	return min(n, maxSize)
}

// AppendEncoded writes an already encoded frame (for example a byte-exact
// copy during compaction). It checks only the frame's size against the
// archive mode; content validation is the caller's job.
func (w *Writer) AppendEncoded(fr []byte) (off int64, size int64, err error) {
	if len(fr) < wire.BaseQuantum || len(fr)%wire.BaseQuantum != 0 || uint64(len(fr)) > w.h.MaxFrameSize() ||
		(w.h.Mode == wire.ModeFixed && uint64(len(fr)) != w.h.MaxFrameSize()) {
		return 0, 0, fmt.Errorf("%w: frame of %d bytes", wire.ErrInvalid, len(fr))
	}
	return w.write(fr)
}

func (w *Writer) write(b []byte) (int64, int64, error) {
	n := int64(len(b))
	w.mu.Lock()
	if w.poisoned != nil {
		w.mu.Unlock()
		return 0, 0, w.poisoned
	}
	off := w.end
	w.end += n
	w.inflight[off] = struct{}{}
	w.mu.Unlock()
	// The page shared with the previous frame (§3.1.1) is rewritten by the
	// OS with that frame's bytes unchanged, because only our range is
	// written.
	_, err := w.f.WriteAt(b, off)
	w.mu.Lock()
	delete(w.inflight, off)
	if err != nil && w.poisoned == nil {
		w.poisoned = fmt.Errorf("%w: %v", ErrPoisoned, err)
	}
	w.cond.Broadcast()
	w.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	return off, n, nil
}

func (w *Writer) poison(err error) {
	w.mu.Lock()
	if w.poisoned == nil {
		w.poisoned = fmt.Errorf("%w: %v", ErrPoisoned, err)
	}
	w.mu.Unlock()
}

// waitBelow waits until every write allocated below end has completed, so
// that a sync never makes a frame durable while an earlier region of the
// blob is still a hole (a hole before a committed frame would SEAL the
// blob after a crash).
func (w *Writer) waitBelow(end int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		if w.poisoned != nil {
			return w.poisoned
		}
		busy := false
		for off := range w.inflight {
			if off < end {
				busy = true
				break
			}
		}
		if !busy {
			return nil
		}
		w.cond.Wait()
	}
}

// Sync makes durable every frame whose Append returned before Sync was
// called, and waits for appends still writing below them. After a failed
// Sync the writer is poisoned: what reached the disk is unknown, and the
// blob must be reopened (fsync is never retried, because a retry can
// falsely succeed).
func (w *Writer) Sync() error {
	if err := w.waitBelow(w.End()); err != nil {
		return err
	}
	if err := w.f.Sync(); err != nil {
		w.poison(err)
		return err
	}
	return nil
}

// Close closes the file without syncing.
func (w *Writer) Close() error { return w.f.Close() }

// IsSealed reports whether err is ErrSealed.
func IsSealed(err error) bool { return errors.Is(err, ErrSealed) }
