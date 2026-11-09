package blob

import (
	"fmt"
	"io"

	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// readAheadSize is the scan window. Frames larger than the window are read
// into a buffer of their own size.
const readAheadSize = 1 << 20

// window is a pooled read-ahead buffer over a file.
type window struct {
	f    vfs.File
	size int64
	pool *bufpool.Pool
	buf  []byte
	off  int64 // file offset of buf[0]
	n    int   // valid bytes in buf
}

// get returns file bytes [off, off+n). The slice is valid until the next
// call. n must already be bounded by validated values and the file size.
func (w *window) get(off int64, n int) ([]byte, error) {
	if off >= w.off && off+int64(n) <= w.off+int64(w.n) {
		s := off - w.off
		return w.buf[s : s+int64(n)], nil
	}
	want := max(n, readAheadSize)
	if cap(w.buf) < want {
		if w.buf != nil {
			w.pool.Put(w.buf)
		}
		w.buf = w.pool.Get(want)
	}
	w.buf = w.buf[:cap(w.buf)]
	r := int(min(int64(len(w.buf)), w.size-off))
	m, err := w.f.ReadAt(w.buf[:r], off)
	if err != nil && !(err == io.EOF && m == r) {
		w.n = 0
		return nil, err
	}
	w.off, w.n = off, m
	if m < n {
		return nil, io.ErrUnexpectedEOF
	}
	return w.buf[:n], nil
}

func (w *window) release() {
	if w.buf != nil {
		w.pool.Put(w.buf)
		w.buf = nil
	}
}

// ScanResult describes an uninterrupted scan from FRAME_AREA_START.
type ScanResult struct {
	// End is E of §10.4.2: the end of the last frame that is valid in an
	// uninterrupted scan (FRAME_AREA_START if none).
	End int64
	// Size is the blob size at scan time.
	Size int64
	// Frames is the number of valid frames before End.
	Frames int
	// Err is why the scan stopped before Size (nil if End == Size).
	Err error
}

// Scan walks frames from FRAME_AREA_START (§11.2, §11.3) and calls fn for
// each valid frame until the first invalid one. The frame passed to fn
// aliases a pooled buffer and is valid only during the call. A non-nil error
// from fn stops the scan and is returned.
func (r *Reader) Scan(fn func(off int64, f *frame.Frame) error) (ScanResult, error) {
	size, err := r.f.Size()
	if err != nil {
		return ScanResult{}, err
	}
	return scan(r.f, r.h, r.k, r.pool, wire.FrameAreaStart, size, fn)
}

// ScanFrom is Scan starting at a known frame boundary from (for example the
// end of the frames a lagging index covers, §10.5.1). End and Frames count
// from there.
func (r *Reader) ScanFrom(from int64, fn func(off int64, f *frame.Frame) error) (ScanResult, error) {
	if from < wire.FrameAreaStart || !wire.OnFrameGrid(uint64(from)) {
		return ScanResult{}, fmt.Errorf("%w: scan start %d is not on the frame grid", wire.ErrInvalid, from)
	}
	size, err := r.f.Size()
	if err != nil {
		return ScanResult{}, err
	}
	return scan(r.f, r.h, r.k, r.pool, from, size, fn)
}

func scan(f vfs.File, h *wire.ArchiveHeader, k *seal.Keys, pool *bufpool.Pool, from, size int64, fn func(int64, *frame.Frame) error) (ScanResult, error) {
	w := &window{f: f, size: size, pool: pool}
	defer w.release()
	res := ScanResult{End: from, Size: size}
	off := from
	for off < size {
		fr, fsz, err := parseAt(w, h, k, off)
		if err != nil {
			if !wire.IsFormatError(err) && err != io.ErrUnexpectedEOF {
				return res, err // I/O error: not a torn tail
			}
			res.Err = err
			return res, nil
		}
		if fn != nil {
			if err := fn(off, fr); err != nil {
				return res, err
			}
		}
		off += fsz
		res.End = off
		res.Frames++
	}
	return res, nil
}

// parseAt validates the frame at off completely.
func parseAt(w *window, h *wire.ArchiveHeader, k *seal.Keys, off int64) (*frame.Frame, int64, error) {
	if off+wire.FramePrefixSize > w.size {
		return nil, 0, io.ErrUnexpectedEOF
	}
	pb, err := w.get(off, wire.FramePrefixSize)
	if err != nil {
		return nil, 0, err
	}
	p, err := wire.DecodeFramePrefix(pb, h)
	if err != nil {
		return nil, 0, err
	}
	fsz := int64(wire.FrameSize(p.FrameQuanta))
	if off+fsz > w.size {
		return nil, 0, io.ErrUnexpectedEOF
	}
	b, err := w.get(off, int(fsz))
	if err != nil {
		return nil, 0, err
	}
	fr, err := frame.ParseKeyed(b, h, k)
	if err != nil {
		return nil, 0, err
	}
	return fr, fsz, nil
}

// TailFrame is a valid frame found at a frame-grid offset at or beyond E.
type TailFrame struct {
	Offset  int64
	Trailer wire.MasterTrailer
	Nonce   []byte // stored Pre-Trailer nonce (encrypted DATA/PACKED), else nil
}

// ProbeTail validates a frame at every frame-grid offset in [from, size),
// including offsets inside the extent of another found frame, so that a
// forged frame cannot hide a real one (§10.4.2, §11.2.1). Probes stop at
// the first failing check, so non-frame bytes cost one prefix CRC each.
func (r *Reader) ProbeTail(from int64) ([]TailFrame, error) {
	size, err := r.f.Size()
	if err != nil {
		return nil, err
	}
	return probeTail(r.f, r.h, r.k, r.pool, from, size)
}

func probeTail(f vfs.File, h *wire.ArchiveHeader, k *seal.Keys, pool *bufpool.Pool, from, size int64) ([]TailFrame, error) {
	w := &window{f: f, size: size, pool: pool}
	defer w.release()
	var out []TailFrame
	for off := from; off+wire.FramePrefixSize <= size; off += wire.BaseQuantum {
		fr, _, err := parseAt(w, h, k, off)
		if err != nil {
			if !wire.IsFormatError(err) && err != io.ErrUnexpectedEOF {
				return nil, err
			}
			continue
		}
		out = append(out, TailFrame{Offset: off, Trailer: fr.Trailer, Nonce: storedNonce(h, &fr.Trailer, fr.PreTrailer)})
	}
	return out, nil
}
