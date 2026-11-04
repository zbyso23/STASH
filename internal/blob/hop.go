package blob

import (
	"stash/internal/vfs"
	"stash/internal/wire"
)

// HopFrame is a frame found by Hop: a valid Prefix and an intact tail
// (outer CRC over Pre-Trailer, length and Master Trailer, §6.4.3). The
// payload is NOT read or hashed.
type HopFrame struct {
	Offset  int64
	Quanta  uint32
	Trailer wire.MasterTrailer
	// Entries are the plaintext Pre-Trailer entries (nil for PARITY, and
	// for encrypted or undecodable Pre-Trailers).
	Entries []wire.Entry
}

// Hop walks the blob frame by frame reading only Prefixes and tails
// (hop-and-read, §11.2): after a frame whose Prefix and tail validate it
// jumps to the frame's end; anywhere else it advances one base quantum, so
// a damaged region is skipped and the walk resynchronizes on the frame
// grid. It is meant for discovery (parity groups, §11.6); a frame it
// reports must still be validated completely before its payload is used.
func (r *Reader) Hop(fn func(HopFrame) error) error {
	_, err := r.HopFrom(wire.FrameAreaStart, fn)
	return err
}

// HopFrom is Hop starting at from (on the frame grid). It returns the end
// of the contiguous run of frames it validated from there: the offset of
// the first position where no frame validated, or where the walk stopped.
func (r *Reader) HopFrom(from int64, fn func(HopFrame) error) (contiguous int64, err error) {
	size, err := r.f.Size()
	if err != nil {
		return from, err
	}
	contiguous = -1
	var buf []byte
	off := from
	for off+wire.BaseQuantum <= size {
		hf, ok, err := tailAt(r.f, r.h, off, size, &buf)
		if err != nil {
			return from, err
		}
		if !ok {
			if contiguous < 0 {
				contiguous = off
			}
			off += wire.BaseQuantum
			continue
		}
		if err := fn(hf); err != nil {
			return from, err
		}
		off += int64(wire.FrameSize(hf.Quanta))
	}
	if contiguous < 0 {
		contiguous = off
	}
	return contiguous, nil
}

// tailAt checks the Prefix and the tail of a frame at off without reading
// its payload. ok is false when they do not validate; err reports I/O
// errors only. buf is a reusable scratch buffer.
func tailAt(f vfs.File, h *wire.ArchiveHeader, off, size int64, buf *[]byte) (HopFrame, bool, error) {
	var pre [wire.FramePrefixSize]byte
	if _, err := f.ReadAt(pre[:], off); err != nil {
		return HopFrame{}, false, err
	}
	p, err := wire.DecodeFramePrefix(pre[:], h)
	if err != nil {
		return HopFrame{}, false, nil
	}
	S := int64(wire.FrameSize(p.FrameQuanta))
	if off+S > size {
		return HopFrame{}, false, nil
	}
	var last [wire.MasterTrailerSize + wire.PreTrailerLenSize]byte
	if _, err := f.ReadAt(last[:], off+S-int64(len(last))); err != nil {
		return HopFrame{}, false, err
	}
	need, err := wire.TailLen(last[:], uint64(S))
	if err != nil {
		return HopFrame{}, false, nil
	}
	if cap(*buf) < need {
		*buf = make([]byte, need)
	}
	tail := (*buf)[:need]
	if _, err := f.ReadAt(tail, off+S-int64(need)); err != nil {
		return HopFrame{}, false, err
	}
	t, err := wire.DecodeTail(tail, uint64(S))
	if err != nil || wire.ValidateTrailer(&t.Trailer, h, p) != nil {
		return HopFrame{}, false, nil
	}
	hf := HopFrame{Offset: off, Quanta: p.FrameQuanta, Trailer: t.Trailer}
	if t.Trailer.BlockType != wire.BlockParity && !h.Encrypted() {
		if es, err := wire.DecodeEntries(t.Body[:len(t.Body)-4]); err == nil {
			hf.Entries = es
		}
	}
	return hf, true, nil
}
