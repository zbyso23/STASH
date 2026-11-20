package blob

import (
	"io"

	"stash/internal/frame"
	"stash/internal/wire"
)

// Region is a byte range [From, To) of a blob.
type Region struct{ From, To int64 }

// ResyncFrame is a frame that validated completely (Prefix, tail, outer
// Pre-Trailer CRC, hash_payload) during a recovery scan.
type ResyncFrame struct {
	Offset  int64
	Size    int64
	Trailer wire.MasterTrailer
	Entries []wire.Entry // nil for PARITY and encrypted Pre-Trailers
	// Candidate: found by resynchronization or after it (§11.2.1);
	// unverified provenance unless a manifest references it.
	Candidate bool
	// Conflict: its extent overlaps another candidate's; neither may be
	// chosen silently.
	Conflict bool
}

// ResyncResult is the outcome of a recovery scan of one blob.
type ResyncResult struct {
	Size   int64
	Frames []ResyncFrame // by offset (Resync only; ResyncEach streams them)
	// NFrames counts the frames found.
	NFrames int
	// Damaged lists bytes no valid frame covers, after the first failure
	// (the first MaxRegions; DamagedRegions and DamagedBytes count all).
	Damaged        []Region
	DamagedRegions int
	DamagedBytes   int64
	// Unscanned is the region left when the hash budget ran out; it is
	// never reported as empty (§11.2.1).
	Unscanned  []Region
	Hashed     int64 // payload bytes hashed by resync probes
	Candidates int
	Conflicts  int
}

// MaxRegions bounds ResyncResult.Damaged.
const MaxRegions = 1000

func (res *ResyncResult) damaged(from, to int64) {
	if to <= from {
		return
	}
	if len(res.Damaged) < MaxRegions {
		res.Damaged = append(res.Damaged, Region{from, to})
	}
	res.DamagedRegions++
	res.DamagedBytes += to - from
}

// DefaultResyncBudget returns the hash budget used when none is given:
// four times the blob size, enough for every legitimate frame to be
// hashed once while forged nested frames cannot make the work quadratic.
func DefaultResyncBudget(size int64) int64 { return 4*size + 64<<20 }

// Resync scans the blob for recovery and returns every frame found (see
// ResyncEach, which streams them).
func (r *Reader) Resync(budget int64) (ResyncResult, error) {
	var fs []ResyncFrame
	res, err := r.ResyncEach(budget, func(f ResyncFrame) error {
		fs = append(fs, f)
		return nil
	})
	res.Frames = fs
	return res, err
}

// ResyncEach scans the blob for recovery (§11.2, §11.2.1, §11.3): a normal
// scan until the first frame that fails validation, then probes at every
// frame-grid offset (every slot in FIXED mode), also inside the extent of
// frames found by probing, so a forged frame cannot hide real ones.
// Frames found from the first failure on are resync candidates; candidates
// with overlapping extents are marked as conflicts. budget bounds the
// payload bytes hashed by probes (<= 0: DefaultResyncBudget).
//
// fn receives the frames in offset order. A candidate is held back only
// until no later probe can overlap it (one frame size), so memory does not
// grow with the blob.
func (r *Reader) ResyncEach(budget int64, fn func(ResyncFrame) error) (ResyncResult, error) {
	size, err := r.f.Size()
	if err != nil {
		return ResyncResult{}, err
	}
	if budget <= 0 {
		budget = DefaultResyncBudget(size)
	}
	res := ResyncResult{Size: size}
	w := &window{f: r.f, size: size, pool: r.pool}
	defer w.release()
	step := int64(wire.BaseQuantum)
	if r.h.Mode == wire.ModeFixed {
		step = int64(r.h.MaxFrameSize())
	}
	off := int64(wire.FrameAreaStart)
	damagedFrom := int64(-1) // first offset of the probing phase
	// normal scan (§11.2): never probes inside a validated frame
	for off < size {
		fr, fsz, err := parseAt(w, r.h, r.k, off)
		if err != nil {
			if !wire.IsFormatError(err) && err != io.ErrUnexpectedEOF {
				return res, err
			}
			damagedFrom = off
			break
		}
		res.NFrames++
		if err := fn(resyncFrame(off, fsz, fr, false)); err != nil {
			return res, err
		}
		off += fsz
	}
	if damagedFrom < 0 {
		return res, nil
	}
	// candidates whose extent a later probe may still overlap; covered is
	// the end of everything emitted, for the damaged regions
	var pending []ResyncFrame
	covered := damagedFrom
	limit := size
	emit := func(f ResyncFrame) error {
		if f.Conflict {
			res.Conflicts++
		}
		if f.Offset > covered {
			res.damaged(covered, min(f.Offset, limit))
		}
		covered = max(covered, f.Offset+f.Size)
		return fn(f)
	}
	settle := func(upTo int64) error {
		n := 0
		for n < len(pending) && pending[n].Offset+pending[n].Size <= upTo {
			n++
		}
		for _, f := range pending[:n] {
			if err := emit(f); err != nil {
				return err
			}
		}
		pending = append(pending[:0], pending[n:]...)
		return nil
	}
	var tailBuf []byte
	for off = damagedFrom + step; off+wire.FramePrefixSize <= size; off += step {
		if err := settle(off); err != nil {
			return res, err
		}
		// cheap checks first: Prefix and bounds, then tail and outer CRC
		hf, ok, err := tailAt(r.f, r.h, r.k, off, size, &tailBuf)
		if err != nil {
			return res, err
		}
		if !ok {
			continue
		}
		dl := int64(hf.Trailer.DataLen)
		if res.Hashed+dl > budget {
			res.Unscanned = append(res.Unscanned, Region{off, size})
			limit = off
			break
		}
		res.Hashed += dl
		fsz := int64(wire.FrameSize(hf.Quanta))
		b, err := w.get(off, int(fsz))
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				continue
			}
			return res, err
		}
		fr, err := frame.ParseKeyed(b, r.h, r.k)
		if err != nil {
			continue // hash_payload or deeper check failed
		}
		f := resyncFrame(off, fsz, fr, true)
		for i := range pending {
			if pending[i].Offset+pending[i].Size > off {
				pending[i].Conflict, f.Conflict = true, true
			}
		}
		pending = append(pending, f)
		res.Candidates++
		res.NFrames++
	}
	for _, f := range pending {
		if err := emit(f); err != nil {
			return res, err
		}
	}
	if covered < limit {
		res.damaged(covered, limit)
	}
	return res, nil
}

func resyncFrame(off, fsz int64, fr *frame.Frame, cand bool) ResyncFrame {
	rf := ResyncFrame{Offset: off, Size: fsz, Trailer: fr.Trailer, Candidate: cand}
	if fr.Entries != nil {
		rf.Entries = append([]wire.Entry(nil), fr.Entries...)
	}
	return rf
}
