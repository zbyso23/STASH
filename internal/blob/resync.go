package blob

import (
	"io"
	"sort"

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
	Size    int64
	Frames  []ResyncFrame // by offset
	Damaged []Region      // bytes no valid frame covers, after the first failure
	// Unscanned is the region left when the hash budget ran out; it is
	// never reported as empty (§11.2.1).
	Unscanned  []Region
	Hashed     int64 // payload bytes hashed by resync probes
	Candidates int
	Conflicts  int
}

// DefaultResyncBudget returns the hash budget used when none is given:
// four times the blob size, enough for every legitimate frame to be
// hashed once while forged nested frames cannot make the work quadratic.
func DefaultResyncBudget(size int64) int64 { return 4*size + 64<<20 }

// Resync scans the blob for recovery (§11.2, §11.2.1, §11.3): a normal scan
// until the first frame that fails validation, then probes at every
// frame-grid offset (every slot in FIXED mode), also inside the extent of
// frames found by probing, so a forged frame cannot hide real ones.
// Frames found from the first failure on are resync candidates; candidates
// with overlapping extents are marked as conflicts. budget bounds the
// payload bytes hashed by probes (<= 0: DefaultResyncBudget).
func (r *Reader) Resync(budget int64) (ResyncResult, error) {
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
		res.Frames = append(res.Frames, resyncFrame(off, fsz, fr, false))
		off += fsz
	}
	if damagedFrom < 0 {
		return res, nil
	}
	var tailBuf []byte
	for off = damagedFrom + step; off+wire.FramePrefixSize <= size; off += step {
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
		res.Frames = append(res.Frames, resyncFrame(off, fsz, fr, true))
		res.Candidates++
	}
	markConflicts(res.Frames)
	for _, f := range res.Frames {
		if f.Conflict {
			res.Conflicts++
		}
	}
	res.Damaged = uncovered(res.Frames, damagedFrom, size, res.Unscanned)
	return res, nil
}

func resyncFrame(off, fsz int64, fr *frame.Frame, cand bool) ResyncFrame {
	rf := ResyncFrame{Offset: off, Size: fsz, Trailer: fr.Trailer, Candidate: cand}
	if fr.Entries != nil {
		rf.Entries = append([]wire.Entry(nil), fr.Entries...)
	}
	return rf
}

// markConflicts flags every pair of candidates whose extents overlap.
func markConflicts(fs []ResyncFrame) {
	sort.Slice(fs, func(i, j int) bool { return fs[i].Offset < fs[j].Offset })
	for i := range fs {
		if !fs[i].Candidate {
			continue
		}
		end := fs[i].Offset + fs[i].Size
		for j := i + 1; j < len(fs) && fs[j].Offset < end; j++ {
			if fs[j].Candidate {
				fs[i].Conflict, fs[j].Conflict = true, true
			}
		}
	}
}

// uncovered returns the parts of [from, size) that no frame covers, minus
// the unscanned region.
func uncovered(fs []ResyncFrame, from, size int64, unscanned []Region) []Region {
	limit := size
	if len(unscanned) > 0 {
		limit = unscanned[0].From
	}
	var out []Region
	at := from
	for _, f := range fs {
		if f.Offset+f.Size <= at {
			continue
		}
		if f.Offset > at {
			out = append(out, Region{at, min(f.Offset, limit)})
		}
		at = max(at, f.Offset+f.Size)
		if at >= limit {
			break
		}
	}
	if at < limit {
		out = append(out, Region{at, limit})
	}
	var clean []Region
	for _, r := range out {
		if r.To > r.From {
			clean = append(clean, r)
		}
	}
	return clean
}
