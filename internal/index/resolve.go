package index

import (
	"encoding/binary"
	"fmt"
	"slices"

	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Status reports how an index was obtained by Open.
type Status struct {
	// Discarded is why a stored index was not used (nil if it was).
	Discarded error
	// Rebuilt is true when the index was built by a full scan.
	Rebuilt bool
	// CaughtUp counts frames added by scanning past a lagging index.
	CaughtUp int
}

// Open loads the stored index of a blob, validates it, and catches up if it
// lags (§10.5.1). A missing or invalid index is rebuilt by a scan in memory;
// the caller decides whether to persist it with Write (a writer should,
// a read-only opener must not).
func Open(env *Env, fsys vfs.FS, name string, r *blob.Reader, h *wire.ArchiveHeader, ordinal uint8, pool *bufpool.Pool) (*Index, Status, error) {
	var st Status
	size, err := r.Size()
	if err != nil {
		return nil, st, err
	}
	x, err := Load(env, fsys, name, h, ordinal, size, pool)
	if err == nil {
		st.CaughtUp, err = x.CatchUp(r)
		if err != nil {
			x.Close()
			return nil, st, err
		}
		return x, st, nil
	}
	if !isDiscard(err) {
		return nil, st, err
	}
	st.Discarded = err
	x, _, err = Build(env, r, h, ordinal)
	if err != nil {
		return nil, st, err
	}
	st.Rebuilt = true
	return x, st, nil
}

// Resolution says how Find located a frame.
type Resolution int

const (
	// NotFound: neither the index nor the fallback scan found the frame.
	NotFound Resolution = iota
	// ViaIndex: an index candidate validated.
	ViaIndex
	// ViaScan: only the fallback scan found it; the index is defective and
	// SHOULD be rebuilt (§10.5.1).
	ViaScan
)

// Find returns the first frame with frame_hash hash that validates
// completely and that accept approves (accept may check block type, object
// metadata or Pre-Trailer entries to pick among payload-identical frames;
// nil accepts any). Index candidates are tried first, in offset order; if
// none qualifies, a streaming scan of the blob follows before the frame is
// reported missing. The returned Ref must be released.
func (x *Index) Find(r *blob.Reader, hash [wire.HashSize]byte, accept func(*blob.Ref) bool) (*blob.Ref, Resolution, error) {
	ref, err := x.findIndexed(r, hash, accept)
	if ref != nil || err != nil {
		return ref, ViaIndex, err
	}
	// no candidate validated (or the stored file changed under us): the
	// bounded streaming scan of §10.5.1, without holding the index
	var found []int64
	if _, err := r.Scan(func(off int64, f *frame.Frame) error {
		if f.Trailer.HashPayload == hash {
			found = append(found, off)
		}
		return nil
	}); err != nil {
		return nil, NotFound, err
	}
	for _, off := range found {
		ref, err := r.ReadFrame(off)
		if err != nil {
			if wire.IsFormatError(err) {
				continue
			}
			return nil, NotFound, err
		}
		if accept == nil || accept(ref) {
			return ref, ViaScan, nil
		}
		ref.Release()
	}
	return nil, NotFound, nil
}

// findIndexed tries the index candidates in offset order, streaming them
// (a hash shared by many frames is never collected in memory). A failure
// to read the index itself is not an error here: it is treated like a
// miss, so the caller falls back to the scan.
func (x *Index) findIndexed(r *blob.Reader, hash [wire.HashSize]byte, accept func(*blob.Ref) bool) (*blob.Ref, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.closed {
		return nil, nil
	}
	for c := x.candidates(hash); c.next(); {
		ref, err := r.ReadFrame(int64(c.rec.PhysicalOffset))
		if err != nil {
			if wire.IsFormatError(err) {
				continue
			}
			return nil, err
		}
		t := &ref.Trailer
		if t.HashPayload == hash && t.FrameQuanta == c.rec.FrameQuanta && t.BlockType == c.rec.BlockType &&
			t.FrameOrdinal == c.rec.FrameOrdinal && (accept == nil || accept(ref)) {
			return ref, nil
		}
		ref.Release()
	}
	return nil, nil
}

// FindAt tries the single frame at off, which must be an index candidate
// of hash: a locator hint is checked against the validated index before
// the frame is read, and the frame is validated like any candidate. nil
// means the hint did not hold; the caller then uses Find.
func (x *Index) FindAt(r *blob.Reader, hash [wire.HashSize]byte, off uint64, accept func(*blob.Ref) bool) (*blob.Ref, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.closed {
		return nil, nil
	}
	rec, found, err := x.recordAt(hash, off)
	if err != nil || !found {
		return nil, nil // an unreadable index is a miss here, as in Find
	}
	ref, err := r.ReadFrame(int64(off))
	if err != nil {
		if wire.IsFormatError(err) {
			return nil, nil
		}
		return nil, err
	}
	t := &ref.Trailer
	if t.HashPayload == hash && t.FrameQuanta == rec.FrameQuanta && t.BlockType == rec.BlockType &&
		t.FrameOrdinal == rec.FrameOrdinal && (accept == nil || accept(ref)) {
		return ref, nil
	}
	ref.Release()
	return nil, nil
}

// recordAt finds the record (hash, off) by binary search in every source,
// so a hinted lookup costs O(log) record reads however many frames share
// the hash. x.mu is held.
func (x *Index) recordAt(hash [wire.HashSize]byte, off uint64) (wire.IndexRecord, bool, error) {
	cache := x.env.cache()
	files := x.runs
	if x.base != nil {
		files = append([]*idxFile{x.base}, x.runs...)
	}
	for _, f := range files {
		i, err := cache.lowerBoundAt(f, &hash, off)
		if err != nil {
			return wire.IndexRecord{}, false, err
		}
		if i >= f.n {
			continue
		}
		raw, err := cache.raw(f, i)
		if err != nil {
			return wire.IndexRecord{}, false, err
		}
		if [wire.HashSize]byte(raw[:wire.HashSize]) != hash || binary.LittleEndian.Uint64(raw[32:40]) != off {
			continue
		}
		r, err := wire.DecodeIndexRecord(raw, x.h)
		if err != nil {
			return wire.IndexRecord{}, false, fmt.Errorf("%w: %w", ErrDiscard, err)
		}
		return r, true, nil
	}
	want := wire.IndexRecord{FrameHash: hash, PhysicalOffset: off}
	if i, ok := slices.BinarySearchFunc(x.recs, want, func(a, b wire.IndexRecord) int { return less(&a, &b) }); ok {
		return x.recs[i], true, nil
	}
	for _, r := range x.pending {
		if r.FrameHash == hash && r.PhysicalOffset == off {
			return r, true, nil
		}
	}
	return wire.IndexRecord{}, false, nil
}

// EachCandidate streams the index records of hash in offset order until
// fn returns false.
func (x *Index) EachCandidate(hash [wire.HashSize]byte, fn func(wire.IndexRecord) bool) error {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.closed {
		return nil
	}
	c := x.candidates(hash)
	for c.next() {
		if !fn(c.rec) {
			break
		}
	}
	return c.err
}
