package index

import (
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
func Open(fsys vfs.FS, name string, r *blob.Reader, h *wire.ArchiveHeader, ordinal uint8, pool *bufpool.Pool) (*Index, Status, error) {
	var st Status
	size, err := r.Size()
	if err != nil {
		return nil, st, err
	}
	x, err := Load(fsys, name, h, ordinal, size, pool)
	if err == nil {
		st.CaughtUp, err = x.CatchUp(r)
		if err != nil {
			return nil, st, err
		}
		return x, st, nil
	}
	if !isDiscard(err) {
		return nil, st, err
	}
	st.Discarded = err
	x, _, err = Build(r, h, ordinal)
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
	for _, c := range x.Lookup(hash) {
		ref, err := r.ReadFrame(int64(c.PhysicalOffset))
		if err != nil {
			if wire.IsFormatError(err) {
				continue
			}
			return nil, NotFound, err
		}
		t := &ref.Trailer
		if t.HashPayload == hash && t.FrameQuanta == c.FrameQuanta && t.BlockType == c.BlockType &&
			t.FrameOrdinal == c.FrameOrdinal && (accept == nil || accept(ref)) {
			return ref, ViaIndex, nil
		}
		ref.Release()
	}
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
