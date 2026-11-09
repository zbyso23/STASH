package blob

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// FrameKey identifies the frame a manifest loc resolves to (§9.1): its
// frame_hash plus the object metadata that selects among payload-identical
// frames. For a PACKED frame Offset is 0 and Path/FileVer name the entry.
type FrameKey struct {
	Hash    [32]byte
	Path    string
	FileVer uint64
	Offset  uint64
}

// Committed describes what the manifest graph (all LF-terminated records,
// anchored or not) references in this blob, for the torn-tail decision of
// §10.4.2. The manifest layer supplies it. The zero value means "nothing is
// referenced", which is correct only for a blob no manifest record names.
type Committed struct {
	// Refs holds every frame of this blob that a loc references, whether
	// the record is committed, live, dead, or inside an open transaction.
	Refs map[FrameKey]struct{}
	// GroupReferenced reports whether a loc anywhere references a frame
	// carrying groupID (non-zero). nil means no group is referenced.
	GroupReferenced func(groupID uint32) bool
	// TailMayHoldCommitted is set when a committed parity group lacks a
	// member that no blob holds intact: such a member may lie in this
	// blob's [E, EOF), so the tail is not truncated (§10.4.2, E1-22).
	TailMayHoldCommitted bool
	// Verified is an optional checkpoint from a clean close (E1-23).
	Verified Checkpoint
}

// Checkpoint records that every frame below End was validated completely
// and durably flushed; the frame [LastOff, End) carries LastHash. Below
// End the open scan checks Prefixes and tails only (no payload hashing);
// the frame ending at End is validated completely. A checkpoint that does
// not match the blob is ignored.
type Checkpoint struct {
	End, LastOff int64
	LastHash     [32]byte
}

// keysOf returns the keys under which a validated frame satisfies locs.
func keysOf(f *frame.Frame) []FrameKey { return keysOfTail(&f.Trailer, f.Entries) }

func keysOfTail(t *wire.MasterTrailer, entries []wire.Entry) []FrameKey {
	switch t.BlockType {
	case wire.BlockData:
		if len(entries) == 1 {
			e := entries[0]
			return []FrameKey{{Hash: t.HashPayload, Path: e.Path, FileVer: e.FileVer, Offset: e.Offset}}
		}
	case wire.BlockPacked:
		ks := make([]FrameKey, len(entries))
		for i, e := range entries {
			ks[i] = FrameKey{Hash: t.HashPayload, Path: e.Path, FileVer: e.FileVer}
		}
		return ks
	}
	return nil
}

// protects reports why the tail starting at E may not be truncated: a
// referenced frame is not among the valid frames before E (it lies in the
// damaged region, valid or not), or a valid frame beyond E carries a
// referenced group_id.
func (c *Committed) protects(E int64, satisfied int, tail []TailFrame, atE *HopFrame) error {
	if satisfied < len(c.Refs) {
		return fmt.Errorf("%w: %d referenced frame(s) are not in the valid run before %d", ErrSealed, len(c.Refs)-satisfied, E)
	}
	if c.TailMayHoldCommitted {
		return fmt.Errorf("%w: a committed parity group lacks a member that may lie in [%d, EOF)", ErrSealed, E)
	}
	if c.GroupReferenced == nil {
		return nil
	}
	if atE != nil && atE.Trailer.GroupID != 0 && c.GroupReferenced(atE.Trailer.GroupID) {
		// a damaged frame whose tail is intact belongs to a committed group
		return fmt.Errorf("%w: damaged frame at %d belongs to committed parity group %d", ErrSealed, E, atE.Trailer.GroupID)
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
	// Checkpointed is the number of frames below a matching checkpoint
	// whose payloads were not hashed (E1-23).
	Checkpointed int
	// MaxGroupID and MaxOrdinal are the largest group_id and frame_ordinal
	// over every valid frame found (valid run and tail), for the allocator
	// cold-start checks (§2.1.3.1); HasFrames is false when there are none.
	MaxGroupID uint32
	MaxOrdinal uint64
	HasFrames  bool
	// MaxNonceOrdinal is the largest frame_ordinal encoded in a stored
	// nonce whose (generation_id, blob_ordinal) prefix is this namespace
	// (encrypted archives, §2.1.3.1, §2.1.3.4); copied frames keep the
	// nonce of their origin and do not count. HasNonce is false if none.
	MaxNonceOrdinal uint64
	HasNonce        bool
	gen             uint64
	ordinal         uint8
}

func (r *OpenResult) see(t *wire.MasterTrailer, nonce []byte) {
	r.HasFrames = true
	r.MaxGroupID = max(r.MaxGroupID, t.GroupID)
	r.MaxOrdinal = max(r.MaxOrdinal, t.FrameOrdinal)
	if len(nonce) == wire.AEADNonceSize {
		if g, b, o := seal.SplitFrameNonce(nonce); g == r.gen && b == r.ordinal {
			r.MaxNonceOrdinal = max(r.MaxNonceOrdinal, o)
			r.HasNonce = true
		}
	}
}

// Writer appends frames to one blob. Methods are safe for concurrent use:
// only the allocation of the next offset is serialized (§12.2); building
// frames (hashing) and writing them run in parallel.
type Writer struct {
	f       vfs.File
	h       *wire.ArchiveHeader
	k       *seal.Keys
	ordinal uint8
	pool    *bufpool.Pool

	mu       sync.Mutex
	cond     sync.Cond          // signals completion of an in-flight write
	inflight map[int64]struct{} // offsets allocated but not yet written
	end      int64              // next frame offset
	poisoned error
}

// OpenWriter opens a blob for appending. It scans the blob, applies the
// torn-tail rules of §10.4.2 and returns a writer positioned at E:
//
//   - a referenced frame is not in the valid run before E, or a valid frame
//     beyond E carries a referenced group_id: the blob is SEALED; ErrSealed
//     is returned together with the OpenResult and no writer;
//   - otherwise (no valid frame there, or only uncommitted ones): truncate
//     to E and sync.
//
// A blob whose header is incomplete and that holds nothing beyond it (a
// crash inside Create) is re-initialized.
func OpenWriter(fsys vfs.FS, name string, h *wire.ArchiveHeader, pool *bufpool.Pool, committed Committed) (*Writer, OpenResult, error) {
	return OpenWriterKeyed(fsys, name, h, pool, committed, nil, 0)
}

// OpenWriterKeyed is OpenWriter for the blob with the given ordinal, with
// the keys of an encrypted archive: committed references are matched
// through decrypted Pre-Trailers, stored nonces of this namespace are
// reported (OpenResult.MaxNonceOrdinal), and appended DATA/PACKED frames
// are sealed with nonces of (generation_id, ordinal, frame_ordinal).
func OpenWriterKeyed(fsys vfs.FS, name string, h *wire.ArchiveHeader, pool *bufpool.Pool, committed Committed, k *seal.Keys, ordinal uint8) (*Writer, OpenResult, error) {
	res := OpenResult{gen: h.GenerationID, ordinal: ordinal}
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
	satisfied := map[FrameKey]struct{}{}
	collect := func(_ int64, fr *frame.Frame) error {
		res.see(&fr.Trailer, storedNonce(h, &fr.Trailer, fr.PreTrailer))
		if len(committed.Refs) == 0 {
			return nil
		}
		for _, k := range keysOf(fr) {
			if _, ok := committed.Refs[k]; ok {
				satisfied[k] = struct{}{}
			}
		}
		return nil
	}
	start := int64(wire.FrameAreaStart)
	if n, ok, err := useCheckpoint(f, h, k, pool, committed.Verified, size, func(hf HopFrame) {
		res.see(&hf.Trailer, hf.Nonce)
		for _, k := range keysOfTail(&hf.Trailer, hf.Entries) {
			if _, ok := committed.Refs[k]; ok {
				satisfied[k] = struct{}{}
			}
		}
	}); err != nil {
		return fail(err)
	} else if ok {
		start, res.Checkpointed = committed.Verified.End, n
	} else {
		clear(satisfied)
		res = OpenResult{gen: h.GenerationID, ordinal: ordinal}
	}
	if res.Scan, err = scan(f, h, k, pool, start, size, collect); err != nil {
		return fail(err)
	}
	res.Scan.Frames += res.Checkpointed
	E := res.Scan.End
	if len(satisfied) < len(committed.Refs) {
		// Committed data lies at or beyond E even if nothing validates
		// there (damage of §3.1.1 item 4); the blob is sealed either way.
		if E < size {
			res.Tail, _ = probeTail(f, h, k, pool, E, size)
		}
		return fail(committed.protects(E, len(satisfied), res.Tail, nil))
	}
	if E < size {
		if res.Tail, err = probeTail(f, h, k, pool, E, size); err != nil {
			return fail(err)
		}
		for i := range res.Tail {
			res.see(&res.Tail[i].Trailer, res.Tail[i].Nonce)
		}
		var atE *HopFrame
		var scratch []byte
		if hf, ok, err := tailAt(f, h, k, E, size, &scratch); err != nil {
			return fail(err)
		} else if ok {
			atE = &hf
			res.see(&hf.Trailer, hf.Nonce)
		}
		if err := committed.protects(E, len(satisfied), res.Tail, atE); err != nil {
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
	w := &Writer{f: f, h: h, k: k, ordinal: ordinal, pool: pool, end: E, inflight: map[int64]struct{}{}}
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
	rec, err := w.AppendIndexed(s)
	if err != nil {
		return 0, 0, err
	}
	return int64(rec.PhysicalOffset), int64(wire.FrameSize(rec.FrameQuanta)), nil
}

// AppendIndexed is Append returning the frame's physical index record
// (§10.5), ready for index.Index.Add.
func (w *Writer) AppendIndexed(s *frame.Spec) (wire.IndexRecord, error) {
	w.Seal(s)
	buf := w.pool.Get(estimateFrameSize(w.h, s))
	b, err := frame.AppendFrame(buf[:0], w.h, s)
	if err != nil {
		w.pool.Put(buf)
		return wire.IndexRecord{}, err
	}
	defer w.pool.Put(b) // b may have grown past the estimate
	return w.AppendBuilt(b)
}

// Seal sets the sealing context of s for this blob (encrypted archives):
// the archive keys and this blob's ordinal for the nonce.
func (w *Writer) Seal(s *frame.Spec) {
	if w.k != nil {
		s.Keys, s.Blob = w.k, w.ordinal
	}
}

// AppendBuilt writes a frame that frame.AppendFrame just encoded (so it is
// valid by construction) and returns its index record.
func (w *Writer) AppendBuilt(b []byte) (wire.IndexRecord, error) {
	if len(b) < wire.BaseQuantum {
		return wire.IndexRecord{}, fmt.Errorf("%w: frame of %d bytes", wire.ErrInvalid, len(b))
	}
	t, err := wire.DecodeMasterTrailer(b[len(b)-wire.MasterTrailerSize:])
	if err != nil {
		return wire.IndexRecord{}, err
	}
	off, _, err := w.AppendEncoded(b)
	if err != nil {
		return wire.IndexRecord{}, err
	}
	return wire.IndexRecord{FrameHash: t.HashPayload, PhysicalOffset: uint64(off), FrameQuanta: t.FrameQuanta,
		BlockType: t.BlockType, FrameOrdinal: t.FrameOrdinal}, nil
}

// estimateFrameSize returns an upper bound of the encoded frame size,
// capped at MAX_FRAME_SIZE, so small frames take small pooled buffers.
func estimateFrameSize(h *wire.ArchiveHeader, s *frame.Spec) int {
	maxSize := int(h.MaxFrameSize())
	if h.Mode == wire.ModeFixed || s.FrameQuanta != 0 {
		return maxSize
	}
	n := len(s.Payload) + wire.FrameOverhead + 8 + wire.MinParityPadding + 2*wire.AEADOverhead
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

// useCheckpoint walks [FRAME_AREA_START, cp.End) by Prefix and tail
// (hop-and-read without payload hashing) and validates the frame ending at
// cp.End completely. ok is false when the checkpoint does not match the
// blob exactly (a gap, another last frame, a different length); the
// caller then scans everything. see receives every frame walked.
func useCheckpoint(f vfs.File, h *wire.ArchiveHeader, k *seal.Keys, pool *bufpool.Pool, cp Checkpoint, size int64, see func(HopFrame)) (int, bool, error) {
	if cp.End <= wire.FrameAreaStart || cp.End > size || cp.LastOff < wire.FrameAreaStart || cp.LastOff >= cp.End {
		return 0, false, nil
	}
	var buf []byte
	var seen []HopFrame
	off := int64(wire.FrameAreaStart)
	for off < cp.End {
		hf, ok, err := tailAt(f, h, k, off, cp.End, &buf)
		if err != nil {
			return 0, false, err
		}
		if !ok {
			return 0, false, nil
		}
		seen = append(seen, hf)
		off += int64(wire.FrameSize(hf.Quanta))
	}
	last := seen[len(seen)-1]
	if off != cp.End || last.Offset != cp.LastOff || last.Trailer.HashPayload != cp.LastHash {
		return 0, false, nil
	}
	w := &window{f: f, size: cp.End, pool: pool}
	_, _, err := parseAt(w, h, k, cp.LastOff) // full validation, hash included
	w.release()
	if err != nil {
		if !wire.IsFormatError(err) && err != io.ErrUnexpectedEOF {
			return 0, false, err
		}
		return 0, false, nil
	}
	for _, hf := range seen {
		see(hf)
	}
	return len(seen), true, nil
}
