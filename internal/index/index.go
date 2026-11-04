// Package index maintains the per-generation physical offset index of one
// blob (SPEC §10.5): a sorted multimap frame_hash -> frame records that is
// rebuildable from a blob scan and never authoritative. Every candidate is
// validated against the actual frame before use.
package index

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"

	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/checked"
	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Name returns the normative index file name below a generation directory.
func Name(ordinal uint8) (string, error) {
	if ordinal > wire.MaxBlobOrdinal {
		return "", fmt.Errorf("%w: blob ordinal 0x%02X", wire.ErrInvalid, ordinal)
	}
	return fmt.Sprintf("index/blob-%02X.idx", ordinal), nil
}

// Index is the in-memory index of one blob. It is not safe for concurrent
// mutation; lookups may run concurrently with each other.
type Index struct {
	h       *wire.ArchiveHeader
	ordinal uint8
	recs    []wire.IndexRecord // sorted by (frame_hash, physical_offset)
	pending []wire.IndexRecord // recently added, unsorted
	end     int64              // I of §10.5.1 over recs and pending
}

// New returns an empty index for blob ordinal of the generation h.
func New(h *wire.ArchiveHeader, ordinal uint8) *Index {
	return &Index{h: h, ordinal: ordinal, end: wire.FrameAreaStart}
}

// Len returns the number of records.
func (x *Index) Len() int { return len(x.recs) + len(x.pending) }

// End returns I: the largest end of an indexed frame, or FRAME_AREA_START.
func (x *Index) End() int64 { return x.end }

func less(a, b *wire.IndexRecord) int {
	if c := bytes.Compare(a.FrameHash[:], b.FrameHash[:]); c != 0 {
		return c
	}
	return cmp.Compare(a.PhysicalOffset, b.PhysicalOffset)
}

// RecordOf returns the index record of a validated frame at off.
func RecordOf(off int64, f *frame.Frame) wire.IndexRecord {
	return wire.IndexRecord{
		FrameHash:      f.Trailer.HashPayload,
		PhysicalOffset: uint64(off),
		FrameQuanta:    f.Trailer.FrameQuanta,
		BlockType:      f.Trailer.BlockType,
		FrameOrdinal:   f.Trailer.FrameOrdinal,
	}
}

// Add records a frame (writer hot path). Records are merged into the sorted
// set in batches.
func (x *Index) Add(r wire.IndexRecord) {
	x.pending = append(x.pending, r)
	x.end = max(x.end, int64(r.PhysicalOffset+wire.FrameSize(r.FrameQuanta)))
	if len(x.pending) >= 1024 {
		x.merge()
	}
}

func (x *Index) merge() {
	if len(x.pending) == 0 {
		return
	}
	slices.SortFunc(x.pending, func(a, b wire.IndexRecord) int { return less(&a, &b) })
	out := make([]wire.IndexRecord, 0, len(x.recs)+len(x.pending))
	i, j := 0, 0
	for i < len(x.recs) && j < len(x.pending) {
		if less(&x.recs[i], &x.pending[j]) <= 0 {
			out = append(out, x.recs[i])
			i++
		} else {
			out = append(out, x.pending[j])
			j++
		}
	}
	out = append(append(out, x.recs[i:]...), x.pending[j:]...)
	x.recs, x.pending = out, x.pending[:0]
}

// Lookup returns every record with frame_hash h, ordered by offset. The
// records are candidates only (§10.5).
func (x *Index) Lookup(h [wire.HashSize]byte) []wire.IndexRecord {
	i, _ := slices.BinarySearchFunc(x.recs, h, func(r wire.IndexRecord, h [32]byte) int {
		return bytes.Compare(r.FrameHash[:], h[:])
	})
	var out []wire.IndexRecord
	for ; i < len(x.recs) && x.recs[i].FrameHash == h; i++ {
		out = append(out, x.recs[i])
	}
	for _, r := range x.pending {
		if r.FrameHash == h {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b wire.IndexRecord) int { return cmp.Compare(a.PhysicalOffset, b.PhysicalOffset) })
	return out
}

// Build indexes every frame of the uninterrupted scan of r (§11.2).
func Build(r *blob.Reader, h *wire.ArchiveHeader, ordinal uint8) (*Index, blob.ScanResult, error) {
	x := New(h, ordinal)
	res, err := r.Scan(func(off int64, f *frame.Frame) error {
		x.Add(RecordOf(off, f))
		return nil
	})
	if err != nil {
		return nil, res, err
	}
	x.merge()
	return x, res, nil
}

// CatchUp handles a lagging index (§10.5.1): if a valid frame starts at I,
// it scans forward from I and adds the frames found. It returns how many.
func (x *Index) CatchUp(r *blob.Reader) (int, error) {
	res, err := r.ScanFrom(x.end, func(off int64, f *frame.Frame) error {
		x.Add(RecordOf(off, f))
		return nil
	})
	if err != nil {
		return 0, err
	}
	x.merge()
	return res.Frames, nil
}

// Write durably replaces the index file (§10.5: complete temporary file,
// fsync, atomic rename, directory fsync).
func (x *Index) Write(fsys vfs.FS, name string) error {
	x.merge()
	hdr := wire.IndexHeader{GenerationID: x.h.GenerationID, ArchiveID: x.h.ArchiveID,
		BlobOrdinal: x.ordinal, HashID: x.h.HashID, RecordCount: uint64(len(x.recs))}
	return vfs.ReplaceFileStream(fsys, name, func(w io.Writer) error {
		var b [wire.IndexRecordSize]byte
		hb, err := hdr.AppendBinary(b[:0])
		if err != nil {
			return err
		}
		if _, err := w.Write(hb); err != nil {
			return err
		}
		for i := range x.recs {
			rb, err := x.recs[i].AppendBinary(b[:0])
			if err != nil {
				return err
			}
			if _, err := w.Write(rb); err != nil {
				return err
			}
		}
		return nil
	})
}

// ErrDiscard wraps every reason an index file is not usable. The caller
// discards the file and rebuilds by scan (§10.5).
var ErrDiscard = errors.New("index discarded")

func discard(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrDiscard, wire.ErrCorrupt, fmt.Sprintf(format, args...))
}

// Load reads and structurally validates an index file against the blob's
// identity and current size (§10.5.1). Any violation discards the whole
// index (ErrDiscard); a missing file is reported as fs.ErrNotExist wrapped
// in ErrDiscard. Memory use is bounded by the blob size before any record
// is read: offsets are unique, so there are at most one record per frame-
// grid position.
func Load(fsys vfs.FS, name string, h *wire.ArchiveHeader, ordinal uint8, blobSize int64, pool *bufpool.Pool) (*Index, error) {
	if pool == nil {
		pool = bufpool.Default
	}
	f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", ErrDiscard, err)
		}
		return nil, err
	}
	defer f.Close()
	size, err := f.Size()
	if err != nil {
		return nil, err
	}
	var hb [wire.IndexHeaderSize]byte
	if size < wire.IndexHeaderSize {
		return nil, discard("file of %d bytes", size)
	}
	if _, err := f.ReadAt(hb[:], 0); err != nil {
		return nil, err
	}
	hdr, err := wire.DecodeIndexHeader(hb[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscard, err)
	}
	if hdr.GenerationID != h.GenerationID || hdr.ArchiveID != h.ArchiveID || hdr.BlobOrdinal != ordinal || hdr.HashID != h.HashID {
		return nil, discard("identity does not match blob %02X of generation %016X", ordinal, h.GenerationID)
	}
	body, err := checked.Mul64(hdr.RecordCount, wire.IndexRecordSize)
	if err != nil {
		return nil, discard("record_count %d", hdr.RecordCount)
	}
	if want, err := checked.Add64(body, wire.IndexHeaderSize); err != nil || want != uint64(size) {
		return nil, discard("file size %d, record_count %d", size, hdr.RecordCount)
	}
	maxRecords := uint64(0)
	if blobSize > wire.FrameAreaStart {
		maxRecords = uint64(blobSize-wire.FrameAreaStart) / wire.BaseQuantum
	}
	if hdr.RecordCount > maxRecords {
		return nil, discard("%d records for a blob of %d bytes", hdr.RecordCount, blobSize)
	}
	x := New(h, ordinal)
	x.recs = make([]wire.IndexRecord, 0, hdr.RecordCount)
	buf := pool.Get(1 << 20)
	defer pool.Put(buf)
	chunk := len(buf) / wire.IndexRecordSize * wire.IndexRecordSize
	for off := int64(wire.IndexHeaderSize); off < size; {
		n := int(min(int64(chunk), size-off))
		if _, err := f.ReadAt(buf[:n], off); err != nil {
			return nil, err
		}
		for p := 0; p < n; p += wire.IndexRecordSize {
			r, err := wire.DecodeIndexRecord(buf[p:p+wire.IndexRecordSize], h)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrDiscard, err)
			}
			end := r.PhysicalOffset + wire.FrameSize(r.FrameQuanta) // both bounded: no overflow
			if end > uint64(blobSize) {
				return nil, discard("frame at %d ends at %d past blob size %d", r.PhysicalOffset, end, blobSize)
			}
			if k := len(x.recs); k > 0 && less(&x.recs[k-1], &r) >= 0 {
				return nil, discard("record %d out of order", k)
			}
			x.recs = append(x.recs, r)
			x.end = max(x.end, int64(end))
		}
		off += int64(n)
	}
	offs := make([]uint64, len(x.recs))
	for i := range x.recs {
		offs[i] = x.recs[i].PhysicalOffset
	}
	slices.Sort(offs)
	for i := 1; i < len(offs); i++ {
		if offs[i] == offs[i-1] {
			return nil, discard("physical_offset %d occurs twice", offs[i])
		}
	}
	return x, nil
}

func isDiscard(err error) bool { return errors.Is(err, ErrDiscard) }
