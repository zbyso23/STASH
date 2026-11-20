// Package extsort is the bounded-memory engine under archive-scale
// metadata (SPEC §10.3, §10.5, §16.1): sorted runs on disk, a k-way merge
// and an external sort whose working set is fixed by a memory budget, not
// by the number of records.
//
// A run is an implementation-defined file (never normative, never part of
// the wire format): a header bound to a caller-chosen 32-byte tag, then
// CRC-protected blocks of length-prefixed records in non-decreasing order,
// then an end record with the record and block counts at exactly the end
// of the file. A reader checks all of it while streaming, so a truncated,
// torn, foreign or reordered run is an error, never wrong records.
package extsort

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Compare orders records: negative when a sorts before b, zero when equal.
type Compare func(a, b []byte) int

// Record and block limits. A reader never allocates more than BlockMax for
// a block, whatever a damaged length field says.
const (
	MaxRecord   = 64 << 10
	blockTarget = 64 << 10
	BlockMax    = blockTarget + MaxRecord + binary.MaxVarintLen32
	headerSize  = 64
	blockHead   = 8
	endSize     = 24
)

// ReaderCost is the most memory one open RunReader holds.
const ReaderCost = BlockMax + MaxRecord

// Errors. All of them mean the run cannot be used; a caller holding a
// rebuildable cache discards it and falls back to normative data.
var (
	ErrCorrupt  = errors.New("extsort: run corrupt")
	ErrOrder    = errors.New("extsort: records out of order")
	ErrTag      = errors.New("extsort: run belongs to a different owner")
	ErrTooLarge = errors.New("extsort: record larger than MaxRecord")
)

var (
	castagnoli = crc32.MakeTable(crc32.Castagnoli)
	runMagic   = [8]byte{'S', 'T', 'X', 'R', 'U', 'N', 0, 1}
)

const runVersion = 1

// Tag binds a run to its owner (for a cache: the generation and the
// normative bytes it was derived from), so a run copied from elsewhere is
// refused even when it is internally consistent.
type Tag [32]byte

// RunWriter writes one run sequentially to w.
type RunWriter struct {
	w      io.Writer
	cmp    Compare
	block  []byte
	last   []byte
	have   bool
	count  uint64
	blocks uint64
	err    error
}

// NewRunWriter writes the header and returns a writer. When cmp is not nil
// Add refuses a record that sorts before its predecessor (ErrOrder).
func NewRunWriter(w io.Writer, tag Tag, cmp Compare) (*RunWriter, error) {
	var h [headerSize]byte
	copy(h[0:8], runMagic[:])
	binary.LittleEndian.PutUint32(h[8:12], runVersion)
	copy(h[16:48], tag[:])
	binary.LittleEndian.PutUint32(h[60:64], crc32.Checksum(h[:60], castagnoli))
	if _, err := w.Write(h[:]); err != nil {
		return nil, err
	}
	return &RunWriter{w: w, cmp: cmp, block: make([]byte, blockHead, blockHead+BlockMax)}, nil
}

// Add appends one record.
func (rw *RunWriter) Add(rec []byte) error {
	if rw.err != nil {
		return rw.err
	}
	if len(rec) > MaxRecord {
		return ErrTooLarge
	}
	if rw.cmp != nil {
		if rw.have && rw.cmp(rw.last, rec) > 0 {
			return ErrOrder
		}
		rw.last = append(rw.last[:0], rec...)
		rw.have = true
	}
	rw.block = binary.AppendUvarint(rw.block, uint64(len(rec)))
	rw.block = append(rw.block, rec...)
	rw.count++
	if len(rw.block)-blockHead >= blockTarget {
		rw.err = rw.flush()
	}
	return rw.err
}

// Count returns the records added so far.
func (rw *RunWriter) Count() uint64 { return rw.count }

func (rw *RunWriter) flush() error {
	n := len(rw.block) - blockHead
	if n == 0 {
		return nil
	}
	binary.LittleEndian.PutUint32(rw.block[0:4], uint32(n))
	c := crc32.Update(0, castagnoli, rw.block[0:4])
	binary.LittleEndian.PutUint32(rw.block[4:8], crc32.Update(c, castagnoli, rw.block[blockHead:]))
	if _, err := rw.w.Write(rw.block); err != nil {
		return err
	}
	rw.blocks++
	rw.block = rw.block[:blockHead]
	return nil
}

// Finish writes the last block and the end record. It does not sync.
func (rw *RunWriter) Finish() error {
	if rw.err != nil {
		return rw.err
	}
	if rw.err = rw.flush(); rw.err != nil {
		return rw.err
	}
	var e [endSize]byte
	binary.LittleEndian.PutUint64(e[4:12], rw.count)
	binary.LittleEndian.PutUint64(e[12:20], rw.blocks)
	binary.LittleEndian.PutUint32(e[20:24], crc32.Checksum(e[:20], castagnoli))
	_, rw.err = rw.w.Write(e[:])
	if rw.err == nil {
		rw.err = errors.New("extsort: run already finished")
		return nil
	}
	return rw.err
}

// RunReader streams the records of one run, checking every block CRC, the
// record order (when cmp is not nil), the counts and the exact end.
type RunReader struct {
	r      io.ReaderAt
	size   int64
	cmp    Compare
	off    int64
	buf    []byte
	pos    int
	rec    []byte
	prev   []byte
	have   bool
	count  uint64
	blocks uint64
	done   bool
	err    error
}

// OpenRun reads and checks the header of the run in r[0:size].
func OpenRun(r io.ReaderAt, size int64, tag Tag, cmp Compare) (*RunReader, error) {
	if size < headerSize+endSize {
		return nil, corrupt("run of %d bytes is shorter than header and end", size)
	}
	var h [headerSize]byte
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return nil, err
	}
	if [8]byte(h[0:8]) != runMagic {
		return nil, corrupt("bad magic")
	}
	if crc32.Checksum(h[:60], castagnoli) != binary.LittleEndian.Uint32(h[60:64]) {
		return nil, corrupt("header checksum")
	}
	if v := binary.LittleEndian.Uint32(h[8:12]); v != runVersion {
		return nil, corrupt("version %d", v)
	}
	if Tag(h[16:48]) != tag {
		return nil, ErrTag
	}
	return &RunReader{r: r, size: size, cmp: cmp, off: headerSize}, nil
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
}

// Next advances to the next record. It returns false at the verified end
// of the run or on an error (see Err).
func (rr *RunReader) Next() bool {
	if rr.done || rr.err != nil {
		return false
	}
	for rr.pos >= len(rr.buf) {
		if !rr.readBlock() {
			return false
		}
	}
	n, k := binary.Uvarint(rr.buf[rr.pos:])
	if k <= 0 || n > MaxRecord || uint64(len(rr.buf)-rr.pos-k) < n {
		rr.err = corrupt("record framing at block offset %d", rr.off)
		return false
	}
	rec := rr.buf[rr.pos+k : rr.pos+k+int(n)]
	rr.pos += k + int(n)
	if rr.cmp != nil {
		if rr.have && rr.cmp(rr.prev, rec) > 0 {
			rr.err = ErrOrder
			return false
		}
		rr.prev = append(rr.prev[:0], rec...)
		rr.have = true
	}
	rr.rec = rec
	rr.count++
	return true
}

// readBlock loads the next block, or verifies the end record.
func (rr *RunReader) readBlock() bool {
	var hd [blockHead]byte
	if rr.off+blockHead > rr.size {
		rr.err = corrupt("truncated at %d", rr.off)
		return false
	}
	if _, err := rr.r.ReadAt(hd[:], rr.off); err != nil {
		rr.err = err
		return false
	}
	n := binary.LittleEndian.Uint32(hd[0:4])
	if n == 0 {
		var e [endSize]byte
		if rr.off+endSize != rr.size {
			rr.err = corrupt("end record at %d, file size %d", rr.off, rr.size)
			return false
		}
		if _, err := rr.r.ReadAt(e[:], rr.off); err != nil {
			rr.err = err
			return false
		}
		if crc32.Checksum(e[:20], castagnoli) != binary.LittleEndian.Uint32(e[20:24]) {
			rr.err = corrupt("end checksum")
			return false
		}
		if c, b := binary.LittleEndian.Uint64(e[4:12]), binary.LittleEndian.Uint64(e[12:20]); c != rr.count || b != rr.blocks {
			rr.err = corrupt("end counts %d/%d, read %d/%d", c, b, rr.count, rr.blocks)
			return false
		}
		rr.done = true
		rr.buf, rr.rec = nil, nil
		return false
	}
	if n > BlockMax || rr.off+blockHead+int64(n) > rr.size {
		rr.err = corrupt("block length %d at %d", n, rr.off)
		return false
	}
	if cap(rr.buf) < int(n) {
		rr.buf = make([]byte, n, max(int(n), blockTarget+blockTarget/4))
	}
	rr.buf = rr.buf[:n]
	if _, err := rr.r.ReadAt(rr.buf, rr.off+blockHead); err != nil {
		rr.err = err
		return false
	}
	c := crc32.Update(0, castagnoli, hd[0:4])
	if crc32.Update(c, castagnoli, rr.buf) != binary.LittleEndian.Uint32(hd[4:8]) {
		rr.err = corrupt("block checksum at %d", rr.off)
		return false
	}
	rr.off += blockHead + int64(n)
	rr.pos = 0
	rr.blocks++
	return true
}

// Record returns the current record, valid until the next call to Next.
func (rr *RunReader) Record() []byte { return rr.rec }

// Err returns the first error, nil after a verified end.
func (rr *RunReader) Err() error { return rr.err }

// Done reports whether the verified end was reached.
func (rr *RunReader) Done() bool { return rr.done }

// Count returns the records read so far.
func (rr *RunReader) Count() uint64 { return rr.count }
