// Package kvtab is the bounded-memory sorted key-value table under the
// manifest state (SPEC §16.1): an in-memory delta over immutable sorted
// files in scratch space, merged by level. A file is written and read only
// by the process that created it (it is rebuilt from the normative
// manifest at every open), so its block index stays in memory as a small
// two-level structure, and every block is authenticated with a keyed hash
// under a random per-table key: bytes changed in scratch space are an
// error (ErrTampered), never state.
package kvtab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/zeebo/blake3"

	"stash/internal/vfs"
)

// Limits on keys and values; a block holds at least one record.
const (
	MaxKey      = 8 << 10
	MaxValue    = 256 << 10
	blockTarget = 4 << 10
	macSize     = 16
	blockHead   = 4
)

// ErrTampered reports a scratch file whose bytes changed after they were
// written (or a damaged read); the table cannot be used.
var ErrTampered = errors.New("kvtab: scratch file changed or damaged")

// ErrTooLarge reports a key or value over the limits.
var ErrTooLarge = errors.New("kvtab: key or value too large")

// macer authenticates blocks of one table.
type macer struct{ base *blake3.Hasher }

func newMacer(key [32]byte) *macer {
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	return &macer{base: h}
}

func (m *macer) sum(file uint64, off int64, payload []byte) [macSize]byte {
	h := m.base.Clone()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], file)
	binary.LittleEndian.PutUint64(b[8:16], uint64(off))
	h.Write(b[:])
	h.Write(payload)
	var out [32]byte
	h.Sum(out[:0])
	return [macSize]byte(out[:macSize])
}

// blockRef locates a block in a file.
type blockRef struct {
	first []byte // first key
	off   int64
	n     uint32 // payload length
}

// sst is one immutable sorted file.
type sst struct {
	id     uint64
	f      vfs.File
	fsys   vfs.FS
	name   string
	mac    *macer
	top    []blockRef // index blocks
	count  uint64
	bytes  int64
	level  int
	refs   int32 // iterators and the table
	topMem int64
	// filter skips the file for keys it does not hold (nil: none); its
	// memory is reserved from the table's budget
	filter    *bloom
	filterRes interface{ Release() }
}

// sstWriter streams sorted records into a file.
type sstWriter struct {
	w      io.Writer
	off    int64
	id     uint64
	mac    *macer
	block  []byte
	first  []byte
	last   []byte
	have   bool
	index  []byte // the current index block
	ifirst []byte
	top    []blockRef
	count  uint64
}

func newSSTWriter(w io.Writer, id uint64, mac *macer) *sstWriter {
	return &sstWriter{w: w, id: id, mac: mac, block: make([]byte, 0, blockTarget+MaxKey+MaxValue)}
}

func appendRec(b, k, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(len(k)))
	b = append(b, k...)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func (w *sstWriter) add(k, v []byte) error {
	if len(k) > MaxKey || len(v) > MaxValue {
		return ErrTooLarge
	}
	if w.have && bytes.Compare(w.last, k) >= 0 {
		return fmt.Errorf("kvtab: keys not strictly increasing")
	}
	w.last = append(w.last[:0], k...)
	w.have = true
	if len(w.block) == 0 {
		w.first = append(w.first[:0], k...)
	}
	w.block = appendRec(w.block, k, v)
	w.count++
	if len(w.block) >= blockTarget {
		return w.flushData()
	}
	return nil
}

// writeBlock writes [len][payload][mac] and returns the payload offset.
func (w *sstWriter) writeBlock(payload []byte) (int64, error) {
	var hd [blockHead]byte
	binary.LittleEndian.PutUint32(hd[:], uint32(len(payload)))
	at := w.off
	m := w.mac.sum(w.id, at, payload)
	for _, p := range [][]byte{hd[:], payload, m[:]} {
		n, err := w.w.Write(p)
		w.off += int64(n)
		if err != nil {
			return 0, err
		}
	}
	return at, nil
}

func (w *sstWriter) flushData() error {
	if len(w.block) == 0 {
		return nil
	}
	at, err := w.writeBlock(w.block)
	if err != nil {
		return err
	}
	var v [12]byte
	binary.LittleEndian.PutUint64(v[0:8], uint64(at))
	binary.LittleEndian.PutUint32(v[8:12], uint32(len(w.block)))
	if len(w.index) == 0 {
		w.ifirst = append(w.ifirst[:0], w.first...)
	}
	w.index = appendRec(w.index, w.first, v[:])
	w.block = w.block[:0]
	if len(w.index) >= blockTarget {
		return w.flushIndex()
	}
	return nil
}

func (w *sstWriter) flushIndex() error {
	if len(w.index) == 0 {
		return nil
	}
	at, err := w.writeBlock(w.index)
	if err != nil {
		return err
	}
	w.top = append(w.top, blockRef{first: bytes.Clone(w.ifirst), off: at, n: uint32(len(w.index))})
	w.index = w.index[:0]
	return nil
}

func (w *sstWriter) finish() error {
	if err := w.flushData(); err != nil {
		return err
	}
	return w.flushIndex()
}

// decoded is a parsed block: records by position.
type decoded struct {
	keys, vals [][]byte
	mem        int64
}

func parseBlock(p []byte) (*decoded, error) {
	d := &decoded{mem: allocSize(blockHead + len(p) + macSize)}
	if n := countRecs(p); n > 0 {
		d.keys, d.vals = make([][]byte, 0, n), make([][]byte, 0, n)
	}
	for len(p) > 0 {
		kl, n := binary.Uvarint(p)
		if n <= 0 || kl > MaxKey || uint64(len(p)-n) < kl {
			return nil, ErrTampered
		}
		k := p[n : n+int(kl)]
		p = p[n+int(kl):]
		vl, m := binary.Uvarint(p)
		if m <= 0 || vl > MaxValue || uint64(len(p)-m) < vl {
			return nil, ErrTampered
		}
		d.keys = append(d.keys, k)
		d.vals = append(d.vals, p[m:m+int(vl)])
		p = p[m+int(vl):]
	}
	d.mem += 2*allocSize(cap(d.keys)*24) + 64
	return d, nil
}

// allocSize estimates the heap bytes of an allocation of n bytes: large
// objects take whole 8 KiB pages, small ones a size class (at most 1/8
// over).
func allocSize(n int) int64 {
	if n > 32<<10 {
		return int64((n + 8191) &^ 8191)
	}
	return int64(n + n/8)
}

// countRecs counts the records of a block (0 when it is malformed; the
// parse then reports it).
func countRecs(p []byte) int {
	n := 0
	for len(p) > 0 {
		for range 2 {
			l, m := binary.Uvarint(p)
			if m <= 0 || uint64(len(p)-m) < l {
				return 0
			}
			p = p[m+int(l):]
		}
		n++
	}
	return n
}

// readBlock reads and authenticates the block at off, through the cache.
func (s *sst) readBlock(c *Cache, off int64, n uint32) (*decoded, error) {
	if d := c.get(s.id, off); d != nil {
		return d, nil
	}
	buf := make([]byte, blockHead+int(n)+macSize)
	if _, err := s.f.ReadAt(buf, off); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(buf[:blockHead]) != n {
		return nil, ErrTampered
	}
	payload := buf[blockHead : blockHead+int(n)]
	if m := s.mac.sum(s.id, off, payload); !bytes.Equal(m[:], buf[blockHead+int(n):]) {
		return nil, ErrTampered
	}
	d, err := parseBlock(payload)
	if err != nil {
		return nil, err
	}
	c.put(s.id, off, d)
	return d, nil
}

// sstCursor iterates one file from a key.
type sstCursor struct {
	s    *sst
	c    *Cache
	ti   int      // index block
	ib   *decoded // its entries
	ii   int      // entry in ib
	db   *decoded // data block
	di   int
	err  error
	done bool
}

func (s *sst) seek(c *Cache, key []byte) *sstCursor {
	cur := &sstCursor{s: s, c: c}
	// last index block whose first key <= key
	ti := sort.Search(len(s.top), func(i int) bool { return bytes.Compare(s.top[i].first, key) > 0 }) - 1
	if ti < 0 {
		ti = 0
	}
	cur.ti = ti
	if !cur.loadIndex() {
		return cur
	}
	ii := sort.Search(len(cur.ib.keys), func(i int) bool { return bytes.Compare(cur.ib.keys[i], key) > 0 }) - 1
	if ii < 0 {
		ii = 0
	}
	cur.ii = ii
	if !cur.loadData() {
		return cur
	}
	cur.di = sort.Search(len(cur.db.keys), func(i int) bool { return bytes.Compare(cur.db.keys[i], key) >= 0 })
	cur.settle()
	return cur
}

func (cur *sstCursor) loadIndex() bool {
	if cur.ti >= len(cur.s.top) {
		cur.done = true
		return false
	}
	t := cur.s.top[cur.ti]
	cur.ib, cur.err = cur.s.readBlock(cur.c, t.off, t.n)
	if cur.err != nil {
		cur.done = true
		return false
	}
	cur.ii = 0
	return true
}

func (cur *sstCursor) loadData() bool {
	v := cur.ib.vals[cur.ii]
	if len(v) != 12 {
		cur.err, cur.done = ErrTampered, true
		return false
	}
	cur.db, cur.err = cur.s.readBlock(cur.c, int64(binary.LittleEndian.Uint64(v[0:8])), binary.LittleEndian.Uint32(v[8:12]))
	if cur.err != nil {
		cur.done = true
		return false
	}
	cur.di = 0
	return true
}

// settle moves past exhausted blocks.
func (cur *sstCursor) settle() {
	for !cur.done && cur.di >= len(cur.db.keys) {
		cur.ii++
		if cur.ii >= len(cur.ib.keys) {
			cur.ti++
			if !cur.loadIndex() {
				return
			}
		}
		if !cur.loadData() {
			return
		}
	}
}

func (cur *sstCursor) valid() bool { return !cur.done }
func (cur *sstCursor) key() []byte { return cur.db.keys[cur.di] }
func (cur *sstCursor) val() []byte { return cur.db.vals[cur.di] }
func (cur *sstCursor) next() {
	cur.di++
	cur.settle()
}
