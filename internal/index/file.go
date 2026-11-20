package index

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	"stash/internal/bufpool"
	"stash/internal/checked"
	"stash/internal/extsort"
	"stash/internal/membudget"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// On disk an index file (the normative .idx, or a session run in the same
// layout) is searched in place: records are read through a shared page
// cache, located with a bounded in-memory fence (the first hash of every
// stride-th record), never loaded whole.

const (
	pageSize    = 4096
	pageRecords = pageSize / wire.IndexRecordSize
	fenceEntry  = wire.HashSize + 8
	// fence sizes: the base index of a blob, and a session run
	baseFenceMax = 1 << 16
	runFenceMax  = 1 << 12
	fenceMin     = 16
)

var fileIDs atomic.Uint64

type fence struct {
	hash [wire.HashSize]byte
	rec  uint64
}

// idxFile is one sorted record file opened for lookups.
type idxFile struct {
	id     uint64 // page cache key
	f      vfs.File
	fsys   vfs.FS
	name   string
	remove bool // a session run: deleted on close
	n      uint64
	fence  []fence
	stride uint64
	level  int
	res    *membudget.Reservation // the fence's memory
}

func (f *idxFile) close() {
	if f == nil {
		return
	}
	f.f.Close()
	if f.remove {
		f.fsys.Remove(f.name)
	}
	f.res.Release()
}

// fenceBuilder collects the fence while records stream past in order.
type fenceBuilder struct {
	stride uint64
	out    []fence
}

func newFence(env *Env, n uint64, limit int) (*fenceBuilder, *membudget.Reservation) {
	want := max(min(int64(limit), int64((n+pageRecords-1)/pageRecords)), fenceMin) // at most one per page
	res := env.budget().TryReserve(fenceMin*fenceEntry, want*fenceEntry)
	entries := uint64(fenceMin)
	if res != nil {
		entries = uint64(res.Size() / fenceEntry)
	}
	stride := max(pageRecords, (n+entries-1)/max(entries, 1))
	stride = (stride + pageRecords - 1) / pageRecords * pageRecords // page aligned
	return &fenceBuilder{stride: stride, out: make([]fence, 0, (n+stride-1)/stride)}, res
}

func (b *fenceBuilder) add(i uint64, hash []byte) {
	if i%b.stride == 0 {
		b.out = append(b.out, fence{hash: [wire.HashSize]byte(hash), rec: i})
	}
}

// PageCache is an LRU of index pages shared by the indexes of a view. Its
// size is reserved from the memory budget once.
type PageCache struct {
	mu    sync.Mutex
	max   int
	pages map[pageKey]*list.Element
	lru   list.List
	res   *membudget.Reservation
	hits  atomic.Uint64
	reads atomic.Uint64
}

type pageKey struct {
	f uint64
	p uint64
}

type page struct {
	key  pageKey
	data []byte
}

// NewPageCache returns a cache of up to bytes (rounded down to pages),
// reserved from b; it degrades to what b grants, at least 16 pages.
func NewPageCache(b *membudget.Budget, bytes int64) *PageCache {
	c := &PageCache{pages: map[pageKey]*list.Element{}}
	c.res = b.TryReserve(16*pageSize, max(bytes, 16*pageSize))
	n := int64(16 * pageSize)
	if c.res != nil {
		n = c.res.Size()
	}
	c.max = int(n / pageSize)
	return c
}

// Close releases the cache memory.
func (c *PageCache) Close() {
	c.mu.Lock()
	c.pages, c.max = map[pageKey]*list.Element{}, 0
	c.lru.Init()
	c.mu.Unlock()
	c.res.Release()
}

// Stats returns page hits and disk reads.
func (c *PageCache) Stats() (hits, reads uint64) { return c.hits.Load(), c.reads.Load() }

// page returns the bytes of page p of f. The slice is immutable and stays
// valid after eviction.
func (c *PageCache) page(f *idxFile, p uint64) ([]byte, error) {
	k := pageKey{f.id, p}
	c.mu.Lock()
	if e, ok := c.pages[k]; ok {
		c.lru.MoveToFront(e)
		d := e.Value.(*page).data
		c.mu.Unlock()
		c.hits.Add(1)
		return d, nil
	}
	c.mu.Unlock()
	first := p * pageRecords
	cnt := min(uint64(pageRecords), f.n-first)
	d := make([]byte, cnt*wire.IndexRecordSize)
	if _, err := f.f.ReadAt(d, int64(wire.IndexHeaderSize+first*wire.IndexRecordSize)); err != nil {
		return nil, err
	}
	c.reads.Add(1)
	c.mu.Lock()
	if _, ok := c.pages[k]; !ok && c.max > 0 {
		c.pages[k] = c.lru.PushFront(&page{k, d})
		for c.lru.Len() > c.max {
			old := c.lru.Remove(c.lru.Back()).(*page)
			delete(c.pages, old.key)
		}
	}
	c.mu.Unlock()
	return d, nil
}

// drop evicts every page of f.
func (c *PageCache) drop(f *idxFile) {
	if f == nil {
		return
	}
	c.mu.Lock()
	for e := c.lru.Front(); e != nil; {
		next := e.Next()
		if pg := e.Value.(*page); pg.key.f == f.id {
			c.lru.Remove(e)
			delete(c.pages, pg.key)
		}
		e = next
	}
	c.mu.Unlock()
}

// raw returns the 64 bytes of record i.
func (c *PageCache) raw(f *idxFile, i uint64) ([]byte, error) {
	d, err := c.page(f, i/pageRecords)
	if err != nil {
		return nil, err
	}
	o := (i % pageRecords) * wire.IndexRecordSize
	return d[o : o+wire.IndexRecordSize], nil
}

// lowerBound returns the first record index whose hash is >= h.
func (c *PageCache) lowerBound(f *idxFile, h *[wire.HashSize]byte) (uint64, error) {
	// fence[j-1].hash < h <= fence[j].hash
	j := sort.Search(len(f.fence), func(j int) bool { return bytes.Compare(f.fence[j].hash[:], h[:]) >= 0 })
	lo, hi := uint64(0), f.n
	if j > 0 {
		lo = f.fence[j-1].rec + 1
	}
	if j < len(f.fence) {
		hi = f.fence[j].rec
	}
	var err error
	for lo < hi {
		mid := lo + (hi-lo)/2
		var r []byte
		if r, err = c.raw(f, mid); err != nil {
			return 0, err
		}
		if bytes.Compare(r[:wire.HashSize], h[:]) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo, nil
}

// fileCursor walks the records of one hash in a file, in offset order.
type fileCursor struct {
	c    *PageCache
	f    *idxFile
	h    [wire.HashSize]byte
	hdr  *wire.ArchiveHeader
	i    uint64
	rec  wire.IndexRecord
	err  error
	done bool
}

func (cur *fileCursor) next() bool {
	if cur.done || cur.err != nil || cur.i >= cur.f.n {
		cur.done = true
		return false
	}
	raw, err := cur.c.raw(cur.f, cur.i)
	if err != nil {
		cur.err = err
		return false
	}
	if [wire.HashSize]byte(raw[:wire.HashSize]) != cur.h {
		cur.done = true
		return false
	}
	r, err := wire.DecodeIndexRecord(raw, cur.hdr)
	if err != nil {
		// the file changed after it was validated: never trusted
		cur.err = fmt.Errorf("%w: %w", ErrDiscard, err)
		return false
	}
	cur.rec = r
	cur.i++
	return true
}

// seqReader streams every record of a file in order with its own buffer
// (merges and rewrites; it does not pollute the page cache).
type seqReader struct {
	f   *idxFile
	hdr *wire.ArchiveHeader
	buf []byte
	pos int
	i   uint64 // records consumed from the file into buf
	rec wire.IndexRecord
	raw []byte
	err error
}

func newSeq(f *idxFile, hdr *wire.ArchiveHeader) *seqReader {
	return &seqReader{f: f, hdr: hdr, buf: make([]byte, 0, 256<<10)}
}

func (s *seqReader) next() bool {
	if s.err != nil {
		return false
	}
	if s.pos >= len(s.buf) {
		if s.i >= s.f.n {
			return false
		}
		n := min(uint64(cap(s.buf)/wire.IndexRecordSize), s.f.n-s.i)
		s.buf = s.buf[:n*wire.IndexRecordSize]
		if _, err := s.f.f.ReadAt(s.buf, int64(wire.IndexHeaderSize+s.i*wire.IndexRecordSize)); err != nil {
			s.err = err
			return false
		}
		s.i += n
		s.pos = 0
	}
	s.raw = s.buf[s.pos : s.pos+wire.IndexRecordSize]
	s.pos += wire.IndexRecordSize
	r, err := wire.DecodeIndexRecord(s.raw, s.hdr)
	if err != nil {
		s.err = fmt.Errorf("%w: %w", ErrDiscard, err)
		return false
	}
	s.rec = r
	return true
}

// loadResult is a validated base index.
type loadResult struct {
	file    *idxFile
	end     int64
	last    wire.IndexRecord
	hasLast bool
}

// validate opens name and checks it completely against §10.5.1 in one
// streaming pass with bounded memory: size and identity, the record bound
// before anything is read, every record (reserved bytes, block type, grid,
// quanta, the blob-size bound), the global order, and physical-offset
// uniqueness by an external sort of the offsets. The file stays open for
// lookups. Any violation is ErrDiscard.
func validate(env *Env, fsys vfs.FS, name string, h *wire.ArchiveHeader, ordinal uint8, blobSize int64, pool *bufpool.Pool) (_ *loadResult, err error) {
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
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
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
	n := hdr.RecordCount
	fb, fres := newFence(env, n, baseFenceMax)
	defer func() {
		if !keep {
			fres.Release()
		}
	}()
	// offsets: 8 bytes big endian, sorted externally; a sort that fits in
	// memory never touches the scratch space
	sorter, err := extsort.New(context.Background(), extsort.Config{
		Scratch: env.scratchFn(),
		Compare: bytes.Compare,
		Memory:  sortMemory(env, n),
		Budget:  env.budget(),
	})
	if err != nil {
		return nil, err
	}
	defer sorter.Close()
	res := &loadResult{end: wire.FrameAreaStart}
	buf := pool.Get(1 << 20)
	defer pool.Put(buf)
	chunk := len(buf) / wire.IndexRecordSize * wire.IndexRecordSize
	var prev [wire.IndexRecordSize]byte
	var ob [8]byte
	i := uint64(0)
	for off := int64(wire.IndexHeaderSize); off < size; {
		cnt := int(min(int64(chunk), size-off))
		if _, err := f.ReadAt(buf[:cnt], off); err != nil {
			return nil, err
		}
		for p := 0; p < cnt; p += wire.IndexRecordSize {
			raw := buf[p : p+wire.IndexRecordSize]
			r, err := wire.DecodeIndexRecord(raw, h)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrDiscard, err)
			}
			end := r.PhysicalOffset + wire.FrameSize(r.FrameQuanta) // both bounded: no overflow
			if end > uint64(blobSize) {
				return nil, discard("frame at %d ends at %d past blob size %d", r.PhysicalOffset, end, blobSize)
			}
			if i > 0 && rawLess(prev[:], raw) >= 0 {
				return nil, discard("record %d out of order", i)
			}
			copy(prev[:], raw)
			fb.add(i, raw[:wire.HashSize])
			res.end = max(res.end, int64(end))
			if !res.hasLast || r.PhysicalOffset > res.last.PhysicalOffset {
				res.last, res.hasLast = r, true
			}
			binary.BigEndian.PutUint64(ob[:], r.PhysicalOffset)
			if err := sorter.Add(ob[:]); err != nil {
				return nil, err
			}
			i++
		}
		off += int64(cnt)
	}
	it, err := sorter.Sort()
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var last []byte
	for it.Next() {
		if last != nil && bytes.Equal(last, it.Record()) {
			return nil, discard("physical_offset %d occurs twice", binary.BigEndian.Uint64(last))
		}
		last = append(last[:0], it.Record()...)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	keep = true
	res.file = &idxFile{id: fileIDs.Add(1), f: f, fsys: fsys, name: name, n: n, fence: fb.out, stride: fb.stride, res: fres}
	return res, nil
}

// rawLess orders two encoded records by (frame_hash, physical_offset).
func rawLess(a, b []byte) int {
	if c := bytes.Compare(a[:wire.HashSize], b[:wire.HashSize]); c != 0 {
		return c
	}
	x, y := binary.LittleEndian.Uint64(a[32:40]), binary.LittleEndian.Uint64(b[32:40])
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// recordWriter streams records into an index-format file, building the
// fence for the file it produces.
type recordWriter struct {
	w     *bufio.Writer
	fb    *fenceBuilder
	n     uint64
	want  uint64
	b     [wire.IndexRecordSize]byte
	prev  wire.IndexRecord
	first bool
}

func newRecordWriter(w io.Writer, hdr wire.IndexHeader, fb *fenceBuilder) (*recordWriter, error) {
	bw := bufio.NewWriterSize(w, 256<<10)
	hb, err := hdr.AppendBinary(nil)
	if err != nil {
		return nil, err
	}
	if _, err := bw.Write(hb); err != nil {
		return nil, err
	}
	return &recordWriter{w: bw, fb: fb, want: hdr.RecordCount, first: true}, nil
}

func (rw *recordWriter) add(r *wire.IndexRecord) error {
	if !rw.first && less(&rw.prev, r) >= 0 {
		return fmt.Errorf("index: records out of order or duplicated at %d", rw.n)
	}
	rw.prev, rw.first = *r, false
	rb, err := r.AppendBinary(rw.b[:0])
	if err != nil {
		return err
	}
	if _, err := rw.w.Write(rb); err != nil {
		return err
	}
	if rw.fb != nil {
		rw.fb.add(rw.n, r.FrameHash[:])
	}
	rw.n++
	return nil
}

func (rw *recordWriter) finish() error {
	if rw.n != rw.want {
		return fmt.Errorf("index: wrote %d records, header says %d", rw.n, rw.want)
	}
	return rw.w.Flush()
}

// sortMemory sizes the offset sort of a validation: what n offsets need in
// memory, at most 64 MiB and a quarter of the budget.
func sortMemory(env *Env, n uint64) int64 {
	m := min(int64(n)*24+extsort.BlockMax*4, 64<<20)
	if b := env.budget(); b != nil {
		m = min(m, b.Limit()/4)
	}
	return max(m, extsort.MinMemory)
}
