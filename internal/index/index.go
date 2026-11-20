// Package index maintains the per-generation physical offset index of one
// blob (SPEC §10.5): a sorted multimap frame_hash -> frame records that is
// rebuildable from a blob scan and never authoritative. Every candidate is
// validated against the actual frame before use.
//
// Memory is bounded independently of the blob size (§16.1). The stored
// index file is searched in place through a shared page cache and a
// bounded fence; records added in this session (by the writer, a lag
// catch-up or a rebuild scan) collect in a bounded in-memory delta that is
// spilled as sorted session runs in scratch space and merged by level. A
// session run is never read by a later session: the normative .idx file
// is rewritten by a streaming merge (Write), and after a crash the stored
// index simply lags and is caught up by scan (§10.5.1). Another
// implementation therefore needs nothing but the .idx file.
package index

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/membudget"
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

const (
	// DefaultDelta is the number of session records held in memory per
	// index before they are spilled as a run.
	DefaultDelta = 1 << 16
	minDelta     = 4096
	recMem       = 2 * 56 // an in-memory record, counted twice for merges
	tierFan      = 4      // runs of one level merged into the next
	runPrefix    = "run-"
	runSuffix    = ".idx"
)

// Env is shared by the indexes of one view: the memory budget, the page
// cache and the scratch space for spills and validation sorts. A nil Env,
// or one without Scratch, keeps everything in memory (tests, tools).
type Env struct {
	Budget   *membudget.Budget
	Cache    *PageCache
	Scratch  func() (vfs.FS, string, error)
	DeltaMax int
}

func (e *Env) budget() *membudget.Budget {
	if e == nil {
		return nil
	}
	return e.Budget
}

var errNoScratch = errors.New("index: no scratch space configured")

func (e *Env) scratchFn() func() (vfs.FS, string, error) {
	if e == nil || e.Scratch == nil {
		return func() (vfs.FS, string, error) { return nil, "", errNoScratch }
	}
	return e.Scratch
}

var (
	defaultCacheOnce sync.Once
	defaultCache     *PageCache
)

func (e *Env) cache() *PageCache {
	if e != nil && e.Cache != nil {
		return e.Cache
	}
	defaultCacheOnce.Do(func() { defaultCache = NewPageCache(nil, 8<<20) })
	return defaultCache
}

// Index is the index of one blob. It is safe for concurrent use: lookups
// run concurrently with each other, Add and Write exclude them briefly.
type Index struct {
	env     *Env
	h       *wire.ArchiveHeader
	ordinal uint8

	mu      sync.RWMutex
	base    *idxFile // the validated stored index, nil when none
	runs    []*idxFile
	recs    []wire.IndexRecord // session delta, sorted
	pending []wire.IndexRecord // session delta, unsorted
	delta   int
	dres    *membudget.Reservation
	end     int64 // I of §10.5.1 over every record
	last    wire.IndexRecord
	hasLast bool
	dirty   bool // records exist that the stored file lacks
	sess    string
	seq     int
	closed  bool
}

// New returns an empty index for blob ordinal of the generation h.
func New(env *Env, h *wire.ArchiveHeader, ordinal uint8) *Index {
	want := DefaultDelta
	if env != nil && env.DeltaMax > 0 {
		want = env.DeltaMax
	}
	x := &Index{env: env, h: h, ordinal: ordinal, end: wire.FrameAreaStart, delta: want}
	if env != nil && env.Scratch != nil {
		least := min(minDelta, want)
		x.dres = env.budget().TryReserve(int64(least)*recMem, int64(want)*recMem)
		if x.dres != nil {
			x.delta = int(x.dres.Size() / recMem)
		} else {
			x.delta = least
		}
	}
	var r [6]byte
	rand.Read(r[:])
	x.sess = hex.EncodeToString(r[:])
	return x
}

// Len returns the number of records.
func (x *Index) Len() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return int(x.count())
}

func (x *Index) count() uint64 {
	n := uint64(len(x.recs) + len(x.pending))
	if x.base != nil {
		n += x.base.n
	}
	for _, r := range x.runs {
		n += r.n
	}
	return n
}

// End returns I: the largest end of an indexed frame, or FRAME_AREA_START.
func (x *Index) End() int64 {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.end
}

// Last returns the record with the highest physical offset (the frame
// that ends the indexed region), if any.
func (x *Index) Last() (wire.IndexRecord, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.last, x.hasLast
}

// Spilled returns the number of session runs on disk (tests, health).
func (x *Index) Spilled() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return len(x.runs)
}

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

// Add records a frame (writer hot path). When the in-memory delta is full
// it is spilled as a session run; an error means the record could not be
// kept, and the caller fails the write that produced the frame.
func (x *Index) Add(r wire.IndexRecord) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return errors.New("index: closed")
	}
	x.pending = append(x.pending, r)
	x.end = max(x.end, int64(r.PhysicalOffset+wire.FrameSize(r.FrameQuanta)))
	if !x.hasLast || r.PhysicalOffset > x.last.PhysicalOffset {
		x.last, x.hasLast = r, true
	}
	x.dirty = true
	if len(x.pending) >= 1024 {
		x.merge()
	}
	if len(x.recs)+len(x.pending) >= x.delta && x.env != nil && x.env.Scratch != nil {
		return x.spill()
	}
	return nil
}

func (x *Index) merge() {
	if len(x.pending) == 0 {
		return
	}
	slices.SortFunc(x.pending, func(a, b wire.IndexRecord) int { return less(&a, &b) })
	out := make([]wire.IndexRecord, 0, max(len(x.recs)+len(x.pending), cap(x.recs)))
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

// spill writes the delta as a level-0 session run, then merges levels.
func (x *Index) spill() error {
	x.merge()
	if len(x.recs) == 0 {
		return nil
	}
	f, err := x.writeRun(0, uint64(len(x.recs)), []recIter{&sliceIter{recs: x.recs}})
	if err != nil {
		return err
	}
	x.runs = append(x.runs, f)
	x.recs = x.recs[:0]
	return x.compactRuns()
}

// compactRuns merges tierFan runs of one level into one of the next, so
// a lookup probes O(tierFan * log(records/delta)) runs.
func (x *Index) compactRuns() error {
	for {
		byLevel := map[int][]int{}
		top := -1
		for i, r := range x.runs {
			byLevel[r.level] = append(byLevel[r.level], i)
			if len(byLevel[r.level]) >= tierFan && (top < 0 || r.level < top) {
				top = r.level
			}
		}
		if top < 0 {
			return nil
		}
		idx := byLevel[top]
		var its []recIter
		var n uint64
		for _, i := range idx {
			its = append(its, newSeq(x.runs[i], x.h))
			n += x.runs[i].n
		}
		f, err := x.writeRun(top+1, n, its)
		if err != nil {
			return err
		}
		var keep []*idxFile
		for i, r := range x.runs {
			if slices.Contains(idx, i) {
				x.env.cache().drop(r)
				r.close()
			} else {
				keep = append(keep, r)
			}
		}
		x.runs = append(keep, f)
	}
}

func (x *Index) header(n uint64) wire.IndexHeader {
	return wire.IndexHeader{GenerationID: x.h.GenerationID, ArchiveID: x.h.ArchiveID,
		BlobOrdinal: x.ordinal, HashID: x.h.HashID, RecordCount: n}
}

// writeRun writes the merge of its into a new session run file.
func (x *Index) writeRun(level int, n uint64, its []recIter) (*idxFile, error) {
	fsys, dir, err := x.env.Scratch()
	if err != nil {
		return nil, fmt.Errorf("index: scratch space: %w", err)
	}
	if err := fsys.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := path.Join(dir, fmt.Sprintf("%s%s-%02X-%06d%s", runPrefix, x.sess, x.ordinal, x.seq, runSuffix))
	x.seq++
	f, err := fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	fb, fres := newFence(x.env, n, runFenceMax)
	rw, err := newRecordWriter(&offsetWriter{f: f}, x.header(n), fb)
	if err == nil {
		err = mergeAll(its, rw.add)
	}
	if err == nil {
		err = rw.finish()
	}
	if err != nil {
		f.Close()
		fsys.Remove(name)
		fres.Release()
		return nil, err
	}
	return &idxFile{id: fileIDs.Add(1), f: f, fsys: fsys, name: name, remove: true, n: n,
		fence: fb.out, stride: fb.stride, level: level, res: fres}, nil
}

// CleanScratch removes session runs left in dir by an interrupted
// session (only names this package creates).
func CleanScratch(fsys vfs.FS, dir string) error {
	ents, err := fsys.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(n, runPrefix) && strings.HasSuffix(n, runSuffix) {
			if err := fsys.Remove(path.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// recIter is an ordered record stream for merges.
type recIter interface {
	next() bool
	cur() *wire.IndexRecord
	error() error
}

func (s *seqReader) cur() *wire.IndexRecord { return &s.rec }
func (s *seqReader) error() error           { return s.err }

type sliceIter struct {
	recs []wire.IndexRecord
	i    int
}

func (s *sliceIter) next() bool {
	if s.i >= len(s.recs) {
		return false
	}
	s.i++
	return true
}
func (s *sliceIter) cur() *wire.IndexRecord { return &s.recs[s.i-1] }
func (s *sliceIter) error() error           { return nil }

// mergeAll feeds the k-way merge of its, by (frame_hash, offset), to fn.
// k is small (the runs of one level, or every source of a rewrite).
func mergeAll(its []recIter, fn func(*wire.IndexRecord) error) error {
	live := make([]bool, len(its))
	for i, it := range its {
		live[i] = it.next()
		if err := it.error(); err != nil {
			return err
		}
	}
	for {
		best := -1
		for i, it := range its {
			if live[i] && (best < 0 || less(it.cur(), its[best].cur()) < 0) {
				best = i
			}
		}
		if best < 0 {
			return nil
		}
		if err := fn(its[best].cur()); err != nil {
			return err
		}
		live[best] = its[best].next()
		if err := its[best].error(); err != nil {
			return err
		}
	}
}

// candidates iterates the records of hash h across the stored file, the
// session runs and the delta, in physical-offset order. The caller holds
// x.mu for reading.
type candidates struct {
	curs []*fileCursor
	live []bool
	mem  []wire.IndexRecord
	mi   int
	rec  wire.IndexRecord
	err  error
	init bool
}

func (x *Index) candidates(h [wire.HashSize]byte) *candidates {
	c := &candidates{}
	cache := x.env.cache()
	files := x.runs
	if x.base != nil {
		files = append([]*idxFile{x.base}, x.runs...)
	}
	for _, f := range files {
		lb, err := cache.lowerBound(f, &h)
		if err != nil {
			c.err = err
			return c
		}
		c.curs = append(c.curs, &fileCursor{c: cache, f: f, h: h, hdr: x.h, i: lb})
	}
	i, _ := slices.BinarySearchFunc(x.recs, h, func(r wire.IndexRecord, h [32]byte) int {
		return bytes.Compare(r.FrameHash[:], h[:])
	})
	for ; i < len(x.recs) && x.recs[i].FrameHash == h; i++ {
		c.mem = append(c.mem, x.recs[i])
	}
	for _, r := range x.pending {
		if r.FrameHash == h {
			c.mem = append(c.mem, r)
		}
	}
	slices.SortFunc(c.mem, func(a, b wire.IndexRecord) int { return cmp.Compare(a.PhysicalOffset, b.PhysicalOffset) })
	return c
}

func (c *candidates) next() bool {
	if c.err != nil {
		return false
	}
	if !c.init {
		c.init = true
		c.live = make([]bool, len(c.curs))
		for i, cur := range c.curs {
			if c.live[i] = cur.next(); cur.err != nil {
				c.err = cur.err
				return false
			}
		}
	}
	best, bestOff := -1, uint64(0)
	for i, cur := range c.curs {
		if c.live[i] && (best < 0 || cur.rec.PhysicalOffset < bestOff) {
			best, bestOff = i, cur.rec.PhysicalOffset
		}
	}
	if c.mi < len(c.mem) && (best < 0 || c.mem[c.mi].PhysicalOffset < bestOff) {
		c.rec = c.mem[c.mi]
		c.mi++
		return true
	}
	if best < 0 {
		return false
	}
	c.rec = c.curs[best].rec
	if c.live[best] = c.curs[best].next(); c.curs[best].err != nil {
		c.err = c.curs[best].err
	}
	return true
}

// Lookup returns every record with frame_hash h, ordered by offset. The
// records are candidates only (§10.5). Find streams them instead.
func (x *Index) Lookup(h [wire.HashSize]byte) []wire.IndexRecord {
	x.mu.RLock()
	defer x.mu.RUnlock()
	var out []wire.IndexRecord
	for c := x.candidates(h); c.next(); {
		out = append(out, c.rec)
	}
	return out
}

// Build indexes every frame of the uninterrupted scan of r (§11.2).
func Build(env *Env, r *blob.Reader, h *wire.ArchiveHeader, ordinal uint8) (*Index, blob.ScanResult, error) {
	x := New(env, h, ordinal)
	res, err := r.Scan(func(off int64, f *frame.Frame) error {
		return x.Add(RecordOf(off, f))
	})
	if err != nil {
		x.Close()
		return nil, res, err
	}
	return x, res, nil
}

// CatchUp handles a lagging index (§10.5.1): if a valid frame starts at I,
// it scans forward from I and adds the frames found. It returns how many.
func (x *Index) CatchUp(r *blob.Reader) (int, error) {
	res, err := r.ScanFrom(x.End(), func(off int64, f *frame.Frame) error {
		return x.Add(RecordOf(off, f))
	})
	if err != nil {
		return 0, err
	}
	return res.Frames, nil
}

// Write durably replaces the index file with every record (§10.5:
// complete temporary file, fsync, atomic rename, directory fsync) by a
// streaming merge of the stored file, the session runs and the delta.
// Afterwards the new file is the stored index and the session state is
// empty. Without changes since the stored file was validated it does
// nothing.
func (x *Index) Write(fsys vfs.FS, name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return errors.New("index: closed")
	}
	if !x.dirty && x.base != nil && x.base.fsys == fsys && x.base.name == name {
		return nil
	}
	x.merge()
	n := x.count()
	var its []recIter
	if x.base != nil {
		its = append(its, newSeq(x.base, x.h))
	}
	for _, r := range x.runs {
		its = append(its, newSeq(r, x.h))
	}
	its = append(its, &sliceIter{recs: x.recs})
	fb, fres := newFence(x.env, n, baseFenceMax)
	err := vfs.ReplaceFileStream(fsys, name, func(w io.Writer) error {
		rw, err := newRecordWriter(w, x.header(n), fb)
		if err != nil {
			return err
		}
		if err := mergeAll(its, rw.add); err != nil {
			return err
		}
		return rw.finish()
	})
	if err != nil {
		fres.Release()
		return err
	}
	f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		fres.Release()
		return err
	}
	cache := x.env.cache()
	cache.drop(x.base)
	x.base.close()
	for _, r := range x.runs {
		cache.drop(r)
		r.close()
	}
	x.base = &idxFile{id: fileIDs.Add(1), f: f, fsys: fsys, name: name, n: n, fence: fb.out, stride: fb.stride, res: fres}
	x.runs, x.recs, x.dirty = nil, x.recs[:0], false
	return nil
}

// Close releases the files, the session runs and the memory.
func (x *Index) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil
	}
	x.closed = true
	cache := x.env.cache()
	cache.drop(x.base)
	x.base.close()
	for _, r := range x.runs {
		cache.drop(r)
		r.close()
	}
	x.base, x.runs, x.recs, x.pending = nil, nil, nil, nil
	x.dres.Release()
	return nil
}

// ErrDiscard wraps every reason an index file is not usable. The caller
// discards the file and rebuilds by scan (§10.5).
var ErrDiscard = errors.New("index discarded")

func discard(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrDiscard, wire.ErrCorrupt, fmt.Sprintf(format, args...))
}

// Load validates the stored index file completely (§10.5.1, see validate)
// and returns an index searched in place. A missing file is reported as
// fs.ErrNotExist wrapped in ErrDiscard.
func Load(env *Env, fsys vfs.FS, name string, h *wire.ArchiveHeader, ordinal uint8, blobSize int64, pool *bufpool.Pool) (*Index, error) {
	lr, err := validate(env, fsys, name, h, ordinal, blobSize, pool)
	if err != nil {
		return nil, err
	}
	x := New(env, h, ordinal)
	x.base, x.end, x.last, x.hasLast = lr.file, lr.end, lr.last, lr.hasLast
	return x, nil
}

func isDiscard(err error) bool { return errors.Is(err, ErrDiscard) }

// offsetWriter adapts positional writes to io.Writer.
type offsetWriter struct {
	f   vfs.File
	off int64
}

func (w *offsetWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.off)
	w.off += int64(n)
	return n, err
}
