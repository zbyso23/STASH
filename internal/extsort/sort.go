package extsort

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"stash/internal/membudget"
	"stash/internal/vfs"
)

// MinMemory is the smallest working set a Sorter accepts: enough for a
// spill buffer and a merge of a few runs.
const MinMemory = 1 << 20

// DefaultMemory is the working set when Config.Memory is zero.
const DefaultMemory = 64 << 20

const (
	chunkSize    = 256 << 10
	spanSize     = 12 // bytes per buffered record index entry
	defaultFanIn = 128
	scratchPref  = "sort-"
	scratchSuf   = ".run"
)

// Config configures a Sorter.
type Config struct {
	// FS and Dir hold the scratch runs. Dir is created if needed. Runs
	// are removed by Close; CleanScratch removes runs left by a crash.
	FS  vfs.FS
	Dir string
	// Scratch, when FS is nil, provides FS and Dir lazily on the first
	// spill, so a sort that fits in memory never touches the disk.
	Scratch func() (vfs.FS, string, error)
	// Compare orders records. Records that compare equal keep the order
	// in which they were added (the sort is stable).
	Compare Compare
	// Memory is the working set: the in-memory buffer while adding, the
	// merge readers while reading. Reserved from Budget when it is set.
	Memory int64
	Budget *membudget.Budget
	// FanIn caps the runs merged at once (default 128, lowered to what
	// Memory allows).
	FanIn int
}

// Iterator streams sorted records. Record is valid until the next Next.
// Close releases memory and removes scratch files; it is safe to call
// more than once.
type Iterator interface {
	Next() bool
	Record() []byte
	Err() error
	Close() error
}

type span struct{ c, o, n uint32 }

// Sorter is an external merge sort with a fixed working set.
type Sorter struct {
	ctx    context.Context
	cfg    Config
	res    *membudget.Reservation
	id     string
	bufMax int64
	fanIn  int

	chunks [][]byte
	nalloc int // chunks allocated, including ones kept after a spill
	spans  []span
	runs   []string
	seq    int
	added  uint64
	sorted bool
	closed bool
}

// New reserves the working set and returns an empty Sorter.
func New(ctx context.Context, cfg Config) (*Sorter, error) {
	if cfg.Compare == nil || (cfg.FS == nil && cfg.Scratch == nil) {
		return nil, errors.New("extsort: Compare and FS or Scratch are required")
	}
	if cfg.Memory == 0 {
		cfg.Memory = DefaultMemory
	}
	if cfg.Memory < MinMemory {
		return nil, fmt.Errorf("extsort: memory %d below minimum %d", cfg.Memory, MinMemory)
	}
	res, err := cfg.Budget.Reserve(ctx, cfg.Memory)
	if err != nil {
		return nil, err
	}
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		res.Release()
		return nil, err
	}
	fan := cfg.FanIn
	if fan <= 0 {
		fan = defaultFanIn
	}
	// a merge holds one reader per input plus one writer block
	fan = min(fan, int((cfg.Memory-BlockMax)/ReaderCost))
	if fan < 2 {
		fan = 2
	}
	return &Sorter{
		ctx:    ctx,
		cfg:    cfg,
		res:    res,
		id:     hex.EncodeToString(r[:]),
		bufMax: cfg.Memory - BlockMax - MaxRecord, // room for the spill writer
		fanIn:  fan,
	}, nil
}

// Add copies rec into the sort.
func (s *Sorter) Add(rec []byte) error {
	if s.sorted || s.closed {
		return errors.New("extsort: Add after Sort or Close")
	}
	if len(rec) > MaxRecord {
		return ErrTooLarge
	}
	for !s.fits(len(rec)) {
		if len(s.spans) == 0 {
			return fmt.Errorf("extsort: memory %d too small for a record", s.cfg.Memory)
		}
		if err := s.spill(); err != nil {
			return err
		}
	}
	c := len(s.chunks) - 1
	if c < 0 || len(s.chunks[c])+len(rec) > chunkSize {
		c = s.nextChunk()
	}
	o := len(s.chunks[c])
	s.chunks[c] = append(s.chunks[c], rec...)
	s.spans = append(s.spans, span{uint32(c), uint32(o), uint32(len(rec))})
	s.added++
	return nil
}

// fits reports whether one more record of n bytes stays inside the buffer
// budget, growing the span index when needed. Chunks are never moved, the
// span index grows by doubling with both copies counted.
func (s *Sorter) fits(n int) bool {
	need := len(s.chunks)
	if c := need - 1; c < 0 || len(s.chunks[c])+n > chunkSize {
		need++
	}
	chunks := int64(max(need, s.nalloc)) * chunkSize
	if len(s.spans) < cap(s.spans) {
		return chunks+int64(cap(s.spans))*spanSize <= s.bufMax
	}
	grow := max(2*cap(s.spans), 1024)
	if chunks+int64(cap(s.spans)+grow)*spanSize > s.bufMax {
		return false
	}
	ns := make([]span, len(s.spans), grow)
	copy(ns, s.spans)
	s.spans = ns
	return true
}

// nextChunk appends a chunk, reusing one kept from before a spill.
func (s *Sorter) nextChunk() int {
	n := len(s.chunks)
	if n < cap(s.chunks) {
		s.chunks = s.chunks[:n+1]
		if cap(s.chunks[n]) == 0 {
			s.chunks[n] = make([]byte, 0, chunkSize)
		}
		s.chunks[n] = s.chunks[n][:0]
	} else {
		s.chunks = append(s.chunks, make([]byte, 0, chunkSize))
	}
	if n >= s.nalloc {
		s.nalloc = n + 1
	}
	return n
}

func (s *Sorter) rec(sp span) []byte {
	return s.chunks[sp.c][sp.o : sp.o+sp.n]
}

// sortBuffer sorts the buffered records; ties keep insertion order, which
// is (chunk, offset) order.
func (s *Sorter) sortBuffer() {
	slices.SortFunc(s.spans, func(a, b span) int {
		if r := s.cfg.Compare(s.rec(a), s.rec(b)); r != 0 {
			return r
		}
		if r := cmp.Compare(a.c, b.c); r != 0 {
			return r
		}
		return cmp.Compare(a.o, b.o)
	})
}

// spill writes the sorted buffer as a scratch run and empties the buffer,
// keeping its memory for reuse.
func (s *Sorter) spill() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.sortBuffer()
	name, err := s.writeRun(func(w *RunWriter) error {
		for _, sp := range s.spans {
			if err := w.Add(s.rec(sp)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.runs = append(s.runs, name)
	s.spans = s.spans[:0]
	for i := range s.chunks {
		s.chunks[i] = s.chunks[i][:0]
	}
	s.chunks = s.chunks[:0]
	return nil
}

// writeRun creates a new scratch run filled by fill.
func (s *Sorter) writeRun(fill func(*RunWriter) error) (string, error) {
	if s.seq == 0 {
		if s.cfg.FS == nil {
			fsys, dir, err := s.cfg.Scratch()
			if err != nil {
				return "", fmt.Errorf("extsort: scratch space: %w", err)
			}
			s.cfg.FS, s.cfg.Dir = fsys, dir
		}
		if err := s.cfg.FS.MkdirAll(s.cfg.Dir, 0o755); err != nil {
			return "", err
		}
	}
	name := path.Join(s.cfg.Dir, fmt.Sprintf("%s%s-%06d%s", scratchPref, s.id, s.seq, scratchSuf))
	s.seq++
	f, err := s.cfg.FS.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	w, err := NewRunWriter(&offsetWriter{f: f}, s.tag(), s.cfg.Compare)
	if err == nil {
		err = fill(w)
	}
	if err == nil {
		err = w.Finish()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		s.cfg.FS.Remove(name)
		return "", err
	}
	return name, nil
}

func (s *Sorter) tag() Tag {
	var t Tag
	copy(t[:], "extsort scratch ")
	copy(t[16:], s.id)
	return t
}

// Sort finishes adding and returns the records in order. The Sorter's
// memory and files pass to the iterator; closing either releases them.
func (s *Sorter) Sort() (Iterator, error) {
	if s.sorted || s.closed {
		return nil, errors.New("extsort: Sort called twice or after Close")
	}
	s.sorted = true
	if len(s.runs) == 0 {
		s.sortBuffer()
		return &memIter{s: s, i: -1}, nil
	}
	if len(s.spans) > 0 {
		if err := s.spill(); err != nil {
			s.Close()
			return nil, err
		}
	}
	s.chunks, s.spans = nil, nil // the merge needs the memory
	for len(s.runs) > s.fanIn {
		if err := s.mergePass(); err != nil {
			s.Close()
			return nil, err
		}
	}
	m, err := s.openMerge(s.runs)
	if err != nil {
		s.Close()
		return nil, err
	}
	return &sortIter{s: s, m: m}, nil
}

// mergePass merges consecutive groups of fanIn runs, keeping their order
// so that ties stay stable across passes.
func (s *Sorter) mergePass() error {
	var next []string
	for i := 0; i < len(s.runs); i += s.fanIn {
		group := s.runs[i:min(i+s.fanIn, len(s.runs))]
		if len(group) == 1 {
			next = append(next, group[0])
			continue
		}
		m, err := s.openMerge(group)
		if err != nil {
			s.runs = append(s.runs, next...)
			return err
		}
		name, err := s.writeRun(func(w *RunWriter) error {
			for m.Next() {
				if err := w.Add(m.Record()); err != nil {
					return err
				}
			}
			return m.Err()
		})
		m.closeFiles()
		if err != nil {
			s.runs = append(s.runs, next...)
			return err
		}
		for _, g := range group {
			s.cfg.FS.Remove(g)
		}
		next = append(next, name)
	}
	// later groups' runs are still listed in s.runs for Close until here
	s.runs = next
	return nil
}

func (s *Sorter) openMerge(names []string) (*merger, error) {
	var srcs []mergeSrc
	for _, n := range names {
		f, err := s.cfg.FS.OpenFile(n, os.O_RDONLY, 0)
		if err != nil {
			closeSrcs(srcs)
			return nil, err
		}
		size, err := f.Size()
		var rr *RunReader
		if err == nil {
			rr, err = OpenRun(f, size, s.tag(), s.cfg.Compare)
		}
		if err != nil {
			f.Close()
			closeSrcs(srcs)
			return nil, fmt.Errorf("extsort: scratch run %s: %w", n, err)
		}
		srcs = append(srcs, mergeSrc{rr: rr, c: f})
	}
	return newMerger(s.ctx, srcs, s.cfg.Compare), nil
}

// Close releases the working set and removes scratch runs.
func (s *Sorter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	for _, r := range s.runs {
		s.cfg.FS.Remove(r)
	}
	s.runs = nil
	s.chunks, s.spans = nil, nil
	s.res.Release()
	return nil
}

// Added returns the number of records added.
func (s *Sorter) Added() uint64 { return s.added }

// Spilled reports whether any run was written to disk.
func (s *Sorter) Spilled() bool { return s.seq > 0 }

// CleanScratch removes scratch runs left in dir by an interrupted sort. It
// removes only names this package creates.
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
		if e.Type().IsRegular() && strings.HasPrefix(n, scratchPref) && strings.HasSuffix(n, scratchSuf) {
			if err := fsys.Remove(path.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

type memIter struct {
	s *Sorter
	i int
}

func (m *memIter) Next() bool {
	if m.s.closed || m.i+1 >= len(m.s.spans) {
		m.i = len(m.s.spans)
		return false
	}
	m.i++
	return true
}
func (m *memIter) Record() []byte { return m.s.rec(m.s.spans[m.i]) }
func (m *memIter) Err() error     { return nil }
func (m *memIter) Close() error   { return m.s.Close() }

type sortIter struct {
	s *Sorter
	m *merger
}

func (it *sortIter) Next() bool     { return !it.s.closed && it.m.Next() }
func (it *sortIter) Record() []byte { return it.m.Record() }
func (it *sortIter) Err() error     { return it.m.Err() }
func (it *sortIter) Close() error {
	it.m.closeFiles()
	return it.s.Close()
}

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

var _ io.Writer = (*offsetWriter)(nil)
