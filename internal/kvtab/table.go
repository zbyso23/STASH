package kvtab

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"stash/internal/membudget"
	"stash/internal/vfs"
)

var fileIDs atomic.Uint64

// Cache is an LRU of decoded blocks shared by the tables of a view, sized
// from the memory budget once.
type Cache struct {
	mu    sync.Mutex
	max   int64
	used  int64
	m     map[ckey]*list.Element
	lru   list.List
	res   *membudget.Reservation
	hits  atomic.Uint64
	reads atomic.Uint64
}

type ckey struct {
	f   uint64
	off int64
}

type centry struct {
	k ckey
	d *decoded
}

// NewCache returns a block cache of up to bytes reserved from b (it
// degrades to what b grants, at least 1 MiB).
func NewCache(b *membudget.Budget, bytes int64) *Cache {
	c := &Cache{m: map[ckey]*list.Element{}}
	c.res = b.TryReserve(1<<20, max(bytes, 1<<20))
	c.max = 1 << 20
	if c.res != nil {
		c.max = c.res.Size()
	}
	return c
}

// Close releases the cache memory.
func (c *Cache) Close() {
	c.mu.Lock()
	c.m, c.used, c.max = map[ckey]*list.Element{}, 0, 0
	c.lru.Init()
	c.mu.Unlock()
	c.res.Release()
}

// Used returns the bytes of the cached blocks.
func (c *Cache) Used() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.used
}

// Stats returns block hits and reads.
func (c *Cache) Stats() (hits, reads uint64) { return c.hits.Load(), c.reads.Load() }

func (c *Cache) get(f uint64, off int64) *decoded {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[ckey{f, off}]; ok {
		c.lru.MoveToFront(e)
		c.hits.Add(1)
		return e.Value.(*centry).d
	}
	return nil
}

func (c *Cache) put(f uint64, off int64, d *decoded) {
	c.reads.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	k := ckey{f, off}
	if _, ok := c.m[k]; ok || d.mem > c.max {
		return
	}
	c.m[k] = c.lru.PushFront(&centry{k, d})
	c.used += d.mem
	for c.used > c.max {
		old := c.lru.Remove(c.lru.Back()).(*centry)
		delete(c.m, old.k)
		c.used -= old.d.mem
	}
}

func (c *Cache) drop(f uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for e := c.lru.Front(); e != nil; {
		next := e.Next()
		if ce := e.Value.(*centry); ce.k.f == f {
			c.lru.Remove(e)
			delete(c.m, ce.k)
			c.used -= ce.d.mem
		}
		e = next
	}
}

var (
	defaultCacheOnce sync.Once
	defaultCache     *Cache
)

// Config configures a Table.
type Config struct {
	Budget *membudget.Budget
	Cache  *Cache
	// Scratch provides the directory for the table's files on first use.
	// Without it everything stays in memory (tests, small tools).
	Scratch func() (vfs.FS, string, error)
	// MemLimit is the in-memory delta in bytes before a flush (default
	// 16 MiB, reserved from Budget).
	MemLimit int64
}

const (
	defaultMem = 16 << 20
	tierFan    = 4
	baseLevel  = 1 << 20
	entryMem   = 64 // map overhead per entry
	filePrefix = "kv-"
	fileSuffix = ".sst"
)

// Table is a sorted key-value table. Values are opaque; Put of an existing
// key replaces it. It is safe for concurrent use.
type Table struct {
	cfg  Config
	mac  *macer
	sess string

	mu       sync.RWMutex
	mem      map[string][]byte // value with a leading flag byte; flag 0: deleted
	memBytes int64
	memMax   int64
	res      *membudget.Reservation
	runs     []*sst // oldest first
	seq      int
	closed   bool
	err      error // sticky failure of a flush

	// view is the delta in key order, built by the first iterator after
	// a change and shared, immutable, by iterators until the next change
	viewMu sync.Mutex
	view   *memView
}

// New returns an empty table.
func New(cfg Config) *Table {
	var key [32]byte
	rand.Read(key[:])
	var s [6]byte
	rand.Read(s[:])
	t := &Table{cfg: cfg, mac: newMacer(key), sess: hex.EncodeToString(s[:]), mem: map[string][]byte{}}
	if cfg.Scratch != nil {
		want := cfg.MemLimit
		if want <= 0 {
			want = defaultMem
		}
		t.res = cfg.Budget.TryReserve(min(want, 1<<20), want)
		t.memMax = min(want, 1<<20)
		if t.res != nil {
			t.memMax = t.res.Size()
		}
	}
	return t
}

func (t *Table) cache() *Cache {
	if t.cfg.Cache != nil {
		return t.cfg.Cache
	}
	defaultCacheOnce.Do(func() { defaultCache = NewCache(nil, 8<<20) })
	return defaultCache
}

// Put sets key to val.
func (t *Table) Put(key, val []byte) error { return t.set(key, append([]byte{1}, val...)) }

// Delete removes key.
func (t *Table) Delete(key []byte) error { return t.set(key, []byte{0}) }

func (t *Table) set(key, v []byte) error {
	if len(key) > MaxKey || len(v)-1 > MaxValue {
		return ErrTooLarge
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("kvtab: closed")
	}
	if t.err != nil {
		return t.err
	}
	if old, ok := t.mem[string(key)]; ok {
		t.memBytes -= int64(len(key) + len(old) + entryMem)
	}
	t.mem[string(key)] = v
	t.view = nil
	t.memBytes += int64(len(key) + len(v) + entryMem)
	if t.cfg.Scratch != nil && t.memBytes > t.memMax {
		if err := t.flushLocked(); err != nil {
			t.err = err
			return err
		}
	}
	return nil
}

// Get returns a copy of the value of key.
func (t *Table) Get(key []byte) ([]byte, bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return nil, false, errors.New("kvtab: closed")
	}
	if v, ok := t.mem[string(key)]; ok {
		if v[0] == 0 {
			return nil, false, nil
		}
		return bytes.Clone(v[1:]), true, nil
	}
	for i := len(t.runs) - 1; i >= 0; i-- {
		cur := t.runs[i].seek(t.cache(), key)
		if cur.err != nil {
			return nil, false, cur.err
		}
		if cur.valid() && bytes.Equal(cur.key(), key) {
			v := cur.val()
			if len(v) == 0 {
				return nil, false, ErrTampered
			}
			if v[0] == 0 {
				return nil, false, nil
			}
			return bytes.Clone(v[1:]), true, nil
		}
	}
	return nil, false, nil
}

// Bulk loads sorted records into an empty table as one file (or in memory
// without scratch space). Keys must strictly increase.
func (t *Table) Bulk(fill func(add func(k, v []byte) error) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.runs) > 0 || len(t.mem) > 0 {
		return errors.New("kvtab: Bulk into a non-empty table")
	}
	if t.cfg.Scratch == nil {
		var last []byte
		return fill(func(k, v []byte) error {
			if last != nil && bytes.Compare(last, k) >= 0 {
				return fmt.Errorf("kvtab: keys not strictly increasing")
			}
			last = append(last[:0], k...)
			t.mem[string(k)] = append([]byte{1}, v...)
			t.view = nil
			t.memBytes += int64(len(k) + len(v) + 1 + entryMem)
			return nil
		})
	}
	s, err := t.writeFile(baseLevel, func(add func(k, v []byte) error) error {
		var b []byte
		return fill(func(k, v []byte) error {
			if len(v) > MaxValue {
				return ErrTooLarge
			}
			b = append(append(b[:0], 1), v...)
			return add(k, b)
		})
	})
	if err != nil {
		return err
	}
	if s.count > 0 {
		t.runs = append(t.runs, s)
	} else {
		t.release(s)
	}
	return nil
}

// writeFile writes a new file filled by fill.
func (t *Table) writeFile(level int, fill func(add func(k, v []byte) error) error) (*sst, error) {
	fsys, dir, err := t.cfg.Scratch()
	if err != nil {
		return nil, fmt.Errorf("kvtab: scratch space: %w", err)
	}
	if err := fsys.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := path.Join(dir, fmt.Sprintf("%s%s-%06d%s", filePrefix, t.sess, t.seq, fileSuffix))
	t.seq++
	f, err := fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	s := &sst{id: fileIDs.Add(1), f: f, fsys: fsys, name: name, mac: t.mac, level: level, refs: 1}
	ow := &offsetWriter{f: f}
	w := newSSTWriter(ow, s.id, t.mac)
	err = fill(w.add)
	if err == nil {
		err = w.finish()
	}
	if err != nil {
		f.Close()
		fsys.Remove(name)
		return nil, err
	}
	s.top, s.count, s.bytes = w.top, w.count, ow.off
	for _, r := range s.top {
		s.topMem += int64(len(r.first)) + 40
	}
	return s, nil
}

// flushLocked writes the delta as a level-0 file and merges levels.
func (t *Table) flushLocked() error {
	if len(t.mem) == 0 {
		return nil
	}
	keys := make([]string, 0, len(t.mem))
	for k := range t.mem {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	s, err := t.writeFile(0, func(add func(k, v []byte) error) error {
		for _, k := range keys {
			if err := add([]byte(k), t.mem[k]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	t.runs = append(t.runs, s)
	clear(t.mem)
	t.view = nil
	t.memBytes = 0
	return t.mergeLevels()
}

// mergeLevels merges tierFan files of one session level into the next.
// The bulk-loaded base is never merged in a session, so deletions stay
// recorded as tombstones until the table is rebuilt.
func (t *Table) mergeLevels() error {
	for {
		count := map[int]int{}
		lvl := -1
		for _, r := range t.runs {
			if r.level == baseLevel {
				continue
			}
			count[r.level]++
			if count[r.level] >= tierFan && (lvl < 0 || r.level < lvl) {
				lvl = r.level
			}
		}
		if lvl < 0 {
			return nil
		}
		var in []*sst
		var keep []*sst
		for _, r := range t.runs {
			if r.level == lvl {
				in = append(in, r)
			} else {
				keep = append(keep, r)
			}
		}
		s, err := t.writeFile(lvl+1, func(add func(k, v []byte) error) error {
			m := newMerge(t.cache(), nil, in, nil, false)
			for m.next() {
				if err := add(m.k, m.v); err != nil {
					return err
				}
			}
			return m.err
		})
		if err != nil {
			return err
		}
		for _, r := range in {
			t.release(r)
		}
		// newer than every merged file, older than nothing left above them:
		// merged files were the newest of their level, so append keeps order
		t.runs = append(keep, s)
		slices.SortStableFunc(t.runs, func(a, b *sst) int { return orderOf(a) - orderOf(b) })
	}
}

// orderOf sorts files oldest first: the base, then higher (older) levels.
func orderOf(s *sst) int {
	if s.level == baseLevel {
		return -baseLevel
	}
	return -s.level
}

func (t *Table) release(s *sst) {
	if atomic.AddInt32(&s.refs, -1) == 0 {
		t.cache().drop(s.id)
		s.f.Close()
		s.fsys.Remove(s.name)
	}
}

// Files returns the number of files (tests, health).
func (t *Table) Files() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.runs)
}

// Close removes the table's files once no iterator uses them.
func (t *Table) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	for _, r := range t.runs {
		t.release(r)
	}
	t.runs, t.mem, t.view = nil, nil, nil
	t.res.Release()
	return nil
}

// CleanScratch removes table files left in dir by an interrupted session.
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
		if e.Type().IsRegular() && strings.HasPrefix(n, filePrefix) && strings.HasSuffix(n, fileSuffix) {
			if err := fsys.Remove(path.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// Iter is a snapshot iterator: it sees the table as it was when created.
type Iter struct {
	t    *Table
	m    *merge
	runs []*sst
	k, v []byte
	done bool
}

// Iter returns an iterator over keys >= start.
func (t *Table) Iter(start []byte) *Iter {
	t.mu.RLock()
	defer t.mu.RUnlock()
	it := &Iter{t: t}
	if t.closed {
		it.done = true
		return it
	}
	v := t.memView()
	i, _ := slices.BinarySearch(v.keys, string(start))
	mem := &memSrc{keys: v.keys[i:], vals: v.vals[i:]}
	for _, r := range t.runs {
		atomic.AddInt32(&r.refs, 1)
	}
	it.runs = slices.Clone(t.runs)
	it.m = newMerge(t.cache(), mem, it.runs, start, true)
	return it
}

// Next advances; false at the end or on an error (see Err).
func (it *Iter) Next() bool {
	if it.done || !it.m.next() {
		it.done = true
		return false
	}
	it.k, it.v = it.m.k, it.m.v[1:]
	return true
}

// Key and Value are valid until the next call.
func (it *Iter) Key() []byte   { return it.k }
func (it *Iter) Value() []byte { return it.v }
func (it *Iter) Err() error {
	if it.m == nil {
		return nil
	}
	return it.m.err
}

// Close releases the files the iterator holds.
func (it *Iter) Close() {
	for _, r := range it.runs {
		it.t.release(r)
	}
	it.runs = nil
	it.done = true
}

// memView is a sorted copy of the delta's keys and values.
type memView struct {
	keys []string
	vals [][]byte
}

// memView returns the sorted delta; t.mu is held for reading, so the
// delta does not change while it is built.
func (t *Table) memView() *memView {
	t.viewMu.Lock()
	defer t.viewMu.Unlock()
	if t.view == nil {
		keys := make([]string, 0, len(t.mem))
		for k := range t.mem {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		v := &memView{keys: keys, vals: make([][]byte, len(keys))}
		for i, k := range keys {
			v.vals[i] = t.mem[k]
		}
		t.view = v
	}
	return t.view
}

type memSrc struct {
	keys []string
	vals [][]byte
	i    int
}

// merge is a newest-wins merge of a memory source and files (oldest
// first). With live, deleted keys are skipped; without, tombstones pass.
type merge struct {
	mem  *memSrc
	curs []*sstCursor // oldest first
	live bool
	k, v []byte
	err  error
}

func newMerge(c *Cache, mem *memSrc, files []*sst, start []byte, live bool) *merge {
	m := &merge{mem: mem, live: live}
	for _, f := range files {
		cur := f.seek(c, start)
		if cur.err != nil {
			m.err = cur.err
		}
		m.curs = append(m.curs, cur)
	}
	return m
}

func (m *merge) next() bool {
	for m.err == nil {
		var best []byte
		if m.mem != nil && m.mem.i < len(m.mem.keys) {
			best = []byte(m.mem.keys[m.mem.i])
		}
		for _, c := range m.curs {
			if c.valid() && (best == nil || bytes.Compare(c.key(), best) < 0) {
				best = c.key()
			}
		}
		if best == nil {
			return false
		}
		best = bytes.Clone(best)
		var val []byte
		// newest first: memory, then files from the newest
		if m.mem != nil && m.mem.i < len(m.mem.keys) && m.mem.keys[m.mem.i] == string(best) {
			val = m.mem.vals[m.mem.i]
			m.mem.i++
		}
		for i := len(m.curs) - 1; i >= 0; i-- {
			c := m.curs[i]
			if c.valid() && bytes.Equal(c.key(), best) {
				if val == nil {
					val = bytes.Clone(c.val())
				}
				c.next()
				if c.err != nil {
					m.err = c.err
					return false
				}
			}
		}
		if len(val) == 0 {
			m.err = ErrTampered
			return false
		}
		if m.live && val[0] == 0 {
			continue
		}
		m.k, m.v = best, val
		return true
	}
	return false
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
