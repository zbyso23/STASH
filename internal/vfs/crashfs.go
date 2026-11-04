package vfs

import (
	"bytes"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"sort"
	"sync"
	"time"
)

// Crash models. CrashDropUnsynced and CrashTear keep all data that was
// made durable; CrashTearGarbage may also damage synced bytes that share a
// page with an unsynced write.
const (
	// CrashDropUnsynced keeps exactly the durable state.
	CrashDropUnsynced = iota
	// CrashTear additionally lets a random subset of unsynced 4 KiB pages
	// persist, some only partially (512-byte sectors), in any order.
	CrashTear
	// CrashTearGarbage is CrashTear on storage without atomic sector
	// writes: a sector of a page that was being rewritten may hold garbage,
	// even where the page held synced bytes (SPEC §3.1.1 item 4).
	CrashTearGarbage
)

const (
	pageSize   = 4096
	sectorSize = 512
)

type inode struct {
	cur []byte // what readers see now
	dur []byte // what survives a crash
}

// CrashFS is an in-memory FS with an explicit durability model:
//   - file data becomes durable on File.Sync;
//   - creations, renames and removals become durable on SyncDir of the
//     directory that holds the name;
//   - directories become durable when created (a simplification).
//
// Crash returns the filesystem a reboot would see.
type CrashFS struct {
	mu    sync.Mutex
	ns    map[string]*inode
	durNS map[string]*inode
	dirs  map[string]bool
	// SyncCount counts File.Sync and SyncDir calls (for tests).
	SyncCount int
}

// NewCrashFS returns an empty filesystem with a root directory.
func NewCrashFS() *CrashFS {
	return &CrashFS{ns: map[string]*inode{}, durNS: map[string]*inode{}, dirs: map[string]bool{".": true}}
}

func clean(name string) string { return path.Clean("/" + name)[1:] }

func dirOf(name string) string {
	d := path.Dir(name)
	if d == "" || d == "/" {
		return "."
	}
	return d
}

func (c *CrashFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name = clean(name)
	if !c.dirs[dirOf(name)] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	in, ok := c.ns[name]
	switch {
	case ok && flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrExist}
	case !ok && flag&os.O_CREATE == 0:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	case !ok:
		in = &inode{}
		c.ns[name] = in
	}
	if flag&os.O_TRUNC != 0 {
		in.cur = in.cur[:0]
	}
	writable := flag&(os.O_WRONLY|os.O_RDWR) != 0
	return &crashFile{fs: c, in: in, name: name, writable: writable}, nil
}

func (c *CrashFS) Remove(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	name = clean(name)
	if _, ok := c.ns[name]; !ok {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	delete(c.ns, name)
	return nil
}

func (c *CrashFS) Rename(a, b string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, b = clean(a), clean(b)
	in, ok := c.ns[a]
	if !ok {
		return &fs.PathError{Op: "rename", Path: a, Err: fs.ErrNotExist}
	}
	if !c.dirs[dirOf(b)] {
		return &fs.PathError{Op: "rename", Path: b, Err: fs.ErrNotExist}
	}
	delete(c.ns, a)
	c.ns[b] = in
	return nil
}

func (c *CrashFS) MkdirAll(name string, _ fs.FileMode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for d := clean(name); d != "." && d != ""; d = dirOf(d) {
		c.dirs[d] = true
	}
	return nil
}

func (c *CrashFS) SyncDir(dir string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	dir = clean(dir)
	if dir == "" {
		dir = "."
	}
	if !c.dirs[dir] {
		return &fs.PathError{Op: "syncdir", Path: dir, Err: fs.ErrNotExist}
	}
	c.SyncCount++
	for n := range c.durNS {
		if dirOf(n) == dir {
			if _, ok := c.ns[n]; !ok {
				delete(c.durNS, n)
			}
		}
	}
	for n, in := range c.ns {
		if dirOf(n) == dir {
			c.durNS[n] = in
		}
	}
	return nil
}

type fileInfo struct {
	name string
	size int64
	dir  bool
}

func (f fileInfo) Name() string { return path.Base(f.name) }
func (f fileInfo) Size() int64  { return f.size }
func (f fileInfo) Mode() fs.FileMode {
	if f.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return f.dir }
func (f fileInfo) Sys() any           { return nil }

func (c *CrashFS) Stat(name string) (fs.FileInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name = clean(name)
	if name == "" {
		name = "."
	}
	if c.dirs[name] {
		return fileInfo{name: name, dir: true}, nil
	}
	if in, ok := c.ns[name]; ok {
		return fileInfo{name: name, size: int64(len(in.cur))}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (c *CrashFS) ReadDir(name string) ([]fs.DirEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name = clean(name)
	if name == "" {
		name = "."
	}
	if !c.dirs[name] {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	var out []fs.DirEntry
	for d := range c.dirs {
		if d != name && d != "." && dirOf(d) == name {
			out = append(out, fs.FileInfoToDirEntry(fileInfo{name: d, dir: true}))
		}
	}
	for n, in := range c.ns {
		if dirOf(n) == name {
			out = append(out, fs.FileInfoToDirEntry(fileInfo{name: n, size: int64(len(in.cur))}))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// Crash returns the state after a power loss under the given model. The
// receiver is left unchanged; a seeded rng makes the result reproducible.
func (c *CrashFS) Crash(model int, rng *rand.Rand) *CrashFS {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := NewCrashFS()
	for d := range c.dirs {
		out.dirs[d] = true
	}
	copied := map[*inode]*inode{}
	var names []string
	for n := range c.durNS {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic rng consumption
	for _, n := range names {
		in := c.durNS[n]
		nin, ok := copied[in]
		if !ok {
			var data []byte
			if model == CrashTear || model == CrashTearGarbage {
				data = tear(in.dur, in.cur, rng, model == CrashTearGarbage)
			} else {
				data = append([]byte(nil), in.dur...)
			}
			nin = &inode{cur: data, dur: append([]byte(nil), data...)}
			copied[in] = nin
		}
		out.ns[n] = nin
		out.durNS[n] = nin
	}
	return out
}

// tear mixes durable and pending content page by page and sector by sector.
func tear(dur, cur []byte, rng *rand.Rand, garbage bool) []byte {
	n := len(dur)
	if len(cur) > len(dur) {
		// the file grew: some prefix of the growth may have reached disk
		n = len(dur) + rng.Intn((len(cur)-len(dur))/sectorSize+1)*sectorSize
		if n > len(cur) {
			n = len(cur)
		}
	} else if len(cur) < len(dur) && rng.Intn(2) == 0 {
		n = len(cur) // an unsynced truncate may have persisted
	}
	out := make([]byte, n)
	copy(out, dur)
	for p := 0; p < n; p += pageSize {
		end := min(p+pageSize, n)
		switch rng.Intn(3) {
		case 0: // page not written: durable bytes (or zeros past durable end)
		case 1: // page fully written
			copy(out[p:end], sliceOrZero(cur, p, end))
		case 2: // torn: random sectors written
			dirty := garbage && !bytes.Equal(sliceOrZero(dur, p, end), sliceOrZero(cur, p, end))
			for s := p; s < end; s += sectorSize {
				se := min(s+sectorSize, end)
				switch {
				case rng.Intn(2) == 0:
					copy(out[s:se], sliceOrZero(cur, s, se))
				case dirty && rng.Intn(4) == 0:
					rng.Read(out[s:se])
				}
			}
		}
	}
	return out
}

func sliceOrZero(b []byte, from, to int) []byte {
	out := make([]byte, to-from)
	if from < len(b) {
		copy(out, b[from:min(to, len(b))])
	}
	return out
}

// Names lists every current file name, sorted (for tests).
func (c *CrashFS) Names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for n := range c.ns {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

type crashFile struct {
	fs       *CrashFS
	in       *inode
	name     string
	writable bool
	closed   bool
}

func (f *crashFile) ReadAt(p []byte, off int64) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if off >= int64(len(f.in.cur)) {
		return 0, io.EOF
	}
	n := copy(p, f.in.cur[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *crashFile) WriteAt(p []byte, off int64) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	if !f.writable || off < 0 {
		return 0, fs.ErrPermission
	}
	end := int(off) + len(p)
	if end > len(f.in.cur) {
		f.in.cur = append(f.in.cur, make([]byte, end-len(f.in.cur))...)
	}
	copy(f.in.cur[off:], p)
	return len(p), nil
}

func (f *crashFile) Truncate(size int64) error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if !f.writable || size < 0 {
		return fs.ErrPermission
	}
	if int(size) <= len(f.in.cur) {
		f.in.cur = f.in.cur[:size]
	} else {
		f.in.cur = append(f.in.cur, make([]byte, int(size)-len(f.in.cur))...)
	}
	return nil
}

func (f *crashFile) Sync() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.closed {
		return fs.ErrClosed
	}
	f.fs.SyncCount++
	f.in.dur = append(f.in.dur[:0], f.in.cur...)
	return nil
}

func (f *crashFile) Size() (int64, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	return int64(len(f.in.cur)), nil
}

func (f *crashFile) Close() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	f.closed = true
	return nil
}
