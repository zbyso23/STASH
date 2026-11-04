package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"sync"
	"testing"

	"stash/internal/alloc"
	"stash/internal/vfs"
	"stash/internal/wire"
)

var cfg = Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16}

func data(seed, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(int64(seed))).Read(b)
	return b
}

func mustCreate(t testing.TB, fsys vfs.FS) {
	t.Helper()
	if _, err := Create(fsys, cfg); err != nil {
		t.Fatal(err)
	}
}

func mustOpen(t testing.TB, fsys vfs.FS) *Writer {
	t.Helper()
	w, err := OpenWriter(fsys, Options{MaxExtent: 8192})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestPutGetDeleteReopen(t *testing.T) {
	for _, fsys := range []vfs.FS{vfs.NewCrashFS(), vfs.OS{Root: t.TempDir()}} {
		mustCreate(t, fsys)
		w := mustOpen(t, fsys)
		want := map[string][]byte{}
		sizes := []int{0, 1, 4095, 4096, 8192, 8193, 50000, 100000}
		for i, n := range sizes {
			p := fmt.Sprintf("dir/file-%d", i)
			want[p] = data(i, n)
			if _, err := w.Put(p, want[p]); err != nil {
				t.Fatal(err)
			}
		}
		v1, _ := w.Put("dir/file-3", data(99, 3000)) // new version
		want["dir/file-3"] = data(99, 3000)
		if err := w.Delete("dir/file-0"); err != nil {
			t.Fatal(err)
		}
		delete(want, "dir/file-0")
		check := func(get func(string) ([]byte, error), list []string) {
			t.Helper()
			if len(list) != len(want) {
				t.Fatalf("list %v", list)
			}
			for p, d := range want {
				got, err := get(p)
				if err != nil || !bytes.Equal(got, d) {
					t.Fatalf("%T %s: %v", fsys, p, err)
				}
			}
			if _, err := get("dir/file-0"); !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
		}
		check(w.Get, w.List())
		// a reader works while the writer holds the lock
		r, err := OpenReader(fsys, nil)
		if err != nil {
			t.Fatal(err)
		}
		check(r.Get, r.List())
		r.Close()
		if _, err := OpenWriter(fsys, Options{}); !errors.Is(err, vfs.ErrLocked) {
			t.Fatalf("second writer: %v", err)
		}
		w.Close()
		w = mustOpen(t, fsys)
		check(w.Get, w.List())
		v2, _ := w.Put("dir/file-3", data(100, 10))
		if v2 <= v1 {
			t.Fatalf("file_ver %d after %d", v2, v1)
		}
		if h := w.Health(); len(h.Sealed)+len(h.TornBlobBytes)+len(h.RebuiltIndexes) != 0 {
			t.Fatalf("clean reopen reported %+v", h)
		}
		w.Close()
	}
}

func TestCreateRules(t *testing.T) {
	c := vfs.NewCrashFS()
	mustCreate(t, c)
	if _, err := Create(c, cfg); !errors.Is(err, fs.ErrExist) {
		t.Fatal(err)
	}
	d := vfs.NewCrashFS()
	vfs.ReplaceFile(d, "other", []byte("x"))
	if _, err := Create(d, cfg); !errors.Is(err, fs.ErrExist) {
		t.Fatal("created into a non-empty directory")
	}
	bad := cfg
	bad.MaxFrameQuanta = 1
	if _, err := Create(vfs.NewCrashFS(), bad); err == nil {
		t.Fatal("max_frame_quanta 1 accepted for a new archive")
	}
	if _, err := OpenWriter(vfs.NewCrashFS(), Options{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	// two archives never share an archive_id
	h1, _ := Create(vfs.NewCrashFS(), cfg)
	h2, _ := Create(vfs.NewCrashFS(), cfg)
	if h1.ArchiveID == h2.ArchiveID {
		t.Fatal("archive_id repeated")
	}
}

// snapFS records the state a crash would leave after every mutating
// operation.
type snapFS struct {
	mu sync.Mutex
	*vfs.CrashFS
	rng   *rand.Rand
	snaps []*vfs.CrashFS
	every int
	n     int
}

func (s *snapFS) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.snaps)
}

func (s *snapFS) snap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.every <= 1 || s.n%s.every == 0 {
		s.snaps = append(s.snaps, s.CrashFS.Crash(vfs.CrashTear, s.rng))
	}
}

type snapFile struct {
	vfs.File
	s *snapFS
}

func (f snapFile) WriteAt(b []byte, off int64) (int, error) {
	n, err := f.File.WriteAt(b, off)
	f.s.snap()
	return n, err
}
func (f snapFile) Sync() error            { err := f.File.Sync(); f.s.snap(); return err }
func (f snapFile) Truncate(n int64) error { err := f.File.Truncate(n); f.s.snap(); return err }

func (s *snapFS) OpenFile(n string, fl int, p os.FileMode) (vfs.File, error) {
	f, err := s.CrashFS.OpenFile(n, fl, p)
	if err != nil {
		return nil, err
	}
	if fl&os.O_CREATE != 0 {
		s.snap()
	}
	return snapFile{f, s}, nil
}
func (s *snapFS) Rename(a, b string) error { err := s.CrashFS.Rename(a, b); s.snap(); return err }
func (s *snapFS) SyncDir(d string) error   { err := s.CrashFS.SyncDir(d); s.snap(); return err }
func (s *snapFS) Remove(n string) error    { err := s.CrashFS.Remove(n); s.snap(); return err }

// A crash at any step of Create leaves either a complete empty archive or
// ErrIncomplete / no archive; never a partially valid archive.
func TestCrashDuringCreate(t *testing.T) {
	s := &snapFS{CrashFS: vfs.NewCrashFS(), rng: rand.New(rand.NewSource(1))}
	mustCreate(t, s)
	complete := 0
	for i, c := range s.snaps {
		w, err := OpenWriter(c, Options{})
		switch {
		case err == nil:
			complete++
			if len(w.List()) != 0 {
				t.Fatal("non-empty")
			}
			if _, err := w.Put("x", []byte("ok")); err != nil {
				t.Fatalf("snapshot %d: %v", i, err)
			}
			w.Close()
		case errors.Is(err, ErrIncomplete), errors.Is(err, fs.ErrNotExist):
		default:
			t.Fatalf("snapshot %d of %d: %v", i, len(s.snaps), err)
		}
	}
	if complete == 0 || complete == len(s.snaps) {
		t.Fatalf("%d of %d snapshots complete", complete, len(s.snaps))
	}
	t.Logf("%d crash points, %d complete", len(s.snaps), complete)
}

// Crashes at random points of a Put/Delete workload: every operation that
// returned is durable, an in-flight one is either fully visible or absent,
// the writer reopens without sealing, and identifiers are never reused.
func TestCrashDuringWorkload(t *testing.T) {
	type op struct {
		path string
		data []byte // nil: delete
		at   int    // snapshot count when it returned
	}
	for seed := int64(0); seed < 6; seed++ {
		rng := rand.New(rand.NewSource(seed))
		base := vfs.NewCrashFS()
		mustCreate(t, base)
		s := &snapFS{CrashFS: base, rng: rng, every: 7}
		w := mustOpen(t, s)
		var ops []op
		live := map[string]bool{}
		for i := 0; i < 40; i++ {
			p := fmt.Sprintf("f%d", rng.Intn(6))
			if live[p] && rng.Intn(4) == 0 {
				if err := w.Delete(p); err != nil {
					t.Fatal(err)
				}
				delete(live, p)
				ops = append(ops, op{path: p, at: s.count()})
				continue
			}
			d := data(int(seed)*1000+i, rng.Intn(30000))
			if _, err := w.Put(p, d); err != nil {
				t.Fatal(err)
			}
			live[p] = true
			ops = append(ops, op{path: p, data: d, at: s.count()})
		}
		w.Close()
		for k, snap := range s.snaps {
			w2, err := OpenWriter(snap, Options{MaxExtent: 8192})
			if err != nil {
				t.Fatalf("seed %d snapshot %d: %v", seed, k, err)
			}
			if len(w2.Health().Sealed) != 0 {
				t.Fatalf("seed %d snapshot %d: sealed %v", seed, k, w2.Health().Sealed)
			}
			// expected: ops that returned at or before k; the next op may be visible
			exp := map[string][]byte{}
			alt := map[string][]byte{}
			var next *op
			for i := range ops {
				if ops[i].at <= k {
					exp[ops[i].path] = ops[i].data
				} else if next == nil {
					next = &ops[i]
				}
			}
			for p, d := range exp {
				alt[p] = d
			}
			if next != nil {
				alt[next.path] = next.data
			}
			for p := range live {
				got, err := w2.Get(p)
				e, a := exp[p], alt[p]
				ok := func(want []byte) bool {
					if want == nil {
						return errors.Is(err, ErrNotFound)
					}
					return err == nil && bytes.Equal(got, want)
				}
				if !ok(e) && !ok(a) {
					t.Fatalf("seed %d snapshot %d: %s wrong (%v)", seed, k, p, err)
				}
			}
			if _, err := w2.Put("after", []byte("crash")); err != nil {
				t.Fatalf("seed %d snapshot %d: put after crash: %v", seed, k, err)
			}
			w2.Close()
		}
	}
}

func TestAllocatorRollbackDetected(t *testing.T) {
	c := vfs.NewCrashFS()
	mustCreate(t, c)
	old, _ := vfs.ReadFile(c, alloc.FileName(wire.AllocFileVer, 0), 64)
	w := mustOpen(t, c)
	for i := 0; i < 3; i++ {
		w.Put("p", []byte{byte(i)})
	}
	w.Close()
	vfs.ReplaceFile(c, alloc.FileName(wire.AllocFileVer, 0), old) // reserved_through 1 < used file_ver
	if _, err := OpenWriter(c, Options{}); !errors.Is(err, alloc.ErrRolledBack) {
		t.Fatalf("rolled-back filever.alloc: %v", err)
	}
	vfs.ReplaceFile(c, alloc.FileName(wire.AllocFileVer, 0), nil)
	c.Remove(alloc.FileName(wire.AllocFileVer, 0))
	if _, err := OpenWriter(c, Options{}); err == nil {
		t.Fatal("missing allocator silently recreated")
	}
}

func TestSealedBlob(t *testing.T) {
	c := vfs.NewCrashFS()
	mustCreate(t, c)
	w := mustOpen(t, c)
	for i := 0; i < 6; i++ {
		w.Put(fmt.Sprintf("p%d", i), data(i, 5000))
	}
	w.Close()
	// damage the first frame of blob 01: committed data before E; without
	// the clean-close checkpoint the open hashes every frame (E1-23)
	f, _ := c.OpenFile(path.Join(GenDir(0), "frames/blob-01.stash"), os.O_RDWR, 0)
	f.WriteAt([]byte{0xFF, 0xFF, 0xFF}, 0x40+200)
	f.Sync()
	f.Close()
	dropCheckpoints(t, c)
	w = mustOpen(t, c)
	if _, ok := w.Health().Sealed[1]; !ok {
		t.Fatalf("health %+v", w.Health())
	}
	missing := 0
	for i := 0; i < 6; i++ {
		_, err := w.Get(fmt.Sprintf("p%d", i))
		if errors.Is(err, ErrMissingData) {
			missing++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if missing == 0 {
		t.Fatal("damaged object not reported")
	}
	for i := 0; i < 5; i++ { // writes continue on other blobs
		if _, err := w.Put(fmt.Sprintf("n%d", i), data(i, 100)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
}

func TestAllSealed(t *testing.T) {
	c := vfs.NewCrashFS()
	one := cfg
	one.BlobCount = 1
	if _, err := Create(c, one); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, c)
	w.Put("a", data(1, 100))
	w.Close()
	f, _ := c.OpenFile(path.Join(GenDir(0), "frames/blob-00.stash"), os.O_RDWR, 0)
	f.WriteAt([]byte{0xFF}, 0x40+50)
	f.Sync()
	f.Close()
	w = mustOpen(t, c)
	defer w.Close()
	if _, err := w.Put("b", []byte("x")); !errors.Is(err, ErrNoWritableBlob) {
		t.Fatal(err)
	}
}

func TestGenDirNames(t *testing.T) {
	if GenDir(0xAB) != "generation-00000000000000AB" {
		t.Fatal(GenDir(0xAB))
	}
	for _, bad := range []string{"generation-00000000000000ab", "generation-0", "generation-00000000000000AB0", "gen-00000000000000AB"} {
		if _, ok := ParseGenDir(bad); ok {
			t.Fatalf("%s accepted", bad)
		}
	}
	if v, ok := ParseGenDir("generation-FFFFFFFFFFFFFFFF"); !ok || v != 1<<64-1 {
		t.Fatal(v)
	}
}

func BenchmarkPut64K(b *testing.B) {
	fsys := vfs.OS{Root: b.TempDir()}
	mustCreate(b, fsys)
	w, _ := OpenWriter(fsys, Options{})
	defer w.Close()
	d := data(1, 64<<10)
	b.SetBytes(int64(len(d)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Put(fmt.Sprintf("p%d", i%1000), d); err != nil {
			b.Fatal(err)
		}
	}
}

func TestConcurrentPuts(t *testing.T) {
	c := vfs.NewCrashFS()
	mustCreate(t, c)
	w := mustOpen(t, c)
	done := make(chan error)
	for g := 0; g < 8; g++ {
		go func(g int) {
			var err error
			for i := 0; i < 20 && err == nil; i++ {
				p := fmt.Sprintf("g%d/%d", g, i%5)
				if _, err = w.Put(p, data(g*100+i, 3000+i*700)); err == nil {
					_, err = w.Get(p)
				}
			}
			done <- err
		}(g)
	}
	for g := 0; g < 8; g++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	r, err := OpenReader(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for g := 0; g < 8; g++ {
		for k := 0; k < 5; k++ {
			got, err := r.Get(fmt.Sprintf("g%d/%d", g, k))
			want := data(g*100+15+k, 3000+(15+k)*700)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("g%d/%d: %v", g, k, err)
			}
		}
	}
}

// Group commit under crashes: concurrent writers, each owning one path.
// Every Put that returned before the crash is durable; the one in flight
// is all or nothing.
func TestCrashDuringGroupCommit(t *testing.T) {
	type done struct {
		data []byte
		at   int
	}
	for seed := int64(0); seed < 3; seed++ {
		base := vfs.NewCrashFS()
		mustCreate(t, base)
		s := &snapFS{CrashFS: base, rng: rand.New(rand.NewSource(seed)), every: 11}
		w := mustOpen(t, s)
		const G, N = 6, 12
		hist := make([][]done, G)
		var wg sync.WaitGroup
		for g := 0; g < G; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < N; i++ {
					d := data(int(seed)*10000+g*100+i, 500+i*900)
					if _, err := w.Put(fmt.Sprintf("g%d", g), d); err != nil {
						t.Error(err)
						return
					}
					hist[g] = append(hist[g], done{d, s.count()})
				}
			}(g)
		}
		wg.Wait()
		batches, records := w.CommitStats()
		w.Close()
		if batches >= records {
			t.Logf("seed %d: no batching happened (%d batches, %d records)", seed, batches, records)
		}
		for k, snap := range s.snaps {
			w2, err := OpenWriter(snap, Options{MaxExtent: 8192})
			if err != nil {
				t.Fatalf("seed %d snapshot %d: %v", seed, k, err)
			}
			for g := 0; g < G; g++ {
				var exp, next []byte
				for i, h := range hist[g] {
					if h.at <= k {
						exp = h.data
					} else {
						next = hist[g][i].data
						break
					}
				}
				got, err := w2.Get(fmt.Sprintf("g%d", g))
				okExp := (exp == nil && errors.Is(err, ErrNotFound)) || (exp != nil && err == nil && bytes.Equal(got, exp))
				okNext := next != nil && err == nil && bytes.Equal(got, next)
				if !okExp && !okNext {
					t.Fatalf("seed %d snapshot %d g%d: %v", seed, k, g, err)
				}
			}
			w2.Close()
		}
		t.Logf("seed %d: %d records in %d batches, %d crash points", seed, records, batches, len(s.snaps))
	}
}

func dropCheckpoints(t testing.TB, fsys vfs.FS) {
	t.Helper()
	if err := fsys.Remove(path.Join(GenDir(0), checkpointName)); err != nil {
		t.Fatal(err)
	}
}
