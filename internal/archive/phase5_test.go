package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"stash/internal/index"
	"stash/internal/vfs"
)

// sampleFS takes crash snapshots at a random sample of every write,
// rename, remove and directory sync, scratch space included (reservoir
// sampling: each operation is equally likely to be kept, and only kept
// ones are copied). Each snapshot carries the operation counter at which
// it was taken.
type sampleFS struct {
	*vfs.CrashFS
	mu    sync.Mutex
	rng   *rand.Rand
	keep  int
	n     int
	snaps []sampled
}

type sampled struct {
	at int
	fs *vfs.CrashFS
}

func (s *sampleFS) op() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	switch {
	case len(s.snaps) < s.keep:
		s.snaps = append(s.snaps, sampled{s.n, s.crash()})
	case s.rng.Intn(s.n) < s.keep:
		s.snaps[s.rng.Intn(s.keep)] = sampled{s.n, s.crash()}
	}
}

// crash is a power loss after which the never-synced scratch files of
// the session survive anyway (the OS may have written them back at any
// time), each cut at a random length: a crash in the middle of a merge.
func (s *sampleFS) crash() *vfs.CrashFS {
	c := s.CrashFS.Crash(vfs.CrashTear, s.rng)
	var copyDir func(dir string)
	copyDir = func(dir string) {
		es, _ := s.CrashFS.ReadDir(dir)
		for _, e := range es {
			p := path.Join(dir, e.Name())
			if e.IsDir() {
				copyDir(p)
				continue
			}
			b, err := vfs.ReadFile(s.CrashFS, p, 1<<30)
			if err != nil {
				continue
			}
			c.MkdirAll(dir, 0o755)
			if f, err := c.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644); err == nil {
				f.WriteAt(b[:s.rng.Intn(len(b)+1)], 0)
				f.Close()
			}
		}
	}
	copyDir(ScratchDir)
	return c
}

func (s *sampleFS) now() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func (s *sampleFS) OpenFile(n string, fl int, p os.FileMode) (vfs.File, error) {
	f, err := s.CrashFS.OpenFile(n, fl, p)
	if err != nil {
		return nil, err
	}
	return sampleFile{f, s}, nil
}

type sampleFile struct {
	vfs.File
	s *sampleFS
}

func (f sampleFile) WriteAt(b []byte, off int64) (int, error) {
	n, err := f.File.WriteAt(b, off)
	f.s.op()
	return n, err
}

func (f sampleFile) Sync() error {
	err := f.File.Sync()
	f.s.op() // a snapshot before the sync must not count it
	return err
}

func (f sampleFile) Truncate(n int64) error {
	err := f.File.Truncate(n)
	f.s.op()
	return err
}

func (s *sampleFS) Rename(a, b string) error            { err := s.CrashFS.Rename(a, b); s.op(); return err }
func (s *sampleFS) Remove(n string) error               { err := s.CrashFS.Remove(n); s.op(); return err }
func (s *sampleFS) SyncDir(d string) error              { err := s.CrashFS.SyncDir(d); s.op(); return err }
func (s *sampleFS) Lock(n string) (func() error, error) { return s.CrashFS.Lock(n) }

// withSpills runs fn with the smallest index delta and state tables, so
// every Put spills session runs and table files that merge by level.
func withSpills(fn func()) {
	d, k := testDeltaMax, testKVMem
	testDeltaMax, testKVMem = 4, 1
	defer func() { testDeltaMax, testKVMem = d, k }()
	fn()
}

// A power loss at any point of a workload whose index runs and state
// tables spill and merge all the time, during the final index merge at
// Close and during a compaction (scratch space included, torn as any
// other unsynced file): every reopen succeeds, every acknowledged write
// is there exactly (the operation in flight may or may not be), the
// archive verifies clean after the writer reopened, and no scratch file
// outlives the next session.
func TestCrashDuringMerges(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	type op struct {
		path string
		data []byte // nil: delete
		at   int    // operation counter when it returned
	}
	for seed := int64(0); seed < 6; seed++ {
		rng := rand.New(rand.NewSource(seed))
		base := vfs.NewCrashFS()
		mustCreate(t, base)
		s := &sampleFS{CrashFS: base, rng: rand.New(rand.NewSource(seed + 100)), keep: 48}
		var ops []op
		live := map[string]bool{}
		withSpills(func() {
			w, err := OpenWriter(s, Options{MaxExtent: 4096})
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 150; i++ {
				p := fmt.Sprintf("d%d/f%02d", i%3, rng.Intn(25))
				if live[p] && rng.Intn(5) == 0 {
					if err := w.Delete(p); err != nil {
						t.Fatal(err)
					}
					delete(live, p)
					ops = append(ops, op{path: p, at: s.now()})
					continue
				}
				d := data(int(seed)*1000+i, rng.Intn(20000))
				if _, err := w.Put(p, d); err != nil {
					t.Fatal(err)
				}
				live[p] = true
				ops = append(ops, op{path: p, data: d, at: s.now()})
				if i == 100 {
					if _, err := w.Compact(context.Background(), CompactOptions{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		})
		withScratch := 0
		for _, sn := range s.snaps {
			if es, err := sn.fs.ReadDir(ScratchDir); err == nil && len(es) > 0 {
				withScratch++
			}
		}
		t.Logf("seed %d: %d operations, %d snapshots, %d with scratch files", seed, s.n, len(s.snaps), withScratch)
		paths := map[string]bool{}
		for _, o := range ops {
			paths[o.path] = true
		}
		for k, snap := range s.snaps {
			exp, alt := map[string][]byte{}, map[string][]byte{}
			var next *op
			for i := range ops {
				if ops[i].at <= snap.at {
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
			withSpills(func() {
				w2, err := OpenWriter(snap.fs, Options{MaxExtent: 4096})
				if err != nil {
					t.Fatalf("seed %d snapshot %d (op %d of %d): %v", seed, k, snap.at, s.n, err)
				}
				for p := range paths {
					got, err := w2.Get(p)
					ok := func(want []byte) bool {
						if want == nil {
							return errors.Is(err, ErrNotFound)
						}
						return err == nil && bytes.Equal(got, want)
					}
					if !ok(exp[p]) && !ok(alt[p]) {
						t.Fatalf("seed %d snapshot %d (op %d): %s wrong (%v)", seed, k, snap.at, p, err)
					}
				}
				if _, err := w2.Put("after", []byte("crash")); err != nil {
					t.Fatalf("seed %d snapshot %d: put after crash: %v", seed, k, err)
				}
				if err := w2.Close(); err != nil {
					t.Fatal(err)
				}
				if es, err := snap.fs.ReadDir(ScratchDir); err == nil && len(es) > 0 {
					t.Fatalf("seed %d snapshot %d: %d scratch entries after Close", seed, k, len(es))
				}
				r, err := OpenReader(snap.fs, nil)
				if err != nil {
					t.Fatal(err)
				}
				rep, err := r.Verify(context.Background())
				r.Close()
				if err != nil || !rep.OK() {
					t.Fatalf("seed %d snapshot %d: verify %v %+v", seed, k, err, rep)
				}
			})
		}
	}
}

// Every implementation-defined cache can be destroyed: lost, damaged,
// truncated, lagging, from another blob or another generation, or with a
// dead session's scratch space left behind. Readers then answer exactly
// from the blobs and the manifest (rebuilding in their own scratch), a
// writer rebuilds and rewrites the indexes, and the next open uses them
// again without a scan.
func TestRebuildFromDestroyedCaches(t *testing.T) {
	base := vfs.NewCrashFS()
	mustCreate(t, base)
	want := map[string][]byte{}
	var half *vfs.CrashFS
	withSpills(func() {
		w, err := OpenWriter(base, Options{MaxExtent: 4096})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 120; i++ {
			p := fmt.Sprintf("o%03d", i)
			want[p] = data(i, 100+i*97)
			if _, err := w.Put(p, want[p]); err != nil {
				t.Fatal(err)
			}
			if i == 60 {
				w.Close() // indexes as of half the workload
				half = base.Crash(vfs.CrashDropUnsynced, nil)
				if w, err = OpenWriter(base, Options{MaxExtent: 4096}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	})
	gen := GenDir(0)
	idx := func(b int) string { n, _ := index.Name(uint8(b)); return path.Join(gen, n) }
	read := func(c *vfs.CrashFS, name string) []byte { b, _ := vfs.ReadFile(c, name, 1<<30); return b }
	put := func(c *vfs.CrashFS, name string, b []byte) {
		if err := vfs.ReplaceFile(c, name, b); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		rebuilt string // the writer's RebuiltIndexes
		destroy func(c *vfs.CrashFS)
	}{
		{"lost", "[0 1 2]", func(c *vfs.CrashFS) {
			for b := 0; b < int(cfg.BlobCount); b++ {
				c.Remove(idx(b))
			}
		}},
		{"damaged", "[0 1 2]", func(c *vfs.CrashFS) {
			for b := 0; b < int(cfg.BlobCount); b++ {
				d := read(c, idx(b))
				if len(d) > 100 {
					d[len(d)/2] ^= 0x40
				}
				put(c, idx(b), d)
			}
		}},
		{"truncated", "[0 1 2]", func(c *vfs.CrashFS) {
			for b := 0; b < int(cfg.BlobCount); b++ {
				d := read(c, idx(b))
				put(c, idx(b), d[:len(d)/2])
			}
		}},
		{"lagging", "[]", func(c *vfs.CrashFS) {
			for b := 0; b < int(cfg.BlobCount); b++ {
				put(c, idx(b), read(half, idx(b)))
			}
		}},
		{"other blob", "[1 2]", func(c *vfs.CrashFS) {
			d := read(c, idx(0))
			for b := 1; b < int(cfg.BlobCount); b++ {
				put(c, idx(b), d)
			}
		}},
		{"dead session scratch", "[]", func(c *vfs.CrashFS) {
			c.MkdirAll(ScratchDir+"/idx-dead", 0o755)
			put(c, ScratchDir+"/idx-dead/run-000001.idx", read(c, idx(0)))
			put(c, ScratchDir+"/kv-dead-000001.sst", bytes.Repeat([]byte{0xA5}, 70000))
		}},
		{"all at once", "[0 1]", func(c *vfs.CrashFS) {
			c.Remove(idx(0))
			d := read(c, idx(1))
			d[len(d)-1] ^= 1
			put(c, idx(1), d)
			for b := 2; b < int(cfg.BlobCount); b++ {
				put(c, idx(b), read(half, idx(b)))
			}
			c.MkdirAll(ScratchDir+"/junk", 0o755)
			put(c, ScratchDir+"/junk/x", []byte("left by a crashed session"))
		}},
	}
	check := func(t *testing.T, get func(string) ([]byte, error)) {
		t.Helper()
		for p, d := range want {
			got, err := get(p)
			if err != nil || !bytes.Equal(got, d) {
				t.Fatalf("%s: %v", p, err)
			}
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base.Crash(vfs.CrashDropUnsynced, nil)
			tc.destroy(c)
			before := snapshotNames(c, gen)
			withSpills(func() {
				r, err := OpenReader(c, nil)
				if err != nil {
					t.Fatal(err)
				}
				check(t, r.Get)
				rep, err := r.Verify(context.Background())
				if err != nil || !rep.OK() || rep.Versions != len(want) {
					t.Fatalf("verify %v %+v", err, rep)
				}
				r.Close()
				if after := snapshotNames(c, gen); after != before {
					t.Fatalf("a reader changed the generation:\n%s\n%s", before, after)
				}
				w, err := OpenWriter(c, Options{MaxExtent: 4096})
				if err != nil {
					t.Fatal(err)
				}
				if got := fmt.Sprint(w.Health().RebuiltIndexes); got != tc.rebuilt {
					t.Fatalf("rebuilt %s, want %s", got, tc.rebuilt)
				}
				check(t, w.Get)
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				if es, err := c.ReadDir(ScratchDir); err == nil && len(es) > 0 {
					t.Fatalf("%d scratch entries left", len(es))
				}
				// the rewritten indexes are used as they are
				w, err = OpenWriter(c, Options{MaxExtent: 4096})
				if err != nil {
					t.Fatal(err)
				}
				if h := w.Health(); len(h.RebuiltIndexes) != 0 {
					t.Fatalf("indexes rebuilt again: %v", h.RebuiltIndexes)
				}
				check(t, w.Get)
				w.Close()
			})
		})
	}
}

// snapshotNames lists the generation's files with their sizes.
func snapshotNames(c *vfs.CrashFS, gen string) string {
	var b strings.Builder
	var walk func(dir string)
	walk = func(dir string) {
		es, _ := c.ReadDir(dir)
		for _, e := range es {
			p := path.Join(dir, e.Name())
			if e.IsDir() {
				walk(p)
				continue
			}
			var n int64
			if fi, err := c.Stat(p); err == nil {
				n = fi.Size()
			}
			fmt.Fprintf(&b, "%s %d\n", p, n)
		}
	}
	walk(gen)
	return b.String()
}

var _ fs.FileInfo
