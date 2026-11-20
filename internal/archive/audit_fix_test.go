package archive

// Tests of the fixes for the M20c/R11 audit (see audit_m20c_test.go for
// the auditor's own reproductions).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"stash/internal/anchor"
	"strings"
	"testing"
	"time"

	"stash/internal/kvtab"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// rootFaultFS fails the rename of the root, or the directory sync after
// it, once.
type rootFaultFS struct {
	vfs.FS
	failRename, failSync bool
	renamed              bool
}

func (a *rootFaultFS) Rename(from, to string) error {
	if to == RootName && a.failRename {
		a.failRename = false
		return fs.ErrPermission
	}
	err := a.FS.Rename(from, to)
	if to == RootName && err == nil {
		a.renamed = true
	}
	return err
}

func (a *rootFaultFS) SyncDir(p string) error {
	if a.failSync && a.renamed && p == "." {
		a.failSync = false
		return fs.ErrPermission
	}
	return a.FS.SyncDir(p)
}

// P0: a failed rename leaves the source current and the writer usable; a
// failed sync after the rename keeps the destination, stops the writer
// and a reopen reads the generation the root names.
func TestCompactRootReplaceFaults(t *testing.T) {
	ctx := context.Background()
	for _, failRename := range []bool{true, false} {
		t.Run(fmt.Sprintf("rename=%v", failRename), func(t *testing.T) {
			fsys := &rootFaultFS{FS: vfs.NewCrashFS()}
			mustCreate(t, fsys)
			w := mustOpen(t, fsys)
			if _, err := w.Put("a", data(1, 5000)); err != nil {
				t.Fatal(err)
			}
			before, _ := readRoot(fsys)
			fsys.renamed, fsys.failRename, fsys.failSync = false, failRename, !failRename
			res, err := w.Compact(ctx, CompactOptions{})
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("compact: %v", err)
			}
			root, err := readRoot(fsys)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.Stat(GenDir(root.GenerationID)); err != nil {
				t.Fatalf("root names a missing generation %d: %v", root.GenerationID, err)
			}
			if failRename {
				if root.GenerationID != before.GenerationID {
					t.Fatalf("root moved to %d", root.GenerationID)
				}
				if _, err := fsys.Stat(GenDir(res.To)); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("aborted destination kept: %v", err)
				}
				if _, err := w.Put("b", data(2, 100)); err != nil {
					t.Fatalf("writer stopped after a clean abort: %v", err)
				}
			} else {
				if root.GenerationID != res.To {
					t.Fatalf("root %d, destination %d", root.GenerationID, res.To)
				}
				if _, err := w.Put("b", data(2, 100)); err == nil {
					t.Fatal("writer kept writing to the old generation after an uncertain switch")
				}
			}
			w.Close()
			w = mustOpen(t, fsys)
			defer w.Close()
			checkAll(t, w.Get, map[string][]byte{"a": data(1, 5000)})
			if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
				t.Fatalf("compaction after reopen: %v", err)
			}
		})
	}
}

// P1: a lost version deleted, rewritten, or rewritten and deleted while
// the prune runs is SUPERSEDED: no marker, the final state stands. The
// operator still confirms every lost extent.
func TestPruneConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []string{"delete", "put", "put-delete"} {
		t.Run(tc, func(t *testing.T) {
			fsys := vfs.NewCrashFS()
			mustCreate(t, fsys)
			w := mustOpen(t, fsys)
			w.Put("x", data(1, 100000))
			w.Put("keep", data(2, 100000))
			damageExtent(t, fsys, w, "x", 0)
			damageExtent(t, fsys, w, "keep", 0)
			w.Close()
			w = mustOpen(t, fsys)
			defer w.Close()
			saved := compactTrace
			defer func() { compactTrace = saved }()
			compactTrace = func(phase string, _ time.Duration) {
				if phase != "sweep" {
					return
				}
				var err error
				switch tc {
				case "delete":
					err = w.Delete("x")
				case "put":
					_, err = w.Put("x", data(3, 900))
				case "put-delete":
					if _, err = w.Put("x", data(3, 900)); err == nil {
						err = w.Delete("x")
					}
				}
				if err != nil {
					t.Error(err)
				}
			}
			res, err := w.Compact(ctx, CompactOptions{EmergencyPrune: prune(2)})
			compactTrace = saved
			if err != nil {
				t.Fatal(err)
			}
			if p := res.Prune; p.LostExtents != 2 || p.LostVersions != 1 || p.SupersededVersions != 1 {
				t.Fatalf("report %+v", p)
			}
			d := details(t, w, res.Prune.Record)
			st := map[string]string{}
			for _, o := range d["object"] {
				st[o.Path] = o.Status
			}
			if st["x"] != "SUPERSEDED" || st["keep"] != "UNRECOVERABLE" {
				t.Fatalf("object statuses %v", st)
			}
			for round := 0; round < 2; round++ {
				_, err := w.Get("x")
				if tc == "put" {
					checkAll(t, w.Get, map[string][]byte{"x": data(3, 900)})
				} else if !errors.Is(err, ErrNotFound) || isLost(err) {
					t.Fatalf("round %d x: %v", round, err)
				}
				if _, err := w.Get("keep"); !isLost(err) {
					t.Fatalf("round %d keep: %v", round, err)
				}
				if h := w.Health(); h.Unrecoverable != 1 {
					t.Fatalf("health %+v", h)
				}
				w.Close()
				w = mustOpen(t, fsys)
			}
			recs, _, err := w.PruneRecords()
			if err != nil || len(recs) != 1 || recs[0].SupersededVersions != 1 || recs[0].LostVersions != 1 {
				t.Fatalf("records %+v %v", recs, err)
			}
		})
	}
}

// P1: after a prune every generation has a marker index, an empty one
// once every loss was acknowledged; a missing or foreign index fails the
// open instead of reading the losses as absences.
func TestMarkerIndexRequired(t *testing.T) {
	ctx := context.Background()
	fsys, res := pruneOne(t, nil, "a")
	w := mustOpen(t, fsys)
	if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	root, _ := readRoot(fsys)
	if _, err := fsys.Stat(lostIndexName(root.GenerationID)); err != nil {
		t.Fatalf("normal compaction after a prune dropped the index: %v", err)
	}
	if _, err := w.Get("a"); !isLost(err) {
		t.Fatalf("a: %v", err)
	}
	if err := w.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	root, _ = readRoot(fsys)
	idx := lostIndexName(root.GenerationID)
	b, err := vfs.ReadFile(fsys, idx, 1<<20)
	if err != nil {
		t.Fatalf("every loss acknowledged: no empty index: %v", err)
	}
	w = mustOpen(t, fsys)
	if h := w.Health(); h.Unrecoverable != 0 {
		t.Fatalf("health %+v", h)
	}
	if _, err := w.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acknowledged a: %v", err)
	}
	w.Close()

	// missing: both the reader and the writer refuse to open
	if err := fsys.Remove(idx); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReader(fsys, nil); !errors.Is(err, ErrMarkersMissing) || !errors.Is(err, wire.ErrCorrupt) {
		t.Fatalf("reader without the index: %v", err)
	}
	if _, err := OpenWriter(fsys, Options{}); !errors.Is(err, ErrMarkersMissing) {
		t.Fatalf("writer without the index: %v", err)
	}
	// another generation's index under this name
	old, err := vfs.ReadFile(fsys, lostIndexName(res.To), 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		old = bytes.Clone(b) // removed with its generation: rebind the empty one
		old[8]++
	} else if err != nil {
		t.Fatal(err)
	}
	if err := vfs.ReplaceFile(fsys, idx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReader(fsys, nil); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatalf("foreign index accepted: %v", err)
	}
	// restored, it opens again
	if err := vfs.ReplaceFile(fsys, idx, b); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

// P2: an operator or a reason too long for a record line refuses the
// prune before anything changes.
func TestPruneTextLimit(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	w.Put("x", data(1, 100000))
	damageExtent(t, fsys, w, "x", 0)
	w.Close()
	w = mustOpen(t, fsys)
	defer w.Close()
	before, _ := readRoot(fsys)
	for _, long := range []func(p *EmergencyPrune){
		func(p *EmergencyPrune) { p.Reason = strings.Repeat("r", MaxPruneText+1) },
		func(p *EmergencyPrune) { p.Operator = strings.Repeat("\x01", MaxPruneText+1) },
	} {
		p := prune(1)
		long(p)
		if _, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: p}); !errors.Is(err, ErrPruneRefused) {
			t.Fatalf("long text: %v", err)
		}
	}
	if root, _ := readRoot(fsys); root.GenerationID != before.GenerationID {
		t.Fatal("a refused prune switched")
	}
	// at the limit, with JSON escaping that grows it sixfold, it works
	p := prune(1)
	p.Reason = strings.Repeat("\x01", MaxPruneText)
	if _, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: p}); err != nil {
		t.Fatal(err)
	}
	recs, _, err := w.PruneRecords()
	if err != nil || len(recs) != 1 || recs[0].Reason != p.Reason {
		t.Fatalf("records %v", err)
	}
}

// P2: acknowledgements live in a budgeted table that spills to scratch
// files: many of them do not grow the heap per entry, and they survive a
// reopen from the cleared log.
func TestClearedSetSpills(t *testing.T) {
	fsys := vfs.NewCrashFS()
	const n = 30000
	if err := fsys.MkdirAll(HealthDir, 0o755); err != nil {
		t.Fatal(err)
	}
	digests := make([][32]byte, 0, n)
	for i := 0; i < n; i++ {
		digests = append(digests, pathDigest(nil, fmt.Sprintf("p%06d", i)))
	}
	sortDigests(digests)
	if err := writeLostIndex(fsys, 7, n, func(yield func(d [32]byte, ver, g uint64) error) error {
		for _, d := range digests {
			if err := yield(d, 1, 7); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	scratch := vfs.NewCrashFS()
	kv := kvtab.Config{Scratch: func() (vfs.FS, string, error) { return scratch, "s", nil }}
	s, err := openLostSet(fsys, nil, 7, true, kv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i += 2 {
		if err := s.clear(fmt.Sprintf("p%06d", i)); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := scratch.ReadDir("s")
	if len(ents) == 0 {
		t.Fatal("acknowledged set never spilled")
	}
	s.close()
	s, err = openLostSet(fsys, nil, 7, false, kv)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if s.count() != n/2 {
		t.Fatalf("standing %d", s.count())
	}
	for _, i := range []int{0, 1, 2, n - 1} {
		u, err := s.lookup(fmt.Sprintf("p%06d", i))
		if err != nil || (u == nil) != (i%2 == 0) {
			t.Fatalf("p%06d: %v %v", i, u, err)
		}
	}
}

func sortDigests(d [][32]byte) {
	slices.SortFunc(d, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
}

// P0, HARDENED: the anchor names the destination before the root is
// replaced, so even a failed rename keeps it; a reopen with the anchor
// reads the destination.
func TestCompactRootReplaceFaultsHardened(t *testing.T) {
	ctx := context.Background()
	for _, failRename := range []bool{true, false} {
		t.Run(fmt.Sprintf("rename=%v", failRename), func(t *testing.T) {
			a := anchor.NewMemory()
			fsys := &rootFaultFS{FS: vfs.NewCrashFS()}
			if _, err := Create(fsys, hcfg(a)); err != nil {
				t.Fatal(err)
			}
			w := hopen(t, fsys, a)
			if _, err := w.Put("a", data(1, 5000)); err != nil {
				t.Fatal(err)
			}
			fsys.renamed, fsys.failRename, fsys.failSync = false, failRename, !failRename
			res, err := w.Compact(ctx, CompactOptions{})
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("compact: %v", err)
			}
			if anchoredOf(t, a).GenerationID != res.To {
				t.Fatal("anchor not advanced")
			}
			if _, err := fsys.Stat(GenDir(res.To)); err != nil {
				t.Fatalf("anchored destination removed: %v", err)
			}
			if _, err := w.Put("b", data(2, 100)); err == nil {
				t.Fatal("writer kept writing after an uncertain switch")
			}
			w.Close()
			w = hopen(t, fsys, a)
			defer w.Close()
			checkAll(t, w.Get, map[string][]byte{"a": data(1, 5000)})
			if root, _ := readRoot(fsys); root.GenerationID != res.To {
				t.Fatalf("reopen left root at %d, anchor at %d", root.GenerationID, res.To)
			}
		})
	}
}
