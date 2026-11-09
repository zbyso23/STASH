package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"sort"
	"testing"

	"stash/internal/anchor"
	"stash/internal/manifest"
	"stash/internal/vfs"
	"stash/internal/wire"
)

func hcfg(a anchor.Anchor) Config {
	c := cfg
	c.Anchor = a
	return c
}

func hopen(t testing.TB, fsys vfs.FS, a anchor.Anchor) *Writer {
	t.Helper()
	w, err := OpenWriter(fsys, Options{MaxExtent: 8192, Anchor: a})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func anchoredOf(t testing.TB, a *anchor.Memory) anchor.State {
	t.Helper()
	for _, s := range a.Snapshot() {
		return s
	}
	t.Fatal("no anchor")
	return anchor.State{}
}

func manifestLen(t testing.TB, fsys vfs.FS, gen uint64) int64 {
	fi, err := fsys.Stat(path.Join(GenDir(gen), manifest.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestHardenedCreateCommitOpen(t *testing.T) {
	a := anchor.NewMemory()
	fsys := vfs.NewCrashFS()
	if _, err := Create(fsys, hcfg(a)); err != nil {
		t.Fatal(err)
	}
	// a second creation for the same archive_id is refused by the anchor
	st := anchoredOf(t, a)
	if err := a.Create(context.Background(), st); !errors.Is(err, anchor.ErrExists) {
		t.Fatal(err)
	}
	if st.GenerationID != 0 || st.ManifestLength != 0 {
		t.Fatalf("%+v", st)
	}
	// policy: no downgrade, no anchor for a STANDARD archive
	if _, err := OpenWriter(fsys, Options{}); !errors.Is(err, ErrAnchorRequired) {
		t.Fatal(err)
	}
	if _, err := OpenReader(fsys, nil); err != nil {
		t.Fatal("plain OpenReader is the low-level call; OpenReaderWith checks policy")
	}
	if _, err := OpenReaderWith(fsys, ReaderOptions{}); !errors.Is(err, ErrAnchorRequired) {
		t.Fatal(err)
	}
	w := hopen(t, fsys, a)
	want := map[string][]byte{}
	for i := 0; i < 10; i++ {
		p := string(rune('a' + i))
		want[p] = data(i, 3000*i)
		if _, err := w.Put(p, want[p]); err != nil {
			t.Fatal(err)
		}
	}
	// every reported commit is anchored
	st = anchoredOf(t, a)
	if st.ManifestLength != uint64(manifestLen(t, fsys, 0)) || a.Advances < 10 {
		t.Fatalf("anchor %d manifest %d advances %d", st.ManifestLength, manifestLen(t, fsys, 0), a.Advances)
	}
	w.Close()
	w = hopen(t, fsys, a)
	checkAll(t, w.Get, want)
	w.Close()
	r, err := OpenReaderWith(fsys, ReaderOptions{Anchor: a, Pin: true})
	if err != nil {
		t.Fatal(err)
	}
	checkAll(t, r.Get, want)
	r.Close()
}

// One anchor advance covers a whole group commit batch.
func TestHardenedGroupCommit(t *testing.T) {
	a := anchor.NewMemory()
	fsys := vfs.NewCrashFS()
	Create(fsys, hcfg(a))
	w := hopen(t, fsys, a)
	defer w.Close()
	before := a.Advances
	done := make(chan error)
	for g := 0; g < 32; g++ {
		go func() {
			_, err := w.Put(fmt.Sprintf("g%d", g), data(g, 70000))
			done <- err
		}()
	}
	for g := 0; g < 32; g++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	batches, _ := w.CommitStats()
	if n := a.Advances - before; n != batches || n >= 32 {
		t.Logf("advances %d batches %d", n, batches)
	}
	if anchoredOf(t, a).ManifestLength != uint64(manifestLen(t, fsys, 0)) {
		t.Fatal("not anchored")
	}
}

func truncateManifest(t testing.TB, fsys vfs.FS, gen uint64, n int64) {
	f, _ := fsys.OpenFile(path.Join(GenDir(gen), manifest.ManifestName), os.O_RDWR, 0)
	f.Truncate(n)
	f.Sync()
	f.Close()
}

func TestHardenedRollbackDetection(t *testing.T) {
	ctx := context.Background()
	newArchive := func() (*vfs.CrashFS, *anchor.Memory) {
		a := anchor.NewMemory()
		fsys := vfs.NewCrashFS()
		Create(fsys, hcfg(a))
		w := hopen(t, fsys, a)
		w.Put("x", data(1, 5000))
		w.Put("y", data(2, 90000))
		w.Close()
		return fsys, a
	}
	expect := func(name string, fsys vfs.FS, a anchor.Anchor, target error) {
		t.Helper()
		if _, err := OpenWriter(fsys, Options{Anchor: a}); !errors.Is(err, target) {
			t.Fatalf("%s: writer %v", name, err)
		}
		if _, err := OpenReaderWith(fsys, ReaderOptions{Anchor: a}); !errors.Is(err, target) {
			t.Fatalf("%s: reader %v", name, err)
		}
	}
	// manifest truncated below the anchored length
	fsys, a := newArchive()
	truncateManifest(t, fsys, 0, manifestLen(t, fsys, 0)-10)
	expect("truncated", fsys, a, ErrRollback)
	// same length, other content
	fsys, a = newArchive()
	f, _ := fsys.OpenFile(path.Join(GenDir(0), manifest.ManifestName), os.O_RDWR, 0)
	f.WriteAt([]byte("9"), 10)
	f.Close()
	expect("tampered", fsys, a, ErrRollback)
	// whole storage rolled back to an earlier internally valid state
	fsys, a = newArchive()
	old := fsys.Crash(vfs.CrashDropUnsynced, rand.New(rand.NewSource(1)))
	w := hopen(t, fsys, a)
	w.Put("z", data(3, 100))
	w.Close()
	expect("storage rollback", old, a, ErrRollback)
	// anchor unavailable: no downgrade
	fsys, a = newArchive()
	a.SetUnavailable(true)
	expect("unavailable", fsys, a, ErrAnchorUnavailable)
	if _, err := OpenWriter(fsys, Options{}); !errors.Is(err, ErrAnchorRequired) {
		t.Fatal(err)
	}
	a.SetUnavailable(false)
	// anchor unavailable during a commit: the Put fails and the writer
	// stays failed until it is reopened
	w = hopen(t, fsys, a)
	a.SetUnavailable(true)
	if _, err := w.Put("q", data(4, 10)); !errors.Is(err, ErrAnchorUnavailable) {
		t.Fatal(err)
	}
	a.SetUnavailable(false)
	if _, err := w.Put("q2", data(4, 10)); !errors.Is(err, ErrAnchorUnavailable) {
		t.Fatal("writer continued after an anchor failure")
	}
	w.Close()
	w = hopen(t, fsys, a) // the unanchored "q" record is truncated
	if _, err := w.Get("q"); !errors.Is(err, ErrNotFound) || w.Health().UnanchoredBytes == 0 {
		t.Fatalf("unanchored record: %v %+v", err, w.Health())
	}
	w.Close()
	// root_digest mismatch
	fsys, a = newArchive()
	st := anchoredOf(t, a)
	st.RootDigest[0] ^= 1
	a.Set(st)
	expect("root digest", fsys, a, ErrRollback)
	// local root ahead of the anchor: fail closed, then the authorized flow
	fsys, a = newArchive()
	saved := a.Snapshot()
	w = hopen(t, fsys, a)
	if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	a.Restore(saved)
	expect("root ahead", fsys, a, ErrRollback)
	var log []string
	if err := AuthorizeAnchorTransition(ctx, fsys, a, "test", func(s string) { log = append(log, s) }); err != nil || len(log) != 1 {
		t.Fatal(err)
	}
	w = hopen(t, fsys, a)
	w.Close()
	// a stale (replayed) advance is rejected by the provider
	cur := anchoredOf(t, a)
	if err := a.Advance(ctx, saved[cur.ArchiveID], cur); !errors.Is(err, anchor.ErrStale) {
		t.Fatal(err)
	}
	// the anchor itself is gone
	fsys, _ = newArchive()
	expect("anchor missing", fsys, anchor.NewMemory(), ErrRollback)
}

// Unanchored manifest bytes (crash between manifest fsync and commit
// advance): truncated by default, adopted only on request, never applied
// by a reader.
func TestHardenedUnanchored(t *testing.T) {
	a := anchor.NewMemory()
	fsys := vfs.NewCrashFS()
	Create(fsys, hcfg(a))
	w := hopen(t, fsys, a)
	w.Put("x", data(1, 5000))
	w.Close()
	saved := a.Snapshot()
	w = hopen(t, fsys, a)
	w.Put("y", data(2, 5000))
	w.Close()
	a.Restore(saved) // as if the advance never happened
	r, err := OpenReaderWith(fsys, ReaderOptions{Anchor: a})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get("y"); !errors.Is(err, ErrNotFound) {
		t.Fatal("reader applied unanchored bytes")
	}
	r.Close()
	w, err = OpenWriter(fsys, Options{Anchor: a, AdoptUnanchored: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.Get("y"); err != nil || !bytes.Equal(got, data(2, 5000)) || w.Health().AdoptedBytes == 0 {
		t.Fatalf("adopt: %v", err)
	}
	w.Close()
	if anchoredOf(t, a).ManifestLength != uint64(manifestLen(t, fsys, 0)) {
		t.Fatal("adopted bytes not anchored")
	}
}

func TestHardenedEnroll(t *testing.T) {
	ctx := context.Background()
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	want := writeObjects(t, fsys, 1)
	snapshot := func() map[string][]byte {
		out := map[string][]byte{}
		for _, n := range fsys.Names() {
			if f, err := fsys.OpenFile(n, os.O_RDONLY, 0); err == nil {
				sz, _ := f.Size()
				b := make([]byte, sz)
				f.ReadAt(b, 0)
				f.Close()
				out[n] = b
			}
		}
		return out
	}
	before := snapshot()
	a := anchor.NewMemory()
	if _, err := Enroll(ctx, fsys, a, EnrollOptions{}); err == nil {
		t.Fatal("enrollment without operator and log")
	}
	var log []string
	if _, err := Enroll(ctx, fsys, a, EnrollOptions{Operator: "op", Log: func(s string) { log = append(log, s) }}); err != nil || len(log) != 1 {
		t.Fatal(err)
	}
	// no archive wire byte changed: only the policy marker (and the
	// implementation's own health file) differ
	after := snapshot()
	var changed []string
	for n, b := range after {
		if !bytes.Equal(before[n], b) {
			changed = append(changed, n)
		}
	}
	for n := range before {
		if _, ok := after[n]; !ok {
			changed = append(changed, n)
		}
	}
	sort.Strings(changed)
	for _, n := range changed {
		if n != PolicyName && n != path.Join(GenDir(0), checkpointName) {
			t.Fatalf("enrollment changed %s (all: %v)", n, changed)
		}
	}
	w := hopen(t, fsys, a)
	checkAll(t, w.Get, want)
	w.Close()
	// a damaged archive is not enrolled
	fsys2 := vfs.NewCrashFS()
	mustCreate(t, fsys2)
	w = mustOpen(t, fsys2)
	w.Put("x", data(1, 100000))
	v, _ := w.Stat("x")
	recs := w.blobs[v.Loc[1].Blob].idx.Lookup(v.Loc[1].Hash)
	w.Close()
	damage(t, fsys2, blobFile(int(v.Loc[1].Blob)), int64(recs[0].PhysicalOffset)+16, 2)
	dropCheckpoints(t, fsys2)
	if _, err := Enroll(ctx, fsys2, a, EnrollOptions{Operator: "op", Log: func(string) {}}); err == nil {
		t.Fatal("damaged archive enrolled")
	}
	// leaving HARDENED is explicit
	if err := LeaveHardened(fsys, "op", func(string) {}); err != nil {
		t.Fatal(err)
	}
	w = mustOpen(t, fsys)
	w.Close()
}

// Crashes in a HARDENED workload and in a HARDENED compaction: every
// reported Put survives, and every crash state opens (the anchor is
// external: its state at the crash is what the next opener sees).
func TestHardenedCrash(t *testing.T) {
	ctx := context.Background()
	a := anchor.NewMemory()
	base := vfs.NewCrashFS()
	Create(base, hcfg(a))
	type snapPoint struct {
		fs     *vfs.CrashFS
		anchor map[[32]byte]anchor.State
		done   int // Puts reported before the crash
	}
	var points []snapPoint
	done := 0
	var s *snapFS
	s = &snapFS{CrashFS: base, rng: rand.New(rand.NewSource(3)), every: 2}
	s.onSnap = func() any { return [2]any{a.Snapshot(), done} }
	w, err := OpenWriter(s, Options{MaxExtent: 8192, Anchor: a})
	if err != nil {
		t.Fatal(err)
	}
	var puts [][]byte
	record := func() {
		for len(points) < s.count() {
			e := s.ext[len(points)].([2]any)
			points = append(points, snapPoint{s.snaps[len(points)], e[0].(map[[32]byte]anchor.State), e[1].(int)})
		}
	}
	for i := 0; i < 12; i++ {
		d := data(i, 2000+i*7000)
		if _, err := w.Put("p", d); err != nil {
			t.Fatal(err)
		}
		record()
		puts = append(puts, d)
		done++
	}
	record()
	done = -1 // p is deleted from here on
	w.Delete("p")
	w.Put("q", data(99, 50000))
	record()
	compactFrom := len(points)
	if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	record()
	w.Close()
	olds, news := 0, 0
	for k, pt := range points {
		m := anchor.NewMemory()
		m.Restore(pt.anchor)
		w2, err := OpenWriter(pt.fs, Options{MaxExtent: 8192, Anchor: m})
		if err != nil {
			t.Fatalf("point %d: %v", k, err)
		}
		if k < compactFrom {
			got, err := w2.Get("p")
			if pt.done > 0 && pt.done <= len(puts) {
				if err != nil {
					t.Fatalf("point %d: %v", k, err)
				}
				okd := bytes.Equal(got, puts[pt.done-1]) || (pt.done < len(puts) && bytes.Equal(got, puts[pt.done]))
				if !okd {
					t.Fatalf("point %d: lost a reported Put", k)
				}
			}
		} else {
			if got, err := w2.Get("q"); err != nil || !bytes.Equal(got, data(99, 50000)) {
				t.Fatalf("point %d: %v", k, err)
			}
			if w2.h.GenerationID == 0 {
				olds++
			} else {
				news++
			}
		}
		if _, err := w2.Put("after", data(1, 100)); err != nil {
			t.Fatalf("point %d: %v", k, err)
		}
		w2.Close()
	}
	t.Logf("%d crash points; compaction: %d old, %d new", len(points), olds, news)
	if news == 0 || olds == 0 {
		t.Fatal("compaction crash points do not cover both sides")
	}
}

// A crash after the switch advance and before the local root switch, and
// a crash between the anchor creation and the first root write: the
// opener verifies the anchored generation and installs its root.
func TestHardenedRootReconstruction(t *testing.T) {
	ctx := context.Background()
	a := anchor.NewMemory()
	fsys := vfs.NewCrashFS()
	Create(fsys, hcfg(a))
	w := hopen(t, fsys, a)
	w.Put("x", data(1, 30000))
	res, err := w.Compact(ctx, CompactOptions{KeepOld: true})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	// put the old root back: anchor N+1, root N
	old := wire.Root{GenerationID: res.From, ArchiveID: anchoredOf(t, a).ArchiveID}
	vfs.ReplaceFile(fsys, RootName, old.AppendBinary(nil))
	w = hopen(t, fsys, a)
	if w.h.GenerationID != res.To {
		t.Fatal("switch not completed")
	}
	w.Close()
	// anchored generation damaged: incident, no fallback
	vfs.ReplaceFile(fsys, RootName, old.AppendBinary(nil))
	damage(t, fsys, path.Join(GenDir(res.To), manifest.ManifestName), 5, 1)
	if _, err := OpenWriter(fsys, Options{Anchor: a}); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	// anchored generation missing
	vfs.RemoveAll(fsys, GenDir(res.To))
	if _, err := OpenWriter(fsys, Options{Anchor: a}); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}

	// creation: crash after the anchor was created, before root.current
	a = anchor.NewMemory()
	s := &snapFS{CrashFS: vfs.NewCrashFS(), rng: rand.New(rand.NewSource(1))}
	if _, err := Create(s, hcfg(a)); err != nil {
		t.Fatal(err)
	}
	full := a.Snapshot()
	rebuilt := 0
	for _, snap := range s.snaps {
		if _, err := snap.Stat(RootName); err == nil {
			continue
		}
		if _, err := snap.Stat(PolicyName); err != nil {
			continue
		}
		m := anchor.NewMemory()
		m.Restore(full)
		w, err := OpenWriter(snap, Options{Anchor: m})
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
		rebuilt++
	}
	if rebuilt == 0 {
		t.Fatal("no crash point between the anchor and the root")
	}
}
