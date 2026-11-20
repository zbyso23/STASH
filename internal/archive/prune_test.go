package archive

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"stash/internal/anchor"
	"stash/internal/vfs"
	"stash/internal/wire"
)

var operator = EmergencyPrune{Operator: "ops@test", Reason: "blob 2 sector loss, no replica", Time: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}

// blockedCount runs a plain compaction that must fail as GC-blocked and
// returns the number of extents it reported.
func blockedCount(t testing.TB, w *Writer) int {
	t.Helper()
	_, err := w.Compact(context.Background(), CompactOptions{})
	var be *GCBlockedError
	if !errors.As(err, &be) || !errors.Is(err, ErrMissingData) {
		t.Fatalf("compaction not GC-blocked: %v", err)
	}
	return be.Extents
}

func prune(n int) *EmergencyPrune {
	p := operator
	p.ExpectLostExtents = n
	return &p
}

// damageExtent damages the frame holding extent i of path p.
func damageExtent(t testing.TB, fsys vfs.FS, w *Writer, p string, i int) {
	t.Helper()
	v, err := w.Stat(p)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	l := v.Loc[i]
	recs := w.blobs[l.Blob].idx.Lookup(l.Hash)
	damage(t, fsys, blobFile(int(l.Blob)), int64(recs[0].PhysicalOffset)+16, 2)
}

func details(t testing.TB, w *Writer, rec string) map[string][]PruneDetail {
	t.Helper()
	out := map[string][]PruneDetail{}
	if err := w.PruneDetails(rec, func(d PruneDetail) error {
		out[d.Kind] = append(out[d.Kind], d)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEmergencyPrune(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	w.Put("x", data(1, 100000))
	w.Put("y", data(2, 100))
	w.Put("z", data(3, 30000))
	w.Delete("y")
	w.Put("y", data(4, 200))
	damageExtent(t, fsys, w, "x", 2)
	w.Close()

	w = mustOpen(t, fsys)
	n := blockedCount(t, w)
	if n != 1 {
		t.Fatalf("blocked on %d extents", n)
	}
	ctx := context.Background()
	// refused: no authorization, a wrong count, no reason
	for _, p := range []*EmergencyPrune{prune(0), prune(n + 1), {Operator: "ops", ExpectLostExtents: n}} {
		if _, err := w.Compact(ctx, CompactOptions{EmergencyPrune: p}); !errors.Is(err, ErrPruneRefused) {
			t.Fatalf("%+v: %v", p, err)
		}
	}
	if gens, _ := generations(fsys); len(gens) != 1 {
		t.Fatalf("refused prune left %v", gens)
	}
	if ents, _ := fsys.ReadDir(HealthDir); len(ents) != 0 {
		t.Fatalf("refused prune left a record: %v", ents)
	}

	res, err := w.Compact(ctx, CompactOptions{EmergencyPrune: prune(n)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Prune == nil || res.Prune.LostExtents != 1 || res.Prune.LostVersions != 1 || len(res.Removed) != 1 {
		t.Fatalf("result %+v %+v", res, res.Prune)
	}
	if _, err := w.Get("x"); !isLost(err) {
		t.Fatalf("x after prune: %v", err)
	}
	checkAll(t, w.Get, map[string][]byte{"y": data(4, 200), "z": data(3, 30000)})
	if w.Health().PruneRecords != 1 {
		t.Fatalf("health %+v", w.Health())
	}
	recs, foreign, err := w.PruneRecords()
	if err != nil || len(recs) != 1 || len(foreign) != 0 {
		t.Fatalf("records %+v %v %v", recs, foreign, err)
	}
	r := recs[0]
	if !r.Committed || r.From != res.From || r.To != res.To || r.Operator != operator.Operator || r.Reason != operator.Reason ||
		!r.Time.Equal(operator.Time) || r.LostExtents != 1 || r.Sealed {
		t.Fatalf("record %+v", r)
	}
	d := details(t, w, r.Record)
	if len(d["extent"]) != 1 || d["extent"][0].Path != "x" || len(d["object"]) != 1 || d["object"][0].Status != "UNRECOVERABLE" {
		t.Fatalf("details %+v", d)
	}
	rep, err := w.Verify(ctx)
	if err != nil || rep.FailedCount != 0 || rep.Versions != 2 {
		t.Fatalf("verify %+v %v", rep, err)
	}
	// the archive is ordinary again: writes, a normal compaction, reopen
	w.Put("x", data(5, 7000))
	if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	w = mustOpen(t, fsys)
	defer w.Close()
	checkAll(t, w.Get, map[string][]byte{"x": data(5, 7000), "y": data(4, 200), "z": data(3, 30000)})
	if h := w.Health(); h.PruneRecords != 1 || len(h.ForeignHealth) != 0 {
		t.Fatalf("health after reopen %+v", h)
	}

	// a tampered record is reported as damaged, never read
	f, _ := fsys.OpenFile(r.Record, os.O_RDWR, 0)
	f.WriteAt([]byte("X"), 40)
	f.Close()
	if _, _, err := w.PruneRecords(); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatalf("tampered record: %v", err)
	}
}

// With parity, a group that lost more members than it can rebuild is
// UNRECOVERABLE; its surviving live members go to new, fully protected
// groups, and the destination's parity is healthy (§13.9 steps 3-5).
func TestEmergencyPruneParityImpact(t *testing.T) {
	fsys := vfs.NewCrashFS()
	if _, err := Create(fsys, parityCfg(wire.ParityXOR, 2, 1, 3, wire.ModeVariable)); err != nil {
		t.Fatal(err)
	}
	want := writeObjects(t, fsys, 4)
	fsys.Remove(blobFile(0))
	fsys.Remove(blobFile(1))
	w := mustOpen(t, fsys)
	defer w.Close()
	n := blockedCount(t, w)
	res, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(n)})
	if err != nil {
		t.Fatal(err)
	}
	p := res.Prune
	if p.LostExtents != n || p.UnrecoverableGroups == 0 || len(p.UnavailableBlobs) != 2 {
		t.Fatalf("report %+v", p)
	}
	d := details(t, w, p.Record)
	lost := map[string]bool{}
	for _, o := range d["object"] {
		lost[o.Path] = true
	}
	for _, g := range d["group"] {
		if g.Status == "UNRECOVERABLE" && (g.Dest != "REGROUPED" || g.Present >= g.K+g.M) {
			t.Fatalf("group %+v", g)
		}
	}
	kept := 0
	for pth, b := range want {
		got, err := w.Get(pth)
		switch {
		case lost[pth]:
			if !isLost(err) {
				t.Fatalf("%s lost but %v", pth, err)
			}
		case err != nil || !bytes.Equal(got, b):
			t.Fatalf("%s: %v", pth, err)
		default:
			kept++
		}
	}
	if len(lost) == 0 || kept == 0 {
		t.Fatalf("lost %d kept %d", len(lost), kept)
	}
	rep, err := w.Verify(context.Background())
	if err != nil || rep.FailedCount != 0 || rep.Groups.Healthy != rep.Groups.Total {
		t.Fatalf("verify %+v %v", rep, err)
	}
}

// In an encrypted archive the record names no path in the clear.
func TestEmergencyPruneEncrypted(t *testing.T) {
	fsys := vfs.NewCrashFS()
	c := cfg
	c.Key = testKey
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	w := eopen(t, fsys, testKey)
	w.Put("secret/plan-x", data(1, 100000))
	w.Put("other", data(2, 100))
	damageExtent(t, fsys, w, "secret/plan-x", 1)
	w.Close()
	w = eopen(t, fsys, testKey)
	defer w.Close()
	n := blockedCount(t, w)
	res, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(n)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vfs.ReadFile(fsys, res.Prune.Record, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte(operator.Reason)) {
		t.Fatal("record leaks plaintext")
	}
	d := details(t, w, res.Prune.Record)
	if len(d["object"]) != 1 || d["object"][0].Path != "secret/plan-x" {
		t.Fatalf("details %+v", d)
	}
	recs, _, err := w.PruneRecords()
	if err != nil || len(recs) != 1 || recs[0].Reason != operator.Reason {
		t.Fatalf("%+v %v", recs, err)
	}
}

// Health metadata of another implementation makes parity protection
// unknown: it is reported, never ignored (§13.9).
func TestForeignHealth(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	fsys.MkdirAll(HealthDir, 0o755)
	vfs.ReplaceFile(fsys, HealthDir+"/other-impl.state", []byte("{}"))
	w := mustOpen(t, fsys)
	defer w.Close()
	if h := w.Health(); len(h.ForeignHealth) != 1 || h.ForeignHealth[0] != "other-impl.state" {
		t.Fatalf("%+v", h)
	}
}

// Crash points through an Emergency Pruning: every state opens; before the
// switch nothing is lost and no committed record exists, after it the
// record is committed and the lost version is gone, never the reverse.
func TestEmergencyPruneCrash(t *testing.T) {
	base := vfs.NewCrashFS()
	if _, err := Create(base, cfg); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, base)
	want := map[string][]byte{}
	for i := 0; i < 12; i++ {
		p := "obj/" + string(rune('a'+i))
		want[p] = data(10+i, 3000+i*4000)
		w.Put(p, want[p])
	}
	damageExtent(t, base, w, "obj/k", 0)
	w.Close()
	w = mustOpen(t, base)
	n := blockedCount(t, w)
	w.Close()

	s := &snapFS{CrashFS: base, rng: rand.New(rand.NewSource(7)), every: 2}
	w, err := OpenWriter(s, Options{MaxExtent: 8192})
	if err != nil {
		t.Fatal(err)
	}
	start := s.count()
	if _, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(n)}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	before, after := 0, 0
	for i, snap := range s.snaps[start:] {
		w2, err := OpenWriter(snap, Options{MaxExtent: 8192})
		if err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
		recs, _, err := w2.PruneRecords()
		if err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
		ents, _ := snap.ReadDir(HealthDir)
		for _, e := range ents {
			if strings.Contains(e.Name(), "prepared") {
				t.Fatalf("snapshot %d: unsettled %s", i, e.Name())
			}
		}
		if w2.h.GenerationID == 0 {
			before++
			if len(recs) != 0 || w2.Health().PruneRecords != 0 {
				t.Fatalf("snapshot %d: record before the switch %+v", i, recs)
			}
			if _, err := w2.Stat("obj/k"); err != nil {
				t.Fatalf("snapshot %d: obj/k gone before the switch", i)
			}
		} else {
			after++
			if len(recs) != 1 || !recs[0].Committed || recs[0].To != w2.h.GenerationID {
				t.Fatalf("snapshot %d: records %+v", i, recs)
			}
			if _, err := w2.Get("obj/k"); !isLost(err) {
				t.Fatalf("snapshot %d: obj/k %v", i, err)
			}
		}
		for p, b := range want {
			if p == "obj/k" {
				continue
			}
			if got, err := w2.Get(p); err != nil || !bytes.Equal(got, b) {
				t.Fatalf("snapshot %d: %s: %v", i, p, err)
			}
		}
		w2.Close()
	}
	t.Logf("%d crash points: %d before the switch, %d after", len(s.snaps)-start, before, after)
	if before == 0 || after == 0 {
		t.Fatal("crash points did not cover both sides of the switch")
	}
}

// HARDENED: the prune's switch advances the anchor like any compaction,
// and the pruned archive reopens against it.
func TestEmergencyPruneHardened(t *testing.T) {
	a := anchor.NewMemory()
	fsys := vfs.NewCrashFS()
	if _, err := Create(fsys, hcfg(a)); err != nil {
		t.Fatal(err)
	}
	w := hopen(t, fsys, a)
	w.Put("x", data(1, 100000))
	w.Put("y", data(2, 100))
	damageExtent(t, fsys, w, "x", 0)
	w.Close()
	w = hopen(t, fsys, a)
	n := blockedCount(t, w)
	res, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(n)})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if anchoredOf(t, a).GenerationID != res.To {
		t.Fatal("anchor not advanced")
	}
	r, err := OpenReaderWith(fsys, ReaderOptions{Anchor: a})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Get("x"); !isLost(err) {
		t.Fatal(err)
	}
	if recs, _, err := r.PruneRecords(); err != nil || len(recs) != 1 || !recs[0].Committed {
		t.Fatalf("%+v %v", recs, err)
	}
}

// Nothing lost: an authorized prune is refused and changes nothing.
func TestEmergencyPruneNothingLost(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	defer w.Close()
	w.Put("x", data(1, 50000))
	if _, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(1)}); !errors.Is(err, ErrPruneRefused) {
		t.Fatal(err)
	}
	if root, _ := readRoot(fsys); root.GenerationID != 0 {
		t.Fatal("switched")
	}
	if ents, _ := fsys.ReadDir(HealthDir); len(ents) != 0 {
		t.Fatalf("record left: %v", ents)
	}
	checkAll(t, w.Get, map[string][]byte{"x": data(1, 50000)})
}

// isLost: the error of a pruned path is UNRECOVERABLE and missing data,
// never "not found" (a sync tool must not take it for a deletion).
func isLost(err error) bool {
	var u *UnrecoverableError
	return errors.As(err, &u) && errors.Is(err, ErrUnrecoverable) && errors.Is(err, ErrMissingData) && !errors.Is(err, ErrNotFound)
}

func pruneOne(t *testing.T, key []byte, lose ...string) (*vfs.CrashFS, CompactResult) {
	t.Helper()
	fsys := vfs.NewCrashFS()
	c := cfg
	c.Key = key
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	w := eopen(t, fsys, key)
	for i, p := range []string{"a", "b", "c", "d"} {
		w.Put(p, data(20+i, 70000))
	}
	for _, p := range lose {
		damageExtent(t, fsys, w, p, 0)
	}
	w.Close()
	w = eopen(t, fsys, key)
	defer w.Close()
	res, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(blockedCount(t, w))})
	if err != nil {
		t.Fatal(err)
	}
	return fsys, res
}

// The marker lifecycle: a Put shadows it, a Delete clears it durably, a
// normal compaction carries standing markers and drops cleared ones.
func TestUnrecoverableMarkers(t *testing.T) {
	for _, key := range [][]byte{nil, testKey} {
		fsys, res := pruneOne(t, key, "a", "b", "c")
		w := eopen(t, fsys, key)
		ctx := context.Background()
		for _, p := range []string{"a", "b", "c"} {
			_, err := w.Get(p)
			var u *UnrecoverableError
			if !isLost(err) || !errors.As(err, &u) || u.Path != p || u.PrunedInto != res.To {
				t.Fatalf("%s: %v", p, err)
			}
			if _, err := w.Stat(p); !isLost(err) {
				t.Fatal(err)
			}
			if _, err := w.Open(p); !isLost(err) {
				t.Fatal(err)
			}
		}
		if _, err := w.Get("never"); !errors.Is(err, ErrNotFound) || isLost(err) {
			t.Fatal(err)
		}
		if h := w.Health(); h.Unrecoverable != 3 {
			t.Fatalf("health %+v", h)
		}
		var listed []string
		w.Unrecoverable(func(u UnrecoverableError) bool { listed = append(listed, u.Path); return true })
		if strings.Join(listed, ",") != "a,b,c" {
			t.Fatalf("listed %v", listed)
		}
		// a restores from elsewhere; b is acknowledged; c stays lost
		w.Put("a", data(1, 10))
		if err := w.Delete("b"); err != nil {
			t.Fatal(err)
		}
		if err := w.Delete("b"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second delete: %v", err)
		}
		// a written again and then deleted is deleted, not lost
		if err := w.Delete("a"); err != nil {
			t.Fatal(err)
		}
		w.Close()
		for round := 0; round < 2; round++ {
			w = eopen(t, fsys, key)
			for _, p := range []string{"a", "b"} {
				if _, err := w.Get(p); !errors.Is(err, ErrNotFound) || isLost(err) {
					t.Fatalf("round %d %s: %v", round, p, err)
				}
			}
			if _, err := w.Get("c"); !isLost(err) {
				t.Fatalf("round %d c: %v", round, err)
			}
			checkAll(t, w.Get, map[string][]byte{"d": data(23, 70000)})
			if h := w.Health(); h.Unrecoverable != 1 {
				t.Fatalf("round %d health %+v", round, h)
			}
			if round == 0 {
				if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			w.Close()
		}
		ents, _ := fsys.ReadDir(HealthDir)
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		if len(names) != 3 { // the prune record, the current index and log
			t.Fatalf("health files %v", names)
		}
		if key != nil {
			for _, n := range names {
				b, _ := vfs.ReadFile(fsys, HealthDir+"/"+n, 1<<20)
				if bytes.Contains(b, []byte("\x00c\x00")) {
					t.Fatalf("%s names a path", n)
				}
			}
		}
		r, err := OpenReaderWith(fsys, ReaderOptions{Key: key})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Get("c"); !isLost(err) {
			t.Fatal(err)
		}
		r.Close()
	}
}

// A damaged marker index fails the open, never hides a loss.
func TestUnrecoverableIndexDamaged(t *testing.T) {
	fsys, res := pruneOne(t, nil, "a")
	damage(t, fsys, lostIndexName(res.To), 20, 1)
	if _, err := OpenWriter(fsys, Options{}); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := OpenReaderWith(fsys, ReaderOptions{}); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal(err)
	}
}
