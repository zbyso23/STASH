package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"stash/internal/blob"
	"stash/internal/vfs"
	"stash/internal/wire"
)

func checkWriter(t testing.TB, w *Writer, want map[string][]byte) {
	t.Helper()
	if got := w.List(); len(got) != len(want) {
		t.Fatalf("%d paths, want %d", len(got), len(want))
	}
	checkAll(t, w.Get, want)
}

// workload writes large, small and empty objects, overwrites some and
// deletes others; it returns the live content.
func workload(t testing.TB, w *Writer, seed int) map[string][]byte {
	t.Helper()
	want := map[string][]byte{}
	put := func(p string, d []byte) {
		if _, err := w.Put(p, d); err != nil {
			t.Fatal(err)
		}
		want[p] = d
	}
	for i := 0; i < 40; i++ {
		n := []int{0, 7, 900, 3000, 70001, 20000}[i%6]
		put(fmt.Sprintf("o/%02d", i), data(seed*1000+i, n))
	}
	var wg sync.WaitGroup // concurrent small Puts land in shared PACKED frames
	var mu sync.Mutex
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, d := fmt.Sprintf("s/%02d", i), data(seed*1000+500+i, 100+i*20)
			if _, err := w.Put(p, d); err != nil {
				t.Error(err)
			}
			mu.Lock()
			want[p] = d
			mu.Unlock()
		}()
	}
	wg.Wait()
	for i := 0; i < 40; i += 3 {
		put(fmt.Sprintf("o/%02d", i), data(seed*1000+100+i, 9000))
	}
	for i := 1; i < 40; i += 4 {
		p := fmt.Sprintf("o/%02d", i)
		if err := w.Delete(p); err != nil {
			t.Fatal(err)
		}
		delete(want, p)
	}
	for i := 0; i < 60; i += 2 {
		p := fmt.Sprintf("s/%02d", i)
		w.Delete(p)
		delete(want, p)
	}
	return want
}

var compactCases = []struct {
	name string
	cfg  Config
}{
	{"plain", Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16}},
	{"plain_fixed", Config{Mode: wire.ModeFixed, HashID: wire.HashBLAKE3, BlobCount: 2, MaxFrameQuanta: 4}},
	{"xor_k3", parityCfg(wire.ParityXOR, 3, 1, 4, wire.ModeVariable)},
	{"rs_k3_m2", parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable)},
	{"rs_k2_m2_fixed", parityCfg(wire.ParityRS, 2, 2, 4, wire.ModeFixed)},
}

func TestCompact(t *testing.T) {
	ctx := context.Background()
	for _, tc := range compactCases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := vfs.NewCrashFS()
			if _, err := Create(fsys, tc.cfg); err != nil {
				t.Fatal(err)
			}
			w := mustOpen(t, fsys)
			want := workload(t, w, 1)
			obj, err := w.Open("o/03") // stays readable across the switch
			if err != nil {
				t.Fatal(err)
			}
			partly := hasPartlyDeadPacked(w, want)
			res, err := w.Compact(ctx, CompactOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%+v", res)
			if res.From != 0 || res.To == 0 || res.Versions != len(want) || res.DestBytes >= res.SourceBytes {
				t.Fatalf("%+v", res)
			}
			if partly && res.RepackedObjects == 0 {
				t.Fatal("partly dead PACKED frames were not repacked")
			}
			checkWriter(t, w, want)
			got := make([]byte, len(want["o/03"]))
			if _, err := obj.ReadAt(got, 0); err != nil || !bytes.Equal(got, want["o/03"]) {
				t.Fatalf("object across switch: %v", err)
			}
			if gens, _ := generations(fsys); len(gens) != 2 {
				t.Fatalf("old generation removed while an object used it: %v", gens)
			}
			obj.Close()
			if removed, err := w.GC(); err != nil || len(removed) != 1 || removed[0] != 0 {
				t.Fatalf("GC %v %v", removed, err)
			}
			// writes continue in the new generation
			want["after"] = data(9, 30000)
			if _, err := w.Put("after", want["after"]); err != nil {
				t.Fatal(err)
			}
			rep, err := w.Verify(ctx)
			if err != nil || !rep.OK() {
				t.Fatalf("verify %v %+v", err, rep)
			}
			w.Close()
			w = mustOpen(t, fsys)
			if h := w.Health(); len(h.Sealed)+len(h.TornBlobBytes) != 0 {
				t.Fatalf("health %+v", h)
			}
			checkWriter(t, w, want)
			// a second compaction of an already compact generation
			res2, err := w.Compact(ctx, CompactOptions{})
			if err != nil || res2.RewrittenFrames != 0 || res2.RepackedObjects != 0 || res2.RecomputedParity != 0 {
				t.Fatalf("second %v %+v", err, res2)
			}
			checkWriter(t, w, want)
			w.Close()
			r, err := OpenReader(fsys, nil)
			if err != nil {
				t.Fatal(err)
			}
			checkAll(t, r.Get, want)
			r.Close()
		})
	}
}

// Damaged and lost members are rebuilt and copied, lost PARITY frames
// recomputed; sealed blobs are writable again afterwards.
func TestCompactRepairs(t *testing.T) {
	ctx := context.Background()
	for _, tc := range compactCases[2:] {
		t.Run(tc.name, func(t *testing.T) {
			fsys := vfs.NewCrashFS()
			if _, err := Create(fsys, tc.cfg); err != nil {
				t.Fatal(err)
			}
			w := mustOpen(t, fsys)
			want := workload(t, w, 2)
			w.Close()
			groups, _ := groupsOf(t, fsys)
			hitData, hitParity := 0, 0
			for _, ms := range groups {
				for _, mem := range ms { // one member per group
					damage(t, fsys, blobFile(int(mem.blob)), mem.off+16, 4)
					if mem.t.BlockType == wire.BlockParity {
						hitParity++
					} else {
						hitData++
					}
					break
				}
			}
			dropCheckpoints(t, fsys)
			w = mustOpen(t, fsys)
			if len(w.Health().Sealed) == 0 {
				t.Fatal("nothing sealed")
			}
			res, err := w.Compact(ctx, CompactOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("damaged %d data %d parity: %+v", hitData, hitParity, res)
			if res.RebuiltFrames+res.RewrittenFrames == 0 {
				t.Fatalf("%+v", res)
			}
			if len(w.Health().Sealed) != 0 {
				t.Fatal("still sealed")
			}
			checkWriter(t, w, want)
			rep, err := w.Verify(ctx)
			if err != nil || !rep.OK() {
				t.Fatalf("verify %v %+v %+v", err, rep.Groups, rep.Blobs)
			}
			w.Close()
		})
	}
}

// A lost blob file: the writer opens without it, and compaction rebuilds
// every frame it held into the new generation.
func TestCompactLostBlob(t *testing.T) {
	for _, tc := range compactCases[2:] {
		fsys := vfs.NewCrashFS()
		Create(fsys, tc.cfg)
		w := mustOpen(t, fsys)
		want := workload(t, w, 3)
		w.Close()
		fsys.Remove(blobFile(1))
		w = mustOpen(t, fsys)
		if w.Health().Sealed[1] == nil {
			t.Fatalf("%s: %+v", tc.name, w.Health())
		}
		checkWriter(t, w, want)
		res, err := w.Compact(context.Background(), CompactOptions{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.RebuiltFrames+res.RewrittenFrames+res.RepackedObjects == 0 || len(w.Health().Sealed) != 0 {
			t.Fatalf("%s: %+v", tc.name, res)
		}
		checkWriter(t, w, want)
		if rep, err := w.Verify(context.Background()); err != nil || !rep.OK() {
			t.Fatalf("%s: verify %v %+v", tc.name, err, rep.Groups)
		}
		w.Close()
	}
}

// Writes during the Sweep are merged at the freeze (§13.4).
func TestCompactConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []int{0, 3} {
		fsys := vfs.NewCrashFS()
		Create(fsys, compactCases[tc].cfg)
		w := mustOpen(t, fsys)
		want := workload(t, w, 4)
		var mu sync.Mutex
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rng := rand.New(rand.NewSource(int64(g)))
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					p := fmt.Sprintf("c/%d/%d", g, rng.Intn(20))
					if rng.Intn(4) == 0 {
						if err := w.Delete(p); err == nil {
							mu.Lock()
							delete(want, p)
							mu.Unlock()
						} else if !errors.Is(err, ErrNotFound) {
							t.Error(err)
							return
						}
						continue
					}
					d := data(g*100000+i, rng.Intn(30000))
					if _, err := w.Put(p, d); err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					want[p] = d
					mu.Unlock()
				}
			}()
		}
		var res CompactResult
		var err error
		for i := 0; i < 3 && err == nil; i++ {
			res, err = w.Compact(ctx, CompactOptions{})
		}
		close(stop)
		wg.Wait()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%+v", res)
		checkWriter(t, w, want)
		w.Close()
		w = mustOpen(t, fsys)
		checkWriter(t, w, want)
		w.Close()
	}
}

// Without parity a damaged committed frame blocks the compaction; nothing
// is switched and the aborted attempt is removed.
func TestCompactMissingDataBlocks(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	w.Put("x", data(1, 100000))
	w.Put("y", data(2, 100))
	v, _ := w.Stat("x")
	recs := w.blobs[v.Loc[2].Blob].idx.Lookup(v.Loc[2].Hash)
	w.Close()
	damage(t, fsys, blobFile(int(v.Loc[2].Blob)), int64(recs[0].PhysicalOffset)+16, 2)
	w = mustOpen(t, fsys)
	defer w.Close()
	if _, err := w.Compact(context.Background(), CompactOptions{}); !errors.Is(err, ErrMissingData) {
		t.Fatal(err)
	}
	if root, _ := readRoot(fsys); root.GenerationID != 0 {
		t.Fatal("switched")
	}
	if gens, _ := generations(fsys); len(gens) != 1 {
		t.Fatalf("aborted attempt left: %v", gens)
	}
	if got, err := w.Get("y"); err != nil || !bytes.Equal(got, data(2, 100)) {
		t.Fatal(err)
	}
}

// A pinned reader keeps its generation until it closes (§13.1.1).
func TestCompactPins(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	want := workload(t, w, 5)
	r, err := OpenReaderPinned(fsys, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.Compact(context.Background(), CompactOptions{})
	if err != nil || len(res.Removed) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	checkAll(t, r.Get, want)
	r.Close()
	if removed, err := w.GC(); err != nil || len(removed) != 1 {
		t.Fatalf("%v %v", removed, err)
	}
	w.Close()
}

// A crash at any step of a compaction leaves either the old or the new
// generation authoritative, with every live version intact.
func TestCompactCrash(t *testing.T) {
	for _, tc := range []int{0, 3} {
		base := vfs.NewCrashFS()
		Create(base, compactCases[tc].cfg)
		w := mustOpen(t, base)
		want := workload(t, w, 6)
		w.Close()
		s := &snapFS{CrashFS: base, rng: rand.New(rand.NewSource(int64(tc))), every: 3}
		w, err := OpenWriter(s, Options{MaxExtent: 8192})
		if err != nil {
			t.Fatal(err)
		}
		start := s.count()
		if _, err := w.Compact(context.Background(), CompactOptions{}); err != nil {
			t.Fatal(err)
		}
		w.Close()
		olds, news := 0, 0
		for k, snap := range s.snaps[start:] {
			w2, err := OpenWriter(snap, Options{MaxExtent: 8192})
			if err != nil {
				t.Fatalf("case %d snapshot %d: %v", tc, k, err)
			}
			if w2.h.GenerationID == 0 {
				olds++
			} else {
				news++
			}
			checkWriter(t, w2, want)
			if _, err := w2.GC(); err != nil {
				t.Fatal(err)
			}
			if gens, _ := generations(snap); len(gens) != 1 {
				t.Fatalf("after GC %v", gens)
			}
			if _, err := w2.Put("next", data(1, 5000)); err != nil {
				t.Fatal(err)
			}
			w2.Close()
		}
		t.Logf("case %d: %d crash points, %d old, %d new", tc, len(s.snaps)-start, olds, news)
		if olds == 0 || news == 0 {
			t.Fatal("crash points did not cover both sides of the switch")
		}
	}
}

// A packed parity group with a dead member: the live members are
// rewritten into new groups (§13.7.1) and the dead one is dropped.
func TestCompactRegroup(t *testing.T) {
	fsys := vfs.NewCrashFS()
	Create(fsys, parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable))
	w := mustOpen(t, fsys)
	defer w.Close()
	want := map[string][]byte{}
	var batch []*commitReq
	for i := 0; i < 30; i++ {
		p := fmt.Sprintf("p/%02d", i)
		ver, _ := w.verAlloc.Next()
		want[p] = data(i, 6000)
		batch = append(batch, &commitReq{path: p, fileVer: ver, pack: true, small: want[p]})
	}
	w.writePacked(batch) // one batch: frames in groups of 3
	for _, r := range batch {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if err := w.commit(r); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		p := fmt.Sprintf("p/%02d", i)
		w.Delete(p)
		delete(want, p)
	}
	res, err := w.Compact(context.Background(), CompactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", res)
	if res.RewrittenFrames == 0 || res.DestBytes >= res.SourceBytes {
		t.Fatalf("%+v", res)
	}
	checkWriter(t, w, want)
	if rep, err := w.Verify(context.Background()); err != nil || !rep.OK() {
		t.Fatalf("%v %+v", err, rep.Groups)
	}
}

// hasPartlyDeadPacked reports whether a PACKED frame holds live and dead
// objects (how the group commit batches small Puts depends on timing).
func hasPartlyDeadPacked(w *Writer, want map[string][]byte) bool {
	found := false
	for _, bv := range w.blobs {
		if bv == nil {
			continue
		}
		bv.r.Hop(func(f blob.HopFrame) error {
			if f.Trailer.BlockType != wire.BlockPacked {
				return nil
			}
			live := 0
			for _, e := range f.Entries {
				if _, ok := want[e.Path]; ok {
					live++
				}
			}
			found = found || (live > 0 && live < len(f.Entries))
			return nil
		})
	}
	return found
}
