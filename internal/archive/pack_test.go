package archive

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// frameKinds hops every blob and counts frames by block type, and the
// entry counts of PACKED frames.
func frameKinds(t testing.TB, fsys vfs.FS) (map[wire.BlockType]int, []int) {
	t.Helper()
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	d := r.dir()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := r.refresh(d); err != nil {
		t.Fatal(err)
	}
	kinds := map[wire.BlockType]int{}
	var packed []int
	seen := map[*hopMember]bool{}
	for _, ms := range d.groups {
		for _, m := range ms {
			if m.t.BlockType == wire.BlockParity {
				kinds[wire.BlockParity]++
			}
		}
	}
	for _, ms := range d.byHash {
		for _, m := range ms {
			if seen[m] {
				continue
			}
			seen[m] = true
			kinds[m.t.BlockType]++
			if m.t.BlockType == wire.BlockPacked {
				packed = append(packed, len(m.entries))
			}
		}
	}
	return kinds, packed
}

// Concurrent small Puts share PACKED frames; everything reads back through
// Get, lazy objects, a reader and after reopening.
func TestPackedConcurrent(t *testing.T) {
	for _, c := range []Config{cfg, parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable), parityCfg(wire.ParityXOR, 2, 1, 3, wire.ModeFixed)} {
		fsys := vfs.NewCrashFS()
		if _, err := Create(fsys, c); err != nil {
			t.Fatal(err)
		}
		w := mustOpen(t, fsys)
		want := map[string][]byte{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for g := 0; g < 16; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					p := fmt.Sprintf("d%02d/f%03d", g, i)
					d := data(g*1000+i, (g*37+i*101)%3000)
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
		wg.Wait()
		checkAll(t, w.Get, want)
		for p, d := range want {
			o, err := w.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(d)+1)
			n, _ := o.ReadAt(got, 0)
			o.Close()
			if !bytes.Equal(got[:n], d) {
				t.Fatalf("object %s", p)
			}
		}
		w.Close()
		kinds, packed := frameKinds(t, fsys)
		if kinds[wire.BlockData] != 0 || kinds[wire.BlockPacked] == 0 {
			t.Fatalf("frames %v", kinds)
		}
		multi := 0
		for _, n := range packed {
			if n > 1 {
				multi++
			}
		}
		if multi == 0 {
			t.Fatalf("no PACKED frame holds more than one object: %v", packed)
		}
		r, err := OpenReader(fsys, nil)
		if err != nil {
			t.Fatal(err)
		}
		checkAll(t, r.Get, want)
		r.Close()
		w = mustOpen(t, fsys)
		checkAll(t, w.Get, want)
		w.Close()
		t.Logf("%v: %d objects in %d PACKED frames, %d parity frames", c.ParityScheme, len(want), len(packed), kinds[wire.BlockParity])
	}
}

// The threshold routes objects: up to PackThreshold PACKED, above it DATA;
// a negative threshold disables packing; Put and PutReader agree.
func TestPackThreshold(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w, err := OpenWriter(fsys, Options{MaxExtent: 8192, PackThreshold: 5000})
	if err != nil {
		t.Fatal(err)
	}
	w.Put("a", data(1, 5000))
	w.PutReader(t.Context(), "b", bytes.NewReader(data(2, 5000)))
	w.Put("c", data(3, 5001))
	w.PutReader(t.Context(), "d", bytes.NewReader(data(4, 5001)))
	w.Put("e", nil)
	w.Close()
	kinds, _ := frameKinds(t, fsys)
	if kinds[wire.BlockPacked] != 3 || kinds[wire.BlockData] != 2 {
		t.Fatalf("frames %v", kinds)
	}
	w, err = OpenWriter(fsys, Options{PackThreshold: -1})
	if err != nil {
		t.Fatal(err)
	}
	w.Put("f", data(5, 10))
	if got, err := w.Get("e"); err != nil || len(got) != 0 {
		t.Fatalf("empty packed object: %v", err)
	}
	w.Close()
	kinds, _ = frameKinds(t, fsys)
	if kinds[wire.BlockData] != 3 {
		t.Fatalf("packing not disabled: %v", kinds)
	}
	// the threshold never exceeds what an empty frame holds (§8)
	w = mustOpen(t, fsys)
	defer w.Close()
	if m := w.packMax("x"); m > int(w.h.MaxFrameSize()) || m > DefaultPackThreshold {
		t.Fatalf("packMax %d", m)
	}
	small := Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 1, MaxFrameQuanta: 2}
	f2 := vfs.NewCrashFS()
	Create(f2, small)
	w2 := mustOpen(t, f2)
	defer w2.Close()
	if m := w2.packMax("x"); m != 8192-116-8-entrySize("x") {
		t.Fatalf("packMax in an 8 KiB frame: %d", m)
	}
	if _, err := w2.Put("x", data(9, w2.packMax("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Put("y", data(9, w2.packMax("y")+1)); err != nil { // routed to DATA extents
		t.Fatal(err)
	}
}

// One batch with more objects than MAX_PACKED_ENTRIES needs several
// frames; each holds at most 65535 entries in path order.
func TestPackedEntryLimit(t *testing.T) {
	fsys := vfs.NewCrashFS()
	big := Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 2, MaxFrameQuanta: 1024}
	if _, err := Create(fsys, big); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, fsys)
	const n = wire.MaxPackedEntries + 10
	batch := make([]*commitReq, n)
	for i := range batch {
		batch[i] = &commitReq{path: fmt.Sprintf("e%06d", n-i), fileVer: uint64(i + 1), pack: true, small: []byte{byte(i)}}
	}
	w.writePacked(batch)
	frames := map[[32]byte]int{}
	for _, r := range batch {
		if r.err != nil {
			t.Fatal(r.err)
		}
		frames[r.locs[0].Hash]++
	}
	w.Close()
	if len(frames) < 2 {
		t.Fatalf("%d frames", len(frames))
	}
	for _, c := range frames {
		if c > wire.MaxPackedEntries {
			t.Fatalf("frame with %d entries", c)
		}
	}
	_, packed := frameKinds(t, fsys)
	total := 0
	for _, c := range packed {
		total += c
	}
	if total != n {
		t.Fatalf("%d entries on disk", total)
	}
}

// Crash at every mutating step while concurrent writers commit packed
// objects (with parity): every returned Put is durable, nothing is sealed.
func TestCrashDuringPacking(t *testing.T) {
	for _, c := range []Config{cfg, parityCfg(wire.ParityRS, 2, 2, 4, wire.ModeVariable)} {
		base := vfs.NewCrashFS()
		if _, err := Create(base, c); err != nil {
			t.Fatal(err)
		}
		s := &snapFS{CrashFS: base, rng: rand.New(rand.NewSource(int64(c.ParityScheme)))}
		w := mustOpen(t, s)
		type done struct {
			data []byte
			at   int
		}
		const G, N = 5, 8
		hist := make([][]done, G)
		var wg sync.WaitGroup
		for g := 0; g < G; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < N; i++ {
					d := data(g*100+i, 100+i*700)
					if _, err := w.Put(fmt.Sprintf("g%d", g), d); err != nil {
						t.Error(err)
						return
					}
					hist[g] = append(hist[g], done{d, s.count()})
				}
			}()
		}
		wg.Wait()
		w.Close()
		for k, snap := range s.snaps {
			w2, err := OpenWriter(snap, Options{MaxExtent: 8192})
			if err != nil {
				t.Fatalf("snapshot %d: %v", k, err)
			}
			if len(w2.Health().Sealed) != 0 {
				t.Fatalf("snapshot %d: sealed %v", k, w2.Health().Sealed)
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
					t.Fatalf("snapshot %d g%d: %v", k, g, err)
				}
			}
			if _, err := w2.Put("after", data(1, 500)); err != nil {
				t.Fatalf("snapshot %d: %v", k, err)
			}
			w2.Close()
		}
		t.Logf("parity %d: %d crash points", c.ParityScheme, len(s.snaps))
	}
}
