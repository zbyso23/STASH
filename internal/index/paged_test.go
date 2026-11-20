package index

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"stash/internal/membudget"
	"stash/internal/memprobe"
	"stash/internal/vfs"
	"stash/internal/wire"
)

func pagedHeader() *wire.ArchiveHeader {
	h := &wire.ArchiveHeader{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 1, MaxFrameQuanta: 16,
		GenerationID: 7, ArchiveID: [32]byte{1, 2, 3}}
	if err := h.Validate(); err != nil {
		panic(err)
	}
	return h
}

func scratchEnv(t testing.TB, delta int, b *membudget.Budget) *Env {
	dir := t.TempDir()
	return &Env{Budget: b, Cache: NewPageCache(b, 64*pageSize), DeltaMax: delta,
		Scratch: func() (vfs.FS, string, error) { return vfs.OS{Root: dir}, "s", nil }}
}

// randRecords returns n records with unique grid offsets and hashes drawn
// from a small pool, so many hashes repeat (payload-identical frames).
func randRecords(rng *rand.Rand, n, hashes int) []wire.IndexRecord {
	perm := rng.Perm(n)
	out := make([]wire.IndexRecord, n)
	for i := range out {
		out[i] = wire.IndexRecord{
			FrameHash:      sha256.Sum256([]byte(strconv.Itoa(rng.Intn(hashes)))),
			PhysicalOffset: uint64(wire.FrameAreaStart + perm[i]*4096),
			FrameQuanta:    1,
			BlockType:      wire.BlockData,
			FrameOrdinal:   uint64(i),
		}
	}
	return out
}

// TestPagedEquivalence: an index that spills to session runs, merges them
// by level, is rewritten and reloaded answers every lookup exactly like
// the plain in-memory index, and writes the byte-identical .idx file.
func TestPagedEquivalence(t *testing.T) {
	h := pagedHeader()
	rng := rand.New(rand.NewSource(1))
	recs := randRecords(rng, 30000, 3000)
	ref := New(nil, h, 0)
	env := scratchEnv(t, 50, nil)
	x := New(env, h, 0)
	for _, r := range recs[:20000] {
		ref.Add(r)
		if err := x.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	if x.Spilled() == 0 || x.Spilled() > 40 {
		t.Fatalf("%d session runs", x.Spilled())
	}
	check := func(stage string) {
		t.Helper()
		for k := 0; k < 3000; k += 7 {
			hh := sha256.Sum256([]byte(strconv.Itoa(k)))
			a, b := ref.Lookup(hh), x.Lookup(hh)
			if !slices.Equal(a, b) {
				t.Fatalf("%s: hash %d: %d candidates, want %d", stage, k, len(b), len(a))
			}
			// the hinted lookup finds exactly the records of this hash
			at := map[uint64]wire.IndexRecord{}
			for _, r := range a {
				at[r.PhysicalOffset] = r
			}
			for _, r := range a {
				for _, off := range []uint64{r.PhysicalOffset, r.PhysicalOffset + 4096, r.PhysicalOffset - 4096} {
					want, in := at[off]
					x.mu.RLock()
					got, ok, err := x.recordAt(hh, off)
					x.mu.RUnlock()
					if err != nil || ok != in || got != want {
						t.Fatalf("%s: hash %d recordAt(%d) = %v %v %v", stage, k, off, ok, err, got)
					}
				}
			}
		}
		if x.End() != ref.End() || x.Len() != ref.Len() {
			t.Fatalf("%s: end %d/%d len %d/%d", stage, x.End(), ref.End(), x.Len(), ref.Len())
		}
		la, _ := ref.Last()
		lb, _ := x.Last()
		if la != lb {
			t.Fatalf("%s: last differs", stage)
		}
	}
	check("spilled")
	c := vfs.NewCrashFS()
	c.MkdirAll("index", 0o755)
	if err := x.Write(c, idxName); err != nil {
		t.Fatal(err)
	}
	if x.Spilled() != 0 {
		t.Fatal("runs kept after Write")
	}
	check("rewritten")
	// more records on top of the stored file, spilled again
	for _, r := range recs[20000:] {
		ref.Add(r)
		x.Add(r)
	}
	check("base+runs+delta")
	c2 := vfs.NewCrashFS()
	c2.MkdirAll("index", 0o755)
	x.Write(c, idxName)
	ref.Write(c2, idxName)
	a, _ := vfs.ReadFile(c, idxName, 1<<30)
	b, _ := vfs.ReadFile(c2, idxName, 1<<30)
	if !bytes.Equal(a, b) {
		t.Fatal("rewritten .idx differs from the in-memory index's file")
	}
	size := int64(wire.FrameAreaStart + 30000*4096)
	y, err := Load(env, c, idxName, h, 0, size, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.Close()
	x = y
	check("reloaded")
	x.Close()
	if ents, _ := os.ReadDir(mustScratch(t, env)); len(ents) != 0 {
		t.Fatalf("session runs left after Close: %d", len(ents))
	}
}

func mustScratch(t *testing.T, env *Env) string {
	fsys, dir, _ := env.Scratch()
	return fsys.(vfs.OS).Root + "/" + dir
}

// writeIdx writes an index file from records already in index order,
// without any check (to plant invalid files).
func writeIdx(t testing.TB, fsys vfs.FS, h *wire.ArchiveHeader, recs func(func(wire.IndexRecord)), n uint64) {
	t.Helper()
	fsys.MkdirAll("index", 0o755)
	hdr := wire.IndexHeader{GenerationID: h.GenerationID, ArchiveID: h.ArchiveID, HashID: h.HashID, RecordCount: n}
	err := vfs.ReplaceFileStream(fsys, idxName, func(w io.Writer) error {
		hb, _ := hdr.AppendBinary(nil)
		w.Write(hb)
		var b [64]byte
		var werr error
		recs(func(r wire.IndexRecord) {
			rb, _ := r.AppendBinary(b[:0])
			if _, err := w.Write(rb); err != nil && werr == nil {
				werr = err
			}
		})
		return werr
	})
	if err != nil {
		t.Fatal(err)
	}
}

// synthetic yields n records in index order: hashes spread evenly and
// increasing, offsets a permutation of the frame grid.
func synthetic(n uint64, dupAt uint64) func(func(wire.IndexRecord)) {
	return func(emit func(wire.IndexRecord)) {
		step := ^uint64(0) / max(n, 1)
		p := uint64(1_000_003) // coprime with the test sizes
		for i := uint64(0); i < n; i++ {
			var hsh [32]byte
			binary.BigEndian.PutUint64(hsh[0:8], i*step)
			binary.BigEndian.PutUint64(hsh[8:16], i)
			slot := (i * p) % n
			if dupAt != 0 && i == dupAt {
				slot = (0 * p) % n // the offset of record 0, far away in hash order
			}
			emit(wire.IndexRecord{FrameHash: hsh, PhysicalOffset: uint64(wire.FrameAreaStart) + slot*4096,
				FrameQuanta: 1, BlockType: wire.BlockData, FrameOrdinal: i})
		}
	}
}

// TestValidationIsComplete: every structural rule of §10.5.1 is checked
// before use, including a duplicated physical offset in distant hash
// groups, also when the offset sort spills to scratch space.
func TestValidationIsComplete(t *testing.T) {
	h := pagedHeader()
	const n = 200_000 // with a 4 MiB budget the offset sort spills
	size := int64(wire.FrameAreaStart + n*4096)
	env := scratchEnv(t, 0, membudget.New(4<<20))
	c := vfs.OS{Root: t.TempDir()}
	writeIdx(t, c, h, synthetic(n, 0), n)
	x, err := Load(env, c, idxName, h, 0, size, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.Close()
	if _, err := os.Stat(mustScratch(t, env)); err != nil {
		t.Fatal("the offset sort did not spill")
	}
	writeIdx(t, c, h, synthetic(n, n-5), n)
	if _, err := Load(env, c, idxName, h, 0, size, nil); !errors.Is(err, ErrDiscard) {
		t.Fatalf("duplicate offset in distant hash groups: %v", err)
	}
	// order violation between the last record of one page and the next
	writeIdx(t, c, h, func(emit func(wire.IndexRecord)) {
		var prev *wire.IndexRecord
		synthetic(n, 0)(func(r wire.IndexRecord) {
			if prev == nil && r.FrameOrdinal == pageRecords-1 {
				p := r
				prev = &p
				return
			}
			emit(r)
			if prev != nil && r.FrameOrdinal == pageRecords {
				emit(*prev)
				prev = nil
			}
		})
	}, n)
	if _, err := Load(env, c, idxName, h, 0, size, nil); !errors.Is(err, ErrDiscard) {
		t.Fatalf("swapped records across a page boundary: %v", err)
	}
	// the record bound is checked before anything is read
	writeIdx(t, c, h, synthetic(n, 0), n)
	if _, err := Load(env, c, idxName, h, 0, size-4096, nil); !errors.Is(err, ErrDiscard) {
		t.Fatalf("frame past the blob end: %v", err)
	}
	if ents, _ := os.ReadDir(mustScratch(t, env)); len(ents) != 0 {
		t.Fatalf("validation left scratch files: %d", len(ents))
	}
}

// TestTamperAfterValidation: bytes changed under an open index are never
// trusted; a lookup that meets them reports no candidate (the caller then
// scans), it never returns a record that fails decoding.
func TestTamperAfterValidation(t *testing.T) {
	h := pagedHeader()
	const n = 5000
	size := int64(wire.FrameAreaStart + n*4096)
	root := t.TempDir()
	c := vfs.OS{Root: root}
	writeIdx(t, c, h, synthetic(n, 0), n)
	x, err := Load(scratchEnv(t, 0, nil), c, idxName, h, 0, size, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	var target wire.IndexRecord
	synthetic(n, 0)(func(r wire.IndexRecord) {
		if r.FrameOrdinal == 1234 {
			target = r
		}
	})
	if got := x.Lookup(target.FrameHash); len(got) != 1 || got[0] != target {
		t.Fatalf("lookup before tamper: %v", got)
	}
	f, _ := os.OpenFile(root+"/"+idxName, os.O_RDWR, 0)
	f.WriteAt([]byte{0xff}, wire.IndexHeaderSize+1234*64+46) // a reserved byte
	f.Close()
	x.env.cache().drop(x.base)
	if got := x.Lookup(target.FrameHash); len(got) != 0 {
		t.Fatalf("tampered record returned: %v", got)
	}
}

// TestConcurrentLookups runs lookups against concurrent Adds that spill
// and merge (run with -race).
func TestConcurrentLookups(t *testing.T) {
	h := pagedHeader()
	rng := rand.New(rand.NewSource(2))
	recs := randRecords(rng, 20000, 20000)
	x := New(scratchEnv(t, 64, nil), h, 0)
	defer x.Close()
	for _, r := range recs[:10000] {
		x.Add(r)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := g; ; i = (i + 13) % 10000 {
				select {
				case <-stop:
					return
				default:
				}
				got := x.Lookup(recs[i].FrameHash)
				if !slices.Contains(got, recs[i]) {
					t.Errorf("record %d not found", i)
					return
				}
			}
		}(g)
	}
	for _, r := range recs[10000:] {
		if err := x.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestPageCacheBounded: the cache never holds more than its pages.
func TestPageCacheBounded(t *testing.T) {
	h := pagedHeader()
	const n = 50_000
	c := vfs.OS{Root: t.TempDir()}
	writeIdx(t, c, h, synthetic(n, 0), n)
	env := scratchEnv(t, 0, nil)
	x, err := Load(env, c, idxName, h, 0, int64(wire.FrameAreaStart+n*4096), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 20000; i++ {
		var hsh [32]byte
		k := uint64(rng.Int63n(n))
		binary.BigEndian.PutUint64(hsh[0:8], k*(^uint64(0)/n))
		binary.BigEndian.PutUint64(hsh[8:16], k)
		if len(x.Lookup(hsh)) != 1 {
			t.Fatalf("record %d not found", k)
		}
	}
	env.Cache.mu.Lock()
	held, limit := env.Cache.lru.Len(), env.Cache.max
	env.Cache.mu.Unlock()
	if held > limit {
		t.Fatalf("cache holds %d pages, limit %d", held, limit)
	}
}

// TestIndexScale builds a synthetic stored index and measures what an
// open index keeps in memory and what a lookup costs. The retained heap
// may not grow with the record count. STASH_INDEX_SCALE=100000000 runs the
// 10^8-record (6.4 GB) case; STASH_INDEX_DIR places the file.
func TestIndexScale(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	sizes := []uint64{200_000, 2_000_000}
	if v, err := strconv.ParseUint(os.Getenv("STASH_INDEX_SCALE"), 10, 64); err == nil && v > 0 {
		sizes = []uint64{v / 10, v}
	}
	var kept []float64
	for _, n := range sizes {
		dir := os.Getenv("STASH_INDEX_DIR")
		if dir == "" {
			dir = t.TempDir()
		} else {
			dir, _ = os.MkdirTemp(dir, "scale-")
			defer os.RemoveAll(dir)
		}
		c := vfs.OS{Root: dir}
		h := pagedHeader()
		start := time.Now()
		writeIdx(t, c, h, synthetic(n, 0), n)
		built := time.Since(start)
		b := membudget.New(256 << 20)
		env := scratchEnv(t, 0, b)
		memprobe.ResetPeakRSS()
		base := memprobe.Retained()
		s := memprobe.Start(0)
		start = time.Now()
		x, err := Load(env, c, idxName, h, 0, int64(wire.FrameAreaStart)+int64(n)*4096, nil)
		if err != nil {
			t.Fatal(err)
		}
		opened := time.Since(start)
		peak := s.End()
		retained := memprobe.Retained() - min(base, memprobe.Retained())
		rng := rand.New(rand.NewSource(4))
		const lookups = 20000
		start = time.Now()
		for i := 0; i < lookups; i++ {
			k := uint64(rng.Int63n(int64(n)))
			var hsh [32]byte
			binary.BigEndian.PutUint64(hsh[0:8], k*(^uint64(0)/n))
			binary.BigEndian.PutUint64(hsh[8:16], k)
			if got := x.Lookup(hsh); len(got) != 1 || got[0].FrameOrdinal != k {
				t.Fatalf("record %d: %v", k, got)
			}
		}
		per := time.Since(start) / lookups
		hits, reads := env.Cache.Stats()
		_, rss := memprobe.RSS()
		t.Logf("%d records (%.1f GB): write %v, validated open %v, retained %.2f MB, peak heap %.1f MB, peak RSS %.1f MB, budget peak %.1f MB, lookup %v (page hits %d, reads %d)",
			n, float64(n*64)/1e9, built.Round(time.Millisecond), opened.Round(time.Millisecond), float64(retained)/(1<<20),
			float64(peak-min(peak, base))/(1<<20), float64(rss)/(1<<20), float64(b.Peak())/(1<<20), per, hits, reads)
		kept = append(kept, float64(retained))
		x.Close()
		env.Cache.Close()
		if b.Used() != 0 {
			t.Fatalf("budget not released: %d", b.Used())
		}
		if b.Peak() > b.Limit() {
			t.Fatal("budget exceeded")
		}
	}
	if kept[1] > kept[0]+4<<20 {
		t.Fatalf("10x records grew the retained heap from %.1f to %.1f MB", kept[0]/(1<<20), kept[1]/(1<<20))
	}
}

var _ = fmt.Sprint
