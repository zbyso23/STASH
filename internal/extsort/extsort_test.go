package extsort

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stash/internal/membudget"
	"stash/internal/vfs"
)

// records are a 4-byte key with many duplicates, an 8-byte insertion
// sequence (to check stability) and padding.
func keyCmp(a, b []byte) int { return bytes.Compare(a[:4], b[:4]) }

func mkRec(rng *rand.Rand, seq uint64, keys uint32, size int) []byte {
	r := make([]byte, size)
	binary.BigEndian.PutUint32(r[0:4], uint32(rng.Int63n(int64(keys))))
	binary.BigEndian.PutUint64(r[4:12], seq)
	for i := 12; i < size; i++ {
		r[i] = byte(seq + uint64(i))
	}
	return r
}

func osFS(t *testing.T) vfs.FS { return vfs.OS{Root: t.TempDir()} }

func sortAll(t *testing.T, cfg Config, recs [][]byte) ([][]byte, *Sorter) {
	t.Helper()
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := s.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	it, err := s.Sort()
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var out [][]byte
	for it.Next() {
		out = append(out, append([]byte(nil), it.Record()...))
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return out, s
}

func TestSortStableAgainstReference(t *testing.T) {
	for _, tc := range []struct {
		name   string
		n      int
		mem    int64
		fan    int
		size   int
		spills bool
	}{
		{"memory", 5000, 8 << 20, 0, 64, false},
		{"empty", 0, MinMemory, 0, 64, false},
		{"spill", 60000, MinMemory, 0, 64, true},
		{"multipass", 60000, MinMemory, 2, 64, true},
		{"variable", 20000, MinMemory, 3, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(1))
			recs := make([][]byte, tc.n)
			for i := range recs {
				size := tc.size
				if size == 0 {
					size = 12 + rng.Intn(400)
				}
				recs[i] = mkRec(rng, uint64(i), 500, size)
			}
			fsys := osFS(t)
			got, s := sortAll(t, Config{FS: fsys, Dir: "tmp", Compare: keyCmp, Memory: tc.mem, FanIn: tc.fan}, recs)
			want := slices.Clone(recs)
			slices.SortStableFunc(want, keyCmp)
			if len(got) != len(want) {
				t.Fatalf("%d records, want %d", len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Fatalf("record %d differs (stability or order)", i)
				}
			}
			if s.Spilled() != tc.spills {
				t.Fatalf("spilled %v, want %v", s.Spilled(), tc.spills)
			}
			if ents, _ := fsys.ReadDir("tmp"); len(ents) != 0 {
				t.Fatalf("scratch left after Close: %d files", len(ents))
			}
		})
	}
}

func TestSortRejects(t *testing.T) {
	fsys := osFS(t)
	if _, err := New(context.Background(), Config{FS: fsys, Compare: keyCmp, Memory: MinMemory - 1}); err == nil {
		t.Fatal("memory below minimum accepted")
	}
	s, err := New(context.Background(), Config{FS: fsys, Compare: keyCmp, Memory: MinMemory})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Add(make([]byte, MaxRecord+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized record: %v", err)
	}
	if err := s.Add(make([]byte, MaxRecord)); err != nil {
		t.Fatal(err)
	}
}

func TestSortCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fsys := osFS(t)
	s, err := New(ctx, Config{FS: fsys, Dir: "tmp", Compare: keyCmp, Memory: MinMemory})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	rng := rand.New(rand.NewSource(2))
	for i := 0; ; i++ {
		if err := s.Add(mkRec(rng, uint64(i), 10, 64)); err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			break
		}
	}
	s.Close()
	if ents, _ := fsys.ReadDir("tmp"); len(ents) != 0 {
		t.Fatal("scratch left after cancel")
	}
}

func TestCleanScratch(t *testing.T) {
	fsys := osFS(t)
	fsys.MkdirAll("tmp", 0o755)
	for _, n := range []string{"sort-aa-000001.run", "sort-bb-000002.run", "keep.run", "sort-x.idx"} {
		vfs.ReplaceFile(fsys, "tmp/"+n, []byte("x"))
	}
	if err := CleanScratch(fsys, "tmp"); err != nil {
		t.Fatal(err)
	}
	var left []string
	ents, _ := fsys.ReadDir("tmp")
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if !slices.Equal(left, []string{"keep.run", "sort-x.idx"}) {
		t.Fatalf("left %v", left)
	}
	if err := CleanScratch(fsys, "missing"); err != nil {
		t.Fatal(err)
	}
}

// buildRun returns the bytes of a run; cmp nil writes records unchecked.
func buildRun(t *testing.T, tag Tag, cmp Compare, recs [][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := NewRunWriter(&b, tag, cmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := w.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func readRun(data []byte, tag Tag, cmp Compare) ([][]byte, error) {
	rr, err := OpenRun(bytes.NewReader(data), int64(len(data)), tag, cmp)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for rr.Next() {
		out = append(out, append([]byte(nil), rr.Record()...))
	}
	if rr.Err() == nil && !rr.Done() {
		return out, errors.New("no error but not done")
	}
	return out, rr.Err()
}

func sortedRecs(n int) [][]byte {
	rng := rand.New(rand.NewSource(3))
	recs := make([][]byte, n)
	for i := range recs {
		recs[i] = mkRec(rng, uint64(i), 1<<30, 64)
	}
	slices.SortStableFunc(recs, keyCmp)
	return recs
}

// TestRunDamage: every single-byte change, every truncation and any
// appended byte is an error; a damaged run never reads as complete.
func TestRunDamage(t *testing.T) {
	tag := Tag{1, 2, 3}
	recs := sortedRecs(3000) // several blocks
	data := buildRun(t, tag, keyCmp, recs)
	if got, err := readRun(data, tag, keyCmp); err != nil || len(got) != len(recs) {
		t.Fatalf("clean run: %d records, %v", len(got), err)
	}
	rng := rand.New(rand.NewSource(4))
	for i := 0; i < 4000; i++ {
		d := slices.Clone(data)
		pos := rng.Intn(len(d))
		d[pos] ^= byte(1 + rng.Intn(255))
		if _, err := readRun(d, tag, keyCmp); err == nil {
			t.Fatalf("flip at %d accepted", pos)
		}
	}
	for _, pos := range []int{0, 1, headerSize, headerSize + 4, len(data) - 1, len(data) - endSize} {
		d := slices.Clone(data)
		d[pos] ^= 0x80
		if _, err := readRun(d, tag, keyCmp); err == nil {
			t.Fatalf("flip at %d accepted", pos)
		}
	}
	for n := 0; n < len(data); n += 1 + rng.Intn(997) {
		if _, err := readRun(data[:n], tag, keyCmp); err == nil {
			t.Fatalf("truncation to %d accepted", n)
		}
	}
	if _, err := readRun(append(slices.Clone(data), 0), tag, keyCmp); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := readRun(data, Tag{9}, keyCmp); !errors.Is(err, ErrTag) {
		t.Fatalf("foreign tag: %v", err)
	}
	// internally consistent but out of order: only the order check sees it
	bad := slices.Clone(recs)
	bad[100], bad[2000] = bad[2000], bad[100]
	if _, err := readRun(buildRun(t, tag, nil, bad), tag, keyCmp); !errors.Is(err, ErrOrder) {
		t.Fatalf("reordered run: %v", err)
	}
	// and the writer refuses to produce one
	var b bytes.Buffer
	w, _ := NewRunWriter(&b, tag, keyCmp)
	w.Add(recs[1])
	if err := w.Add(recs[0]); !errors.Is(err, ErrOrder) && keyCmp(recs[1], recs[0]) != 0 {
		t.Fatalf("writer accepted order violation: %v", err)
	}
}

// TestRunCrash: a run being replaced durably, or a scratch run written
// without fsync, is after a power loss either verified in full or refused.
func TestRunCrash(t *testing.T) {
	tag := Tag{7}
	oldRecs, newRecs := sortedRecs(2000), sortedRecs(5000)
	seen := map[string]int{}
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		c := vfs.NewCrashFS()
		c.MkdirAll("idx", 0o755)
		if err := WriteRunFile(c, "idx/a.run", tag, keyCmp, func(w *RunWriter) error {
			for _, r := range oldRecs {
				w.Add(r)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		at := rng.Intn(len(newRecs) + 1)
		if rng.Intn(3) == 0 {
			at = len(newRecs) // crash only after the replacement
		}
		var snap *vfs.CrashFS
		err := WriteRunFile(c, "idx/a.run", tag, keyCmp, func(w *RunWriter) error {
			for i, r := range newRecs {
				if i == at {
					snap = c.Crash(vfs.CrashTearGarbage, rng)
				}
				w.Add(r)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if snap == nil {
			snap = c.Crash(vfs.CrashTearGarbage, rng)
		}
		f, err := OpenRunFile(snap, "idx/a.run", tag, keyCmp)
		if err != nil {
			t.Fatalf("seed %d: durable run unreadable: %v", seed, err)
		}
		var n int
		for f.Next() {
			n++
		}
		f.Close()
		if f.Err() != nil || (n != len(oldRecs) && n != len(newRecs)) {
			t.Fatalf("seed %d: %d records, %v", seed, n, f.Err())
		}
		seen[fmt.Sprint(n)]++

		// an unsynced scratch run torn by the crash
		w, _ := c.OpenFile("idx/s.run", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		rw, _ := NewRunWriter(&offsetWriter{f: w}, tag, keyCmp)
		for _, r := range newRecs[:at] {
			rw.Add(r)
		}
		if rng.Intn(2) == 0 {
			rw.Finish()
		}
		if rng.Intn(3) == 0 {
			w.Sync()
			c.SyncDir("idx")
		}
		w.Close()
		torn := c.Crash(vfs.CrashTearGarbage, rng)
		if f, err := OpenRunFile(torn, "idx/s.run", tag, keyCmp); err == nil {
			var got [][]byte
			for f.Next() {
				got = append(got, slices.Clone(f.Record()))
			}
			f.Close()
			if f.Err() == nil {
				if len(got) != at {
					t.Fatalf("seed %d: torn scratch verified with %d of %d records", seed, len(got), at)
				}
				for i := range got {
					if !bytes.Equal(got[i], newRecs[i]) {
						t.Fatalf("seed %d: torn scratch verified with wrong record %d", seed, i)
					}
				}
				seen["torn-ok"]++
			} else {
				seen["torn-refused"]++
			}
		} else {
			seen["torn-refused"]++
		}
	}
	if seen[fmt.Sprint(len(oldRecs))] == 0 || seen[fmt.Sprint(len(newRecs))] == 0 || seen["torn-refused"] == 0 || seen["torn-ok"] == 0 {
		t.Fatalf("crash model did not exercise both outcomes: %v", seen)
	}
}

// TestSortBadScratch: a scratch run damaged during the sort is an error.
func TestSortBadScratch(t *testing.T) {
	fsys := osFS(t)
	s, err := New(context.Background(), Config{FS: fsys, Dir: "tmp", Compare: keyCmp, Memory: MinMemory})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 40000; i++ {
		s.Add(mkRec(rng, uint64(i), 100, 64))
	}
	ents, _ := fsys.ReadDir("tmp")
	if len(ents) == 0 {
		t.Fatal("no spill")
	}
	f, _ := fsys.OpenFile("tmp/"+ents[0].Name(), os.O_RDWR, 0)
	f.WriteAt([]byte{0xff, 0xff}, 5000)
	f.Close()
	it, err := s.Sort()
	if err == nil {
		for it.Next() {
		}
		err = it.Err()
		it.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("damaged scratch: %v", err)
	}
	if ents, _ := fsys.ReadDir("tmp"); len(ents) != 0 {
		t.Fatal("scratch left after failure")
	}
}

func TestMerge(t *testing.T) {
	a := &sliceSrc{recs: [][]byte{{1, 0, 0, 0, 'a'}, {3, 0, 0, 0, 'a'}}}
	b := &sliceSrc{recs: [][]byte{{1, 0, 0, 0, 'b'}, {2, 0, 0, 0, 'b'}}}
	it := Merge(context.Background(), keyCmp, a, b)
	var got []string
	for it.Next() {
		got = append(got, fmt.Sprintf("%d %c", it.Record()[0], it.Record()[4]))
	}
	if !slices.Equal(got, []string{"1 a", "1 b", "2 b", "3 a"}) || it.Err() != nil {
		t.Fatalf("%v %v", got, it.Err())
	}
}

type sliceSrc struct {
	recs [][]byte
	i    int
}

func (s *sliceSrc) Next() bool     { s.i++; return s.i <= len(s.recs) }
func (s *sliceSrc) Record() []byte { return s.recs[s.i-1] }
func (s *sliceSrc) Err() error     { return nil }

// heapSampler records the peak of live heap objects while running.
type heapSampler struct {
	stop chan struct{}
	done chan struct{}
	peak atomic.Uint64
}

func sampleHeap() *heapSampler {
	h := &heapSampler{stop: make(chan struct{}), done: make(chan struct{})}
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	go func() {
		defer close(h.done)
		for {
			metrics.Read(s)
			if v := s[0].Value.Uint64(); v > h.peak.Load() {
				h.peak.Store(v)
			}
			select {
			case <-h.stop:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	return h
}

func (h *heapSampler) end() uint64 { close(h.stop); <-h.done; return h.peak.Load() }

// TestSortMemoryBounded: the live heap of a sort is set by its working
// set, not by the number of records. Ten times the records may not move
// the peak by more than a small constant; both stay under the budget.
func TestSortMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(5))
	const mem = 8 << 20
	peak := func(n int) uint64 {
		runtime.GC()
		var base runtime.MemStats
		runtime.ReadMemStats(&base)
		fsys := osFS(t)
		h := sampleHeap()
		s, err := New(context.Background(), Config{FS: fsys, Dir: "tmp", Compare: keyCmp, Memory: mem})
		if err != nil {
			t.Fatal(err)
		}
		rng := rand.New(rand.NewSource(6))
		rec := make([]byte, 64)
		for i := 0; i < n; i++ {
			binary.BigEndian.PutUint32(rec, rng.Uint32())
			binary.BigEndian.PutUint64(rec[4:], uint64(i))
			if err := s.Add(rec); err != nil {
				t.Fatal(err)
			}
		}
		it, err := s.Sort()
		if err != nil {
			t.Fatal(err)
		}
		var cnt int
		var prev []byte
		for it.Next() {
			if prev != nil && keyCmp(prev, it.Record()) > 0 {
				t.Fatal("out of order")
			}
			prev = append(prev[:0], it.Record()...)
			cnt++
		}
		if it.Err() != nil || cnt != n {
			t.Fatalf("%d of %d: %v", cnt, n, it.Err())
		}
		it.Close()
		p := h.end() - base.HeapAlloc
		t.Logf("%d records (%d MB): peak live heap above baseline %.1f MB", n, n*64>>20, float64(p)/(1<<20))
		return p
	}
	small, big := peak(300_000), peak(3_000_000)
	if big > mem*3/2 || small > mem*3/2 {
		t.Fatalf("peak heap %d / %d above 1.5x working set %d", small, big, mem)
	}
	if big > small+2<<20 {
		t.Fatalf("10x records grew the peak heap from %d to %d", small, big)
	}
}

func TestBudget(t *testing.T) {
	b := membudget.New(100)
	r1, err := b.Reserve(context.Background(), 60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Reserve(context.Background(), 101); !errors.Is(err, membudget.ErrTooLarge) {
		t.Fatal(err)
	}
	if b.TryReserve(50, 50) != nil {
		t.Fatal("TryReserve over the limit")
	}
	if r := b.TryReserve(10, 80); r == nil || r.Size() != 40 {
		t.Fatalf("TryReserve partial: %v", r)
	} else {
		r.Release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.Reserve(ctx, 50); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked reserve: %v", err)
	}
	got := make(chan error)
	go func() {
		r, err := b.Reserve(context.Background(), 50)
		if err == nil {
			r.Release()
		}
		got <- err
	}()
	time.Sleep(10 * time.Millisecond)
	r1.Release()
	r1.Release() // idempotent
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	if b.Used() != 0 || b.Peak() > 100 {
		t.Fatalf("used %d peak %d", b.Used(), b.Peak())
	}
	var nilB *membudget.Budget
	if r, err := nilB.Reserve(context.Background(), 1<<40); err != nil || r.Size() != 1<<40 {
		t.Fatal("nil budget must grant")
	}
}

// TestConcurrentSortsShareBudget: concurrent sorts wait for each other
// instead of exceeding the shared ceiling.
func TestConcurrentSortsShareBudget(t *testing.T) {
	b := membudget.New(3 * MinMemory)
	fsys := osFS(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			s, err := New(context.Background(), Config{FS: fsys, Dir: "tmp", Compare: keyCmp, Memory: MinMemory, Budget: b})
			if err != nil {
				errs <- err
				return
			}
			rng := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 30000; i++ {
				s.Add(mkRec(rng, uint64(i), 1000, 64))
			}
			it, err := s.Sort()
			if err != nil {
				errs <- err
				return
			}
			n := 0
			for it.Next() {
				n++
			}
			if it.Err() != nil || n != 30000 {
				errs <- fmt.Errorf("sort %d: %d records, %v", g, n, it.Err())
			}
			it.Close()
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if b.Peak() > 3*MinMemory || b.Used() != 0 {
		t.Fatalf("peak %d used %d", b.Peak(), b.Used())
	}
}

var _ io.Reader = (*bytes.Reader)(nil)
