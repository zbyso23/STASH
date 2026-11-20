package index

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"stash/internal/membudget"
	"stash/internal/memprobe"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// TestZZIndexBuild is the phase 5 index harness: STASH_INDEX_BUILD=n
// records are added one by one the way a writer adds frames (offsets in
// order, hashes random) under a 64 MiB budget (STASH_MEMLIMIT MiB), so the
// delta spills into session runs that merge by level, and the whole index
// is written by one streaming merge. Then it is opened with full
// validation from a cold page cache (posix_fadvise DONTNEED) and looked up
// cold and warm from 1, 4 and 16 goroutines. STASH_INDEX_DIR places the
// files. Each step prints one RESULT line.
func TestZZIndexBuild(t *testing.T) {
	n, _ := strconv.ParseUint(os.Getenv("STASH_INDEX_BUILD"), 10, 64)
	if n == 0 {
		t.Skip("index scale harness; set STASH_INDEX_BUILD")
	}
	limit, _ := strconv.ParseInt(os.Getenv("STASH_MEMLIMIT"), 10, 64)
	if limit == 0 {
		limit = 64
	}
	root := os.Getenv("STASH_INDEX_DIR")
	if root == "" {
		root = t.TempDir()
	}
	dir, err := os.MkdirTemp(root, "build-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	c := vfs.OS{Root: dir}
	c.MkdirAll("index", 0o755)
	h := pagedHeader()
	newEnv := func() (*Env, *membudget.Budget) {
		b := membudget.New(limit << 20)
		return &Env{Budget: b, Cache: NewPageCache(b, limit<<20/8),
			Scratch: func() (vfs.FS, string, error) { return c, "scratch", nil }}, b
	}
	measure := func() func(string, string) {
		memprobe.ResetPeakRSS()
		base := memprobe.Retained()
		s := memprobe.Start(0)
		start := time.Now()
		return func(step, extra string) {
			peak := s.End()
			_, rss := memprobe.RSS()
			t.Logf("RESULT step=%s records=%d wall_s=%.1f peak_heap_mb=%.1f peak_rss_mb=%.1f %s", step, n, time.Since(start).Seconds(),
				float64(peak-min(peak, base))/(1<<20), float64(rss)/(1<<20), extra)
		}
	}

	// build
	env, b := newEnv()
	done := measure()
	x := New(env, h, 0)
	maxScratch := int64(0)
	for i := uint64(0); i < n; i++ {
		if err := x.Add(wire.IndexRecord{FrameHash: scaleHash(i), PhysicalOffset: uint64(wire.FrameAreaStart) + i*4096,
			FrameQuanta: 1, BlockType: wire.BlockData, FrameOrdinal: i}); err != nil {
			t.Fatal(err)
		}
		if i%(1<<22) == 0 {
			maxScratch = max(maxScratch, dirSize(filepath.Join(dir, "scratch")))
		}
	}
	runs := x.Spilled()
	maxScratch = max(maxScratch, dirSize(filepath.Join(dir, "scratch")))
	if err := x.Write(c, idxName); err != nil {
		t.Fatal(err)
	}
	x.Close()
	env.Cache.Close()
	done("build", fmt.Sprintf("runs_at_end=%d scratch_peak_gb=%.2f budget_peak_mb=%.1f", runs, float64(maxScratch)/1e9, float64(b.Peak())/(1<<20)))
	if b.Used() != 0 || b.Peak() > b.Limit() {
		t.Fatalf("budget %d used, peak %d", b.Used(), b.Peak())
	}
	if left := dirSize(filepath.Join(dir, "scratch")); left != 0 {
		t.Fatalf("scratch keeps %d bytes", left)
	}

	// cold validated open
	dropCache(t, filepath.Join(dir, idxName))
	env, b = newEnv()
	done = measure()
	x, err = Load(env, c, idxName, h, 0, int64(wire.FrameAreaStart)+int64(n)*4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	done("open", fmt.Sprintf("budget_peak_mb=%.1f", float64(b.Peak())/(1<<20)))
	defer func() { x.Close(); env.Cache.Close() }()

	lookup := func(step string, g, per int, cold bool) {
		if cold {
			dropCache(t, filepath.Join(dir, idxName))
		}
		done := measure()
		var mu sync.Mutex
		var lat []time.Duration
		var wg sync.WaitGroup
		errs := make(chan error, g)
		for w := 0; w < g; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(int64(w) + 99))
				mine := make([]time.Duration, 0, per)
				for k := 0; k < per; k++ {
					i := uint64(rng.Int63n(int64(n)))
					hsh := scaleHash(i)
					miss := k%10 == 9 // a tenth look up absent hashes
					if miss {
						hsh[31] ^= 0xFF
					}
					st := time.Now()
					got := x.Lookup(hsh)
					mine = append(mine, time.Since(st))
					if miss && len(got) != 0 || !miss && (len(got) != 1 || got[0].FrameOrdinal != i) {
						errs <- fmt.Errorf("record %d (miss %v): %v", i, miss, got)
						return
					}
				}
				mu.Lock()
				lat = append(lat, mine...)
				mu.Unlock()
			}(w)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		slices.Sort(lat)
		q := func(p float64) float64 { return float64(lat[int(p*float64(len(lat)-1))].Microseconds()) }
		hits, reads := env.Cache.Stats()
		done(step, fmt.Sprintf("goroutines=%d lookups=%d p50_us=%.0f p99_us=%.0f max_us=%.0f page_hits=%d page_reads=%d",
			g, len(lat), q(0.5), q(0.99), q(1), hits, reads))
	}
	lookup("lookup-cold", 1, 2000, true)
	for _, g := range []int{1, 4, 16} {
		lookup(fmt.Sprintf("lookup-warm-%d", g), g, 200000/g, false)
	}
	lookup("lookup-cold-16", 16, 500, true)
}

// scaleHash is the frame hash of record i: random-looking, unique.
func scaleHash(i uint64) [32]byte {
	var h [32]byte
	z := i
	for j := 0; j < 4; j++ {
		z += 0x9E3779B97F4A7C15
		v := z
		v = (v ^ v>>30) * 0xBF58476D1CE4E5B9
		v = (v ^ v>>27) * 0x94D049BB133111EB
		binary.BigEndian.PutUint64(h[j*8:], v^v>>31)
	}
	binary.BigEndian.PutUint64(h[24:], i) // unique whatever the mix does
	return h
}

func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// dropCache evicts the file from the OS page cache (clean pages), so the
// next reads come from the device.
func dropCache(t testing.TB, name string) {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const fadvDontneed = 4
	if _, _, e := syscall.Syscall6(syscall.SYS_FADVISE64, f.Fd(), 0, 0, fadvDontneed, 0, 0); e != 0 {
		t.Fatalf("fadvise: %v", e)
	}
}
