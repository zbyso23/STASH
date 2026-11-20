package archive

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"testing"
	"time"

	"stash/internal/memprobe"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// TestZZMemory is the memory scale harness (tools/memscale.sh drives it,
// one fresh process per phase). It is skipped unless STASH_DIR is set.
//
//	STASH_DIR    archive directory
//	STASH_KIND   extents (10 x 4 KiB frames per object) or small (PACKED)
//	STASH_N      objects (default 5000 extents / 100000 small)
//	STASH_MEMLIMIT  memory limit of writer and reader in MiB (0: default);
//	             the caches fill up to their share of it
//	STASH_HEAPPROF  write a heap profile at the measurement
//	STASH_PHASE  build | writer | reader | read (concurrent Gets)
//	STASH_READERS goroutines for the read phase (default 16)
//	STASH_SAME    non-empty: objects share most frame content (duplicate frame hashes)
//	STASH_NOHINT  non-empty: read without locator hints (comparison)
//	STASH_GETS    Gets per reader goroutine (default 2000)
//
// Each phase prints one RESULT line: retained heap per unit (frame or
// object) after open, peak live heap during the phase and the RSS
// high-water mark of the phase.
func TestZZMemory(t *testing.T) {
	dir, kind, phase := os.Getenv("STASH_DIR"), os.Getenv("STASH_KIND"), os.Getenv("STASH_PHASE")
	if dir == "" {
		t.Skip("memory harness; set STASH_DIR")
	}
	fsys := vfs.OS{Root: dir}
	n := 5000
	if kind == "small" {
		n = 100000
	}
	if v, err := strconv.Atoi(os.Getenv("STASH_N")); err == nil && v > 0 {
		n = v
	}
	units := n * 10
	if kind == "small" {
		units = n
	}
	name := func(j int) string { return fmt.Sprintf("dir%03d/object-%07d.bin", j%100, j) }
	memprobe.ResetPeakRSS()
	base := memprobe.Retained()
	s := memprobe.Start(0)
	report := func(what string, retained uint64, cache int64) {
		peak := s.End()
		_, hwm := memprobe.RSS()
		rest := retained - min(retained, uint64(cache))
		t.Logf("RESULT kind=%s phase=%s units=%d retained_per_unit=%.1f cache_mb=%.1f retained_nocache_per_unit=%.1f peak_heap_mb=%.1f peak_rss_mb=%.1f",
			kind, what, units, float64(retained)/float64(units), float64(cache)/(1<<20), float64(rest)/float64(units), float64(peak-min(peak, base))/(1<<20), float64(hwm)/(1<<20))
		if p := os.Getenv("STASH_HEAPPROF"); p != "" { // what the retained heap is
			runtime.GC()
			if f, err := os.Create(p); err == nil {
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}
	}
	switch phase {
	case "build":
		if _, err := Create(fsys, Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 4, MaxFrameQuanta: 16}); err != nil {
			t.Fatal(err)
		}
		opt := Options{}
		if kind != "small" {
			opt = Options{MaxExtent: 4096, PackThreshold: -1, UncompressedExtents: true}
		}
		w, err := OpenWriter(fsys, opt)
		if err != nil {
			t.Fatal(err)
		}
		size := 40960
		if kind == "small" {
			size = 100
		}
		for i := 0; i < n; i += 500 {
			errs := make(chan error, 500)
			for j := i; j < min(i+500, n); j++ {
				go func(j int) {
					d := make([]byte, size)
					if os.Getenv("STASH_SAME") == "" {
						rand.New(rand.NewSource(int64(j))).Read(d) // distinct frames
					}
					d[0], d[1], d[2] = byte(j), byte(j>>8), byte(j>>16)
					_, err := w.Put(name(j), d)
					errs <- err
				}(j)
			}
			for j := i; j < min(i+500, n); j++ {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		report("build", 0, 0)
	case "writer":
		w, err := OpenWriter(fsys, Options{MaxExtent: 4096, MemoryLimit: memLimit()})
		if err != nil {
			t.Fatal(err)
		}
		report("writer", memprobe.Retained()-base, cacheBytes(w.env, w.stEnv))
		w.Close()
	case "reader":
		r, err := OpenReaderWith(fsys, ReaderOptions{MemoryLimit: memLimit()})
		if err != nil {
			t.Fatal(err)
		}
		report("reader", memprobe.Retained()-base, cacheBytes(r.env, r.stEnv))
		r.Close()
	case "read":
		r, err := OpenReaderWith(fsys, ReaderOptions{MemoryLimit: memLimit()})
		if err != nil {
			t.Fatal(err)
		}
		retained := memprobe.Retained() - base
		cache := cacheBytes(r.env, r.stEnv)
		if os.Getenv("STASH_NOHINT") != "" {
			r.view.hints = nil // the candidate walk alone, for comparison
		}
		g, _ := strconv.Atoi(os.Getenv("STASH_READERS"))
		if g <= 0 {
			g = 16
		}
		gets, _ := strconv.Atoi(os.Getenv("STASH_GETS"))
		if gets <= 0 {
			gets = 2000
		}
		var wg sync.WaitGroup
		errs := make(chan error, g)
		start := time.Now()
		for i := 0; i < g; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(int64(i)))
				for k := 0; k < gets; k++ {
					if _, err := r.Get(name(rng.Intn(n))); err != nil {
						errs <- err
						return
					}
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		el := time.Since(start)
		t.Logf("RESULT kind=%s phase=get-%d units=%d gets=%d us_per_get=%.1f wall_s=%.2f", kind, g, units, g*gets, float64(el.Microseconds())/float64(g*gets)*float64(g), el.Seconds())
		report(fmt.Sprintf("read-%d", g), retained, cache)
		r.Close()
	default:
		t.Fatalf("unknown STASH_PHASE %q", phase)
	}
}

func memLimit() int64 {
	n, _ := strconv.ParseInt(os.Getenv("STASH_MEMLIMIT"), 10, 64)
	return n << 20
}
