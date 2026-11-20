package recovery

import (
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"stash/internal/memprobe"
	"stash/internal/vfs"
)

// TestZZRecoverMemory measures a raw recovery scan of the archive in
// STASH_DIR (built by the archive package's memory harness) in a fresh
// process: the scan, then the default selection streamed and, with
// STASH_EXTRACT set, every selected version read. STASH_MEMLIMIT is the
// scan's memory limit in MiB, STASH_WORKDIR its work directory. It prints
// one RESULT line with the peak live heap and the RSS high-water mark.
func TestZZRecoverMemory(t *testing.T) {
	dir := os.Getenv("STASH_DIR")
	if dir == "" {
		t.Skip("memory harness; set STASH_DIR")
	}
	limit, _ := strconv.ParseInt(os.Getenv("STASH_MEMLIMIT"), 10, 64)
	memprobe.ResetPeakRSS()
	base := memprobe.Retained()
	s := memprobe.Start(0)
	start := time.Now()
	rc, err := Scan(vfs.OS{Root: dir}, Options{MemoryLimit: limit << 20, WorkDir: os.Getenv("STASH_WORKDIR")})
	if err != nil {
		t.Fatal(err)
	}
	scan := time.Since(start)
	n, bytes := 0, int64(0)
	if err := rc.Default()(func(v *Version) bool {
		n++
		if os.Getenv("STASH_EXTRACT") != "" {
			if err := rc.Extract(v, io.Discard); err != nil {
				t.Fatal(err)
			}
		}
		bytes += int64(v.End)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	peak := s.End()
	_, hwm := memprobe.RSS()
	t.Logf("RESULT phase=recover versions=%d all=%d bytes=%d scan_s=%.2f total_s=%.2f peak_heap_mb=%.1f peak_rss_mb=%.1f",
		n, rc.NVersions, bytes, scan.Seconds(), time.Since(start).Seconds(), float64(peak-min(peak, base))/(1<<20), float64(hwm)/(1<<20))
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
}
