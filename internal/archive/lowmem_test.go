package archive

import (
	"context"
	"fmt"
	"testing"
	"time"

	"stash/internal/vfs"
)

// With a small memory limit every long-lived holder (page caches, state
// and directory tables) takes its share, and the sorts of a load that runs
// inside a compaction (the destination journal) must still get memory:
// they degrade instead of waiting for a budget that never frees up.
func TestCompactVerifyLowMemory(t *testing.T) {
	for _, tc := range []int{0, 3} {
		t.Run(compactCases[tc].name, func(t *testing.T) {
			fsys := vfs.OS{Root: t.TempDir()}
			if _, err := Create(fsys, compactCases[tc].cfg); err != nil {
				t.Fatal(err)
			}
			const limit = 8 << 20
			w, err := OpenWriter(fsys, Options{MaxExtent: 8192, MemoryLimit: limit})
			if err != nil {
				t.Fatal(err)
			}
			want := workload(t, w, 3)
			for i := 0; i < 300; i++ {
				p := fmt.Sprintf("more/%03d", i)
				want[p] = data(i, 3000+i)
				if _, err := w.Put(p, want[p]); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
				t.Fatal(err)
			}
			checkWriter(t, w, want)
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := OpenReaderWith(fsys, ReaderOptions{MemoryLimit: limit, TempDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			rep, err := r.Verify(ctx)
			if err != nil || !rep.OK() || rep.Versions != len(want) {
				t.Fatalf("verify: %v ok=%v versions=%d", err, rep != nil && rep.OK(), rep.Versions)
			}
		})
	}
}
