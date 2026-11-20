package archive

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"sync"
	"testing"

	"stash/internal/index"
	"stash/internal/vfs"
)

// TestIndexSpills: with a tiny in-memory delta the writer spills session
// runs to ScratchDir while it writes, lookups during the session see
// spilled records, Close merges them into the normative .idx and removes
// the scratch space, and a reader (with its own private scratch) and a
// reopened writer find everything through the stored index alone.
func TestIndexSpills(t *testing.T) {
	defer func(d int) { testDeltaMax = d }(testDeltaMax)
	testDeltaMax = 4
	root := t.TempDir()
	fsys := vfs.OS{Root: root}
	mustCreate(t, fsys)
	// leftovers of a crashed session are removed at open
	fsys.MkdirAll(ScratchDir, 0o755)
	vfs.ReplaceFile(fsys, ScratchDir+"/run-dead-00-000000.idx", []byte("x"))
	w := mustOpen(t, fsys)
	if _, err := fsys.Stat(ScratchDir + "/run-dead-00-000000.idx"); err == nil {
		t.Fatal("stale scratch survived the writer open")
	}
	want := map[string][]byte{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				p := fmt.Sprintf("g%d/f%03d", g, i)
				d := data(g*1000+i, 9000+i*37)
				if _, err := w.Put(p, d); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				want[p] = d
				mu.Unlock()
				// read back while other goroutines append and spill
				if got, err := w.Get(p); err != nil || !bytes.Equal(got, d) {
					t.Errorf("%s during session: %v", p, err)
				}
			}
		}(g)
	}
	wg.Wait()
	spilled := 0
	for _, bv := range w.blobs {
		spilled += bv.idx.Spilled()
	}
	ents, _ := fsys.ReadDir(ScratchDir)
	if spilled == 0 || len(ents) == 0 {
		t.Fatalf("no session runs (spilled %d, scratch files %d)", spilled, len(ents))
	}
	for p, d := range want {
		if got, err := w.Get(p); err != nil || !bytes.Equal(got, d) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Stat(ScratchDir); err == nil {
		t.Fatal("scratch directory left after Close")
	}
	tmp := t.TempDir()
	r, err := OpenReaderWith(fsys, ReaderOptions{TempDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	for b, bv := range r.blobs {
		if bv.idx.Spilled() != 0 {
			t.Fatalf("blob %d: reader spilled although the stored index is complete", b)
		}
	}
	for p, d := range want {
		if got, err := r.Get(p); err != nil || !bytes.Equal(got, d) {
			t.Fatalf("reader %s: %v", p, err)
		}
	}
	for _, bv := range r.blobs {
		if bv.defective {
			t.Fatal("a lookup needed the fallback scan")
		}
	}
	r.Close()

	// a reader rebuilding a missing index spills into its own temp dir,
	// never into the archive, and removes it on Close
	gen := w.gen
	for b := 0; b < int(cfg.BlobCount); b++ {
		iname, _ := index.Name(uint8(b))
		os.Remove(path.Join(root, gen, iname))
	}
	r, err = OpenReaderWith(fsys, ReaderOptions{TempDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	spilled = 0
	for _, bv := range r.blobs {
		spilled += bv.idx.Spilled()
	}
	if spilled == 0 {
		t.Fatal("rebuild did not spill")
	}
	if _, err := fsys.Stat(ScratchDir); err == nil {
		t.Fatal("reader wrote scratch into the archive")
	}
	for p, d := range want {
		if got, err := r.Get(p); err != nil || !bytes.Equal(got, d) {
			t.Fatalf("rebuilt %s: %v", p, err)
		}
	}
	r.Close()
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("reader scratch left: %v", left)
	}
}
