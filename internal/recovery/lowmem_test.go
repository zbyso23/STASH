package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"stash/internal/archive"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// An unusable work directory is a controlled error, never a fallback into
// memory or the archive.
func TestWorkDirUnavailable(t *testing.T) {
	c, _, _ := fixture(t, plain)
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o644)
	for _, dir := range []string{file, filepath.Join(file, "below"), filepath.Join(t.TempDir(), "missing")} {
		if rc, err := Scan(c, Options{WorkDir: dir}); !errors.Is(err, ErrWorkDir) {
			if rc != nil {
				rc.Close()
			}
			t.Fatalf("%s: %v", dir, err)
		}
	}
}

// The scan's tables live in a private directory below WorkDir, which
// Close removes.
func TestWorkDirRemoved(t *testing.T) {
	c, _, _ := fixture(t, plain)
	dir := t.TempDir()
	rc, err := Scan(c, Options{WorkDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Fatalf("work dir holds %d entries", len(es))
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Fatalf("work dir not removed: %d entries", len(es))
	}
}

// A scan whose working tables spill (smallest delta, 8 MiB limit) finds
// exactly what an in-memory one finds, on an archive with lost frames
// rebuilt from parity and a lost manifest.
func TestScanLowMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	cfg := plain
	cfg.BlobCount, cfg.ParityScheme, cfg.ParityK, cfg.ParityM = 5, wire.ParityRS, 3, 2
	c := vfs.NewCrashFS()
	if _, err := archive.Create(c, cfg); err != nil {
		t.Fatal(err)
	}
	w, err := archive.OpenWriter(c, archive.Options{MaxExtent: 4096})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{}
	for i := 0; i < 3000; i++ {
		p := fmt.Sprintf("d%02d/o%05d", i%37, i)
		want[p] = data(i, []int{10, 300, 5000, 13000}[i%4])
		if _, err := w.Put(p, want[p]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	damage(t, c, blobFile(1), 5000, 64)
	damage(t, c, blobFile(3), 40000, 64)
	for _, noManifest := range []bool{false, true} {
		ref, err := Scan(c, Options{NoManifest: noManifest})
		if err != nil {
			t.Fatal(err)
		}
		saved := testKVMem
		testKVMem = 1
		low, err := Scan(c, Options{NoManifest: noManifest, MemoryLimit: 8 << 20, WorkDir: t.TempDir()})
		testKVMem = saved
		if err != nil {
			t.Fatal(err)
		}
		a, b := mustAll(t, ref), mustAll(t, low)
		if len(a) != len(b) || ref.NVersions != len(a) || !reflect.DeepEqual(ref.Report.Groups, low.Report.Groups) {
			t.Fatalf("%d vs %d versions, groups %+v vs %+v", len(a), len(b), ref.Report.Groups, low.Report.Groups)
		}
		if ref.Groups.RebuiltFrames == 0 {
			t.Fatal("nothing rebuilt")
		}
		for i := range a {
			if !reflect.DeepEqual(a[i], b[i]) {
				t.Fatalf("version %d: %+v vs %+v", i, a[i], b[i])
			}
		}
		n := 0
		if err := low.Default()(func(v *Version) bool {
			var buf bytes.Buffer
			if err := low.Extract(v, &buf); err != nil || !bytes.Equal(buf.Bytes(), want[v.Path]) {
				t.Fatalf("%s: %v", v.Path, err)
			}
			n++
			return true
		}); err != nil {
			t.Fatal(err)
		}
		if n != len(want) {
			t.Fatalf("default selection %d of %d", n, len(want))
		}
		ref.Close()
		low.Close()
	}
}
