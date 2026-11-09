package archive

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// faultFS fails reads of the pin directory or of pin files on demand.
type faultFS struct {
	*vfs.CrashFS
	dir, file atomic.Bool
}

var errIO = errors.New("injected I/O error")

func (f *faultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == PinDir && f.dir.Load() {
		return nil, errIO
	}
	return f.CrashFS.ReadDir(name)
}

func (f *faultFS) OpenFile(name string, flag int, perm fs.FileMode) (vfs.File, error) {
	if strings.HasPrefix(name, PinDir+"/") && flag == os.O_RDONLY && f.file.Load() {
		return nil, errIO
	}
	return f.CrashFS.OpenFile(name, flag, perm)
}

// §13.1.1: GC must not treat an unreadable pin directory or pin file as
// "no pins"; it stops and keeps the old generation.
func TestGCStopsOnPinReadError(t *testing.T) {
	ff := &faultFS{CrashFS: vfs.NewCrashFS()}
	mustCreate(t, ff)
	w := mustOpen(t, ff)
	want := workload(t, w, 5)
	r, err := OpenReaderPinned(ff, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ff.dir.Store(true)
	res, err := w.Compact(context.Background(), CompactOptions{})
	if !errors.Is(err, errIO) || len(res.Removed) != 0 {
		t.Fatalf("compact GC with an unreadable pin dir: %v %+v", err, res)
	}
	ff.dir.Store(false)
	ff.file.Store(true)
	if removed, err := w.GC(); !errors.Is(err, errIO) || len(removed) != 0 {
		t.Fatalf("GC with an unreadable pin: %v %v", removed, err)
	}
	ff.file.Store(false)
	checkAll(t, r.Get, want) // the pinned generation is still there
	r.Close()
	if removed, err := w.GC(); err != nil || len(removed) != 1 {
		t.Fatalf("GC after release: %v %v", removed, err)
	}
	w.Close()
}

// Audit finding 8: a tiny pin TTL is refused instead of panicking in the
// renewal goroutine.
func TestPinTTLMinimum(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	for _, ttl := range []time.Duration{time.Nanosecond, time.Second, -time.Second} {
		if _, err := OpenReaderPinned(fsys, nil, ttl); !errors.Is(err, wire.ErrInvalid) {
			t.Fatalf("ttl %v: %v", ttl, err)
		}
	}
	r, err := OpenReaderPinned(fsys, nil, MinPinTTL)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

// Audit finding 5 end to end: a link planted in a retired generation
// directory is removed by GC, its target outside the archive survives.
func TestGCDoesNotFollowLinks(t *testing.T) {
	d := t.TempDir()
	root, outside := filepath.Join(d, "a"), filepath.Join(d, "outside")
	os.MkdirAll(root, 0o755)
	os.MkdirAll(outside, 0o755)
	victim := filepath.Join(outside, "victim")
	os.WriteFile(victim, []byte("keep"), 0o644)
	fsys := vfs.OS{Root: root}
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	workload(t, w, 2)
	if _, err := w.Compact(context.Background(), CompactOptions{KeepOld: true}); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, GenDir(0))
	os.Symlink(outside, filepath.Join(old, "frames", "evil"))
	os.Symlink(victim, filepath.Join(old, "evil-file"))
	removed, err := w.GC()
	if err != nil || len(removed) != 1 {
		t.Fatalf("GC: %v %v", removed, err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
		t.Fatalf("outside file: %q %v", b, err)
	}
	if _, err := os.Lstat(old); err == nil {
		t.Fatal("old generation left")
	}
	w.Close()
}
