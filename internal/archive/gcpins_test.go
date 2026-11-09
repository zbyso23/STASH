package archive

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"stash/internal/vfs"
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
