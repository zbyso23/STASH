package archive

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"stash/internal/vfs"
)

type auditSyncFS struct {
	vfs.FS
	rootRenamed bool
	fail        bool
}

func (a *auditSyncFS) Rename(from, to string) error {
	err := a.FS.Rename(from, to)
	if to == RootName && err == nil {
		a.rootRenamed = true
	}
	return err
}
func (a *auditSyncFS) SyncDir(p string) error {
	if a.fail && a.rootRenamed && p == "." {
		a.fail = false
		return fs.ErrPermission
	}
	return a.FS.SyncDir(p)
}

func TestAuditRootSyncError(t *testing.T) {
	backing := vfs.NewCrashFS()
	fsys := &auditSyncFS{FS: backing}
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	defer w.Close()
	if _, err := w.Put("a", []byte("content")); err != nil {
		t.Fatal(err)
	}
	fsys.rootRenamed, fsys.fail = false, true
	_, err := w.Compact(context.Background(), CompactOptions{})
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("wrong error: %v", err)
	}
	root, err := readRoot(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Stat(GenDir(root.GenerationID)); err != nil {
		t.Fatalf("root points to deleted generation %d: %v", root.GenerationID, err)
	}
}

func TestAuditClearLogCrash(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	if _, err := w.Put("x", data(1, 100000)); err != nil {
		t.Fatal(err)
	}
	damageExtent(t, fsys, w, "x", 2)
	w.Close()
	w = mustOpen(t, fsys)
	if _, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(1)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Delete("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before crash: %v", err)
	}
	w.Close()
	fsys = fsys.Crash(vfs.CrashDropUnsynced, nil)
	w = mustOpen(t, fsys)
	defer w.Close()
	if _, err := w.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acknowledged marker returned after crash: %v", err)
	}
}

func TestAuditPruneConcurrentDelete(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	if _, err := w.Put("x", data(1, 100000)); err != nil {
		t.Fatal(err)
	}
	damageExtent(t, fsys, w, "x", 2)
	w.Close()
	w = mustOpen(t, fsys)
	defer w.Close()
	saved := compactTrace
	defer func() { compactTrace = saved }()
	compactTrace = func(phase string, _ time.Duration) {
		if phase == "sweep" {
			if err := w.Delete("x"); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(1)})
	if err != nil && !errors.Is(err, ErrPruneRefused) {
		t.Fatal(err)
	}
	if _, err := w.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("concurrent deletion became a lost marker: %v", err)
	}
}

func TestAuditMissingMarkerIndex(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	if _, err := w.Put("x", data(1, 100000)); err != nil {
		t.Fatal(err)
	}
	damageExtent(t, fsys, w, "x", 2)
	w.Close()
	w = mustOpen(t, fsys)
	res, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(1)})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if err := fsys.Remove(lostIndexName(res.To)); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(fsys, nil)
	if err != nil {
		return
	}
	defer r.Close()
	if _, err := r.Get("x"); errors.Is(err, ErrNotFound) {
		t.Fatalf("loss silently reported as absence: %v", err)
	}
}

func TestAuditPruneWritesUnreadableEvent(t *testing.T) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	if _, err := w.Put("x", data(1, 100000)); err != nil {
		t.Fatal(err)
	}
	damageExtent(t, fsys, w, "x", 2)
	w.Close()
	w = mustOpen(t, fsys)
	defer w.Close()
	p := prune(1)
	p.Reason = strings.Repeat("r", 1<<20)
	res, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: p})
	if errors.Is(err, ErrPruneRefused) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.PruneRecords(); err != nil {
		t.Fatalf("prune switched to %d and wrote an unreadable event: %v", res.To, err)
	}
}
