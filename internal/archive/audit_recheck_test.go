// The auditor's recheck reproductions (M20c/R11 audit, second round).

package archive

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"stash/internal/vfs"
	"stash/internal/wire"
	"strings"
	"testing"
)

func TestRecheckAckAfterNormalCompactCrash(t *testing.T) {
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
	if _, err := w.Compact(context.Background(), CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Delete("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before crash: %v", err)
	}
	w.Close()
	survived := fsys.Crash(vfs.CrashDropUnsynced, nil)
	w = mustOpen(t, survived)
	defer w.Close()
	if _, err := w.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after crash: %v", err)
	}
}

func TestRecheckAckAfterLogRecreateCrash(t *testing.T) {
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
	if err := fsys.Remove(clearedName(res.To)); err != nil {
		t.Fatal(err)
	}
	if err := fsys.SyncDir(HealthDir); err != nil {
		t.Fatal(err)
	}
	w = mustOpen(t, fsys)
	if err := w.Delete("x"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	w = mustOpen(t, fsys.Crash(vfs.CrashDropUnsynced, nil))
	defer w.Close()
	if _, err := w.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after crash: %v", err)
	}
}

func TestRecheckRootReopenGCCrash(t *testing.T) {
	b := vfs.NewCrashFS()
	f := &rootFaultFS{FS: b}
	mustCreate(t, f)
	w := mustOpen(t, f)
	if _, err := w.Put("x", data(1, 10000)); err != nil {
		t.Fatal(err)
	}
	f.renamed, f.failSync = false, true
	if _, err := w.Compact(context.Background(), CompactOptions{}); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("compact: %v", err)
	}
	w.Close()
	w = mustOpen(t, f)
	f.failSync = true
	if _, err := w.GC(); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("gc: %v", err)
	}
	w.Close()
	after := b.Crash(vfs.CrashDropUnsynced, nil)
	r, err := OpenReader(after, nil)
	if err != nil {
		t.Fatalf("reopen after GC crash: %v", err)
	}
	defer r.Close()
	if _, err := r.Get("x"); err != nil {
		t.Fatal(err)
	}
}

func TestRecheckOldMarkerFormat(t *testing.T) {
	f := vfs.NewCrashFS()
	mustCreate(t, f)
	w := mustOpen(t, f)
	if _, err := w.Put("x", data(1, 100000)); err != nil {
		t.Fatal(err)
	}
	damageExtent(t, f, w, "x", 2)
	w.Close()
	w = mustOpen(t, f)
	res, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(1)})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	name := lostIndexName(res.To)
	raw, err := vfs.ReadFile(f, name, 4096)
	if err != nil {
		t.Fatal(err)
	}
	old := append([]byte("STUNREC1"), raw[16:len(raw)-32]...)
	sum := sha256.Sum256(old)
	if err := vfs.ReplaceFile(f, name, append(old, sum[:]...)); err != nil {
		t.Fatal(err)
	}
	// decided: the pre-release format is refused, clearly, never read as
	// "no markers" (the auditor's version expected it to be read)
	r, err := OpenReader(f, nil)
	if err == nil {
		r.Close()
		t.Fatal("pre-release index accepted")
	}
	if !errors.Is(err, wire.ErrCorrupt) || !strings.Contains(err.Error(), "STUNREC1") {
		t.Fatalf("unclear refusal: %v", err)
	}
}

func TestRecheckPoisonedDeleteMutates(t *testing.T) {
	b := vfs.NewCrashFS()
	f := &rootFaultFS{FS: b}
	mustCreate(t, f)
	w := mustOpen(t, f)
	if _, err := w.Put("x", data(1, 100000)); err != nil {
		t.Fatal(err)
	}
	damageExtent(t, f, w, "x", 2)
	w.Close()
	w = mustOpen(t, f)
	if _, err := w.Compact(context.Background(), CompactOptions{EmergencyPrune: prune(1)}); err != nil {
		t.Fatal(err)
	}
	f.renamed, f.failSync = false, true
	if _, err := w.Compact(context.Background(), CompactOptions{}); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("compact: %v", err)
	}
	if _, err := w.Get("x"); !isLost(err) {
		t.Fatalf("before delete: %v", err)
	}
	if err := w.Delete("x"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("delete: %v", err)
	}
	if _, err := w.Get("x"); !isLost(err) {
		t.Fatalf("rejected delete mutated marker: %v", err)
	}
	w.Close()
}
