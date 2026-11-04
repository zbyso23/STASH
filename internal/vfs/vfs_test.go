package vfs

import (
	"bytes"
	"errors"
	"io/fs"
	"math/rand"
	"os"
	"testing"
)

func write(t *testing.T, fsys FS, name string, data []byte, off int64) File {
	t.Helper()
	f, err := fsys.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(data, off); err != nil {
		t.Fatal(err)
	}
	return f
}

func read(t *testing.T, fsys FS, name string) []byte {
	t.Helper()
	b, err := ReadFile(fsys, name, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCrashDropsUnsynced(t *testing.T) {
	c := NewCrashFS()
	f := write(t, c, "a", []byte("hello"), 0)
	// file data synced but the name is not: the file vanishes
	f.Sync()
	if got := c.Crash(CrashDropUnsynced, nil).Names(); len(got) != 0 {
		t.Fatalf("unsynced name survived: %v", got)
	}
	c.SyncDir(".")
	f.WriteAt([]byte(" world"), 5)
	after := c.Crash(CrashDropUnsynced, nil)
	if got := read(t, after, "a"); string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	f.Sync()
	if got := read(t, c.Crash(CrashDropUnsynced, nil), "a"); string(got) != "hello world" {
		t.Fatalf("got %q", got)
	}
}

func TestCrashRemoveAndRenameNeedSyncDir(t *testing.T) {
	c := NewCrashFS()
	f := write(t, c, "a", []byte("x"), 0)
	f.Sync()
	c.SyncDir(".")
	c.Remove("a")
	if got := c.Crash(CrashDropUnsynced, nil).Names(); len(got) != 1 {
		t.Fatalf("unsynced remove persisted: %v", got)
	}
	c.SyncDir(".")
	if got := c.Crash(CrashDropUnsynced, nil).Names(); len(got) != 0 {
		t.Fatalf("synced remove lost: %v", got)
	}
}

func TestCrashTearKeepsSyncedPrefix(t *testing.T) {
	c := NewCrashFS()
	base := bytes.Repeat([]byte{1}, 3*pageSize+100)
	f := write(t, c, "b", base, 0)
	f.Sync()
	c.SyncDir(".")
	more := bytes.Repeat([]byte{2}, 5*pageSize)
	f.WriteAt(more, int64(len(base)))
	f.WriteAt(bytes.Repeat([]byte{3}, 200), 10) // unsynced overwrite of synced bytes
	sawGrowth := false
	for seed := int64(0); seed < 200; seed++ {
		got := read(t, c.Crash(CrashTear, rand.New(rand.NewSource(seed))), "b")
		if len(got) < len(base) || len(got) > len(base)+len(more) {
			t.Fatalf("seed %d: length %d", seed, len(got))
		}
		if len(got) > len(base) {
			sawGrowth = true
		}
		for i, x := range got {
			switch {
			case i >= 10 && i < 210:
				if x != 1 && x != 3 {
					t.Fatalf("seed %d: byte %d = %d", seed, i, x)
				}
			case i < len(base):
				if x != 1 {
					t.Fatalf("seed %d: synced byte %d changed to %d", seed, i, x)
				}
			default:
				if x != 2 && x != 0 {
					t.Fatalf("seed %d: growth byte %d = %d", seed, i, x)
				}
			}
		}
	}
	if !sawGrowth {
		t.Fatal("tear model never persisted part of the growth")
	}
}

func TestReplaceFileAtomic(t *testing.T) {
	c := NewCrashFS()
	c.MkdirAll("g", 0o755)
	if err := ReplaceFile(c, "g/root", []byte("old-content")); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash at every point of a second replace by checking the
	// state after each operation of the protocol.
	newData := bytes.Repeat([]byte("N"), 9000)
	steps := []func(){}
	var f File
	steps = append(steps,
		func() { f, _ = c.OpenFile("g/root.tmp", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644) },
		func() { f.WriteAt(newData, 0) },
		func() { f.Sync() },
		func() { f.Close(); c.Rename("g/root.tmp", "g/root") },
		func() { c.SyncDir("g") },
	)
	for i, step := range steps {
		step()
		for seed := int64(0); seed < 20; seed++ {
			after := c.Crash(CrashTear, rand.New(rand.NewSource(seed)))
			got := read(t, after, "g/root")
			if string(got) != "old-content" && !bytes.Equal(got, newData) {
				t.Fatalf("after step %d seed %d: mixed content (%d bytes)", i, seed, len(got))
			}
			if i == len(steps)-1 && !bytes.Equal(got, newData) {
				t.Fatal("completed replace not durable")
			}
		}
	}
}

func TestReadFileBound(t *testing.T) {
	c := NewCrashFS()
	write(t, c, "big", make([]byte, 100), 0)
	if _, err := ReadFile(c, "big", 99); err == nil {
		t.Fatal("bound not enforced")
	}
}

func TestOSFS(t *testing.T) {
	o := OS{Root: t.TempDir()}
	if err := o.MkdirAll("d/e", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(o, "d/e/f", []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got := read(t, o, "d/e/f"); string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
	f, err := o.OpenFile("d/e/f", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Size(); n != 3 {
		t.Fatal(n)
	}
	f.Truncate(1)
	f.Close()
	if _, err := o.OpenFile("d/e/f", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("O_EXCL: %v", err)
	}
	ents, _ := o.ReadDir("d/e")
	if len(ents) != 1 || ents[0].Name() != "f" {
		t.Fatalf("readdir %v", ents)
	}
}

func TestCrashFSErrors(t *testing.T) {
	c := NewCrashFS()
	if _, err := c.OpenFile("nodir/x", os.O_CREATE|os.O_RDWR, 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := c.OpenFile("x", os.O_RDONLY, 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	f := write(t, c, "x", []byte("1"), 0)
	if _, err := c.OpenFile("x", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0); !errors.Is(err, fs.ErrExist) {
		t.Fatal(err)
	}
	r, _ := c.OpenFile("x", os.O_RDONLY, 0)
	if _, err := r.WriteAt([]byte("z"), 0); err == nil {
		t.Fatal("write through read-only handle")
	}
	f.Close()
	if _, err := f.WriteAt([]byte("z"), 0); err == nil {
		t.Fatal("write after close")
	}
	c.MkdirAll("a/b", 0)
	ents, _ := c.ReadDir(".")
	if len(ents) != 2 { // a, x
		t.Fatalf("%v", ents)
	}
}

func TestLocks(t *testing.T) {
	for _, fsys := range []FS{NewCrashFS(), OS{Root: t.TempDir()}} {
		u, err := fsys.Lock("writer.lock")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fsys.Lock("writer.lock"); !errors.Is(err, ErrLocked) {
			t.Fatalf("%T: second lock: %v", fsys, err)
		}
		u()
		u2, err := fsys.Lock("writer.lock")
		if err != nil {
			t.Fatal(err)
		}
		u2()
	}
}
