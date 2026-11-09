package fusefs

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"stash"
)

func rnd(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func mount(t *testing.T, dir string, o Options) (*Server, string) {
	t.Helper()
	mnt := t.TempDir()
	s, err := Mount(dir, mnt, o)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "fusermount") || strings.Contains(err.Error(), "/dev/fuse") {
			t.Skipf("FUSE not available: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Unmount(); err != nil { // a file left open by a failed test
			exec.Command("umount", "-l", mnt).Run()
		}
	})
	return s, mnt
}

// tree reads every regular file under mnt.
func tree(t *testing.T, mnt string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(mnt, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(mnt, p)
			out[filepath.ToSlash(rel)] = b
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func create(t *testing.T, o stash.CreateOptions, ro stash.Options, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := stash.Create(dir, o); err != nil {
		t.Fatal(err)
	}
	a, err := stash.Open(dir, ro)
	if err != nil {
		t.Fatal(err)
	}
	for p, d := range files {
		if _, err := a.Put(p, d); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

var sample = map[string][]byte{
	"a.txt":                []byte("hello"),
	"empty":                nil,
	"dir/b.bin":            rnd(1, 3<<20+17),
	"dir/sub/deep/c.txt":   bytes.Repeat([]byte("compressible line\n"), 100000),
	"čeština/žluťoučký.md": []byte("kůň"),
	"many/0":               []byte("0"),
}

func TestMountTree(t *testing.T) {
	key, _ := stash.NewKey()
	for _, tc := range []struct {
		name string
		o    stash.CreateOptions
		key  []byte
	}{
		{"baseline", stash.CreateOptions{}, nil},
		{"secure_rs_zstd", stash.CreateOptions{Key: key, Compression: stash.ZstdDefault, Blobs: 3, MaxFrameSize: 64 << 10,
			Parity: stash.Parity{Scheme: stash.ReedSolomon, K: 2, M: 1}}, key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{}
			for p, d := range sample {
				files[p] = d
			}
			for i := 0; i < 300; i++ { // a large directory
				files["many/"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+"-"+time.Duration(i).String()] = []byte{byte(i)}
			}
			files["shadow"] = []byte("file") // hidden by the directory shadow/
			files["shadow/inner"] = []byte("inner")
			dir := create(t, tc.o, stash.Options{Key: tc.key}, files)
			var logs []string
			s, mnt := mount(t, dir, Options{Read: stash.ReadOptions{Key: tc.key}, Log: func(m string) { logs = append(logs, m) }})
			got := tree(t, mnt)
			want := map[string][]byte{}
			for p, d := range files {
				if p != "shadow" {
					want[p] = d
				}
			}
			if len(got) != len(want) {
				t.Fatalf("%d files, want %d", len(got), len(want))
			}
			for p, d := range want {
				if !bytes.Equal(got[p], d) {
					t.Fatalf("%s differs", p)
				}
			}
			if sh := s.Shadowed(); len(sh) != 1 || sh[0] != "shadow" || len(logs) != 1 {
				t.Fatalf("shadowed %v, logs %v", sh, logs)
			}
			// attributes
			fi, err := os.Stat(filepath.Join(mnt, "dir/b.bin"))
			if err != nil || fi.Size() != 3<<20+17 || fi.Mode().Perm() != 0o444 || !fi.Mode().IsRegular() {
				t.Fatalf("stat %v %v", fi, err)
			}
			if fi, err := os.Stat(filepath.Join(mnt, "dir/sub")); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o555 {
				t.Fatalf("dir stat %v %v", fi, err)
			}
			ents, _ := os.ReadDir(filepath.Join(mnt, "many"))
			names := make([]string, len(ents))
			for i, e := range ents {
				names[i] = e.Name()
			}
			if len(names) != 301 || !sort.StringsAreSorted(names) {
				t.Fatalf("readdir %d", len(names))
			}
			if _, err := os.Stat(filepath.Join(mnt, "nope")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
			// read-only
			if err := os.WriteFile(filepath.Join(mnt, "new"), []byte("x"), 0o644); err == nil {
				t.Fatal("write succeeded")
			}
			if _, err := os.OpenFile(filepath.Join(mnt, "a.txt"), os.O_WRONLY, 0); err == nil {
				t.Fatal("open for writing succeeded")
			}
			if err := os.Remove(filepath.Join(mnt, "a.txt")); err == nil {
				t.Fatal("remove succeeded")
			}
			// xattrs
			buf := make([]byte, 64)
			n, err := syscall.Getxattr(filepath.Join(mnt, "a.txt"), "user.stash.version", buf)
			if err != nil || n == 0 {
				t.Fatalf("xattr %v", err)
			}
			// random concurrent reads of one open file
			f, err := os.Open(filepath.Join(mnt, "dir/b.bin"))
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					r := rand.New(rand.NewSource(int64(g)))
					b := make([]byte, 70000)
					for i := 0; i < 20; i++ {
						off := r.Int63n(3<<20 + 17)
						n, _ := f.ReadAt(b, off)
						if !bytes.Equal(b[:n], files["dir/b.bin"][off:off+int64(n)]) || n == 0 {
							t.Errorf("ReadAt %d", off)
							return
						}
					}
				}(g)
			}
			wg.Wait()
			f.Close()
			var st syscall.Statfs_t
			if err := syscall.Statfs(mnt, &st); err != nil || st.Files != uint64(len(want)) {
				t.Fatalf("statfs %+v %v", st, err)
			}
		})
	}
}

// With Refresh the mount follows a writer; a file opened before keeps
// reading its version, even across a compaction that replaces the
// generation (the snapshot is pinned).
func TestMountRefresh(t *testing.T) {
	dir := create(t, stash.CreateOptions{}, stash.Options{}, map[string][]byte{"x": []byte("version one")})
	s, mnt := mount(t, dir, Options{Refresh: time.Hour})
	f, err := os.Open(filepath.Join(mnt, "x"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := stash.Open(dir, stash.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a.Put("x", []byte("version two, longer"))
	a.Put("y", []byte("new"))
	if _, err := a.Compact(context.Background(), stash.CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 100)
	n, _ := f.ReadAt(b, 0)
	if string(b[:n]) != "version one" {
		t.Fatalf("open file reads %q", b[:n])
	}
	f.Close()
	time.Sleep(1100 * time.Millisecond) // entry/attr timeout of a refreshing mount
	got := tree(t, mnt)
	if string(got["x"]) != "version two, longer" || string(got["y"]) != "new" {
		t.Fatalf("after refresh %q %q", got["x"], got["y"])
	}
}

// Damaged committed data without parity: the read fails with EIO, never
// returns other bytes.
func TestMountDamage(t *testing.T) {
	d := rnd(5, 200000)
	dir := create(t, stash.CreateOptions{Blobs: 1, MaxFrameSize: 64 << 10}, stash.Options{}, map[string][]byte{"d": d})
	blob := filepath.Join(dir, "generation-0000000000000000", "frames", "blob-00.stash")
	fh, _ := os.OpenFile(blob, os.O_RDWR, 0)
	fh.WriteAt([]byte("XXXXXXXX"), 4096+100000)
	fh.Close()
	_, mnt := mount(t, dir, Options{})
	_, err := os.ReadFile(filepath.Join(mnt, "d"))
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("read of damaged data: %v", err)
	}
	// the last extent is intact and still readable
	f, err := os.Open(filepath.Join(mnt, "d"))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1000)
	n, err := f.ReadAt(b, int64(len(d)-1000))
	f.Close()
	if err != nil || !bytes.Equal(b[:n], d[len(d)-1000:]) {
		t.Fatalf("intact end: %d %v", n, err)
	}
}

// With parity the same damage is repaired on read through the mount.
func TestMountParityRepair(t *testing.T) {
	d := rnd(6, 500000)
	dir := create(t, stash.CreateOptions{Blobs: 3, MaxFrameSize: 64 << 10, Parity: stash.Parity{Scheme: stash.ReedSolomon, K: 2, M: 1}},
		stash.Options{}, map[string][]byte{"d": d})
	blob := filepath.Join(dir, "generation-0000000000000000", "frames", "blob-01.stash")
	fh, _ := os.OpenFile(blob, os.O_RDWR, 0)
	fh.WriteAt(bytes.Repeat([]byte("X"), 5000), 4096+30000)
	fh.Close()
	_, mnt := mount(t, dir, Options{})
	got, err := os.ReadFile(filepath.Join(mnt, "d"))
	if err != nil || !bytes.Equal(got, d) {
		t.Fatalf("repaired read: %v", err)
	}
}
