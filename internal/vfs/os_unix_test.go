//go:build unix

package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// planted returns an archive root and an outside directory with a file.
func planted(t *testing.T) (OS, string, string) {
	t.Helper()
	d := t.TempDir()
	root, outside := filepath.Join(d, "archive"), filepath.Join(d, "outside")
	os.MkdirAll(filepath.Join(root, "gen"), 0o755)
	os.MkdirAll(outside, 0o755)
	victim := filepath.Join(outside, "victim")
	os.WriteFile(victim, []byte("outside data"), 0o644)
	return OS{Root: root}, outside, victim
}

func intact(t *testing.T, victim string) {
	t.Helper()
	if b, err := os.ReadFile(victim); err != nil || string(b) != "outside data" {
		t.Fatalf("outside file changed: %q %v", b, err)
	}
}

// A link inside a tree being removed is removed itself; what it points to
// survives (audit finding 5).
func TestRemoveAllDoesNotFollowLinks(t *testing.T) {
	o, outside, victim := planted(t)
	os.WriteFile(filepath.Join(o.Root, "gen", "f"), []byte("x"), 0o644)
	os.Symlink(outside, filepath.Join(o.Root, "gen", "dirlink"))
	os.Symlink(victim, filepath.Join(o.Root, "gen", "filelink"))
	if err := RemoveAll(o, "gen"); err != nil {
		t.Fatal(err)
	}
	intact(t, victim)
	if _, err := os.Lstat(filepath.Join(o.Root, "gen")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("tree not removed")
	}
	// the tree itself is a link: the link goes, the target stays
	os.Symlink(outside, filepath.Join(o.Root, "gen2"))
	if err := RemoveAll(o, "gen2"); err != nil {
		t.Fatal(err)
	}
	intact(t, victim)
}

// A planted temporary name or a link at the final name never makes a
// durable replacement write outside the root (audit finding 6).
func TestReplaceFileDoesNotFollowLinks(t *testing.T) {
	o, _, victim := planted(t)
	os.Symlink(victim, filepath.Join(o.Root, "root.current.tmp"))
	if err := ReplaceFile(o, "root.current", []byte("new root")); err != nil {
		t.Fatal(err)
	}
	intact(t, victim)
	os.Symlink(victim, filepath.Join(o.Root, "link.current"))
	if err := ReplaceFile(o, "link.current", []byte("replaced")); err != nil {
		t.Fatal(err)
	}
	intact(t, victim)
	if b, _ := os.ReadFile(filepath.Join(o.Root, "link.current")); string(b) != "replaced" {
		t.Fatalf("%q", b)
	}
	if fi, _ := os.Lstat(filepath.Join(o.Root, "link.current")); fi.Mode()&fs.ModeSymlink != 0 {
		t.Fatal("still a link")
	}
}

// Links anywhere in a name are refused for every operation; special files
// are refused without blocking; names cannot climb out of the root.
func TestOSRefusesLinksAndSpecialFiles(t *testing.T) {
	o, outside, victim := planted(t)
	os.Symlink(outside, filepath.Join(o.Root, "gen", "sub"))
	os.Symlink(victim, filepath.Join(o.Root, "gen", "file"))
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"open through a dir link", func() error { _, err := o.OpenFile("gen/sub/victim", os.O_RDWR, 0); return err }()},
		{"create through a dir link", func() error {
			_, err := o.OpenFile("gen/sub/new", os.O_RDWR|os.O_CREATE, 0o644)
			return err
		}()},
		{"open a file link", func() error { _, err := o.OpenFile("gen/file", os.O_RDWR|os.O_TRUNC, 0); return err }()},
		{"mkdir through a link", o.MkdirAll("gen/sub/x/y", 0o755)},
		{"readdir a link", func() error { _, err := o.ReadDir("gen/sub"); return err }()},
		{"remove through a link", o.Remove("gen/sub/victim")},
		{"rename through a link", o.Rename("gen/sub/victim", "stolen")},
		{"sync a link", o.SyncDir("gen/sub")},
	} {
		if !errors.Is(tc.err, ErrSymlink) && !errors.Is(tc.err, syscall.ENOTDIR) {
			t.Errorf("%s: %v", tc.name, tc.err)
		}
	}
	intact(t, victim)
	if _, err := os.Stat(filepath.Join(outside, "new")); err == nil {
		t.Fatal("created outside")
	}
	if st, err := o.Stat("gen/file"); err != nil || st.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Stat followed the link: %v %v", st, err)
	}
	for _, bad := range []string{"../outside/victim", "/etc/passwd", "gen/../../outside/victim"} {
		if _, err := o.OpenFile(bad, os.O_RDONLY, 0); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	fifo := filepath.Join(o.Root, "gen", "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := o.OpenFile("gen/fifo", os.O_RDONLY, 0); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrSymlink) {
			t.Fatalf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("open of a planted FIFO blocked")
	}
	// ordinary operations still work
	if err := o.MkdirAll("a/b/c", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(o, "a/b/c/f", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(o, "a/b/c/f", 10); err != nil || string(b) != "ok" {
		t.Fatal(b, err)
	}
	if ents, err := o.ReadDir("."); err != nil || len(ents) != 2 {
		t.Fatal(ents, err)
	}
	if err := o.Rename("a/b/c/f", "a/g"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAll(o, "a"); err != nil {
		t.Fatal(err)
	}
	unlock, err := o.Lock("writer.lock")
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
