package fusefs

import (
	"fmt"
	"strings"
	"testing"

	"stash"
)

// The snapshot answers directory queries from the sorted state without a
// tree in memory: children in name order with their kind, lookups,
// shadowing and the statfs totals.
func TestSnapshotTree(t *testing.T) {
	files := map[string][]byte{
		"a":       []byte("shadowed by a/"),
		"a/b":     []byte("b"),
		"a/c/d":   []byte("d"),
		"a/c/e":   []byte("e"),
		"a0":      []byte("a0"),
		"a-z":     []byte("dash sorts before /"),
		"ab/x":    []byte("x"),
		"b":       []byte("b"),
		"c/c/c/c": []byte("deep"),
	}
	for i := 0; i < 300; i++ {
		files[fmt.Sprintf("big/%03d", i)] = []byte{byte(i)}
	}
	for i := 0; i < 50; i++ {
		files[fmt.Sprintf("big/sub%02d/x", i)] = []byte{byte(i)}
	}
	dir := create(t, stash.CreateOptions{}, stash.Options{}, files)
	r, err := stash.OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSnapshot(r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.release()

	ls := func(d string) string {
		kids, err := s.children(d)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range kids {
			n := c.name
			if c.isDir {
				n += "/"
			}
			out = append(out, n)
		}
		return strings.Join(out, " ")
	}
	for _, w := range []struct{ dir, want string }{
		{"", "a/ a-z a0 ab/ b big/ c/"},
		{"a", "b c/"},
		{"a/c", "d e"},
		{"c/c", "c/"},
		{"ab", "x"},
	} {
		if got := ls(w.dir); got != w.want {
			t.Errorf("children(%q) = %q, want %q", w.dir, got, w.want)
		}
	}
	if kids, _ := s.children("big"); len(kids) != 350 || !kids[349].isDir || kids[0].name != "000" {
		t.Fatalf("big: %d entries", len(kids))
	}
	for p, want := range map[string]bool{"": true, "a": true, "a/c": true, "c/c/c": true, "b": false, "a/b": false, "nope": false, "a/c/d": false} {
		if got, err := s.isDir(p); err != nil || got != want {
			t.Errorf("isDir(%q) = %v %v", p, got, err)
		}
	}
	if _, ok, _ := s.file("a"); ok {
		t.Error("shadowed object is a file")
	}
	if in, ok, err := s.file("a/c/e"); err != nil || !ok || in.Size != 1 {
		t.Errorf("file a/c/e: %v %v %v", in, ok, err)
	}
	if _, ok, _ := s.file("a/c"); ok {
		t.Error("directory is a file")
	}
	if s.nshadow != 1 || fmt.Sprint(s.shadowed) != "[a]" {
		t.Fatalf("shadowed %d %v", s.nshadow, s.shadowed)
	}
	var bytes int64
	for p, d := range files {
		if p != "a" {
			bytes += int64(len(d))
		}
	}
	if s.files != int64(len(files)-1) || s.bytes != bytes {
		t.Fatalf("totals %d files %d bytes, want %d %d", s.files, s.bytes, len(files)-1, bytes)
	}
}
