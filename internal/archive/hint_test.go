package archive

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"stash/internal/vfs"
)

// objects sharing most of their 4 KiB extents: every shared extent has the
// same frame_hash in many frames
func sharedObjects(n int) map[string][]byte {
	common := data(1, 4096)
	out := map[string][]byte{}
	for i := 0; i < n; i++ {
		var b bytes.Buffer
		for j := 0; j < 6; j++ {
			if j == i%6 {
				b.Write(data(1000+i, 4096)) // one extent of its own
			} else {
				b.Write(common)
			}
		}
		out[fmt.Sprintf("obj/%04d", i)] = b.Bytes()
	}
	return out
}

func writeShared(t *testing.T, fsys vfs.FS, files map[string][]byte) {
	t.Helper()
	mustCreate(t, fsys)
	w, err := OpenWriter(fsys, Options{MaxExtent: 4096, PackThreshold: -1})
	if err != nil {
		t.Fatal(err)
	}
	for p, d := range files {
		if _, err := w.Put(p, d); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// Reads among payload-identical frames go through locator hints after
// one group read, and return the right object's bytes.
func TestLocatorHints(t *testing.T) {
	fsys := vfs.NewCrashFS()
	files := sharedObjects(200)
	writeShared(t, fsys, files)
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for pass := 0; pass < 2; pass++ {
		for p, want := range files {
			got, err := r.Get(p)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("pass %d %s: %v", pass, p, err)
			}
		}
	}
	// the common extent is one group per blob; each is learned once
	if n := r.view.learned.Load(); n == 0 || n > uint64(r.h.BlobCount) {
		t.Fatalf("%d groups learned", n)
	}
	// second pass: every shared extent (5 per object) via its hint
	if h := r.view.hinted.Load(); h < 200*5 {
		t.Fatalf("%d hinted reads", h)
	}
	// a writer learns the same way, also for objects of its own session
	w, err := OpenWriter(fsys, Options{MaxExtent: 4096, PackThreshold: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	more := sharedObjects(260)
	for p, d := range more {
		if _, ok := files[p]; !ok {
			if _, err := w.Put(p, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	for pass := 0; pass < 2; pass++ {
		for p, want := range more {
			got, err := w.Get(p)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("writer pass %d %s: %v", pass, p, err)
			}
		}
	}
	if h := w.view.hinted.Load(); h < 260*5 {
		t.Fatalf("writer: %d hinted reads", h)
	}
}

type fakeHints struct {
	b    uint8
	phys uint64
	err  error
}

func (f fakeHints) Hint(string, uint64, uint64) (uint8, uint64, bool, error) {
	return f.b, f.phys, f.err == nil, f.err
}
func (fakeHints) SetHint(string, uint64, uint64, uint8, uint64) error { return nil }

// A hint is never authoritative: pointing at another object's identical
// frame, at a non-frame offset, at another blob, or failing to read, it
// costs a miss and the read is still exact.
func TestWrongHints(t *testing.T) {
	fsys := vfs.NewCrashFS()
	files := sharedObjects(24)
	writeShared(t, fsys, files)
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// an offset of a real frame with the common hash, of some object
	v, _, err := r.st.Lookup("obj/0000")
	if err != nil {
		t.Fatal(err)
	}
	l := v.Loc[1] // common content
	recs := r.blobs[l.Blob].idx.Lookup(l.Hash)
	if len(recs) < 2 {
		t.Fatalf("%d frames share the hash", len(recs))
	}
	for _, h := range []fakeHints{
		{b: l.Blob, phys: recs[len(recs)-1].PhysicalOffset}, // another object's frame
		{b: l.Blob, phys: recs[0].PhysicalOffset + 4096},    // inside a frame
		{b: l.Blob ^ 1, phys: recs[0].PhysicalOffset},       // another blob
		{b: l.Blob, phys: 1 << 40},                          // past the end
		{err: errors.New("scratch gone")},
	} {
		r.view.hints = h
		for p, want := range files {
			got, err := r.Get(p)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("hint %+v: %s: %v", h, p, err)
			}
		}
	}
}
