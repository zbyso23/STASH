package blob

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

func packedSpec(i, n int) *frame.Spec {
	var payload []byte
	var es []wire.Entry
	for j := 0; j < n; j++ {
		d := []byte(fmt.Sprintf("frame %d object %d", i, j))
		es = append(es, wire.Entry{Path: fmt.Sprintf("p/%03d/%03d", i, j), FileVer: 1, Offset: uint64(len(payload)), Length: uint64(len(d))})
		payload = append(payload, d...)
	}
	return &frame.Spec{BlockType: wire.BlockPacked, Payload: payload, FrameOrdinal: uint64(i), Entries: es}
}

// Reading the frames of many small objects one after another parses each
// frame's entries once; a hit returns exactly what a parse returns, and
// bytes changed on disk are parsed (and rejected) again, never served
// from the cache.
func TestParseCache(t *testing.T) {
	c := vfs.NewCrashFS()
	h := header(wire.ModeVariable, 4)
	w := newBlob(t, c, h)
	var offs []int64
	for i := 0; i < parsedFrames+4; i++ {
		off, _, err := w.Append(packedSpec(i, 30))
		if err != nil {
			t.Fatal(err)
		}
		offs = append(offs, off)
	}
	w.Sync()
	w.Close()
	r, err := Open(c, "frames/blob-00.stash", h, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	read := func(i int) *Ref {
		t.Helper()
		ref, err := r.ReadFrame(offs[i])
		if err != nil {
			t.Fatal(err)
		}
		want := packedSpec(i, 30)
		if !bytes.Equal(ref.Payload, want.Payload) || len(ref.Entries) != 30 || ref.Entries[29] != want.Entries[29] ||
			ref.Trailer.FrameOrdinal != uint64(i) || len(ref.PreTrailer) == 0 || &ref.PreTrailer[0] != &ref.buf[cap(ref.buf)-cap(ref.PreTrailer)] {
			t.Fatalf("frame %d differs", i)
		}
		return ref
	}
	for i := 0; i < 3; i++ {
		for k := 0; k < 30; k++ { // one read per object of the frame
			ref := read(i)
			ref.Release()
		}
	}
	if hits, misses := r.ParseCacheStats(); hits != 87 || misses != 3 {
		t.Fatalf("hits %d misses %d", hits, misses)
	}
	// the cache keeps the newest parsedFrames frames
	for i := range offs {
		read(i).Release()
	}
	_, m0 := r.ParseCacheStats()
	read(0).Release()
	if _, m := r.ParseCacheStats(); m != m0+1 {
		t.Fatal("frame 0 was not evicted")
	}
	read(len(offs) - 1).Release()
	if _, m := r.ParseCacheStats(); m != m0+1 {
		t.Fatal("the newest frame was evicted")
	}
	// changed bytes: never a hit
	last := offs[len(offs)-1]
	f, _ := c.OpenFile("frames/blob-00.stash", 2, 0)
	f.WriteAt([]byte{'X'}, last+wire.FramePrefixSize+3)
	f.Close()
	if _, err := r.ReadFrame(last); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatalf("changed frame: %v", err)
	}
}
