package archive

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"testing"

	"stash/internal/blob"
	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// dataFrames returns, per live DATA frame of the current generation, the
// logical length and the frame size.
func dataFrames(t testing.TB, fsys vfs.FS, key []byte) (logical []uint64, quanta []uint32) {
	t.Helper()
	root, _ := readRoot(fsys)
	h, _ := readHeader(fsys, GenDir(root.GenerationID), root)
	k, _ := archiveKeys(fsys, h, key)
	for b := 0; b < int(h.BlobCount); b++ {
		name, _ := blob.Name(uint8(b))
		r, err := blob.OpenKeyed(fsys, path.Join(GenDir(root.GenerationID), name), h, nil, k)
		if err != nil {
			t.Fatal(err)
		}
		r.Scan(func(_ int64, f *frame.Frame) error {
			if f.Trailer.BlockType == wire.BlockData {
				n, _ := f.LogicalLength()
				logical = append(logical, n)
				quanta = append(quanta, f.Trailer.FrameQuanta)
			}
			return nil
		})
		r.Close()
	}
	return
}

// mixed is compressible text with incompressible runs, so the split has
// to shrink extents in the middle of a window.
func mixed(seed, n int) []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < n; i++ {
		if i%3 == 2 {
			b.Write(data(seed+i, 20000))
		} else {
			b.Write(text(seed+i, 50000))
		}
	}
	return b.Bytes()[:n]
}

// §6.6.1: with a compressing codec the writer puts as many logical bytes
// into a frame as compress into it, up to MAX_FRAME_SIZE; the frame stays
// within its physical limit; everything reads back, verifies and compacts. UncompressedExtents restores the M15 writer.
func TestCompressedExtents(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		c    Config
		key  []byte
	}{
		{"variable", Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16, Codec: wire.CodecZstdDefault}, nil},
		{"fixed_encrypted", Config{Mode: wire.ModeFixed, HashID: wire.HashBLAKE3, BlobCount: 2, MaxFrameQuanta: 8, Codec: wire.CodecZstdFast}, testKey},
		{"rs_encrypted", parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable), testKey},
		{"xor_fixed", parityCfg(wire.ParityXOR, 2, 1, 3, wire.ModeFixed), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, uncompressed := range []bool{false, true} {
				fsys := vfs.NewCrashFS()
				c := tc.c
				c.Key = tc.key
				if c.Codec == wire.CodecStore {
					c.Codec = wire.CodecZstdDense
				}
				h, err := Create(fsys, c)
				if err != nil {
					t.Fatal(err)
				}
				w, err := OpenWriter(fsys, Options{Key: tc.key, UncompressedExtents: uncompressed})
				if err != nil {
					t.Fatal(err)
				}
				want := map[string][]byte{
					"text":   text(1, 3<<20+77),
					"mixed":  mixed(2, 2<<20+5),
					"random": data(3, 700000),
					"one":    text(4, int(h.MaxFrameSize())), // exactly one window
				}
				for p, d := range want {
					if _, err := w.Put(p, d); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := w.PutReader(ctx, "stream", bytes.NewReader(want["mixed"])); err != nil {
					t.Fatal(err)
				}
				want["stream"] = want["mixed"]
				capacity := uint64(w.frameCapacity("mixed"))
				logical, quanta := dataFrames(t, fsys, tc.key)
				var above int
				for i, n := range logical {
					if n > h.MaxFrameSize() || quanta[i] > h.MaxFrameQuanta {
						t.Fatalf("frame %d: logical %d quanta %d", i, n, quanta[i])
					}
					if n > capacity {
						above++
					}
				}
				if uncompressed != (above == 0) {
					t.Fatalf("uncompressed=%v: %d of %d frames above capacity %d", uncompressed, above, len(logical), capacity)
				}
				t.Logf("uncompressed=%v: %d DATA frames, %d above the uncompressed capacity", uncompressed, len(logical), above)
				checkWriter(t, w, want)
				o, _ := w.Open("text")
				part := make([]byte, 100000)
				if _, err := o.ReadAt(part, 1<<20+333); err != nil || !bytes.Equal(part, want["text"][1<<20+333:][:100000]) {
					t.Fatal("ReadAt", err)
				}
				o.Close()
				w.Close()
				w, err = OpenWriter(fsys, Options{Key: tc.key})
				if err != nil {
					t.Fatal(err)
				}
				checkWriter(t, w, want)
				if rep, err := w.Verify(ctx); err != nil || !rep.OK() {
					t.Fatal(rep, err)
				}
				if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
					t.Fatal(err)
				}
				checkWriter(t, w, want)
				w.Close()
			}
		})
	}
}

// Many concurrent compressed Puts with small MaxExtent windows and a
// cancelled stream: no buffer is leaked or reused while in flight.
func TestCompressedExtentsConcurrent(t *testing.T) {
	fsys := vfs.NewCrashFS()
	c := parityCfg(wire.ParityRS, 2, 1, 4, wire.ModeVariable)
	c.Codec = wire.CodecZstdFast
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWriter(fsys, Options{MaxExtent: 40000})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{}
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		p := fmt.Sprintf("c%d", i)
		want[p] = mixed(i*7, 300000+i*1000)
		go func(p string, d []byte) { _, err := w.Put(p, d); errs <- err }(p, want[p])
	}
	for i := 0; i < 16; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.PutReader(ctx, "cancelled", bytes.NewReader(text(1, 1<<20))); err == nil {
		t.Fatal("cancelled stream committed")
	}
	checkWriter(t, w, want)
	w.Close()
}
