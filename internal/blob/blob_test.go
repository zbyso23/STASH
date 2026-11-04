package blob

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"

	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

func header(mode wire.FrameSizeMode, q uint32) *wire.ArchiveHeader {
	h := &wire.ArchiveHeader{Mode: mode, HashID: wire.HashSHA256, BlobCount: 1, MaxFrameQuanta: q, GenerationID: 1}
	h.ArchiveID[0] = 0x5A
	if err := h.Validate(); err != nil {
		panic(err)
	}
	return h
}

func spec(i, n int) *frame.Spec {
	p := make([]byte, n)
	for j := range p {
		p[j] = byte(i*31 + j)
	}
	return &frame.Spec{BlockType: wire.BlockData, Payload: p, FrameOrdinal: uint64(i),
		Entries: []wire.Entry{{Path: fmt.Sprintf("obj/%d", i), Length: uint64(n), FileVer: 1}}}
}

func newBlob(t testing.TB, fsys vfs.FS, h *wire.ArchiveHeader) *Writer {
	t.Helper()
	fsys.MkdirAll("frames", 0o755)
	if err := Create(fsys, "frames/blob-00.stash", h); err != nil {
		t.Fatal(err)
	}
	w, _, err := OpenWriter(fsys, "frames/blob-00.stash", h, nil, Committed{})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func scanAll(t testing.TB, fsys vfs.FS, h *wire.ArchiveHeader) (ScanResult, []int64) {
	t.Helper()
	r, err := Open(fsys, "frames/blob-00.stash", h, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var offs []int64
	res, err := r.Scan(func(off int64, f *frame.Frame) error {
		offs = append(offs, off)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return res, offs
}

func TestName(t *testing.T) {
	if n, _ := Name(0xAB); n != "frames/blob-AB.stash" {
		t.Fatal(n)
	}
	if _, err := Name(0xFF); err == nil {
		t.Fatal("0xFF accepted")
	}
}

func TestAppendScanRead(t *testing.T) {
	for _, mode := range []wire.FrameSizeMode{wire.ModeVariable, wire.ModeFixed} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			c := vfs.NewCrashFS()
			h := header(mode, 4)
			w := newBlob(t, c, h)
			var offs []int64
			for i, n := range []int{0, 1, 3000, 4096*4 - 200, 5000} {
				off, size, err := w.Append(spec(i, n))
				if err != nil {
					t.Fatal(err)
				}
				if mode == wire.ModeFixed && (size != int64(h.MaxFrameSize()) || (off-0x40)%size != 0) {
					t.Fatalf("FIXED frame at %d size %d", off, size)
				}
				offs = append(offs, off)
			}
			if err := w.Sync(); err != nil {
				t.Fatal(err)
			}
			res, got := scanAll(t, c, h)
			if fmt.Sprint(got) != fmt.Sprint(offs) || res.End != res.Size || res.Err != nil {
				t.Fatalf("scan %v want %v (%+v)", got, offs, res)
			}
			r, _ := Open(c, "frames/blob-00.stash", h, nil)
			defer r.Close()
			for i, off := range offs {
				ref, err := r.ReadFrame(off)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ref.Payload, spec(i, len(ref.Payload)).Payload) || ref.Entries[0].Path != fmt.Sprintf("obj/%d", i) {
					t.Fatalf("frame %d content", i)
				}
				ref.Release()
				ref.Release()
			}
			if _, err := r.ReadFrame(offs[1] + 4096*1000); err == nil {
				t.Fatal("read past end")
			}
			if _, err := r.ReadFrame(0x41); err == nil {
				t.Fatal("off-grid read")
			}
		})
	}
}

func TestHeaderChecks(t *testing.T) {
	c := vfs.NewCrashFS()
	h := header(wire.ModeVariable, 4)
	newBlob(t, c, h).Close()
	other := *h
	other.GenerationID = 2
	if _, err := Open(c, "frames/blob-00.stash", &other, nil); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatalf("foreign header: %v", err)
	}
	if err := Create(c, "frames/blob-00.stash", h); err == nil {
		t.Fatal("Create overwrote an existing blob")
	}
}

// A crash inside Create leaves a file with an incomplete header and nothing
// else; OpenWriter re-initializes it.
func TestCrashDuringCreate(t *testing.T) {
	h := header(wire.ModeVariable, 4)
	c := vfs.NewCrashFS()
	c.MkdirAll("frames", 0o755)
	f, _ := c.OpenFile("frames/blob-00.stash", os.O_RDWR|os.O_CREATE, 0o644)
	f.WriteAt([]byte("STSH"), 0)
	f.Sync()
	c.SyncDir("frames")
	w, _, err := OpenWriter(c, "frames/blob-00.stash", h, nil, Committed{})
	if err != nil {
		t.Fatal(err)
	}
	w.Append(spec(0, 10))
	w.Sync()
	if res, offs := scanAll(t, c, h); len(offs) != 1 || res.End != res.Size {
		t.Fatal(res, offs)
	}
}

// committedSet models the manifest: frames (by offset, for assertions)
// whose commit was reported durable.
type committedSet map[int64]FrameKey

func (s committedSet) c() Committed {
	refs := map[FrameKey]struct{}{}
	for _, k := range s {
		refs[k] = struct{}{}
	}
	return Committed{Refs: refs}
}

// keyOf is the key a manifest loc would use for the frame built from s.
func keyOf(s *frame.Spec) FrameKey {
	e := s.Entries[0]
	return FrameKey{Hash: sha256.Sum256(s.Payload), Path: e.Path, FileVer: e.FileVer, Offset: e.Offset}
}

// Synced frames survive any crash under the tear model; the unsynced tail is
// truncated and appending continues.
func TestCrashTornTail(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	truncated := 0
	for seed := int64(0); seed < 300; seed++ {
		rng := rand.New(rand.NewSource(seed))
		c := vfs.NewCrashFS()
		w := newBlob(t, c, h)
		committed := committedSet{}
		var order []int64
		for i := 0; i < 1+rng.Intn(4); i++ {
			sp := spec(i, rng.Intn(20000))
			off, _, err := w.Append(sp)
			if err != nil {
				t.Fatal(err)
			}
			committed[off] = keyOf(sp)
			order = append(order, off)
		}
		w.Sync()
		for i := 0; i < rng.Intn(4); i++ {
			w.Append(spec(100+i, rng.Intn(30000)))
		}
		after := c.Crash(vfs.CrashTear, rng)
		w2, res, err := OpenWriter(after, "frames/blob-00.stash", h, nil, committed.c())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if res.Truncated > 0 {
			truncated++
		}
		_, offs := scanAll(t, after, h)
		for i, off := range order {
			if i >= len(offs) || offs[i] != off {
				t.Fatalf("seed %d: committed frame at %d lost (scan %v)", seed, off, offs)
			}
		}
		// the writer continues at E and the new frame is valid
		off, _, err := w2.Append(spec(999, 100))
		if err != nil || off != res.Scan.End {
			t.Fatalf("seed %d: append at %d, E %d: %v", seed, off, res.Scan.End, err)
		}
		w2.Sync()
		if r2, _ := scanAll(t, after, h); r2.End != r2.Size {
			t.Fatalf("seed %d: blob not clean after append: %+v", seed, r2)
		}
	}
	if truncated == 0 {
		t.Fatal("no seed produced a torn tail")
	}
}

// buildAt places raw frames at given offsets of a fresh synced blob.
func blobWith(t *testing.T, h *wire.ArchiveHeader, frames ...[]byte) (*vfs.CrashFS, []int64) {
	t.Helper()
	c := vfs.NewCrashFS()
	w := newBlob(t, c, h)
	var offs []int64
	for _, f := range frames {
		off, _, err := w.AppendEncoded(f)
		if err != nil {
			t.Fatal(err)
		}
		offs = append(offs, off)
	}
	w.Sync()
	w.Close()
	return c, offs
}

func build(t *testing.T, h *wire.ArchiveHeader, s *frame.Spec) []byte {
	t.Helper()
	b, err := frame.Build(h, s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func damage(t *testing.T, c vfs.FS, off int64) {
	t.Helper()
	f, _ := c.OpenFile("frames/blob-00.stash", os.O_RDWR, 0)
	f.WriteAt([]byte{0xFF, 0xFF}, off)
	f.Sync()
	f.Close()
}

// Pages persisted out of order: frame N torn, N+1 complete. Nothing
// references either, so the tail is truncated; if N+1 is referenced the blob
// is SEALED.
func TestOutOfOrderPersistence(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	a, b, x := build(t, h, spec(0, 100)), build(t, h, spec(1, 5000)), build(t, h, spec(2, 100))
	for _, refX := range []bool{false, true} {
		c, offs := blobWith(t, h, a, b, x)
		damage(t, c, offs[1]+5000) // inside b's payload: hash fails
		ref := committedSet{offs[0]: keyOf(spec(0, 100))}
		if refX {
			ref[offs[2]] = keyOf(spec(2, 100))
		}
		w, res, err := OpenWriter(c, "frames/blob-00.stash", h, nil, ref.c())
		if len(res.Tail) != 1 || res.Tail[0].Offset != offs[2] {
			t.Fatalf("tail %+v", res.Tail)
		}
		if refX {
			if !IsSealed(err) || w != nil {
				t.Fatalf("referenced frame beyond damage: %v", err)
			}
			if sz, _ := c.Stat("frames/blob-00.stash"); sz.Size() != offs[2]+int64(len(x)) {
				t.Fatal("sealed blob was modified")
			}
			continue
		}
		if err != nil || res.Scan.End != offs[1] || res.Truncated != int64(len(b)+len(x)) {
			t.Fatalf("err %v res %+v", err, res)
		}
		w.Close()
	}
}

// A group_id referenced elsewhere protects a frame beyond E (§10.4.2).
func TestTailGroupReference(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	h.ParityScheme, h.ParityK, h.ParityM, h.BlobCount = wire.ParityXOR, 2, 1, 3
	a := build(t, h, spec(0, 100))
	xs := spec(1, 100)
	xs.GroupID, xs.GroupIndex, xs.GroupK, xs.GroupM = 42, 0, 2, 1
	x := build(t, h, xs)
	d := build(t, h, spec(2, 100))
	c, offs := blobWith(t, h, a, d, x)
	damage(t, c, offs[1]+20)
	cm := committedSet{offs[0]: keyOf(spec(0, 100))}.c()
	cm.GroupReferenced = func(g uint32) bool { return g == 42 }
	if _, _, err := OpenWriter(c, "frames/blob-00.stash", h, nil, cm); !IsSealed(err) {
		t.Fatal(err)
	}
	cm.GroupReferenced = func(g uint32) bool { return false }
	w, res, err := OpenWriter(c, "frames/blob-00.stash", h, nil, cm)
	if err != nil || res.Scan.End != offs[1] {
		t.Fatal(err, res)
	}
	w.Close()
}

// A referenced frame that no longer validates (damage of §3.1.1 item 4)
// seals the blob too: committed data is never truncated.
func TestDamagedCommittedFrameSeals(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	c, offs := blobWith(t, h, build(t, h, spec(0, 100)), build(t, h, spec(1, 100)))
	damage(t, c, offs[1]+30)
	if _, _, err := OpenWriter(c, "frames/blob-00.stash", h, nil, committedSet{offs[0]: keyOf(spec(0, 100)), offs[1]: keyOf(spec(1, 100))}.c()); !IsSealed(err) {
		t.Fatal(err)
	}
}

func TestEmbeddedFrameInPayload(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	inner := build(t, h, spec(7, 300))
	payload := append(bytes.Repeat([]byte{'p'}, wire.BaseQuantum-wire.FramePrefixSize), inner...)
	payload = append(payload, bytes.Repeat([]byte{'q'}, 700)...)
	first := build(t, h, spec(0, 10))
	outer := build(t, h, &frame.Spec{BlockType: wire.BlockData, Payload: payload,
		Entries: []wire.Entry{{Path: "evil", Length: uint64(len(payload)), FileVer: 1}}})
	c, offs := blobWith(t, h, first, outer)
	// intact: a normal scan never probes inside a validated frame
	if res, got := scanAll(t, c, h); len(got) != 2 || res.End != res.Size {
		t.Fatalf("intact scan %v", got)
	}
	damage(t, c, offs[1]+int64(len(outer))-40) // tear the outer trailer
	w, res, err := OpenWriter(c, "frames/blob-00.stash", h, nil, committedSet{offs[0]: keyOf(spec(0, 10))}.c())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if len(res.Tail) != 1 || res.Tail[0].Offset != offs[1]+wire.BaseQuantum || res.Scan.End != offs[1] {
		t.Fatalf("tail %+v E %d", res.Tail, res.Scan.End)
	}
}

// Appending onto the page shared with the previous frame (§3.1.1) leaves the
// previous frame's bytes unchanged.
func TestSharedPageUnchanged(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	c := vfs.NewCrashFS()
	w := newBlob(t, c, h)
	off0, n0, _ := w.Append(spec(0, 1234))
	w.Sync()
	f, _ := c.OpenFile("frames/blob-00.stash", os.O_RDONLY, 0)
	before := make([]byte, n0)
	f.ReadAt(before, off0)
	w.Append(spec(1, 50))
	w.Sync()
	after := make([]byte, n0)
	f.ReadAt(after, off0)
	if !bytes.Equal(before, after) {
		t.Fatal("previous frame changed")
	}
	if (off0+n0)%4096 != 64 {
		t.Fatalf("frame boundary %d is not 64 bytes past a page", off0+n0)
	}
}

// On storage without atomic sector writes an append can damage the tail of
// the committed frame on the shared page. The writer must then either keep
// every committed frame or report SEALED; it never silently drops one.
func TestCrashGarbageNeverLosesCommitted(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	sealed := 0
	for seed := int64(0); seed < 300; seed++ {
		rng := rand.New(rand.NewSource(seed))
		c := vfs.NewCrashFS()
		w := newBlob(t, c, h)
		committed := committedSet{}
		var last int64
		for i := 0; i < 3; i++ {
			sp := spec(i, rng.Intn(9000))
			last, _, _ = w.Append(sp)
			committed[last] = keyOf(sp)
		}
		w.Sync()
		w.Append(spec(10, rng.Intn(9000)))
		w.Append(spec(11, rng.Intn(9000)))
		after := c.Crash(vfs.CrashTearGarbage, rng)
		_, res, err := OpenWriter(after, "frames/blob-00.stash", h, nil, committed.c())
		switch {
		case IsSealed(err):
			sealed++
		case err != nil:
			t.Fatalf("seed %d: %v", seed, err)
		default:
			if res.Scan.End <= last {
				t.Fatalf("seed %d: committed frame at %d truncated (E %d)", seed, last, res.Scan.End)
			}
		}
	}
	t.Logf("%d of 300 seeds damaged a committed frame and sealed the blob", sealed)
}

func TestConcurrentAppend(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	c := vfs.NewCrashFS()
	w := newBlob(t, c, h)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if _, _, err := w.Append(spec(g*1000+i, (g*i*977)%20000)); err != nil {
					t.Error(err)
					return
				}
				if i%10 == 0 {
					if err := w.Sync(); err != nil {
						t.Error(err)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	w.Sync()
	res, offs := scanAll(t, c, h)
	if len(offs) != 320 || res.End != res.Size || res.End != w.End() {
		t.Fatalf("%d frames, %+v", len(offs), res)
	}
}

type failFS struct {
	vfs.FS
	failWrite bool
}

type failFile struct {
	vfs.File
	fs *failFS
}

func (f failFS) OpenFile(n string, fl int, p os.FileMode) (vfs.File, error) {
	x, err := f.FS.OpenFile(n, fl, p)
	if err != nil {
		return nil, err
	}
	return failFile{x, &f}, nil
}

var errInjected = errors.New("injected I/O error")

func (f failFile) WriteAt(b []byte, off int64) (int, error) {
	if off >= wire.FrameAreaStart && f.fs.failWrite {
		return 0, errInjected
	}
	return f.File.WriteAt(b, off)
}

func TestPoisonAfterWriteError(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	c := vfs.NewCrashFS()
	c.MkdirAll("frames", 0o755)
	Create(c, "frames/blob-00.stash", h)
	w, _, err := OpenWriter(failFS{FS: c, failWrite: true}, "frames/blob-00.stash", h, nil, Committed{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Append(spec(0, 10)); !errors.Is(err, errInjected) {
		t.Fatal(err)
	}
	if _, _, err := w.Append(spec(1, 10)); !errors.Is(err, ErrPoisoned) {
		t.Fatal(err)
	}
	if err := w.Sync(); !errors.Is(err, ErrPoisoned) {
		t.Fatal(err)
	}
}

func benchAppend(b *testing.B, pool *bufpool.Pool) {
	h := header(wire.ModeVariable, 64)
	c := vfs.OS{Root: b.TempDir()}
	c.MkdirAll("frames", 0o755)
	Create(c, "frames/blob-00.stash", h)
	w, _, err := OpenWriter(c, "frames/blob-00.stash", h, pool, Committed{})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	s := spec(1, 60000)
	b.SetBytes(60000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := w.Append(s); err != nil {
			b.Fatal(err)
		}
	}
}

func benchScan(b *testing.B, pool *bufpool.Pool) {
	h := header(wire.ModeVariable, 64)
	c := vfs.OS{Root: b.TempDir()}
	c.MkdirAll("frames", 0o755)
	Create(c, "frames/blob-00.stash", h)
	w, _, _ := OpenWriter(c, "frames/blob-00.stash", h, pool, Committed{})
	for i := 0; i < 200; i++ {
		w.Append(spec(i, 60000))
	}
	w.Close()
	r, _ := Open(c, "frames/blob-00.stash", h, pool)
	defer r.Close()
	b.SetBytes(200 * 60000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res, err := r.Scan(nil); err != nil || res.Frames != 200 {
			b.Fatal(res, err)
		}
	}
}

// noPool retains nothing, so every Get allocates.
func noPool() *bufpool.Pool { return bufpool.New(1) }

func BenchmarkAppendPooled(b *testing.B)   { benchAppend(b, bufpool.New(0)) }
func BenchmarkAppendUnpooled(b *testing.B) { benchAppend(b, noPool()) }
func BenchmarkScanPooled(b *testing.B)     { benchScan(b, bufpool.New(0)) }
func BenchmarkScanUnpooled(b *testing.B)   { benchScan(b, noPool()) }

func benchAppendParallel(b *testing.B, pool *bufpool.Pool) {
	h := header(wire.ModeVariable, 64)
	c := vfs.OS{Root: b.TempDir()}
	c.MkdirAll("frames", 0o755)
	Create(c, "frames/blob-00.stash", h)
	w, _, err := OpenWriter(c, "frames/blob-00.stash", h, pool, Committed{})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	s := spec(1, 60000)
	b.SetBytes(60000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, err := w.Append(s); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkAppendParallelPooled(b *testing.B)   { benchAppendParallel(b, bufpool.New(0)) }
func BenchmarkAppendParallelUnpooled(b *testing.B) { benchAppendParallel(b, noPool()) }

// A payload-identical frame of another object before E does not satisfy a
// reference: keys include the object metadata (§9.1).
func TestRefKeyIncludesObject(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	same := func(i int) *frame.Spec {
		s := spec(i, 100)
		s.Payload = bytes.Repeat([]byte{9}, 100)
		return s
	}
	c, offs := blobWith(t, h, build(t, h, same(0)), build(t, h, spec(1, 100)), build(t, h, same(2)))
	damage(t, c, offs[1]+30)
	cm := committedSet{offs[0]: keyOf(same(0)), offs[2]: keyOf(same(2))}.c()
	if _, _, err := OpenWriter(c, "frames/blob-00.stash", h, nil, cm); !IsSealed(err) {
		t.Fatal(err)
	}
}
