package index

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"stash/internal/blob"
	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

type golden struct {
	GenerationID string `json:"generation_id"`
	ArchiveID    string `json:"archive_id"`
	BlobOrdinal  uint8  `json:"blob_ordinal"`
	HashID       uint8  `json:"hash_id"`
	Records      []struct {
		Hash      string `json:"hash"`
		Offset    uint64 `json:"offset"`
		Quanta    uint32 `json:"quanta"`
		BlockType uint8  `json:"block_type"`
		Ordinal   uint64 `json:"ordinal"`
	} `json:"records_unsorted"`
	BlobSize int64  `json:"blob_size"`
	FileHex  string `json:"file_hex"`
}

func TestGoldenIndexFile(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	gen, _ := strconv.ParseUint(g.GenerationID, 10, 64)
	aid, _ := hex.DecodeString(g.ArchiveID)
	h := &wire.ArchiveHeader{Mode: wire.ModeVariable, HashID: wire.HashID(g.HashID), BlobCount: 8, MaxFrameQuanta: 8,
		GenerationID: gen, ArchiveID: [32]byte(aid)}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	x := New(h, g.BlobOrdinal)
	for _, r := range g.Records {
		hb, _ := hex.DecodeString(r.Hash)
		x.Add(wire.IndexRecord{FrameHash: [32]byte(hb), PhysicalOffset: r.Offset, FrameQuanta: r.Quanta,
			BlockType: wire.BlockType(r.BlockType), FrameOrdinal: r.Ordinal})
	}
	c := vfs.NewCrashFS()
	c.MkdirAll("index", 0o755)
	if err := x.Write(c, "index/blob-07.idx"); err != nil {
		t.Fatal(err)
	}
	got, _ := vfs.ReadFile(c, "index/blob-07.idx", 1<<20)
	want, _ := hex.DecodeString(g.FileHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("index file differs from independent encoding\n got %x\nwant %x", got, want)
	}
	y, err := Load(c, "index/blob-07.idx", h, g.BlobOrdinal, g.BlobSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	if y.Len() != len(g.Records) || y.End() != g.BlobSize {
		t.Fatalf("len %d end %d", y.Len(), y.End())
	}
	hb, _ := hex.DecodeString(g.Records[0].Hash)
	if c := y.Lookup([32]byte(hb)); len(c) != 2 || c[0].PhysicalOffset >= c[1].PhysicalOffset {
		t.Fatalf("duplicate-hash lookup %+v", c)
	}
	if _, err := Load(c, "index/blob-07.idx", h, g.BlobOrdinal, g.BlobSize-1, nil); !errors.Is(err, ErrDiscard) {
		t.Fatalf("record past blob end accepted: %v", err)
	}
}

// --- fixtures over real blobs ---

func header() *wire.ArchiveHeader {
	h := &wire.ArchiveHeader{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 1, MaxFrameQuanta: 8, GenerationID: 3}
	h.ArchiveID[5] = 9
	return h
}

func spec(i int, payload string) *frame.Spec {
	return &frame.Spec{BlockType: wire.BlockData, Payload: []byte(payload), FrameOrdinal: uint64(i),
		Entries: []wire.Entry{{Path: fmt.Sprintf("f%d", i), Length: uint64(len(payload)), FileVer: 1}}}
}

const blobName, idxName = "frames/blob-00.stash", "index/blob-00.idx"

func setup(t *testing.T, payloads ...string) (*vfs.CrashFS, *wire.ArchiveHeader, *blob.Writer, []int64) {
	t.Helper()
	c := vfs.NewCrashFS()
	c.MkdirAll("frames", 0o755)
	c.MkdirAll("index", 0o755)
	h := header()
	if err := blob.Create(c, blobName, h); err != nil {
		t.Fatal(err)
	}
	w, _, err := blob.OpenWriter(c, blobName, h, nil, blob.Committed{})
	if err != nil {
		t.Fatal(err)
	}
	var offs []int64
	for i, p := range payloads {
		off, _, err := w.Append(spec(i, p))
		if err != nil {
			t.Fatal(err)
		}
		offs = append(offs, off)
	}
	w.Sync()
	return c, h, w, offs
}

func reader(t *testing.T, c vfs.FS, h *wire.ArchiveHeader) *blob.Reader {
	t.Helper()
	r, err := blob.Open(c, blobName, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func hashOf(s string) [32]byte {
	var x [32]byte
	f, _ := frame.Build(header(), spec(0, s))
	fr, _ := frame.Parse(f, header())
	x = fr.Trailer.HashPayload
	return x
}

func TestOpenMissingRebuildsThenLagging(t *testing.T) {
	c, h, w, _ := setup(t, "a", "b", "c")
	r := reader(t, c, h)
	x, st, err := Open(c, idxName, r, h, 0, nil)
	if err != nil || !st.Rebuilt || !errors.Is(st.Discarded, ErrDiscard) || x.Len() != 3 {
		t.Fatalf("%v %+v len %d", err, st, x.Len())
	}
	if err := x.Write(c, idxName); err != nil {
		t.Fatal(err)
	}
	w.Append(spec(3, "d"))
	w.Append(spec(4, "e"))
	w.Sync()
	x, st, err = Open(c, idxName, r, h, 0, nil)
	if err != nil || st.Rebuilt || st.CaughtUp != 2 || x.Len() != 5 {
		t.Fatalf("%v %+v len %d", err, st, x.Len())
	}
	if ref, how, err := x.Find(r, hashOf("e"), nil); err != nil || how != ViaIndex || string(ref.Payload) != "e" {
		t.Fatalf("find %v %v", how, err)
	} else {
		ref.Release()
	}
}

func TestStaleIdentityRebuilds(t *testing.T) {
	c, h, _, _ := setup(t, "a", "b")
	r := reader(t, c, h)
	x, _, _ := Build(r, h, 0)
	other := *h
	other.GenerationID = 2
	x.h = &other
	x.Write(c, idxName)
	_, st, err := Open(c, idxName, r, h, 0, nil)
	if err != nil || !st.Rebuilt {
		t.Fatalf("stale index used: %v %+v", err, st)
	}
}

func TestFindDuplicatesAndFallback(t *testing.T) {
	c, h, _, offs := setup(t, "same", "other", "same")
	r := reader(t, c, h)
	x, _, _ := Build(r, h, 0)
	want := func(path string) func(*blob.Ref) bool {
		return func(ref *blob.Ref) bool { return ref.Entries[0].Path == path }
	}
	ref, how, err := x.Find(r, hashOf("same"), want("f2"))
	if err != nil || how != ViaIndex || ref.Offset != offs[2] {
		t.Fatalf("duplicate resolution %v %v", how, err)
	}
	ref.Release()
	// an index missing the record: the scan finds it and flags the index
	empty := New(h, 0)
	ref, how, err = empty.Find(r, hashOf("other"), nil)
	if err != nil || how != ViaScan || ref.Offset != offs[1] {
		t.Fatalf("fallback %v %v", how, err)
	}
	ref.Release()
	// a wrong record (points at another frame) is rejected by validation
	bad := New(h, 0)
	bad.Add(wire.IndexRecord{FrameHash: hashOf("other"), PhysicalOffset: uint64(offs[0]), FrameQuanta: 1})
	if ref, how, _ = bad.Find(r, hashOf("other"), nil); how != ViaScan || ref.Offset != offs[1] {
		t.Fatalf("wrong candidate trusted: %v", how)
	}
	ref.Release()
	if _, how, err = x.Find(r, hashOf("nope"), nil); how != NotFound || err != nil {
		t.Fatalf("missing %v %v", how, err)
	}
}

// Every structural violation of §10.5.1 discards the whole index.
func TestLoadRejects(t *testing.T) {
	c, h, _, _ := setup(t, "a", "b", "c")
	r := reader(t, c, h)
	x, _, _ := Build(r, h, 0)
	x.Write(c, idxName)
	good, _ := vfs.ReadFile(c, idxName, 1<<20)
	size, _ := r.Size()
	rec := func(i int) int { return 64 + 64*i }
	put64 := func(b []byte, at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }
	cases := map[string]func(b []byte) []byte{
		"magic":         func(b []byte) []byte { b[0] = 'X'; return b },
		"version":       func(b []byte) []byte { b[8] = 5; return b },
		"header_size":   func(b []byte) []byte { b[10] = 63; return b },
		"generation":    func(b []byte) []byte { b[12] ^= 1; return b },
		"archive_id":    func(b []byte) []byte { b[20] ^= 1; return b },
		"blob_ordinal":  func(b []byte) []byte { b[52] = 1; return b },
		"hash_id":       func(b []byte) []byte { b[53] = 1; return b },
		"record_size":   func(b []byte) []byte { b[54] = 32; return b },
		"count+1":       func(b []byte) []byte { put64(b, 56, 4); return b },
		"count huge":    func(b []byte) []byte { put64(b, 56, 1<<60); return b },
		"trailing byte": func(b []byte) []byte { return append(b, 0) },
		"short":         func(b []byte) []byte { return b[:40] },
		"reserved":      func(b []byte) []byte { b[rec(1)+46] = 1; return b },
		"reserved2":     func(b []byte) []byte { b[rec(1)+60] = 1; return b },
		"block_type":    func(b []byte) []byte { b[rec(0)+44] = 3; return b },
		"off grid":      func(b []byte) []byte { b[rec(0)+32]++; return b },
		"quanta 0":      func(b []byte) []byte { binary.LittleEndian.PutUint32(b[rec(0)+40:], 0); return b },
		"quanta > max":  func(b []byte) []byte { binary.LittleEndian.PutUint32(b[rec(0)+40:], 9); return b },
		"past blob end": func(b []byte) []byte { put64(b, rec(2)+32, uint64(size)); return b },
		"order":         func(b []byte) []byte { copy(b[rec(0):rec(0)+32], bytes.Repeat([]byte{0xFF}, 32)); return b },
		"dup offset":    func(b []byte) []byte { copy(b[rec(1)+32:rec(1)+40], b[rec(0)+32:rec(0)+40]); return b },
		"too many recs": func(b []byte) []byte { return b }, // checked with a small blob size below
	}
	for name, mut := range cases {
		b := mut(append([]byte(nil), good...))
		vfs.ReplaceFile(c, idxName, b)
		bs := size
		if name == "too many recs" {
			bs = 0x40 + 2*4096
		}
		if _, err := Load(c, idxName, h, 0, bs, nil); !errors.Is(err, ErrDiscard) {
			t.Errorf("%s: %v", name, err)
		}
	}
	vfs.ReplaceFile(c, idxName, good)
	if _, err := Load(c, idxName, h, 0, size, nil); err != nil {
		t.Fatal(err)
	}
}

// A completed index rewrite survives any crash (the atomicity of the
// replace protocol itself is tested in vfs).
func TestCrashDuringWrite(t *testing.T) {
	c, h, w, _ := setup(t, "a", "b")
	r := reader(t, c, h)
	x, _, _ := Build(r, h, 0)
	x.Write(c, idxName)
	w.Append(spec(2, "c"))
	w.Sync()
	x.CatchUp(r)
	size, _ := r.Size()
	for seed := int64(0); seed < 50; seed++ {
		cc := c.Crash(vfs.CrashDropUnsynced, nil) // fresh copy to write into
		y := New(h, 0)
		for _, rr := range x.recs {
			y.Add(rr)
		}
		// write the new index but crash at a random point by tearing
		y.Write(cc, idxName)
		after := cc.Crash(vfs.CrashTear, rand.New(rand.NewSource(seed)))
		z, err := Load(after, idxName, h, 0, size, nil)
		if err != nil {
			t.Fatalf("seed %d: completed write not durable: %v", seed, err)
		}
		if z.Len() != 3 {
			t.Fatalf("seed %d: %d records", seed, z.Len())
		}
	}
}

func FuzzLoad(f *testing.F) {
	c, h, _, _ := setupF(f)
	good, _ := vfs.ReadFile(c, idxName, 1<<20)
	f.Add(good)
	f.Add(good[:64])
	f.Fuzz(func(t *testing.T, b []byte) {
		fsys := vfs.NewCrashFS()
		fsys.MkdirAll("index", 0o755)
		vfs.ReplaceFile(fsys, idxName, b)
		x, err := Load(fsys, idxName, h, 0, 0x40+16*4096, nil)
		if err != nil {
			if !errors.Is(err, ErrDiscard) {
				t.Fatalf("non-discard error %v", err)
			}
			return
		}
		if int64(len(b)) != 64+64*int64(x.Len()) {
			t.Fatal("size rule")
		}
	})
}

func setupF(f *testing.F) (*vfs.CrashFS, *wire.ArchiveHeader, *Index, int64) {
	c := vfs.NewCrashFS()
	c.MkdirAll("frames", 0o755)
	c.MkdirAll("index", 0o755)
	h := header()
	blob.Create(c, blobName, h)
	w, _, _ := blob.OpenWriter(c, blobName, h, nil, blob.Committed{})
	for i := 0; i < 3; i++ {
		w.Append(spec(i, fmt.Sprint(i)))
	}
	w.Sync()
	r, _ := blob.Open(c, blobName, h, nil)
	defer r.Close()
	x, _, _ := Build(r, h, 0)
	x.Write(c, idxName)
	size, _ := r.Size()
	return c, h, x, size
}

func BenchmarkLookup(b *testing.B) {
	h := header()
	x := New(h, 0)
	rng := rand.New(rand.NewSource(1))
	var keys [][32]byte
	for i := 0; i < 100000; i++ {
		var k [32]byte
		rng.Read(k[:])
		keys = append(keys, k)
		x.Add(wire.IndexRecord{FrameHash: k, PhysicalOffset: uint64(0x40 + i*4096), FrameQuanta: 1})
	}
	x.merge()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(x.Lookup(keys[i%len(keys)])) != 1 {
			b.Fatal("miss")
		}
	}
}

// The writer keeps the index in step with appends; a persisted index is
// identical to a rebuild and needs no catch-up.
func TestWriterPathMatchesRebuild(t *testing.T) {
	c, h, w, _ := setup(t)
	x := New(h, 0)
	for i := 0; i < 2500; i++ { // crosses the 1024-record merge batch
		rec, err := w.AppendIndexed(spec(i, fmt.Sprint(i%700)))
		if err != nil {
			t.Fatal(err)
		}
		x.Add(rec)
	}
	w.Sync()
	if err := x.Write(c, idxName); err != nil {
		t.Fatal(err)
	}
	r := reader(t, c, h)
	y, st, err := Open(c, idxName, r, h, 0, nil)
	if err != nil || st.Rebuilt || st.CaughtUp != 0 || y.Len() != 2500 {
		t.Fatalf("%v %+v %d", err, st, y.Len())
	}
	z, _, _ := Build(r, h, 0)
	z.Write(c, "index/rebuilt.idx")
	a, _ := vfs.ReadFile(c, idxName, 1<<30)
	b, _ := vfs.ReadFile(c, "index/rebuilt.idx", 1<<30)
	if !bytes.Equal(a, b) {
		t.Fatal("writer-maintained index differs from rebuild")
	}
	if n := len(y.Lookup(hashOf("5"))); n < 3 {
		t.Fatalf("payload-identical frames: %d candidates", n)
	}
}
