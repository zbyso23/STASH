package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"path"
	"testing"

	"stash/internal/alloc"
	"stash/internal/anchor"
	"stash/internal/blob"
	"stash/internal/compress"
	"stash/internal/frame"
	"stash/internal/manifest"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

var testKey = bytes.Repeat([]byte{0x5A}, 32)

func eopen(t testing.TB, fsys vfs.FS, key []byte) *Writer {
	t.Helper()
	w, err := OpenWriter(fsys, Options{MaxExtent: 8192, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// text returns compressible data.
func text(seed, n int) []byte {
	r := rand.New(rand.NewSource(int64(seed)))
	words := []string{"stash ", "frame ", "parity ", "zstd ", "nonce ", "anchor ", "\n"}
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(words[r.Intn(len(words))])
	}
	return b.Bytes()[:n]
}

// mixedWorkload is workload plus compressible objects.
func mixedWorkload(t testing.TB, w *Writer, seed int) map[string][]byte {
	want := workload(t, w, seed)
	for i, n := range []int{0, 10, 3000, 20000, 70000} {
		p := fmt.Sprintf("t/%d", i)
		d := text(seed*10+i, n)
		if _, err := w.Put(p, d); err != nil {
			t.Fatal(err)
		}
		want[p] = d
	}
	return want
}

var profileCases = []struct {
	name  string
	codec wire.CodecID
	key   []byte
	base  Config
}{
	{"fast", wire.CodecZstdFast, nil, Config{Mode: wire.ModeVariable, HashID: wire.HashBLAKE3, BlobCount: 3, MaxFrameQuanta: 16}},
	{"dense_fixed", wire.CodecZstdDense, nil, Config{Mode: wire.ModeFixed, HashID: wire.HashSHA256, BlobCount: 2, MaxFrameQuanta: 4}},
	{"secure", wire.CodecStore, testKey, Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16}},
	{"secure_zstd_rs", wire.CodecZstdDefault, testKey, parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable)},
	{"secure_fixed_xor", wire.CodecZstdFast, testKey, parityCfg(wire.ParityXOR, 2, 1, 3, wire.ModeFixed)},
}

// Every profile combination: write, reopen, read, verify, compact, read
// again, recover with the key, recover keyless.
func TestProfiles(t *testing.T) {
	ctx := context.Background()
	for _, tc := range profileCases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := vfs.NewCrashFS()
			c := tc.base
			c.Codec, c.Key = tc.codec, tc.key
			h, err := Create(fsys, c)
			if err != nil {
				t.Fatal(err)
			}
			if h.Encrypted() != (tc.key != nil) || h.CodecID != tc.codec {
				t.Fatalf("header %+v", h)
			}
			w := eopen(t, fsys, tc.key)
			want := mixedWorkload(t, w, 3)
			w.Close()
			kinds := codecKinds(t, fsys, tc.key)
			if tc.codec != wire.CodecStore && kinds[tc.codec] == 0 {
				t.Fatalf("no %d frames: %v", tc.codec, kinds)
			}
			w = eopen(t, fsys, tc.key)
			checkWriter(t, w, want)
			rep, err := w.Verify(ctx)
			if err != nil || !rep.OK() {
				t.Fatalf("verify %+v %v", rep, err)
			}
			if _, err := w.Compact(ctx, CompactOptions{}); err != nil {
				t.Fatal(err)
			}
			checkWriter(t, w, want)
			w.Close()
			r, err := OpenReaderWith(fsys, ReaderOptions{Key: tc.key})
			if err != nil {
				t.Fatal(err)
			}
			checkAll(t, r.Get, want)
			r.Close()
			if tc.key != nil {
				if _, err := OpenReader(fsys, nil); !errors.Is(err, ErrKeyRequired) {
					t.Fatalf("keyless reader: %v", err)
				}
				bad := bytes.Clone(tc.key)
				bad[3] ^= 1
				if _, err := OpenWriter(fsys, Options{Key: bad}); !errors.Is(err, ErrWrongKey) {
					t.Fatalf("wrong key: %v", err)
				}
			} else if _, err := OpenWriter(fsys, Options{Key: testKey}); !errors.Is(err, wire.ErrInvalid) {
				t.Fatal("key accepted for an unencrypted archive")
			}
		})
	}
}

// codecKinds counts the live generation's DATA/PACKED frames by codec.
func codecKinds(t testing.TB, fsys vfs.FS, key []byte) map[wire.CodecID]int {
	t.Helper()
	root, _ := readRoot(fsys)
	h, _ := readHeader(fsys, GenDir(root.GenerationID), root)
	k, _ := archiveKeys(fsys, h, key)
	out := map[wire.CodecID]int{}
	for b := 0; b < int(h.BlobCount); b++ {
		name, _ := blob.Name(uint8(b))
		r, err := blob.OpenKeyed(fsys, path.Join(GenDir(root.GenerationID), name), h, nil, k)
		if err != nil {
			t.Fatal(err)
		}
		r.Scan(func(_ int64, f *frame.Frame) error {
			if f.Trailer.BlockType != wire.BlockParity {
				out[f.Trailer.CodecID]++
			}
			return nil
		})
		r.Close()
	}
	return out
}

// framesOf returns every DATA/PACKED frame's bytes of a generation by
// hash_payload.
func framesOf(t testing.TB, fsys vfs.FS, gen uint64) map[[32]byte][]byte {
	t.Helper()
	root := wire.Root{GenerationID: gen}
	rb, _ := readRoot(fsys)
	root.ArchiveID = rb.ArchiveID
	h, err := readHeader(fsys, GenDir(gen), root)
	if err != nil {
		t.Fatal(err)
	}
	out := map[[32]byte][]byte{}
	for b := 0; b < int(h.BlobCount); b++ {
		name, _ := blob.Name(uint8(b))
		r, err := blob.Open(fsys, path.Join(GenDir(gen), name), h, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Scan(func(off int64, f *frame.Frame) error {
			if f.Trailer.BlockType != wire.BlockParity {
				ref, _ := r.ReadFrame(off)
				out[f.Trailer.HashPayload] = bytes.Clone(ref.Bytes())
				ref.Release()
			}
			return nil
		})
		r.Close()
	}
	return out
}

// §13.3/§15.7/§17.9: encrypted compaction across several generations
// copies live frames byte for byte (nonce, ciphertext, tag, hash,
// frame_ordinal), and raw recovery after compaction decrypts with the
// stored nonce, not the current location.
func TestEncryptedCompactionOpaqueCopy(t *testing.T) {
	ctx := context.Background()
	fsys := vfs.NewCrashFS()
	c := Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16, Key: testKey, Codec: wire.CodecZstdFast}
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	w := eopen(t, fsys, testKey)
	big := text(1, 60000)
	if _, err := w.Put("big", big); err != nil {
		t.Fatal(err)
	}
	want := mixedWorkload(t, w, 4)
	want["big"] = big
	g0 := framesOf(t, fsys, 0)
	ver, _ := w.Stat("big")
	var gens []uint64
	for i := 0; i < 3; i++ {
		res, err := w.Compact(ctx, CompactOptions{KeepOld: true})
		if err != nil {
			t.Fatal(err)
		}
		gens = append(gens, res.To)
		cur := framesOf(t, fsys, res.To)
		for _, l := range ver.Loc { // DATA frames of "big" are copied unchanged
			if !bytes.Equal(cur[l.Hash], g0[l.Hash]) || cur[l.Hash] == nil {
				t.Fatalf("generation %d: frame %x not byte-identical", res.To, l.Hash[:4])
			}
			n := cur[l.Hash][16:28]
			if g, _, _ := seal.SplitFrameNonce(n); g != 0 {
				t.Fatalf("nonce names generation %d", g)
			}
		}
	}
	checkWriter(t, w, want)
	w.Close()
	// recovery of the newest generation (stored nonces of generation 0)
	rc := recoverWith(t, fsys, testKey)
	if v := rc["big"]; !bytes.Equal(v, big) {
		t.Fatal("recovered big differs")
	}
	t.Logf("generations %v", gens)
}

// recoverWith is a small keyed raw recovery through the view: every
// frame of the current generation is decrypted with its stored nonce.
func recoverWith(t testing.TB, fsys vfs.FS, key []byte) map[string][]byte {
	t.Helper()
	r, err := OpenReaderWith(fsys, ReaderOptions{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out := map[string][]byte{}
	for _, p := range r.List() {
		b, err := r.Get(p)
		if err != nil {
			t.Fatal(err)
		}
		out[p] = b
	}
	return out
}

// §2.1.3.1/§16.8: a rolled-back frame-ordinal allocator of an encrypted
// archive is detected from the stored nonces at cold start.
func TestEncryptedOrdinalRollback(t *testing.T) {
	fsys := vfs.NewCrashFS()
	c := cfg
	c.Key = testKey
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	name := path.Join(GenDir(0), alloc.FileName(wire.AllocFrameOrdinal, 0))
	before, _ := vfs.ReadFile(fsys, name, 1024)
	w := eopen(t, fsys, testKey)
	for i := 0; i < 20; i++ {
		w.Put(fmt.Sprintf("f%d", i), data(i, 9000))
	}
	w.Close()
	vfs.ReplaceFile(fsys, name, before)
	if _, err := OpenWriter(fsys, Options{Key: testKey}); !errors.Is(err, alloc.ErrRolledBack) {
		t.Fatalf("rollback not detected: %v", err)
	}
}

// §2.1.3.5: in an encrypted HARDENED archive allocator reservations are
// bound in the anchor before use; a local file below the anchored value is
// a security incident until acknowledged, then the writer continues from
// the anchored value.
func TestHardenedReservationBinding(t *testing.T) {
	a := anchor.NewMemory()
	fsys := vfs.NewCrashFS()
	c := hcfg(a)
	c.Key = testKey
	h, err := Create(fsys, c)
	if err != nil {
		t.Fatal(err)
	}
	st := anchoredOf(t, a)
	if len(st.Reservations) != 2+int(h.BlobCount) {
		t.Fatalf("initial reservations %+v", st.Reservations)
	}
	seqName := path.Join(GenDir(0), alloc.FileName(wire.AllocManifestSeq, 0))
	before, _ := vfs.ReadFile(fsys, seqName, 1024)
	w, err := OpenWriter(fsys, Options{Anchor: a, Key: testKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Put("a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	st = anchoredOf(t, a)
	var seqRes uint64
	for _, r := range st.Reservations {
		if r.Kind == wire.AllocManifestSeq {
			seqRes = r.ReservedThrough
		}
	}
	if seqRes <= 1 {
		t.Fatalf("seq reservation not anchored: %+v", st.Reservations)
	}
	// roll the local seq allocator back below the anchor
	vfs.ReplaceFile(fsys, seqName, before)
	if _, err := OpenWriter(fsys, Options{Anchor: a, Key: testKey}); !errors.Is(err, ErrAllocatorRollback) {
		t.Fatalf("allocator rollback: %v", err)
	}
	w, err = OpenWriter(fsys, Options{Anchor: a, Key: testKey, AcknowledgeAllocatorRollback: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Put("b", []byte("y")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	// the new record's seq is above the anchored reservation: no reuse
	var maxSeq uint64
	manifest.LoadWith(fsys, GenDir(0), h, manifest.LoadOptions{Crypto: &manifest.Crypto{Keys: mustKeys(t, h), GenerationID: 0}}, func(r *manifest.Record, _ int) {
		maxSeq = max(maxSeq, r.Seq)
	})
	if maxSeq < seqRes {
		t.Fatalf("seq %d reused below the anchored %d", maxSeq, seqRes)
	}
	// compaction switches with the destination's reservations
	w, err = OpenWriter(fsys, Options{Anchor: a, Key: testKey})
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.Compact(context.Background(), CompactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Put("c", []byte("z")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	st = anchoredOf(t, a)
	if st.GenerationID != res.To || len(st.Reservations) != 2+int(h.BlobCount) {
		t.Fatalf("after switch %+v", st)
	}
	r, err := OpenReaderWith(fsys, ReaderOptions{Anchor: a, Key: testKey})
	if err != nil {
		t.Fatal(err)
	}
	checkAll(t, r.Get, map[string][]byte{"a": []byte("x"), "b": []byte("y"), "c": []byte("z")})
	r.Close()
}

func mustKeys(t testing.TB, h *wire.ArchiveHeader) *seal.Keys {
	k, err := seal.New(testKey, h.ArchiveID)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// §6.6.1: a reader accepts a compressed extent whose logical length is
// up to MAX_FRAME_SIZE, far above what the frame could hold uncompressed.
func TestCompressedExtentBeyondPhysicalBudget(t *testing.T) {
	for _, key := range [][]byte{nil, testKey} {
		fsys := vfs.NewCrashFS()
		c := cfg // MAX_FRAME_SIZE 64 KiB
		c.Codec, c.Key = wire.CodecZstdDefault, key
		h, err := Create(fsys, c)
		if err != nil {
			t.Fatal(err)
		}
		w := eopen(t, fsys, key)
		logical := text(9, int(h.MaxFrameSize())) // exactly MAX_FRAME_SIZE
		codec, stored, err := compress.Encode(wire.CodecZstdDefault, logical, nil)
		if err != nil || codec == wire.CodecStore {
			t.Fatal("not compressible", err)
		}
		ord, _ := w.ordAlloc[0].Next()
		ver, _ := w.verAlloc.Next()
		s := &frame.Spec{BlockType: wire.BlockData, Codec: codec, Payload: stored, FrameOrdinal: ord,
			Entries: []wire.Entry{{Path: "dense", Length: uint64(len(logical)), FileVer: ver}}}
		rec, err := w.writers[0].AppendIndexed(s)
		if err != nil {
			t.Fatal(err)
		}
		if rec.FrameQuanta >= h.MaxFrameQuanta/2 {
			t.Fatalf("frame of %d quanta", rec.FrameQuanta)
		}
		w.blobs[0].idx.Add(rec)
		err = w.commit(&commitReq{path: "dense", fileVer: ver, blobs: map[int]bool{0: true},
			locs: []manifest.Loc{{Blob: 0, Hash: rec.FrameHash, Length: uint64(len(logical))}}})
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
		w = eopen(t, fsys, key)
		if got, err := w.Get("dense"); err != nil || !bytes.Equal(got, logical) {
			t.Fatal("read", err)
		}
		o, _ := w.Open("dense")
		part := make([]byte, 1000)
		if _, err := o.ReadAt(part, 60000); err != nil || !bytes.Equal(part, logical[60000:61000]) {
			t.Fatal("ReadAt", err)
		}
		o.Close()
		if rep, err := w.Verify(context.Background()); err != nil || !rep.OK() {
			t.Fatal(rep, err)
		}
		if _, err := w.Compact(context.Background(), CompactOptions{}); err != nil {
			t.Fatal(err)
		}
		if got, err := w.Get("dense"); err != nil || !bytes.Equal(got, logical) {
			t.Fatal("read after compaction", err)
		}
		w.Close()
	}
}

// Crash consistency of an encrypted, compressed archive (§16): every torn
// snapshot reopens with the key, holds a prefix of the returned operations
// (plus possibly the one in flight), verifies its live versions and accepts new writes
// with fresh nonces.
func TestEncryptedCrashDuringWorkload(t *testing.T) {
	for ci, c := range []Config{
		{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16, Codec: wire.CodecZstdFast},
		parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable),
	} {
		c.Key = testKey
		if ci == 1 {
			c.Codec = wire.CodecZstdDefault
		}
		for seed := int64(0); seed < 3; seed++ {
			rng := rand.New(rand.NewSource(seed))
			base := vfs.NewCrashFS()
			if _, err := Create(base, c); err != nil {
				t.Fatal(err)
			}
			s := &snapFS{CrashFS: base, rng: rng, every: 5}
			w := eopen(t, s, testKey)
			type op struct {
				path string
				data []byte
				at   int
			}
			var ops []op
			for i := 0; i < 25; i++ {
				p := fmt.Sprintf("f%d", rng.Intn(5))
				d := text(int(seed)*100+i, rng.Intn(25000))
				if i%3 == 0 {
					d = data(i, rng.Intn(9000))
				}
				if _, err := w.Put(p, d); err != nil {
					t.Fatal(err)
				}
				ops = append(ops, op{p, d, s.count()})
			}
			w.Close()
			for k, snap := range s.snaps {
				w2, err := OpenWriter(snap, Options{MaxExtent: 8192, Key: testKey})
				if err != nil {
					t.Fatalf("cfg %d seed %d snapshot %d: %v", ci, seed, k, err)
				}
				exp, alt := map[string][]byte{}, map[string][]byte{}
				var next *op
				for i := range ops {
					if ops[i].at <= k {
						exp[ops[i].path] = ops[i].data
					} else if next == nil {
						next = &ops[i]
					}
				}
				for p, d := range exp {
					alt[p] = d
				}
				if next != nil {
					alt[next.path] = next.data
				}
				for i := 0; i < 5; i++ {
					p := fmt.Sprintf("f%d", i)
					got, err := w2.Get(p)
					ok := func(want []byte) bool {
						if want == nil {
							return errors.Is(err, ErrNotFound)
						}
						return err == nil && bytes.Equal(got, want)
					}
					if !ok(exp[p]) && !ok(alt[p]) {
						t.Fatalf("cfg %d seed %d snapshot %d: %s wrong (%v)", ci, seed, k, p, err)
					}
				}
				// a torn group of uncommitted frames may show as degraded
				// (as without encryption); no live version may fail
				if rep, err := w2.Verify(context.Background()); err != nil || len(rep.Failed) != 0 || rep.Groups.Unrecoverable != 0 {
					t.Fatalf("cfg %d seed %d snapshot %d: verify %+v %v", ci, seed, k, rep, err)
				}
				if _, err := w2.Put("after", text(1, 20000)); err != nil {
					t.Fatalf("put after crash: %v", err)
				}
				w2.Close()
			}
		}
	}
}
