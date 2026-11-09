package stash_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/iotest"

	"stash"
)

func rnd(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func newArchive(t testing.TB, o stash.CreateOptions) (string, *stash.Archive) {
	dir := t.TempDir()
	if err := stash.Create(dir, o); err != nil {
		t.Fatal(err)
	}
	a, err := stash.Open(dir, stash.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return dir, a
}

func TestPublicRoundTrip(t *testing.T) {
	for _, o := range []stash.CreateOptions{{}, {Mode: stash.Fixed, MaxFrameSize: 64 << 10, Blobs: 2}, {Hash: stash.BLAKE3, Blobs: 1}} {
		dir, a := newArchive(t, o)
		files := map[string][]byte{"a": nil, "b/c.txt": []byte("hello"), "big.bin": rnd(1, 9<<20+123)}
		for p, d := range files {
			if _, err := a.Put(p, d); err != nil {
				t.Fatal(err)
			}
		}
		for p, d := range files {
			got, err := a.Get(p)
			if err != nil || !bytes.Equal(got, d) {
				t.Fatalf("%+v %s: %v", o, p, err)
			}
		}
		info, _ := a.Stat("big.bin")
		if info.Size != 9<<20+123 || info.Extents < 3 {
			t.Fatalf("%+v", info)
		}
		a.Close()
		r, err := stash.OpenReadOnly(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := r.Get("b/c.txt"); string(got) != "hello" {
			t.Fatal(string(got))
		}
		if l := r.List(); len(l) != 3 {
			t.Fatal(l)
		}
		r.Close()
	}
}

func TestNFCPaths(t *testing.T) {
	_, a := newArchive(t, stash.CreateOptions{})
	defer a.Close()
	if _, err := a.Put("café", []byte("x")); err != nil { // decomposed é
		t.Fatal(err)
	}
	if got, err := a.Get("café"); err != nil || string(got) != "x" { // composed é
		t.Fatal(err)
	}
	for _, bad := range []string{"", "/abs", "a//b", "a/../b", "a\\b", "x\x01"} {
		if _, err := a.Put(bad, nil); !errors.Is(err, stash.ErrInvalid) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if _, err := a.Get("nope"); !errors.Is(err, stash.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestStreamingAndObject(t *testing.T) {
	_, a := newArchive(t, stash.CreateOptions{MaxFrameSize: 256 << 10})
	defer a.Close()
	want := rnd(7, 3<<20+777)
	// a reader that returns short reads exercises the chunking
	if _, err := a.PutReader(context.Background(), "s", iotest.HalfReader(bytes.NewReader(want))); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutReader(context.Background(), "empty", bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	o, err := a.OpenObject("s")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	all, err := io.ReadAll(o)
	if err != nil || !bytes.Equal(all, want) {
		t.Fatalf("ReadAll: %v", err)
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		off := rng.Intn(len(want))
		n := rng.Intn(600000)
		buf := make([]byte, n)
		m, err := o.ReadAt(buf, int64(off))
		if end := min(off+n, len(want)); m != end-off || !bytes.Equal(buf[:m], want[off:end]) || (end < off+n) != (err == io.EOF) {
			t.Fatalf("ReadAt(%d, %d) = %d, %v", off, n, m, err)
		}
	}
	if _, err := o.Seek(-10, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	tail, _ := io.ReadAll(o)
	if !bytes.Equal(tail, want[len(want)-10:]) {
		t.Fatal("seek")
	}
	e, _ := a.Get("empty")
	if len(e) != 0 {
		t.Fatal("empty object")
	}
}

type failingReader struct{ n int }

func (f *failingReader) Read(b []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("source broke")
	}
	n := min(len(b), f.n)
	f.n -= n
	return n, nil
}

func TestPutReaderFailureAndCancel(t *testing.T) {
	_, a := newArchive(t, stash.CreateOptions{})
	defer a.Close()
	a.Put("p", []byte("v1"))
	if _, err := a.PutReader(context.Background(), "p", &failingReader{n: 10 << 20}); err == nil {
		t.Fatal("source error lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.PutReader(ctx, "p", bytes.NewReader(rnd(1, 1<<20))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got, _ := a.Get("p"); string(got) != "v1" {
		t.Fatal("failed writes changed the object")
	}
	if _, err := a.Put("p", []byte("v2")); err != nil { // path free again
		t.Fatal(err)
	}
}

func TestConcurrentGroupCommit(t *testing.T) {
	dir, a := newArchive(t, stash.CreateOptions{})
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := a.Put(fmt.Sprintf("g%d/%d", g, i), rnd(int64(g*100+i), 2000)); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	a.Close()
	r, _ := stash.OpenReadOnly(dir)
	defer r.Close()
	if n := len(r.List()); n != 320 {
		t.Fatal(n)
	}
	for g := 0; g < 16; g++ {
		got, err := r.Get(fmt.Sprintf("g%d/19", g))
		if err != nil || !bytes.Equal(got, rnd(int64(g*100+19), 2000)) {
			t.Fatal(err)
		}
	}
}

func TestSingleWriter(t *testing.T) {
	dir, a := newArchive(t, stash.CreateOptions{})
	defer a.Close()
	if _, err := stash.Open(dir, stash.Options{}); !errors.Is(err, stash.ErrLocked) {
		t.Fatal(err)
	}
	if err := stash.Create(dir, stash.CreateOptions{}); err == nil {
		t.Fatal("created over an existing archive")
	}
}

func benchPut(b *testing.B, size, par int) { benchPutOpt(b, size, par, stash.CreateOptions{}) }

func benchPutOpt(b *testing.B, size, par int, o stash.CreateOptions) {
	benchPutOpen(b, size, par, o, stash.Options{})
}

func benchPutOpen(b *testing.B, size, par int, o stash.CreateOptions, oo stash.Options) {
	dir := b.TempDir()
	if err := stash.Create(dir, o); err != nil {
		b.Fatal(err)
	}
	a, err := stash.Open(dir, oo)
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	d := rnd(1, size)
	b.SetBytes(int64(size))
	if par == 0 {
		for i := 0; i < b.N; i++ {
			if _, err := a.Put(fmt.Sprintf("p%d", i), d); err != nil {
				b.Fatal(err)
			}
		}
		return
	}
	b.SetParallelism(par)
	var n sync.Mutex
	i := 0
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n.Lock()
			i++
			k := i
			n.Unlock()
			if _, err := a.Put(fmt.Sprintf("p%d", k), d); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// sequential, and 16 goroutines per CPU (group commit)
func BenchmarkPut64KSequential(b *testing.B) { benchPut(b, 64<<10, 0) }
func BenchmarkPut64KParallel(b *testing.B)   { benchPut(b, 64<<10, 16) }
func BenchmarkPut64MSequential(b *testing.B) { benchPut(b, 64<<20, 0) }

var rs42 = stash.CreateOptions{Blobs: 6, Parity: stash.Parity{Scheme: stash.ReedSolomon, K: 4, M: 2}}

func BenchmarkPut64KParallelRS42(b *testing.B) { benchPutOpt(b, 64<<10, 16, rs42) }
func BenchmarkPut64MRS42(b *testing.B)         { benchPutOpt(b, 64<<20, 0, rs42) }

// 4 KiB objects, 16 goroutines per CPU: PACKED vs one DATA frame each
func BenchmarkPut4KParallelPacked(b *testing.B) { benchPutOpt(b, 4<<10, 16, stash.CreateOptions{}) }
func BenchmarkPut4KParallelUnpacked(b *testing.B) {
	benchPutOpen(b, 4<<10, 16, stash.CreateOptions{}, stash.Options{PackThreshold: -1})
}
func BenchmarkPut4KParallelPackedRS42(b *testing.B) { benchPutOpt(b, 4<<10, 16, rs42) }
func BenchmarkPut4KParallelUnpackedRS42(b *testing.B) {
	benchPutOpen(b, 4<<10, 16, rs42, stash.Options{PackThreshold: -1})
}

func BenchmarkGet64M(b *testing.B) {
	_, a := newArchive(b, stash.CreateOptions{})
	defer a.Close()
	a.Put("x", rnd(1, 64<<20))
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Get("x"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestPublicParity(t *testing.T) {
	for _, o := range []stash.CreateOptions{
		{Blobs: 3, Parity: stash.Parity{Scheme: stash.XOR, K: 2}},
		{Blobs: 4, MaxFrameSize: 64 << 10, Parity: stash.Parity{Scheme: stash.ReedSolomon, K: 2, M: 2}},
	} {
		dir, a := newArchive(t, o)
		files := map[string][]byte{"a": nil, "b": []byte("hello"), "big": rnd(3, 700<<10+5)}
		for p, d := range files {
			if _, err := a.Put(p, d); err != nil {
				t.Fatal(err)
			}
		}
		if w := a.Health().ParityWarning; w != "" {
			t.Fatal(w)
		}
		a.Close()
		// lose one whole blob: the snapshot reader rebuilds from parity
		if err := os.Remove(filepath.Join(dir, "generation-0000000000000000", "frames", "blob-01.stash")); err != nil {
			t.Fatal(err)
		}
		r, err := stash.OpenReadOnly(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Unavailable()) != 1 {
			t.Fatalf("unavailable %v", r.Unavailable())
		}
		for p, d := range files {
			got, err := r.Get(p)
			if err != nil || !bytes.Equal(got, d) {
				t.Fatalf("%s: %v", p, err)
			}
		}
		if r.Repairs().Rebuilt == 0 {
			t.Fatal("nothing rebuilt")
		}
		r.Close()
	}
	bad := []stash.Parity{{Scheme: stash.XOR, K: 2, M: 2}, {Scheme: stash.ReedSolomon, K: 0, M: 1},
		{Scheme: stash.ReedSolomon, K: 200, M: 57}, {Scheme: stash.NoParity, K: 1}, {Scheme: 7, K: 1, M: 1}}
	for _, p := range bad {
		if err := stash.Create(t.TempDir(), stash.CreateOptions{Blobs: 4, Parity: p}); !errors.Is(err, stash.ErrInvalid) {
			t.Fatalf("%+v: %v", p, err)
		}
	}
	if err := stash.Create(t.TempDir(), stash.CreateOptions{Blobs: 1, Parity: stash.Parity{Scheme: stash.XOR, K: 2}}); err == nil {
		t.Fatal("parity with one blob")
	}
}

// streaming a 64 MiB object through the lazy reader (read-ahead)
func BenchmarkObjectCopy64M(b *testing.B) {
	_, a := newArchive(b, stash.CreateOptions{})
	defer a.Close()
	a.Put("x", rnd(1, 64<<20))
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o, err := a.OpenObject("x")
		if err != nil {
			b.Fatal(err)
		}
		if n, err := io.Copy(io.Discard, o); err != nil || n != 64<<20 {
			b.Fatal(n, err)
		}
		o.Close()
	}
}

// reading through parity with one of six blobs missing
func BenchmarkGet64MRS42LostBlob(b *testing.B) {
	dir, a := newArchive(b, rs42)
	a.Put("x", rnd(1, 64<<20))
	a.Close()
	os.Remove(filepath.Join(dir, "generation-0000000000000000", "frames", "blob-02.stash"))
	r, err := stash.OpenReadOnly(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Get("x"); err != nil {
			b.Fatal(err)
		}
	}
}

// Opening an archive with 256 MiB in 64 large objects and 20,000 small
// ones (writer: torn-tail scan of every blob, manifest replay, indexes).
var openDir struct {
	once sync.Once
	dir  string
}

func openFixture(b *testing.B) string {
	openDir.once.Do(func() {
		dir, err := os.MkdirTemp("", "stash-open-bench")
		if err != nil {
			b.Fatal(err)
		}
		stash.Create(dir, stash.CreateOptions{})
		a, err := stash.Open(dir, stash.Options{})
		if err != nil {
			b.Fatal(err)
		}
		big := rnd(1, 4<<20)
		for i := 0; i < 64; i++ {
			a.Put(fmt.Sprintf("big/%d", i), big)
		}
		var wg sync.WaitGroup
		for g := 0; g < 50; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 400; i++ {
					a.Put(fmt.Sprintf("small/%d/%d", g, i), big[:1000+i])
				}
			}()
		}
		wg.Wait()
		a.Close()
		openDir.dir = dir
	})
	return openDir.dir
}

func BenchmarkOpenWriter(b *testing.B) {
	dir := openFixture(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := stash.Open(dir, stash.Options{})
		if err != nil {
			b.Fatal(err)
		}
		a.Close()
	}
}

func BenchmarkOpenWriterVerifyAll(b *testing.B) {
	dir := openFixture(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := stash.Open(dir, stash.Options{VerifyAll: true})
		if err != nil {
			b.Fatal(err)
		}
		a.Close()
	}
}

func BenchmarkOpenReader(b *testing.B) {
	dir := openFixture(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := stash.OpenReadOnly(dir)
		if err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
}

func TestPublicCompactVerifyRecover(t *testing.T) {
	ctx := context.Background()
	dir, a := newArchive(t, stash.CreateOptions{Blobs: 5, MaxFrameSize: 256 << 10, Parity: stash.Parity{Scheme: stash.ReedSolomon, K: 3, M: 2}})
	want := map[string][]byte{}
	for i := 0; i < 30; i++ {
		p := fmt.Sprintf("f/%02d", i)
		want[p] = rnd(int64(i), []int{10, 3000, 90000, 1 << 20}[i%4])
		if _, err := a.Put(p, want[p]); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 30; i += 3 {
		p := fmt.Sprintf("f/%02d", i)
		a.Delete(p)
		delete(want, p)
	}
	r, err := stash.OpenReadOnly(dir) // pinned: survives the compaction
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Compact(ctx, stash.CompactOptions{})
	if err != nil || res.DestBytes >= res.SourceBytes || len(res.Removed) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	for p, d := range want {
		if got, err := r.Get(p); err != nil || !bytes.Equal(got, d) {
			t.Fatalf("pinned reader %s: %v", p, err)
		}
	}
	r.Close()
	if removed, err := a.GC(); err != nil || len(removed) != 1 {
		t.Fatalf("GC %v %v", removed, err)
	}
	rep, err := a.Verify(ctx)
	if err != nil || !rep.OK() || rep.Versions != len(want) {
		t.Fatalf("verify %v %+v", err, rep)
	}
	a.Close()

	rc, err := stash.Recover(dir, stash.RecoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	sel := rc.DefaultSelection()
	if len(sel) != len(want) {
		t.Fatalf("selection %d of %d", len(sel), len(want))
	}
	out := filepath.Join(t.TempDir(), "salvaged")
	if sr, err := stash.Salvage(ctx, rc, out, sel); err != nil || sr.Written != len(want) {
		t.Fatalf("%v %+v", err, sr)
	}
	s, err := stash.OpenReadOnlyWith(out, stash.ReadOptions{NoPin: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for p, d := range want {
		if got, err := s.Get(p); err != nil || !bytes.Equal(got, d) {
			t.Fatalf("salvaged %s: %v", p, err)
		}
	}
}

// BenchmarkCompact64M: 64 MiB of objects, half deleted, RS 4+2.
func BenchmarkCompact64M(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dir := b.TempDir()
		stash.Create(dir, stash.CreateOptions{Blobs: 6, Parity: stash.Parity{Scheme: stash.ReedSolomon, K: 4, M: 2}})
		a, _ := stash.Open(dir, stash.Options{})
		for j := 0; j < 64; j++ {
			a.Put(fmt.Sprintf("o/%02d", j), rnd(int64(j), 1<<20))
		}
		for j := 0; j < 64; j += 2 {
			a.Delete(fmt.Sprintf("o/%02d", j))
		}
		b.SetBytes(32 << 20)
		b.StartTimer()
		if _, err := a.Compact(context.Background(), stash.CompactOptions{}); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		a.Close()
	}
}

// BenchmarkRecover64M: raw recovery scan of 64 MiB without parity.
func BenchmarkRecover64M(b *testing.B) {
	dir := b.TempDir()
	stash.Create(dir, stash.CreateOptions{})
	a, _ := stash.Open(dir, stash.Options{})
	for j := 0; j < 64; j++ {
		a.Put(fmt.Sprintf("o/%02d", j), rnd(int64(j), 1<<20))
	}
	a.Close()
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc, err := stash.Recover(dir, stash.RecoverOptions{})
		if err != nil || len(rc.Versions) != 64 {
			b.Fatal(err)
		}
		rc.Close()
	}
}

func TestPublicHardened(t *testing.T) {
	ctx := context.Background()
	anc, err := stash.NewFileAnchor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := stash.Create(dir, stash.CreateOptions{Anchor: anc}); err != nil {
		t.Fatal(err)
	}
	if _, err := stash.Open(dir, stash.Options{}); !errors.Is(err, stash.ErrAnchorRequired) {
		t.Fatal(err)
	}
	a, err := stash.Open(dir, stash.Options{Anchor: anc})
	if err != nil {
		t.Fatal(err)
	}
	a.Put("x", []byte("anchored"))
	a.Put("y", rnd(1, 100000))
	if _, err := a.Compact(ctx, stash.CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	r, err := stash.OpenReadOnlyWith(dir, stash.ReadOptions{Anchor: anc})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get("x"); string(got) != "anchored" {
		t.Fatal("read")
	}
	r.Close()
	// enrollment of a STANDARD archive
	dir2, b := newArchive(t, stash.CreateOptions{})
	b.Put("z", []byte("1"))
	b.Close()
	if _, err := stash.Enroll(ctx, dir2, anc, "tester", func(string) {}); err != nil {
		t.Fatal(err)
	}
	if b, err = stash.Open(dir2, stash.Options{Anchor: anc}); err != nil {
		t.Fatal(err)
	}
	b.Close()
}

// BenchmarkPut64KParallelHardened: 64 writers, every commit batch advances
// a file anchor (one more durable replace per batch).
func BenchmarkPut64KParallelHardened(b *testing.B) {
	anc, _ := stash.NewFileAnchor(b.TempDir())
	dir := b.TempDir()
	stash.Create(dir, stash.CreateOptions{Anchor: anc})
	a, err := stash.Open(dir, stash.Options{Anchor: anc})
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	d := rnd(1, 64<<10)
	b.SetBytes(int64(len(d)))
	b.SetParallelism(16)
	var n int64
	var mu sync.Mutex
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			n++
			p := fmt.Sprintf("p/%d", n)
			mu.Unlock()
			if _, err := a.Put(p, d); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// The Secure and Fast profiles end to end on a real directory: write,
// reopen, read-only open, compaction, verification and recovery; keys are
// required and checked.
func TestPublicProfiles(t *testing.T) {
	key, err := stash.NewKey()
	if err != nil || len(key) != stash.KeySize {
		t.Fatal(err)
	}
	text := bytes.Repeat([]byte("compressible stash text "), 200000)
	for _, tc := range []struct {
		name string
		o    stash.CreateOptions
		key  []byte
	}{
		{"fast", stash.CreateOptions{Profile: stash.Fast}, nil},
		{"secure", stash.CreateOptions{Profile: stash.Secure, Key: key}, key},
		{"custom_dense_encrypted", stash.CreateOptions{Compression: stash.ZstdDense, Key: key, Parity: stash.Parity{Scheme: stash.ReedSolomon, K: 2, M: 1}, Blobs: 3}, key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := stash.Create(dir, tc.o); err != nil {
				t.Fatal(err)
			}
			a, err := stash.Open(dir, stash.Options{Key: tc.key})
			if err != nil {
				t.Fatal(err)
			}
			files := map[string][]byte{"empty": nil, "small": []byte("hi"), "text": text, "rand": rnd(7, 3<<20+5)}
			for p, d := range files {
				if _, err := a.Put(p, d); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.Compact(context.Background(), stash.CompactOptions{}); err != nil {
				t.Fatal(err)
			}
			if rep, err := a.Verify(context.Background()); err != nil || !rep.OK() {
				t.Fatal(rep, err)
			}
			a.Close()
			r, err := stash.OpenReadOnlyWith(dir, stash.ReadOptions{Key: tc.key})
			if err != nil {
				t.Fatal(err)
			}
			for p, d := range files {
				if got, err := r.Get(p); err != nil || !bytes.Equal(got, d) {
					t.Fatalf("%s: %v", p, err)
				}
			}
			r.Close()
			rc, err := stash.Recover(dir, stash.RecoverOptions{Key: tc.key})
			if err != nil {
				t.Fatal(err)
			}
			if n := len(rc.DefaultSelection()); n != len(files) {
				t.Fatalf("recovered %d", n)
			}
			rc.Close()
			if tc.key != nil {
				if _, err := stash.Open(dir, stash.Options{}); !errors.Is(err, stash.ErrKeyRequired) {
					t.Fatalf("no key: %v", err)
				}
				other, _ := stash.NewKey()
				if _, err := stash.OpenReadOnlyWith(dir, stash.ReadOptions{Key: other}); !errors.Is(err, stash.ErrWrongKey) {
					t.Fatalf("wrong key: %v", err)
				}
			}
		})
	}
	if err := stash.Create(t.TempDir(), stash.CreateOptions{Profile: stash.Secure}); !errors.Is(err, stash.ErrInvalid) {
		t.Fatalf("Secure without key: %v", err)
	}
}

// Secure (AES-256-GCM) and Fast (zstd level 1 on incompressible data: the
// encoder runs, then STORE is kept) against the BASELINE benchmarks above.
var benchKey = bytes.Repeat([]byte{7}, 32)

func BenchmarkPut64KParallelSecure(b *testing.B) {
	benchPutOpen(b, 64<<10, 16, stash.CreateOptions{Profile: stash.Secure, Key: benchKey}, stash.Options{Key: benchKey})
}
func BenchmarkPut64MSecure(b *testing.B) {
	benchPutOpen(b, 64<<20, 0, stash.CreateOptions{Profile: stash.Secure, Key: benchKey}, stash.Options{Key: benchKey})
}
func BenchmarkPut64MFast(b *testing.B) {
	benchPutOpt(b, 64<<20, 0, stash.CreateOptions{Profile: stash.Fast})
}

func BenchmarkGet64MSecureZstdText(b *testing.B) {
	dir := b.TempDir()
	if err := stash.Create(dir, stash.CreateOptions{Compression: stash.ZstdDefault, Key: benchKey}); err != nil {
		b.Fatal(err)
	}
	a, err := stash.Open(dir, stash.Options{Key: benchKey})
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	d := bytes.Repeat([]byte("STASH reference text, compressible. "), 64<<20/36+1)[:64<<20]
	a.Put("x", d)
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Get("x"); err != nil {
			b.Fatal(err)
		}
	}
}
