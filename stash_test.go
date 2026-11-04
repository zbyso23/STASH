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
	_, a := newArchive(b, o)
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
