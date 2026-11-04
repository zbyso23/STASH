package bufpool

import (
	"sync"
	"testing"
)

func TestClasses(t *testing.T) {
	for _, tc := range []struct{ n, c int }{{0, 0}, {1, 0}, {4096, 0}, {4097, 1}, {8192, 1}, {1 << 24, 12}, {1<<24 + 1, 13}} {
		if got := classOf(tc.n); got != tc.c {
			t.Errorf("classOf(%d)=%d want %d", tc.n, got, tc.c)
		}
	}
}

func TestReuseAndCap(t *testing.T) {
	p := New(64 << 10)
	a := p.Get(5000)
	if len(a) != 5000 || cap(a) != 8192 {
		t.Fatalf("len %d cap %d", len(a), cap(a))
	}
	p.Put(a)
	b := p.Get(6000)
	if &a[:1][0] != &b[:1][0] || p.Hits.Load() != 1 {
		t.Fatal("buffer not reused")
	}
	p.Put(b)
	// fill past the cap: 64 KiB allows eight 8 KiB buffers
	var bs [][]byte
	for i := 0; i < 12; i++ {
		bs = append(bs, p.Get(8192))
	}
	for _, x := range bs {
		p.Put(x)
	}
	if p.Retained() > 64<<10 || p.Drops.Load() == 0 {
		t.Fatalf("retained %d drops %d", p.Retained(), p.Drops.Load())
	}
	p.Put(make([]byte, 100))     // foreign: ignored
	p.Put(make([]byte, 0, 5000)) // not a class size: ignored
	if p.Retained() > 64<<10 {
		t.Fatal("foreign buffer retained")
	}
	if big := p.Get(1<<24 + 1); len(big) != 1<<24+1 {
		t.Fatal("oversize")
	}
}

func TestConcurrent(t *testing.T) {
	p := New(1 << 20)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				b := p.Get(4096 << (i % 4))
				b[0] = byte(g)
				p.Put(b)
			}
		}(g)
	}
	wg.Wait()
	if p.Retained() > 1<<20 || p.Retained() < 0 {
		t.Fatalf("retained %d", p.Retained())
	}
}

func BenchmarkGetPut64K(b *testing.B) {
	p := New(0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.Put(p.Get(64 << 10))
	}
}
