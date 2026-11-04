package frame

import (
	"bytes"
	"testing"

	"stash/internal/wire"
)

// AppendFrame into a dirty, reused buffer must produce exactly the bytes of
// Build (padding is zeroed explicitly, nothing from the old content leaks).
func TestAppendFrameDirtyBuffer(t *testing.T) {
	h := baseline()
	specs := []*Spec{dataSpec(0), dataSpec(1), dataSpec(3000), dataSpec(4096*3 - 200)}
	packed := &Spec{BlockType: wire.BlockPacked, Payload: []byte("abcdef"),
		Entries: []wire.Entry{{Path: "a", Offset: 0, Length: 3, FileVer: 1}, {Path: "b", Offset: 3, Length: 3, FileVer: 2}}}
	specs = append(specs, packed)
	for i, s := range specs {
		want, err := Build(&h, s)
		if err != nil {
			t.Fatal(i, err)
		}
		dirty := bytes.Repeat([]byte{0xA5}, len(want)+100)
		prefix := []byte("keep")
		dst := append(dirty[:0], prefix...)
		got, err := AppendFrame(dst, &h, s)
		if err != nil {
			t.Fatal(i, err)
		}
		if !bytes.Equal(got[:4], prefix) || !bytes.Equal(got[4:], want) {
			t.Fatalf("spec %d: AppendFrame differs from Build", i)
		}
		if _, err := Parse(got[4:], &h); err != nil {
			t.Fatal(i, err)
		}
	}
}

func TestAppendFrameErrorKeepsDst(t *testing.T) {
	h := baseline()
	dst := []byte("xyz")
	bad := dataSpec(10)
	bad.Entries[0].Length = 11
	out, err := AppendFrame(dst, &h, bad)
	if err == nil || string(out) != "xyz" {
		t.Fatalf("err %v out %q", err, out)
	}
}

func TestAppendFrameNoAllocs(t *testing.T) {
	h := baseline()
	s := dataSpec(60000)
	buf := make([]byte, 0, h.MaxFrameSize())
	allocs := testing.AllocsPerRun(50, func() {
		if _, err := AppendFrame(buf[:0], &h, s); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 0 {
		t.Fatalf("%v allocations per frame", allocs)
	}
}

func BenchmarkAppendFrame64K(b *testing.B) {
	h := baseline()
	s := dataSpec(60000)
	buf := make([]byte, 0, h.MaxFrameSize())
	b.SetBytes(60000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := AppendFrame(buf[:0], &h, s); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuild64K(b *testing.B) {
	h := baseline()
	s := dataSpec(60000)
	b.SetBytes(60000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Build(&h, s); err != nil {
			b.Fatal(err)
		}
	}
}
