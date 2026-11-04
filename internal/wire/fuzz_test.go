package wire

import (
	"bytes"
	"testing"
)

// §17.3: decoders never panic, never allocate from untrusted sizes, and a
// value they accept re-encodes to the same bytes.

func FuzzDecodeArchiveHeader(f *testing.F) {
	h := testHeader()
	b, _ := h.AppendBinary(nil)
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := DecodeArchiveHeader(in)
		if err != nil {
			return
		}
		out, err := v.AppendBinary(nil)
		if err != nil || !bytes.Equal(out, in[:ArchiveHeaderSize]) {
			t.Fatalf("round trip: %x vs %x (%v)", out, in, err)
		}
	})
}

func FuzzDecodeRoot(f *testing.F) {
	f.Add((&Root{GenerationID: 1}).AppendBinary(nil))
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := DecodeRoot(in)
		if err != nil {
			return
		}
		if out := v.AppendBinary(nil); !bytes.Equal(out, in) {
			t.Fatal("round trip")
		}
	})
}

func FuzzDecodeFramePrefix(f *testing.F) {
	b, _ := FramePrefix{FrameQuanta: 2}.AppendBinary(nil)
	f.Add(b)
	h := testHeader()
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := DecodeFramePrefix(in, &h)
		if err != nil {
			return
		}
		out, _ := v.AppendBinary(nil)
		if !bytes.Equal(out, in[:FramePrefixSize]) {
			t.Fatal("round trip")
		}
	})
}

func FuzzDecodeMasterTrailer(f *testing.F) {
	tr := MasterTrailer{HashID: HashSHA256, BlockType: BlockData, FrameQuanta: 1}
	b, _ := tr.AppendBinary(nil)
	f.Add(b)
	h := testHeader()
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := DecodeMasterTrailer(in)
		if err != nil {
			return
		}
		out, _ := v.AppendBinary(nil)
		if !bytes.Equal(out, in) {
			t.Fatal("round trip")
		}
		_ = ValidateTrailer(&v, &h, FramePrefix{FrameQuanta: v.FrameQuanta})
	})
}

func FuzzDecodeAllocState(f *testing.F) {
	a := AllocState{Kind: AllocGroupID, GenerationID: 1, ReservedThrough: 99}
	b, _ := a.AppendBinary(nil)
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := DecodeAllocState(in)
		if err != nil {
			return
		}
		out, _ := v.AppendBinary(nil)
		if !bytes.Equal(out, in) {
			t.Fatal("round trip")
		}
	})
}

func FuzzDecodeIndex(f *testing.F) {
	ih := IndexHeader{HashID: HashSHA256}
	b, _ := ih.AppendBinary(nil)
	r := IndexRecord{PhysicalOffset: 0x40, FrameQuanta: 1}
	rb, _ := r.AppendBinary(nil)
	f.Add(append(b, rb...))
	h := testHeader()
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) < 128 {
			return
		}
		if v, err := DecodeIndexHeader(in[:64]); err == nil {
			out, _ := v.AppendBinary(nil)
			if !bytes.Equal(out, in[:64]) {
				t.Fatal("header round trip")
			}
		}
		if v, err := DecodeIndexRecord(in[64:128], &h); err == nil {
			out, _ := v.AppendBinary(nil)
			if !bytes.Equal(out, in[64:128]) {
				t.Fatal("record round trip")
			}
		}
	})
}

func FuzzDecodePathLen(f *testing.F) {
	f.Add([]byte{0x80, 0x20})
	f.Fuzz(func(t *testing.T, in []byte) {
		n, used, err := DecodePathLen(in)
		if err != nil {
			return
		}
		out, err := AppendPathLen(nil, n)
		if err != nil || !bytes.Equal(out, in[:used]) {
			t.Fatal("non-canonical accepted")
		}
	})
}

func FuzzDecodeFrameTail(f *testing.F) {
	f.Add(make([]byte, 4096))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 3*4096 {
			return
		}
		tail, err := DecodeFrameTail(in)
		if err != nil {
			return
		}
		if len(tail.Body) < 8 || len(tail.Body) > len(in)-FrameOverhead {
			t.Fatalf("body length %d outside bounds", len(tail.Body))
		}
	})
}
