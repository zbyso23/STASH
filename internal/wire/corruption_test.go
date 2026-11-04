package wire

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func testHeader() ArchiveHeader {
	var id [32]byte
	for i := range id {
		id[i] = byte(0x20 + i)
	}
	return ArchiveHeader{Mode: ModeVariable, HashID: HashSHA256, CodecID: CodecStore, ParityScheme: ParityXOR,
		ParityK: 1, ParityM: 1, BlobCount: 2, MaxFrameQuanta: 4, ArchiveID: id}
}

// minParityFrame builds a valid 4096-byte PARITY frame with the production
// encoders (the golden test checks the same frame against independent bytes).
func minParityFrame(t *testing.T) []byte {
	t.Helper()
	f, err := FramePrefix{FrameQuanta: 1}.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	f = append(f, make([]byte, ParityShardLen(1))...)
	tr := MasterTrailer{HashID: HashSHA256, CodecID: CodecStore, BlockType: BlockParity, GroupID: 1, GroupIndex: 1,
		GroupK: 1, GroupM: 1, DataLen: uint32(ParityShardLen(1)), FrameQuanta: 1, FrameOrdinal: 7}
	tb, err := tr.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{0, 0, 0, 0}
	crc := OuterCRC(body, 8, tb)
	f = binary.LittleEndian.AppendUint32(f, 0)
	f = binary.LittleEndian.AppendUint32(f, crc)
	f = binary.LittleEndian.AppendUint32(f, 8)
	f = append(f, tb...)
	if len(f) != BaseQuantum {
		t.Fatalf("frame %d bytes", len(f))
	}
	return f
}

// §17.2: every single-bit flip of the Frame Prefix is rejected.
func TestPrefixEveryBitFlipRejected(t *testing.T) {
	h := testHeader()
	good, _ := FramePrefix{FrameQuanta: 3}.AppendBinary(nil)
	if _, err := DecodeFramePrefix(good, &h); err != nil {
		t.Fatal(err)
	}
	for bit := 0; bit < FramePrefixSize*8; bit++ {
		b := append([]byte(nil), good...)
		b[bit/8] ^= 1 << (bit % 8)
		if _, err := DecodeFramePrefix(b, &h); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("bit %d: flip accepted (err=%v)", bit, err)
		}
	}
}

// §17.2: every single-bit flip of the Master Trailer, and of pre_trailer_len
// and the minimal zero-entry Pre-Trailer, is rejected by the outer CRC before
// any trailer field is trusted.
func TestTrailerEveryBitFlipRejected(t *testing.T) {
	good := minParityFrame(t)
	if _, err := DecodeFrameTail(good); err != nil {
		t.Fatal(err)
	}
	tailStart := len(good) - MasterTrailerSize - PreTrailerLenSize - 8
	for bit := tailStart * 8; bit < len(good)*8; bit++ {
		b := append([]byte(nil), good...)
		b[bit/8] ^= 1 << (bit % 8)
		if _, err := DecodeFrameTail(b); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("byte %d bit %d: flip accepted (err=%v)", bit/8-tailStart, bit%8, err)
		}
	}
}

func TestHeaderRejections(t *testing.T) {
	base := testHeader()
	good, err := base.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		mut   func(b []byte)
		class error
	}{
		{"magic", func(b []byte) { b[0] = 'X' }, ErrCorrupt},
		{"legacy 0x0002", func(b []byte) { b[4] = 2 }, ErrLegacyVersion},
		{"legacy 0x0005", func(b []byte) { b[4] = 5 }, ErrLegacyVersion},
		{"future 0x0007", func(b []byte) { b[4] = 7 }, ErrUnsupported},
		{"version 0x0001", func(b []byte) { b[4] = 1 }, ErrUnsupported},
		{"mode", func(b []byte) { b[6] = 2 }, ErrUnsupported},
		{"hash 0", func(b []byte) { b[7] = 0 }, ErrUnsupported},
		{"hash 3", func(b []byte) { b[7] = 3 }, ErrUnsupported},
		{"codec 4", func(b []byte) { b[8] = 4 }, ErrUnsupported},
		{"parity 3", func(b []byte) { b[9] = 3 }, ErrUnsupported},
		{"xor m=2", func(b []byte) { b[11] = 2 }, ErrCorrupt},
		{"xor k=0", func(b []byte) { b[10] = 0 }, ErrCorrupt},
		{"none with k", func(b []byte) { b[9] = 0 }, ErrCorrupt},
		{"parity one blob", func(b []byte) { b[12] = 1 }, ErrCorrupt},
		{"blob_count 0", func(b []byte) { b[12] = 0 }, ErrCorrupt},
		{"flags bit1", func(b []byte) { b[13] = 2 }, ErrCorrupt},
		{"header_size", func(b []byte) { b[14] = 65 }, ErrCorrupt},
		{"max_frame_quanta 0", func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0) }, ErrCorrupt},
		{"max_frame_quanta max+1", func(b []byte) { binary.LittleEndian.PutUint32(b[16:], MaxMaxFrameQuanta+1) }, ErrCorrupt},
		{"max_frame_quanta MaxUint32", func(b []byte) { binary.LittleEndian.PutUint32(b[16:], math.MaxUint32) }, ErrCorrupt},
		{"reserved", func(b []byte) { b[30] = 1 }, ErrCorrupt},
	}
	for _, c := range cases {
		b := append([]byte(nil), good...)
		c.mut(b)
		if _, err := DecodeArchiveHeader(b); !errors.Is(err, c.class) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.class)
		}
	}
	// RS k+m > 256
	rs := base
	rs.ParityScheme, rs.ParityK, rs.ParityM = ParityRS, 200, 57
	if _, err := rs.AppendBinary(nil); !errors.Is(err, ErrCorrupt) {
		t.Errorf("k+m=257 accepted: %v", err)
	}
	rs.ParityM = 56
	if _, err := rs.AppendBinary(nil); err != nil {
		t.Errorf("k+m=256 rejected: %v", err)
	}
	// boundaries of max_frame_quanta that are valid
	for _, q := range []uint32{1, MaxMaxFrameQuanta} {
		v := base
		v.MaxFrameQuanta = q
		b, err := v.AppendBinary(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeArchiveHeader(b); err != nil {
			t.Errorf("max_frame_quanta %d rejected: %v", q, err)
		}
	}
	// truncation
	for n := 0; n < ArchiveHeaderSize; n++ {
		if _, err := DecodeArchiveHeader(good[:n]); err == nil {
			t.Fatalf("truncated %d accepted", n)
		}
	}
}

func TestHeaderSameArchive(t *testing.T) {
	a, b := testHeader(), testHeader()
	b.GenerationID = 9
	if !a.SameArchive(&b) {
		t.Error("generation must not matter")
	}
	b.CodecID = CodecZstdFast
	if a.SameArchive(&b) {
		t.Error("codec differs")
	}
}

func TestPrefixQuantaBounds(t *testing.T) {
	h := testHeader() // max 4
	for _, c := range []struct {
		q  uint32
		ok bool
	}{{0, false}, {1, true}, {4, true}, {5, false}, {math.MaxUint32, false}} {
		b := make([]byte, FramePrefixSize)
		copy(b, MagicFramePrefix[:])
		binary.LittleEndian.PutUint32(b[4:], c.q)
		binary.LittleEndian.PutUint32(b[8:], prefixCRC(b))
		_, err := DecodeFramePrefix(b, &h)
		if (err == nil) != c.ok {
			t.Errorf("q=%d: err=%v", c.q, err)
		}
	}
	fixed := h
	fixed.Mode = ModeFixed
	b, _ := FramePrefix{FrameQuanta: 3}.AppendBinary(nil)
	if _, err := DecodeFramePrefix(b, &fixed); !errors.Is(err, ErrCorrupt) {
		t.Error("FIXED frame_quanta != max accepted")
	}
	b, _ = FramePrefix{FrameQuanta: 4}.AppendBinary(nil)
	if _, err := DecodeFramePrefix(b, &fixed); err != nil {
		t.Error(err)
	}
	if _, err := (FramePrefix{FrameQuanta: MaxMaxFrameQuanta + 1}).AppendBinary(nil); !errors.Is(err, ErrInvalid) {
		t.Error("encoder accepted quanta > max")
	}
}

func TestRootRejections(t *testing.T) {
	good := (&Root{GenerationID: 5}).AppendBinary(nil)
	for i := 0; i < RootSize*8; i++ {
		b := append([]byte(nil), good...)
		b[i/8] ^= 1 << (i % 8)
		if _, err := DecodeRoot(b); err == nil {
			t.Fatalf("root bit %d flip accepted", i)
		}
	}
	if _, err := DecodeRoot(good[:63]); err == nil {
		t.Error("short root accepted")
	}
}

func TestAllocRejections(t *testing.T) {
	ok := []AllocState{
		{Kind: AllocGeneration, ReservedThrough: 1},
		{Kind: AllocFrameOrdinal, BlobOrdinal: 0xFE, GenerationID: 3},
		{Kind: AllocGroupID, GenerationID: 3},
	}
	for _, a := range ok {
		b, err := a.AppendBinary(nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < AllocStateSize*8; i++ {
			c := append([]byte(nil), b...)
			c[i/8] ^= 1 << (i % 8)
			if _, err := DecodeAllocState(c); err == nil {
				t.Fatalf("kind %d bit %d flip accepted", a.Kind, i)
			}
		}
	}
	bad := []AllocState{
		{Kind: 5},
		{Kind: AllocFileVer, BlobOrdinal: 1},
		{Kind: AllocFrameOrdinal, BlobOrdinal: 0xFF},
		{Kind: AllocGeneration, GenerationID: 1},
		{Kind: AllocFileVer, GenerationID: 1},
	}
	for _, a := range bad {
		if _, err := a.AppendBinary(nil); err == nil {
			t.Errorf("%+v accepted", a)
		}
	}
}

func TestAllocKindPolicy(t *testing.T) {
	// §2.1.3.4: SKIP is at least 256 x MAX_RESERVATION_BLOCK, and kind 0 survives
	// 65,536 re-initializations inside the 32-bit encrypted generation space.
	for k := AllocGeneration; k <= AllocGroupID; k++ {
		if k.ReinitSkip() < 256*k.MaxReservationBlock() {
			t.Errorf("kind %d: skip %d block %d", k, k.ReinitSkip(), k.MaxReservationBlock())
		}
	}
	if uint64(MaxEncryptedGenerationID)/AllocGeneration.ReinitSkip() < 65535 {
		t.Error("generation skip too large")
	}
}

func TestIndexRecordRejections(t *testing.T) {
	h := testHeader()
	r := IndexRecord{PhysicalOffset: FrameAreaStart + 4096, FrameQuanta: 2, BlockType: BlockData}
	good, _ := r.AppendBinary(nil)
	if _, err := DecodeIndexRecord(good, &h); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func([]byte){
		"block_type": func(b []byte) { b[44] = 3 },
		"reserved1":  func(b []byte) { b[46] = 1 },
		"reserved2":  func(b []byte) { b[63] = 1 },
		"off grid":   func(b []byte) { binary.LittleEndian.PutUint64(b[32:], 4096) },
		"zero quanta": func(b []byte) {
			binary.LittleEndian.PutUint32(b[40:], 0)
		},
		"quanta > max": func(b []byte) { binary.LittleEndian.PutUint32(b[40:], 5) },
	}
	for name, m := range mut {
		b := append([]byte(nil), good...)
		m(b)
		if _, err := DecodeIndexRecord(b, &h); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	ih := IndexHeader{HashID: HashSHA256, BlobOrdinal: 3}
	hb, _ := ih.AppendBinary(nil)
	for name, m := range map[string]func([]byte){
		"magic": func(b []byte) { b[7] = 1 }, "version": func(b []byte) { b[8] = 5 },
		"header_size": func(b []byte) { b[10] = 1 }, "record_size": func(b []byte) { b[54] = 1 },
		"blob 0xFF": func(b []byte) { b[52] = 0xFF }, "hash": func(b []byte) { b[53] = 9 },
	} {
		b := append([]byte(nil), hb...)
		m(b)
		if _, err := DecodeIndexHeader(b); err == nil {
			t.Errorf("index header %s accepted", name)
		}
	}
}

func TestPathLenCanonical(t *testing.T) {
	bad := [][]byte{
		{}, {0x00}, {0x80}, {0x81, 0x00}, {0x80, 0x80, 0x01}, {0x81, 0x80}, {0x81, 0x20}, // 4097
	}
	for _, b := range bad {
		if _, _, err := DecodePathLen(b); err == nil {
			t.Errorf("%x accepted", b)
		}
	}
	for n := 1; n <= MaxPathLen; n++ {
		b, err := AppendPathLen(nil, n)
		if err != nil {
			t.Fatal(err)
		}
		got, used, err := DecodePathLen(b)
		if err != nil || got != n || used != len(b) {
			t.Fatalf("n=%d: %d %d %v", n, got, used, err)
		}
	}
	for _, n := range []int{0, -1, MaxPathLen + 1} {
		if _, err := AppendPathLen(nil, n); err == nil {
			t.Errorf("encode %d accepted", n)
		}
	}
}

func TestLayoutBudget(t *testing.T) {
	// exact fit: 16 + data + pt + 4 + 96 = 4096
	l, err := ComputeLayout(1, 4096-116-8, 8)
	if err != nil || l.PaddingLen != 0 || l.PreTrailerStart != 4096-100-8 {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := ComputeLayout(1, 4096-116-8+1, 8); !errors.Is(err, ErrCorrupt) {
		t.Error("overlap accepted")
	}
	if _, err := ComputeLayout(1, math.MaxUint64, 8); !errors.Is(err, ErrCorrupt) {
		t.Error("overflow accepted")
	}
	if _, err := ComputeLayout(1, 0, math.MaxUint64); !errors.Is(err, ErrCorrupt) {
		t.Error("overflow accepted")
	}
	if ParityShardLen(1) != 4096-124 {
		t.Error("parity shard len")
	}
}

func TestGeometry(t *testing.T) {
	for _, c := range []struct {
		off uint64
		ok  bool
	}{{0, false}, {0x40, true}, {0x40 + 4096, true}, {4096, false}, {0x41, false}, {math.MaxUint64, false}} {
		if OnFrameGrid(c.off) != c.ok {
			t.Errorf("OnFrameGrid(%d)", c.off)
		}
	}
	h := testHeader()
	h.Mode, h.MaxFrameQuanta = ModeFixed, MaxMaxFrameQuanta
	if off, err := FixedSlotOffset(3, &h); err != nil || off != 0x40+3*(1<<32) {
		t.Errorf("slot 3: %d %v", off, err)
	}
	if _, err := FixedSlotOffset(math.MaxUint64, &h); !errors.Is(err, ErrResource) {
		t.Error("slot overflow accepted")
	}
	if _, err := FrameEnd(0x40, 1, 0x40+4095); !errors.Is(err, ErrCorrupt) {
		t.Error("frame past blob end accepted")
	}
	if end, err := FrameEnd(0x40, 1, 0x40+4096); err != nil || end != 0x40+4096 {
		t.Error("frame at blob end")
	}
	if _, err := FrameEnd(math.MaxUint64-63, MaxMaxFrameQuanta, math.MaxUint64); err == nil {
		t.Error("frame end overflow accepted")
	}
}
