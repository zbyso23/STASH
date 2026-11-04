package frame

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"stash/internal/wire"
)

type gHeader struct {
	Mode           uint8  `json:"mode"`
	HashID         uint8  `json:"hash_id"`
	CodecID        uint8  `json:"codec_id"`
	ParityScheme   uint8  `json:"parity_scheme"`
	ParityK        uint8  `json:"parity_k"`
	ParityM        uint8  `json:"parity_m"`
	BlobCount      uint8  `json:"blob_count"`
	Flags          uint8  `json:"flags"`
	MaxFrameQuanta uint32 `json:"max_frame_quanta"`
	ArchiveID      string `json:"archive_id"`
}

func (g gHeader) value() wire.ArchiveHeader {
	var id [32]byte
	b, _ := hex.DecodeString(g.ArchiveID)
	copy(id[:], b)
	return wire.ArchiveHeader{Mode: wire.FrameSizeMode(g.Mode), HashID: wire.HashID(g.HashID), CodecID: wire.CodecID(g.CodecID),
		ParityScheme: wire.ParityScheme(g.ParityScheme), ParityK: g.ParityK, ParityM: g.ParityM, BlobCount: g.BlobCount,
		Flags: g.Flags, MaxFrameQuanta: g.MaxFrameQuanta, ArchiveID: id}
}

type gFrame struct {
	Name      string
	Header    gHeader
	BlockType uint8 `json:"block_type"`
	Payload   string
	Entries   []struct {
		Path    string
		Offset  uint64
		Length  uint64
		FileVer uint64 `json:"file_ver"`
	}
	FrameQuanta  uint32 `json:"frame_quanta"`
	FrameOrdinal uint64 `json:"frame_ordinal"`
	Group        [4]uint32
	Trailer      struct {
		ObjectID    string `json:"object_id"`
		HashPayload string `json:"hash_payload"`
	}
	Padding   uint64
	MinQuanta bool `json:"min_quanta"`
	Hex       string
}

func loadFrames(t testing.TB) []gFrame {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct{ Frames []gFrame }
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Frames) == 0 {
		t.Fatal("no frames")
	}
	return g.Frames
}

func (c *gFrame) spec(q uint32) *Spec {
	payload, _ := hex.DecodeString(c.Payload)
	s := &Spec{BlockType: wire.BlockType(c.BlockType), Codec: wire.CodecStore, Payload: payload,
		GroupID: c.Group[0], GroupIndex: uint8(c.Group[1]), GroupK: uint8(c.Group[2]), GroupM: uint8(c.Group[3]),
		FrameOrdinal: c.FrameOrdinal, FrameQuanta: q}
	for _, e := range c.Entries {
		s.Entries = append(s.Entries, wire.Entry{Path: e.Path, Offset: e.Offset, Length: e.Length, FileVer: e.FileVer})
	}
	return s
}

func TestGoldenFrames(t *testing.T) {
	for _, c := range loadFrames(t) {
		t.Run(c.Name, func(t *testing.T) {
			h := c.Header.value()
			if err := h.Validate(); err != nil {
				t.Fatal(err)
			}
			want, _ := hex.DecodeString(c.Hex)
			got, err := Build(&h, c.spec(c.FrameQuanta))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encoder differs from independent bytes")
			}
			if c.MinQuanta { // automatic size selection agrees with the generator
				auto, err := Build(&h, c.spec(0))
				if err != nil || !bytes.Equal(auto, want) {
					t.Fatalf("automatic frame size differs: %v", err)
				}
			}
			f, err := Parse(want, &h)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(f.Trailer.ObjectID[:]) != c.Trailer.ObjectID ||
				hex.EncodeToString(f.Trailer.HashPayload[:]) != c.Trailer.HashPayload {
				t.Fatal("trailer identity")
			}
			if hex.EncodeToString(f.Payload) != c.Payload || len(f.Entries) != len(c.Entries) {
				t.Fatal("payload or entries")
			}
			for i, e := range c.Entries {
				if f.Entries[i] != (wire.Entry{Path: e.Path, Offset: e.Offset, Length: e.Length, FileVer: e.FileVer}) {
					t.Fatalf("entry %d: %+v", i, f.Entries[i])
				}
			}
		})
	}
}

func baseline() wire.ArchiveHeader {
	return wire.ArchiveHeader{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 2, MaxFrameQuanta: 16,
		ParityScheme: wire.ParityXOR, ParityK: 2, ParityM: 1}
}

func dataSpec(n int) *Spec {
	return &Spec{BlockType: wire.BlockData, Payload: bytes.Repeat([]byte{7}, n),
		Entries: []wire.Entry{{Path: "f", Length: uint64(n), FileVer: 1}}}
}

// rebuild recomputes the outer CRC after a deliberate semantic edit so the
// test reaches the semantic check rather than the CRC.
func reCRC(f []byte) {
	n := len(f)
	ptl := int(binary.LittleEndian.Uint32(f[n-100:]))
	body := f[n-100-ptl : n-100]
	binary.LittleEndian.PutUint32(body[len(body)-4:], wire.OuterCRC(body[:len(body)-4], uint32(ptl), f[n-96:]))
}

func TestParseRejectsSemanticCorruption(t *testing.T) {
	h := baseline()
	good, err := Build(&h, dataSpec(100))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(good, &h); err != nil {
		t.Fatal(err)
	}
	n := len(good)
	cases := map[string]func(b []byte){
		"payload byte":   func(b []byte) { b[20] ^= 1 },
		"padding":        func(b []byte) { b[16+100] = 1 },
		"file_ver":       func(b []byte) { b[n-100-4-1] ^= 1; reCRC(b) }, // high byte of file_ver
		"object_id":      func(b []byte) { b[n-96+0x18] ^= 1; reCRC(b) },
		"logical_length": func(b []byte) { b[n-96+0x30] ^= 1; reCRC(b) },
		"prefix crc":     func(b []byte) { b[9] ^= 1 },
		"outer crc":      func(b []byte) { b[n-101] ^= 1 },
	}
	for name, mut := range cases {
		b := append([]byte(nil), good...)
		mut(b)
		if _, err := Parse(b, &h); !errors.Is(err, wire.ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Parse(good[:4096-1], &h); err == nil {
		t.Error("truncated frame accepted")
	}
	if _, err := Parse(append(append([]byte(nil), good...), make([]byte, 4096)...), &h); err == nil {
		t.Error("frame longer than prefix accepted")
	}
}

func TestBuildRejectsInvalidSpecs(t *testing.T) {
	h := baseline()
	bad := map[string]*Spec{
		"two entries": {BlockType: wire.BlockData, Entries: []wire.Entry{{Path: "a"}, {Path: "b"}}},
		"bad path":    {BlockType: wire.BlockData, Entries: []wire.Entry{{Path: "/a"}}},
		"unsorted": {BlockType: wire.BlockPacked, Payload: []byte("ab"),
			Entries: []wire.Entry{{Path: "b", Length: 1}, {Path: "a", Offset: 1, Length: 1}}},
		"duplicate": {BlockType: wire.BlockPacked, Payload: []byte("ab"),
			Entries: []wire.Entry{{Path: "a", Length: 1}, {Path: "a", Offset: 1, Length: 1}}},
		"gap": {BlockType: wire.BlockPacked, Payload: []byte("ab"),
			Entries: []wire.Entry{{Path: "a", Length: 1}, {Path: "b", Offset: 2, Length: 1}}},
		"store length": {BlockType: wire.BlockData, Payload: []byte("abc"), Entries: []wire.Entry{{Path: "a", Length: 2}}},
		"too large":    dataSpec(16*4096 - 100),
		"parity entries": {BlockType: wire.BlockParity, Payload: make([]byte, 4096-124), GroupID: 1, GroupIndex: 2, GroupK: 2, GroupM: 1,
			Entries: []wire.Entry{{Path: "a"}}},
		"parity size": {BlockType: wire.BlockParity, Payload: make([]byte, 100), GroupID: 1, GroupIndex: 2, GroupK: 2, GroupM: 1},
	}
	for name, s := range bad {
		if _, err := Build(&h, s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	enc := h
	enc.Flags = wire.HeaderFlagEncrypted
	if _, err := Build(&enc, dataSpec(1)); err == nil {
		t.Error("encrypted build accepted")
	}
}

func TestParityFrameRoundTrip(t *testing.T) {
	h := baseline()
	for _, q := range []uint32{1, 3} {
		s := &Spec{BlockType: wire.BlockParity, Payload: bytes.Repeat([]byte{0xAB}, int(wire.ParityShardLen(q))),
			GroupID: 4, GroupIndex: 2, GroupK: 2, GroupM: 1, FrameOrdinal: 9}
		b, err := Build(&h, s)
		if err != nil {
			t.Fatal(err)
		}
		f, err := Parse(b, &h)
		if err != nil || f.Prefix.FrameQuanta != q || len(f.Entries) != 0 {
			t.Fatalf("q=%d: %v", q, err)
		}
	}
}

// §7.2: a parity group member always keeps at least 112 bytes of padding.
func TestParityMemberPadding(t *testing.T) {
	h := baseline()
	for n := 3800; n <= 4000; n++ {
		s := dataSpec(n)
		s.GroupID, s.GroupK, s.GroupM = 1, 2, 1
		b, err := Build(&h, s)
		if err != nil {
			t.Fatal(err)
		}
		f, _ := Parse(b, &h)
		pad := uint64(len(b)) - 16 - uint64(n) - uint64(len(f.PreTrailer)) - 100
		if pad < wire.MinParityPadding {
			t.Fatalf("n=%d padding %d", n, pad)
		}
	}
}

func TestFixedModeAndLimits(t *testing.T) {
	h := baseline()
	h.Mode, h.MaxFrameQuanta = wire.ModeFixed, 2
	b, err := Build(&h, dataSpec(10))
	if err != nil || len(b) != 8192 {
		t.Fatalf("%d %v", len(b), err)
	}
	s := dataSpec(10)
	s.FrameQuanta = 1
	if _, err := Build(&h, s); err == nil {
		t.Error("FIXED with smaller quanta accepted")
	}
	// logical_length ceiling: a frame describing MAX_FRAME_SIZE+1 bytes is rejected (§6.6.1)
	v := baseline()
	v.MaxFrameQuanta = 1
	s = dataSpec(1)
	s.Codec = wire.CodecZstdFast
	s.Entries[0].Length = 4097
	if _, err := Build(&v, s); !errors.Is(err, wire.ErrCorrupt) {
		t.Errorf("logical_length > MAX accepted: %v", err)
	}
	s.Entries[0].Length = 4096
	if _, err := Build(&v, s); err != nil {
		t.Errorf("logical_length == MAX rejected: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	h := baseline()
	for _, c := range loadFrames(f) {
		b, _ := hex.DecodeString(c.Hex)
		f.Add(b)
	}
	b, _ := Build(&h, dataSpec(10))
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 4*4096 {
			return
		}
		fr, err := Parse(in, &h)
		if err != nil {
			return
		}
		if uint64(len(in)) != wire.FrameSize(fr.Prefix.FrameQuanta) {
			t.Fatal("size")
		}
	})
}

func FuzzDecodeEntries(f *testing.F) {
	body, _ := wire.AppendEntries(nil, []wire.Entry{{Path: "a/b", Length: 3, FileVer: 1}})
	f.Add(body)
	f.Fuzz(func(t *testing.T, in []byte) {
		es, err := wire.DecodeEntries(in)
		if err != nil {
			return
		}
		out, err := wire.AppendEntries(nil, es)
		if err != nil || !bytes.Equal(out, in) {
			t.Fatal("round trip")
		}
	})
}
