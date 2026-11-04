package parity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"testing"

	"stash/internal/frame"
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
	GenerationID   uint64 `json:"generation_id"`
	ArchiveID      string `json:"archive_id"`
}

func (g gHeader) value() wire.ArchiveHeader {
	h := wire.ArchiveHeader{Mode: wire.FrameSizeMode(g.Mode), HashID: wire.HashID(g.HashID), CodecID: wire.CodecID(g.CodecID),
		ParityScheme: wire.ParityScheme(g.ParityScheme), ParityK: g.ParityK, ParityM: g.ParityM, BlobCount: g.BlobCount,
		Flags: g.Flags, MaxFrameQuanta: g.MaxFrameQuanta, GenerationID: g.GenerationID}
	id, _ := hex.DecodeString(g.ArchiveID)
	copy(h.ArchiveID[:], id)
	return h
}

type golden struct {
	Field struct {
		Products [][3]int
		Inverses [][2]int
	}
	Matrices []struct {
		K, M       int
		ParityRows []string `json:"parity_rows"`
	}
	Codes []struct {
		Name         string
		Scheme, K, M int
		Data, Parity []string
	}
	Groups []struct {
		Name        string
		Header      gHeader
		GroupID     uint32 `json:"group_id"`
		FrameQuanta uint32 `json:"frame_quanta"`
		K, M        int
		Members     []struct {
			BlockType uint8 `json:"block_type"`
			Payload   string
			Entries   []struct {
				Path           string
				Offset, Length uint64
				FileVer        uint64 `json:"file_ver"`
			}
		}
		Padding []uint64
		Shards  []string
		Frames  []string
	}
	PaddingEdgePayload int `json:"padding_edge_payload"`
}

func load(t testing.TB) *golden {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return &g
}

func unhex(t testing.TB, ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func TestField(t *testing.T) {
	g := load(t)
	for _, p := range g.Field.Products {
		if got := gfMul(byte(p[0]), byte(p[1])); got != byte(p[2]) {
			t.Fatalf("%#x * %#x = %#x, want %#x", p[0], p[1], got, p[2])
		}
	}
	for _, p := range g.Field.Inverses {
		if got := gfInv(byte(p[0])); got != byte(p[1]) {
			t.Fatalf("inv %#x = %#x, want %#x", p[0], got, p[1])
		}
	}
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("a * a^-1 != 1 for %d", a)
		}
	}
}

func TestEncodingMatrices(t *testing.T) {
	for _, c := range load(t).Matrices {
		e, err := EncodingMatrix(c.K, c.M)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < c.K; i++ {
			for j := 0; j < c.K; j++ {
				if (e[i][j] == 1) != (i == j) || e[i][j] > 1 {
					t.Fatalf("k=%d m=%d: top rows are not the identity", c.K, c.M)
				}
			}
		}
		for j, want := range unhex(t, c.ParityRows) {
			if !bytes.Equal(e[c.K+j], want) {
				t.Fatalf("k=%d m=%d row %d: %x, want %x", c.K, c.M, j, e[c.K+j], want)
			}
		}
	}
}

func TestGoldenCodes(t *testing.T) {
	for _, c := range load(t).Codes {
		t.Run(c.Name, func(t *testing.T) {
			code, err := New(wire.ParityScheme(c.Scheme), c.K, c.M)
			if err != nil {
				t.Fatal(err)
			}
			data, want := unhex(t, c.Data), unhex(t, c.Parity)
			par := make([][]byte, c.M)
			for j := range par {
				par[j] = bytes.Repeat([]byte{0xA5}, len(data[0])) // dirty buffers
			}
			if err := code.Encode(data, par); err != nil {
				t.Fatal(err)
			}
			for j := range want {
				if !bytes.Equal(par[j], want[j]) {
					t.Fatalf("parity %d differs from the independent encoder", j)
				}
			}
			// erase up to m shards in several patterns and rebuild
			all := append(append([][]byte{}, data...), par...)
			rng := rand.New(rand.NewPCG(uint64(c.K), uint64(c.M)))
			for trial := 0; trial < 20; trial++ {
				shards := make([][]byte, len(all))
				present := make([]bool, len(all))
				for i := range all {
					shards[i] = append([]byte(nil), all[i]...)
					present[i] = true
				}
				lose := 1 + rng.IntN(c.M)
				for _, i := range rng.Perm(len(all))[:lose] {
					present[i] = false
					for b := range shards[i] {
						shards[i][b] = 0xEE
					}
				}
				if err := code.Reconstruct(shards, present); err != nil {
					t.Fatal(err)
				}
				for i := range all {
					if !bytes.Equal(shards[i], all[i]) {
						t.Fatalf("trial %d: shard %d not rebuilt", trial, i)
					}
				}
			}
			// one loss too many
			shards := append([][]byte{}, all...)
			present := make([]bool, len(all))
			for i := c.M + 1; i < len(all); i++ {
				present[i] = true
			}
			if err := code.Reconstruct(shards, present); !errors.Is(err, ErrTooFewShards) {
				t.Fatalf("m+1 losses: %v", err)
			}
		})
	}
}

func TestRSIsNotXOR(t *testing.T) {
	xor, _ := New(wire.ParityXOR, 2, 1)
	rs, _ := New(wire.ParityRS, 2, 1)
	d := [][]byte{{1}, {1}}
	px, pr := [][]byte{{0}}, [][]byte{{0}}
	xor.Encode(d, px)
	rs.Encode(d, pr)
	if px[0][0] == pr[0][0] {
		t.Fatal("RS m=1 must differ from XOR (§7.2.1)")
	}
}

func TestReservedSchemes(t *testing.T) {
	for s := 3; s < 256; s++ {
		if _, err := New(wire.ParityScheme(s), 2, 1); !errors.Is(err, wire.ErrUnsupported) {
			t.Fatalf("scheme %d: %v", s, err)
		}
	}
	if _, err := New(wire.ParityNone, 2, 1); err == nil {
		t.Fatal("NONE is not a code")
	}
	for _, km := range [][2]int{{0, 1}, {1, 0}, {200, 57}} {
		if _, err := New(wire.ParityRS, km[0], km[1]); err == nil {
			t.Fatalf("k=%d m=%d accepted", km[0], km[1])
		}
	}
	if _, err := New(wire.ParityXOR, 3, 2); err == nil {
		t.Fatal("XOR with m=2 accepted")
	}
}

// TestGoldenGroups checks the canonical recovery shards and complete
// PARITY frames against the independent generator, and rebuilds every
// lost member byte for byte (§7.2, §7.3, §17.8).
func TestGoldenGroups(t *testing.T) {
	for _, c := range load(t).Groups {
		t.Run(c.Name, func(t *testing.T) {
			h := c.Header.value()
			if err := h.Validate(); err != nil {
				t.Fatal(err)
			}
			want := unhex(t, c.Frames)
			wantShards := unhex(t, c.Shards)
			code, err := New(h.ParityScheme, c.K, c.M)
			if err != nil {
				t.Fatal(err)
			}
			shards := make([][]byte, c.K+c.M)
			for i, m := range c.Members {
				payload, _ := hex.DecodeString(m.Payload)
				s := &frame.Spec{BlockType: wire.BlockType(m.BlockType), Codec: wire.CodecStore, Payload: payload,
					GroupID: c.GroupID, GroupIndex: uint8(i), GroupK: uint8(c.K), GroupM: uint8(c.M),
					FrameQuanta: c.FrameQuanta}
				tr, err := frame.Parse(want[i], &h)
				if err != nil {
					t.Fatal(err)
				}
				s.FrameOrdinal = tr.Trailer.FrameOrdinal
				for _, e := range m.Entries {
					s.Entries = append(s.Entries, wire.Entry{Path: e.Path, Offset: e.Offset, Length: e.Length, FileVer: e.FileVer})
				}
				fr, err := frame.Build(&h, s)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(fr, want[i]) {
					t.Fatalf("member %d frame differs", i)
				}
				if shards[i], err = frame.AppendRecoveryShard(nil, fr); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(shards[i], wantShards[i]) {
					t.Fatalf("member %d canonical shard differs", i)
				}
			}
			shardLen := int(wire.ParityShardLen(c.FrameQuanta))
			for j := 0; j < c.M; j++ {
				shards[c.K+j] = make([]byte, shardLen)
			}
			if err := code.Encode(shards[:c.K], shards[c.K:]); err != nil {
				t.Fatal(err)
			}
			for j := 0; j < c.M; j++ {
				ord := uint64(0)
				if tr, err := frame.Parse(want[c.K+j], &h); err == nil {
					ord = tr.Trailer.FrameOrdinal
				} else {
					t.Fatal(err)
				}
				fr, err := frame.Build(&h, &frame.Spec{BlockType: wire.BlockParity, Codec: wire.CodecStore, Payload: shards[c.K+j],
					GroupID: c.GroupID, GroupIndex: uint8(c.K + j), GroupK: uint8(c.K), GroupM: uint8(c.M),
					FrameOrdinal: ord, FrameQuanta: c.FrameQuanta})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(fr, want[c.K+j]) {
					t.Fatalf("PARITY frame %d differs from the independent generator", j)
				}
			}
			// lose each data member (and up to m members) and rebuild it
			for lost := 0; lost < c.K; lost++ {
				work := make([][]byte, c.K+c.M)
				present := make([]bool, c.K+c.M)
				for i := range work {
					work[i] = append([]byte(nil), shards[i]...)
					present[i] = true
				}
				for i := 0; i < c.M; i++ { // lose m members starting at lost
					x := (lost + i) % (c.K + c.M)
					present[x] = false
					clear(work[x])
				}
				if err := code.Reconstruct(work, present); err != nil {
					t.Fatal(err)
				}
				fr, err := frame.AppendFromRecoveryShard(nil, work[lost], c.FrameQuanta)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(fr, want[lost]) {
					t.Fatalf("rebuilt member %d is not byte-identical", lost)
				}
				if _, err := frame.Parse(fr, &h); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPaddingBoundary(t *testing.T) {
	g := load(t)
	h := g.Groups[0].Header.value()
	h.ParityScheme, h.ParityK, h.ParityM = wire.ParityXOR, 2, 1
	edge := g.PaddingEdgePayload
	mk := func(n int, group bool) (*frame.Spec, error) {
		s := &frame.Spec{BlockType: wire.BlockData, Codec: wire.CodecStore, Payload: make([]byte, n), FrameQuanta: 1,
			Entries: []wire.Entry{{Path: "b", Length: uint64(n), FileVer: 1}}}
		if group {
			s.GroupID, s.GroupK, s.GroupM = 2, 1, 1
		}
		return s, nil
	}
	s, _ := mk(edge, true)
	fr, err := frame.Build(&h, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := frame.AppendRecoveryShard(nil, fr); err != nil {
		t.Fatalf("112 bytes of padding: %v", err)
	}
	// one byte more: a group member does not fit one quantum
	s, _ = mk(edge+1, true)
	if _, err := frame.Build(&h, s); err == nil {
		t.Fatal("group member with 111 bytes of padding built")
	}
	if q, _ := frame.RequiredQuanta(uint64(edge+1), uint64(len("b"))+1+24+8, true); q != 2 {
		t.Fatalf("RequiredQuanta = %d, want 2", q)
	}
	// a frame outside any group may use that padding, but has no shard
	s, _ = mk(edge+1, false)
	fr, err = frame.Build(&h, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := frame.AppendRecoveryShard(nil, fr); err == nil {
		t.Fatal("shard of a frame with 111 bytes of padding")
	}
}

func TestShardRejects(t *testing.T) {
	g := load(t)
	c := g.Groups[0]
	h := c.Header.value()
	shard := unhex(t, c.Shards[:1])[0]
	if _, err := frame.AppendFromRecoveryShard(nil, shard[:len(shard)-1], c.FrameQuanta); err == nil {
		t.Fatal("short shard accepted")
	}
	bad := append([]byte(nil), shard...)
	bad[0] ^= 1 // recovery_image_len
	fr, err := frame.AppendFromRecoveryShard(nil, bad, c.FrameQuanta)
	if err == nil {
		if _, err := frame.Parse(fr, &h); err == nil {
			t.Fatal("damaged image length produced a valid frame")
		}
	}
	bad = append([]byte(nil), shard...)
	bad[100] ^= 1 // payload byte: rebuilt frame must fail the hash
	fr, err = frame.AppendFromRecoveryShard(nil, bad, c.FrameQuanta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := frame.Parse(fr, &h); err == nil {
		t.Fatal("damaged payload validated")
	}
	parityFrame := unhex(t, c.Frames[c.K:c.K+1])[0]
	if _, err := frame.AppendRecoveryShard(nil, parityFrame); err == nil {
		t.Fatal("PARITY frame has a recovery shard")
	}
}

func BenchmarkEncode(b *testing.B) {
	for _, km := range [][3]int{{1, 4, 1}, {2, 4, 2}, {2, 10, 4}} {
		code, _ := New(wire.ParityScheme(km[0]), km[1], km[2])
		size := 1 << 20
		data := make([][]byte, km[1])
		for i := range data {
			data[i] = make([]byte, size)
			for j := range data[i] {
				data[i][j] = byte(j * (i + 3))
			}
		}
		par := make([][]byte, km[2])
		for j := range par {
			par[j] = make([]byte, size)
		}
		b.Run(map[int]string{1: "XOR", 2: "RS"}[km[0]]+"_"+string(rune('0'+km[1]/10))+string(rune('0'+km[1]%10))+"+"+string(rune('0'+km[2])), func(b *testing.B) {
			b.SetBytes(int64(size * km[1]))
			for i := 0; i < b.N; i++ {
				code.Encode(data, par)
			}
		})
	}
}
