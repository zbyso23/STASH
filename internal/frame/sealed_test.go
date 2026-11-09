package frame

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"stash/internal/compress"
	"stash/internal/seal"
	"stash/internal/wire"
)

type sealedGolden struct {
	DEK       string `json:"dek"`
	ArchiveID string `json:"archive_id"`
	Frames    []struct {
		Name   string
		Header struct {
			gHeader
			GenerationID uint64 `json:"generation_id"`
		}
		BlockType    uint8  `json:"block_type"`
		CodecID      uint8  `json:"codec_id"`
		PayloadPlain string `json:"payload_plain"`
		Logical      string
		Entries      []gSealedEntry
		FrameQuanta  uint32 `json:"frame_quanta"`
		FrameOrdinal uint64 `json:"frame_ordinal"`
		Blob         uint8
		Group        [4]uint32
		ObjectID     string `json:"object_id"`
		Hex          string
	}
}

type gSealedEntry struct {
	Path           string
	Offset, Length uint64
	FileVer        uint64 `json:"file_ver"`
}

func toEntries(es []gSealedEntry) []wire.Entry {
	out := make([]wire.Entry, len(es))
	for i, e := range es {
		out[i] = wire.Entry{Path: e.Path, Offset: e.Offset, Length: e.Length, FileVer: e.FileVer}
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadSealed(t *testing.T) (sealedGolden, *seal.Keys) {
	t.Helper()
	b, err := os.ReadFile("../seal/testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g sealedGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	k, err := seal.New(mustHex(t, g.DEK), [32]byte(mustHex(t, g.ArchiveID)))
	if err != nil {
		t.Fatal(err)
	}
	return g, k
}

// reintegrity recomputes hash_payload and the outer CRC after a test
// modified a frame, as an attacker without the key can: only AEAD stands.
func reintegrity(fr []byte) {
	ts := len(fr) - wire.MasterTrailerSize
	ptLen := binary.LittleEndian.Uint32(fr[ts-4:])
	dataLen := binary.LittleEndian.Uint32(fr[ts+16:])
	lay, err := wire.ComputeLayout(uint32(len(fr)/wire.BaseQuantum), uint64(dataLen), uint64(ptLen))
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(fr[lay.PayloadStart:lay.PayloadEnd])
	copy(fr[ts+0x40:ts+0x60], sum[:])
	body := fr[lay.PreTrailerStart : lay.PreTrailerStart+uint64(ptLen)-4]
	binary.LittleEndian.PutUint32(fr[lay.PreTrailerStart+uint64(len(body)):], wire.OuterCRC(body, ptLen, fr[ts:]))
}

// §17.1/§17.9: encrypted frames built by an independent implementation are
// reproduced byte for byte (numeric nonces make sealing deterministic),
// parse keyless and keyed, and decrypt (and decompress) to the logical data.
func TestSealedGolden(t *testing.T) {
	g, k := loadSealed(t)
	for _, c := range g.Frames {
		t.Run(c.Name, func(t *testing.T) {
			h := c.Header.value()
			h.GenerationID = c.Header.GenerationID
			if err := h.Validate(); err != nil {
				t.Fatal(err)
			}
			want := mustHex(t, c.Hex)
			s := &Spec{BlockType: wire.BlockType(c.BlockType), Codec: wire.CodecID(c.CodecID), Payload: mustHex(t, c.PayloadPlain),
				Entries: toEntries(c.Entries), FrameOrdinal: c.FrameOrdinal, FrameQuanta: c.FrameQuanta, Keys: k, Blob: c.Blob,
				GroupID: c.Group[0], GroupIndex: uint8(c.Group[1]), GroupK: uint8(c.Group[2]), GroupM: uint8(c.Group[3])}
			got, err := Build(&h, s)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				for i := range want {
					if i >= len(got) || got[i] != want[i] {
						t.Fatalf("frame differs from the golden vector at %d of %d (len %d)", i, len(want), len(got))
					}
				}
				t.Fatalf("frame differs from the golden vector (len %d vs %d)", len(got), len(want))
			}
			// keyless: structure only
			f, err := Parse(want, &h)
			if err != nil {
				t.Fatal(err)
			}
			if f.Entries != nil || hex.EncodeToString(f.Trailer.ObjectID[:]) != c.ObjectID && c.BlockType == 0 {
				t.Fatal("keyless parse")
			}
			if _, err := OpenPayload(f, &h, nil, want, nil); err == nil {
				t.Fatal("payload opened without keys")
			}
			// keyed
			f, err = ParseKeyed(want, &h, k)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Entries) != len(c.Entries) {
				t.Fatalf("entries %v", f.Entries)
			}
			plain, err := OpenPayload(f, &h, k, want, nil)
			if err != nil || !bytes.Equal(plain, mustHex(t, c.PayloadPlain)) {
				t.Fatal("payload", err)
			}
			n, _ := f.LogicalLength()
			logical, err := compress.Decode(f.Trailer.CodecID, plain, n, h.MaxFrameSize(), nil)
			if err != nil || !bytes.Equal(logical, mustHex(t, c.Logical)) {
				t.Fatal("logical", err)
			}
			// the stored nonce equals the numeric nonce (§15.5.1)
			nonce, _ := seal.FrameNonce(h.GenerationID, c.Blob, c.FrameOrdinal)
			if !bytes.Equal(f.Payload[:12], nonce[:]) || !bytes.Equal(f.PreTrailer[:12], nonce[:]) {
				t.Fatal("stored nonces")
			}
		})
	}
}

// §17.9: tampering with tag, AAD-covered fields or the stored nonce is
// rejected even when hash and CRC are recomputed.
func TestSealedTamper(t *testing.T) {
	g, k := loadSealed(t)
	c := g.Frames[0]
	h := c.Header.value()
	h.GenerationID = c.Header.GenerationID
	orig := mustHex(t, c.Hex)
	ts := len(orig) - wire.MasterTrailerSize
	tail, _ := wire.DecodeFrameTail(orig)
	lay, _ := wire.ComputeLayout(uint32(len(orig)/wire.BaseQuantum), uint64(tail.Trailer.DataLen), uint64(len(tail.Body)))
	cases := map[string]func(b []byte){
		"payload tag":       func(b []byte) { b[lay.PayloadEnd-1] ^= 1 },
		"payload nonce":     func(b []byte) { b[lay.PayloadStart] ^= 1 },
		"pretrailer tag":    func(b []byte) { b[lay.PreTrailerStart+uint64(len(tail.Body))-5] ^= 1 },
		"pretrailer nonce":  func(b []byte) { b[lay.PreTrailerStart+4] ^= 1 },
		"aad frame_ordinal": func(b []byte) { b[ts+0x38] ^= 1 },
		"aad logical_off":   func(b []byte) { b[ts+0x29] ^= 0x10 },
	}
	for name, mut := range cases {
		b := bytes.Clone(orig)
		mut(b)
		reintegrity(b)
		f, err := ParseKeyed(b, &h, k)
		if err == nil {
			_, err = OpenPayload(f, &h, k, b, nil)
		}
		if !errors.Is(err, wire.ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// another archive_id in the AAD (same key schedule bytes otherwise)
	h2 := h
	h2.ArchiveID[0] ^= 1
	if _, err := ParseKeyed(orig, &h2, k); err == nil {
		t.Fatal("frame accepted under another archive_id")
	}
	// a key schedule of another archive cannot build into this one
	s := &Spec{BlockType: wire.BlockData, Payload: []byte("x"), Entries: []wire.Entry{{Path: "a", Length: 1}}}
	if _, err := Build(&h, s); !errors.Is(err, wire.ErrInvalid) {
		t.Fatal("encrypted frame built without keys")
	}
	// limits are checked before encryption
	hh := h
	hh.GenerationID = seal.MaxGenerationID + 1
	s.Keys = k
	if _, err := Build(&hh, s); !errors.Is(err, seal.ErrNonceLimit) {
		t.Fatalf("generation limit: %v", err)
	}
	s.FrameOrdinal = seal.MaxFrameOrdinal + 1
	if _, err := Build(&h, s); !errors.Is(err, seal.ErrNonceLimit) {
		t.Fatalf("ordinal limit: %v", err)
	}
}
