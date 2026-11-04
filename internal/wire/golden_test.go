package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Golden vectors come from testdata/gen/gen_golden.py, an independent
// generator (SPEC §17.1). Each case is checked in three directions:
// value -> encoder -> exact bytes, bytes -> decoder -> exact value, round trip.

type goldenCase struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	Fields json.RawMessage `json:"fields"`
	Hex    string          `json:"hex"`
}

func loadGolden(t *testing.T) []goldenCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Cases []goldenCase }
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no golden cases")
	}
	return f.Cases
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hex32(t *testing.T, s string) (a [32]byte) { copy(a[:], mustHex(t, s)); return }
func hex16(t *testing.T, s string) (a [16]byte) { copy(a[:], mustHex(t, s)); return }

type jHeader struct {
	Mode, HashID, CodecID, ParityScheme, ParityK, ParityM, BlobCount, Flags uint8
	MaxFrameQuanta                                                          uint32
	GenerationID                                                            uint64
	ArchiveID                                                               string
}

func (j jHeader) value(t *testing.T) ArchiveHeader {
	return ArchiveHeader{Mode: FrameSizeMode(j.Mode), HashID: HashID(j.HashID), CodecID: CodecID(j.CodecID),
		ParityScheme: ParityScheme(j.ParityScheme), ParityK: j.ParityK, ParityM: j.ParityM, BlobCount: j.BlobCount,
		Flags: j.Flags, MaxFrameQuanta: j.MaxFrameQuanta, GenerationID: j.GenerationID, ArchiveID: hex32(t, j.ArchiveID)}
}

type jTrailer struct {
	HashID, CodecID, BlockType                 uint8
	GroupID                                    uint32
	GroupIndex, GroupK, GroupM                 uint8
	DataLen, FrameQuanta                       uint32
	ObjectID                                   string
	LogicalOffset, LogicalLength, FrameOrdinal uint64
	HashPayload                                string
}

func (j jTrailer) value(t *testing.T) MasterTrailer {
	return MasterTrailer{HashID: HashID(j.HashID), CodecID: CodecID(j.CodecID), BlockType: BlockType(j.BlockType),
		GroupID: j.GroupID, GroupIndex: j.GroupIndex, GroupK: j.GroupK, GroupM: j.GroupM, DataLen: j.DataLen,
		FrameQuanta: j.FrameQuanta, ObjectID: hex16(t, j.ObjectID), LogicalOffset: j.LogicalOffset,
		LogicalLength: j.LogicalLength, FrameOrdinal: j.FrameOrdinal, HashPayload: hex32(t, j.HashPayload)}
}

// snake_case JSON keys -> Go fields: decode via a map with renamed keys.
func decodeFields(t *testing.T, raw json.RawMessage, v any) {
	t.Helper()
	var m map[string]any
	md := json.NewDecoder(bytes.NewReader(raw))
	md.UseNumber() // keep uint64 values exact
	if err := md.Decode(&m); err != nil {
		t.Fatal(err)
	}
	conv := map[string]any{}
	for k, val := range m {
		conv[camel(k)] = val
	}
	b, _ := json.Marshal(conv)
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("fields: %v", err)
	}
}

func camel(s string) string {
	out := []byte{}
	up := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' {
			up = true
			continue
		}
		if up && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		up = false
		out = append(out, c)
	}
	r := string(out)
	switch r { // Go initialisms used in this package
	case "HashId":
		return "HashID"
	case "CodecId":
		return "CodecID"
	case "ArchiveId":
		return "ArchiveID"
	case "GenerationId":
		return "GenerationID"
	case "GroupId":
		return "GroupID"
	case "ObjectId":
		return "ObjectID"
	}
	return r
}

func checkBytes(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: encoder bytes differ\n got %x\nwant %x", name, got, want)
	}
}

func TestGoldenVectors(t *testing.T) {
	seen := map[string]int{}
	for _, c := range loadGolden(t) {
		want := mustHex(t, c.Hex)
		seen[c.Kind]++
		t.Run(c.Kind+"/"+c.Name, func(t *testing.T) {
			switch c.Kind {
			case "archive_header":
				var j jHeader
				decodeFields(t, c.Fields, &j)
				v := j.value(t)
				got, err := v.AppendBinary(nil)
				if err != nil {
					t.Fatal(err)
				}
				checkBytes(t, c.Name, got, want)
				d, err := DecodeArchiveHeader(want)
				if err != nil || d != v {
					t.Fatalf("decode: %+v %v", d, err)
				}
			case "root":
				var j struct {
					GenerationID uint64
					ArchiveID    string
				}
				decodeFields(t, c.Fields, &j)
				v := Root{GenerationID: j.GenerationID, ArchiveID: hex32(t, j.ArchiveID)}
				checkBytes(t, c.Name, v.AppendBinary(nil), want)
				d, err := DecodeRoot(want)
				if err != nil || d != v {
					t.Fatalf("decode: %+v %v", d, err)
				}
			case "frame_prefix":
				var j struct{ FrameQuanta uint32 }
				decodeFields(t, c.Fields, &j)
				v := FramePrefix{FrameQuanta: j.FrameQuanta}
				got, err := v.AppendBinary(nil)
				if err != nil {
					t.Fatal(err)
				}
				checkBytes(t, c.Name, got, want)
				h := ArchiveHeader{Mode: ModeVariable, MaxFrameQuanta: MaxMaxFrameQuanta}
				d, err := DecodeFramePrefix(want, &h)
				if err != nil || d != v {
					t.Fatalf("decode: %+v %v", d, err)
				}
			case "master_trailer":
				var j jTrailer
				decodeFields(t, c.Fields, &j)
				v := j.value(t)
				got, err := v.AppendBinary(nil)
				if err != nil {
					t.Fatal(err)
				}
				checkBytes(t, c.Name, got, want)
				d, err := DecodeMasterTrailer(want)
				if err != nil || d != v {
					t.Fatalf("decode: %+v %v", d, err)
				}
			case "alloc_state":
				var j struct {
					Kind, BlobOrdinal             uint8
					GenerationID, ReservedThrough uint64
					ArchiveID                     string
				}
				decodeFields(t, c.Fields, &j)
				v := AllocState{Kind: AllocKind(j.Kind), BlobOrdinal: j.BlobOrdinal, GenerationID: j.GenerationID,
					ReservedThrough: j.ReservedThrough, ArchiveID: hex32(t, j.ArchiveID)}
				got, err := v.AppendBinary(nil)
				if err != nil {
					t.Fatal(err)
				}
				checkBytes(t, c.Name, got, want)
				d, err := DecodeAllocState(want)
				if err != nil || d != v {
					t.Fatalf("decode: %+v %v", d, err)
				}
			case "index_header":
				var j struct {
					GenerationID, RecordCount uint64
					ArchiveID                 string
					BlobOrdinal, HashID       uint8
				}
				decodeFields(t, c.Fields, &j)
				v := IndexHeader{GenerationID: j.GenerationID, ArchiveID: hex32(t, j.ArchiveID), BlobOrdinal: j.BlobOrdinal,
					HashID: HashID(j.HashID), RecordCount: j.RecordCount}
				got, err := v.AppendBinary(nil)
				if err != nil {
					t.Fatal(err)
				}
				checkBytes(t, c.Name, got, want)
				d, err := DecodeIndexHeader(want)
				if err != nil || d != v {
					t.Fatalf("decode: %+v %v", d, err)
				}
			case "index_record":
				var j struct {
					FrameHash                    string
					PhysicalOffset, FrameOrdinal uint64
					FrameQuanta                  uint32
					BlockType                    uint8
				}
				decodeFields(t, c.Fields, &j)
				v := IndexRecord{FrameHash: hex32(t, j.FrameHash), PhysicalOffset: j.PhysicalOffset, FrameQuanta: j.FrameQuanta,
					BlockType: BlockType(j.BlockType), FrameOrdinal: j.FrameOrdinal}
				got, err := v.AppendBinary(nil)
				if err != nil {
					t.Fatal(err)
				}
				checkBytes(t, c.Name, got, want)
				h := ArchiveHeader{Mode: ModeVariable, MaxFrameQuanta: MaxMaxFrameQuanta}
				d, err := DecodeIndexRecord(want, &h)
				if err != nil || d != v {
					t.Fatalf("decode: %+v %v", d, err)
				}
			case "path_len":
				var j struct{ Value int }
				decodeFields(t, c.Fields, &j)
				got, err := AppendPathLen(nil, j.Value)
				if err != nil {
					t.Fatal(err)
				}
				checkBytes(t, c.Name, got, want)
				n, used, err := DecodePathLen(want)
				if err != nil || n != j.Value || used != len(want) {
					t.Fatalf("decode: %d %d %v", n, used, err)
				}
			case "min_parity_frame":
				var j struct {
					Trailer     json.RawMessage
					OuterCrc32c uint32
					Header      json.RawMessage
				}
				decodeFields(t, c.Fields, &j)
				var tj jTrailer
				decodeFields(t, j.Trailer, &tj)
				var hj jHeader
				decodeFields(t, j.Header, &hj)
				h := hj.value(t)
				if err := h.Validate(); err != nil {
					t.Fatal(err)
				}
				p, err := DecodeFramePrefix(want, &h)
				if err != nil {
					t.Fatal(err)
				}
				tail, err := DecodeFrameTail(want)
				if err != nil {
					t.Fatal(err)
				}
				if tail.Trailer != tj.value(t) {
					t.Fatalf("trailer %+v", tail.Trailer)
				}
				if err := ValidateTrailer(&tail.Trailer, &h, p); err != nil {
					t.Fatal(err)
				}
				lay, err := ComputeLayout(p.FrameQuanta, uint64(tail.Trailer.DataLen), uint64(len(tail.Body)))
				if err != nil || lay.PaddingLen != 0 || uint64(tail.Trailer.DataLen) != ParityShardLen(1) {
					t.Fatalf("layout %+v %v", lay, err)
				}
			default:
				t.Fatalf("unknown golden kind %q", c.Kind)
			}
		})
	}
	for _, k := range []string{"archive_header", "root", "frame_prefix", "master_trailer", "alloc_state", "index_header", "index_record", "path_len", "min_parity_frame"} {
		if seen[k] == 0 {
			t.Errorf("no golden vector for %s", k)
		}
	}
	if seen["alloc_state"] != 5 {
		t.Errorf("want Allocator State vectors for all 5 kinds, got %d", seen["alloc_state"])
	}
}
