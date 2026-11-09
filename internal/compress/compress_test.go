package compress

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"stash/internal/wire"
)

const maxFrame = 16 << 20

// §17.7: libzstd frames (independent encoder) decode exactly; malformed,
// truncated, multi-frame, skippable, dictionary and wrong-length cases
// fail closed before or during decoding.
func TestGoldenLibzstd(t *testing.T) {
	b, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Cases []struct {
			Name, Logical, Frame string
			OK                   bool
			Expected             uint64
		}
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	for _, c := range g.Cases {
		logical, _ := hex.DecodeString(c.Logical)
		fr, _ := hex.DecodeString(c.Frame)
		out, err := Decode(wire.CodecZstdDefault, fr, c.Expected, maxFrame, nil)
		if c.OK {
			if err != nil || !bytes.Equal(out, logical) {
				t.Errorf("%s: %v", c.Name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", c.Name)
		} else if !errors.Is(err, wire.ErrCorrupt) {
			t.Errorf("%s: wrong class %v", c.Name, err)
		}
	}
}

// §17.7: exact round trip for every codec; STORE when compression does
// not help; Go output satisfies §5.1.1.
func TestRoundTrip(t *testing.T) {
	text := bytes.Repeat([]byte("round trip text with some redundancy "), 3000)
	random := make([]byte, 50000)
	rand.Read(random)
	for _, c := range []wire.CodecID{wire.CodecStore, wire.CodecZstdFast, wire.CodecZstdDefault, wire.CodecZstdDense} {
		got, stored, err := Encode(c, text, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c != wire.CodecStore {
			if got != c || len(stored) >= len(text) {
				t.Fatalf("codec %d: %d -> %d bytes as %d", c, len(text), len(stored), got)
			}
			fi, err := Inspect(stored, uint64(len(text)), maxFrame)
			if err != nil || fi.Checksum || fi.WindowSize != uint64(len(text)) {
				t.Fatalf("codec %d frame: %+v %v", c, fi, err)
			}
		}
		out, err := Decode(got, stored, uint64(len(text)), maxFrame, nil)
		if err != nil || !bytes.Equal(out, text) {
			t.Fatalf("codec %d decode: %v", c, err)
		}
		if got, stored, _ := Encode(c, random, nil); got != wire.CodecStore || &stored[0] != &random[0] {
			t.Fatalf("codec %d: incompressible data not stored", c)
		}
		if got, _, _ := Encode(c, nil, nil); got != wire.CodecStore {
			t.Fatal("empty payload must be STORE")
		}
	}
	if _, err := Decode(wire.CodecID(4), text, 1, maxFrame, nil); !errors.Is(err, wire.ErrUnsupported) {
		t.Fatal("reserved codec accepted")
	}
	if _, _, err := Encode(wire.CodecID(4), text, nil); err == nil {
		t.Fatal("reserved codec encoded")
	}
	// declared output limit: the frame says N, the caller expects less
	_, stored, _ := Encode(wire.CodecZstdFast, text, nil)
	if _, err := Decode(wire.CodecZstdFast, stored, uint64(len(text))-1, maxFrame, nil); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal("output limit")
	}
	if _, err := Decode(wire.CodecZstdFast, stored, uint64(len(text)), uint64(len(text))-1, nil); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal("MAX_FRAME_SIZE ceiling")
	}
	// truncated at every length fails closed, never panics
	for n := 0; n < len(stored); n += 7 {
		if _, err := Decode(wire.CodecZstdFast, stored[:n], uint64(len(text)), maxFrame, nil); err == nil {
			t.Fatalf("truncated to %d accepted", n)
		}
	}
}

func FuzzDecode(f *testing.F) {
	_, s, _ := Encode(wire.CodecZstdFast, bytes.Repeat([]byte("fuzz"), 500), nil)
	f.Add(s, uint32(2000))
	f.Fuzz(func(t *testing.T, b []byte, n uint32) {
		out, err := Decode(wire.CodecZstdDefault, b, uint64(n%(1<<20)), 1<<20, nil)
		if err == nil && uint64(len(out)) != uint64(n%(1<<20)) {
			t.Fatal("length")
		}
	})
}
