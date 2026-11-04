package canonpath

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type golden struct {
	Assigned15 [][2]rune
	Paths      []struct {
		PathHex string `json:"path_hex"`
		Valid   bool
	}
}

func load(t *testing.T) golden {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// The checked-in table (from Go's 15.0.0 tables) must equal the table the
// independent generator derives from Python's 15.1 data minus 15.1 additions.
func TestAssignedTableMatchesIndependentSource(t *testing.T) {
	g := load(t)
	if len(g.Assigned15) != len(assigned15) {
		t.Fatalf("ranges: generator %d, table %d", len(g.Assigned15), len(assigned15))
	}
	for i := range assigned15 {
		if g.Assigned15[i] != assigned15[i] {
			t.Fatalf("range %d: generator %X, table %X", i, g.Assigned15[i], assigned15[i])
		}
	}
	for _, c := range []struct {
		r  rune
		ok bool
	}{{'a', true}, {0x0378, false}, {0xFDD0, false}, {0xFFFF, false}, {0xE000, true}, {0x1FAE8, true},
		{0x2EBF0, false}, {0x31EF, false}, {0x10FFFF, false}, {0x10FFFD, true}} {
		if Assigned(c.r) != c.ok {
			t.Errorf("Assigned(U+%04X) = %v", c.r, !c.ok)
		}
	}
}

func TestGoldenPaths(t *testing.T) {
	for _, c := range load(t).Paths {
		b, _ := hex.DecodeString(c.PathHex)
		err := Validate(string(b))
		if (err == nil) != c.Valid {
			t.Errorf("%q: valid=%v err=%v", b, c.Valid, err)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: error class %v", b, err)
		}
	}
}

func TestValidateExtra(t *testing.T) {
	for _, p := range []string{"a\xffb", "\xed\xa0\x80", "a/./b", "a\u009fb"} {
		if Validate(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	// a 4096-byte path made of 2-byte characters
	if err := Validate(strings.Repeat("č", 2048)); err != nil {
		t.Error(err)
	}
	if Validate(strings.Repeat("č", 2048)+"x") == nil {
		t.Error("4097 bytes accepted")
	}
}

func TestNormalize(t *testing.T) {
	n, err := Normalize("čt") // NFD č
	if err != nil || n != "čt" {
		t.Fatalf("%q %v", n, err)
	}
	for _, p := range []string{"/a", "a//b", "a/../b", "a\xff"} {
		if _, err := Normalize(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestCompareBytewise(t *testing.T) {
	if Compare("a", "a/b") >= 0 || Compare("a/b", "a0") >= 0 || Compare("Z", "a") >= 0 || Compare("ž", "z") <= 0 {
		t.Error("ordering")
	}
}

func FuzzValidate(f *testing.F) {
	f.Add("a/b")
	f.Fuzz(func(t *testing.T, p string) {
		if Validate(p) == nil {
			n, err := Normalize(p)
			if err != nil || n != p {
				t.Fatalf("canonical path changed by Normalize: %q -> %q (%v)", p, n, err)
			}
		}
	})
}
