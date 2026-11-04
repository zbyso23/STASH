package ident

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"stash/internal/wire"
)

func TestObjectIDGolden(t *testing.T) {
	raw, err := os.ReadFile("../frame/testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		ObjectIDs []struct {
			Path    string
			FileVer uint64 `json:"file_ver"`
			SHA256  string `json:"sha256"`
			HMACKey string `json:"hmac_key"`
			HMAC    string `json:"hmac"`
		} `json:"object_ids"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.ObjectIDs) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range g.ObjectIDs {
		id, err := ObjectID(wire.HashSHA256, c.Path, c.FileVer)
		if err != nil || hex.EncodeToString(id[:]) != c.SHA256 {
			t.Errorf("sha256 %q: %x %v", c.Path, id, err)
		}
		key, _ := hex.DecodeString(c.HMACKey)
		kid, err := KeyedObjectID(key, c.Path, c.FileVer)
		if err != nil || hex.EncodeToString(kid[:]) != c.HMAC {
			t.Errorf("hmac %q: %x %v", c.Path, kid, err)
		}
		if kid == id {
			t.Error("keyed id equals unkeyed id")
		}
	}
	if _, err := KeyedObjectID(make([]byte, 16), "a", 1); err == nil {
		t.Error("short key accepted")
	}
}

// BLAKE3 known answer from the official BLAKE3 test vectors (empty input).
func TestBLAKE3KnownAnswer(t *testing.T) {
	h, err := Hash(wire.HashBLAKE3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(h[:]); got != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" {
		t.Fatal(got)
	}
	if _, err := Hash(0, nil); err == nil {
		t.Error("hash_id 0 accepted")
	}
	a, _ := ObjectID(wire.HashBLAKE3, "a", 1)
	b, _ := ObjectID(wire.HashSHA256, "a", 1)
	if a == b {
		t.Error("BLAKE3 and SHA-256 object ids equal")
	}
}
