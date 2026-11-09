package seal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"stash/internal/ident"
	"stash/internal/wire"
)

type golden struct {
	DEK       string            `json:"dek"`
	ArchiveID string            `json:"archive_id"`
	Keys      map[string]string `json:"keys"`
	ObjectIDs []struct {
		Path     string `json:"path"`
		FileVer  uint64 `json:"file_ver"`
		ObjectID string `json:"object_id"`
	} `json:"object_ids"`
	FrameNonces []struct {
		Gen, Ordinal uint64
		Blob         uint8
		Nonce        string
	} `json:"frame_nonces"`
	ManifestNonces []struct {
		Gen, Seq uint64
		Nonce    string
	} `json:"manifest_nonces"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T) (golden, []byte, [32]byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g, unhex(t, g.DEK), [32]byte(unhex(t, g.ArchiveID))
}

// §17.9: HKDF golden vectors for all four keys (and the key check).
func TestDeriveGolden(t *testing.T) {
	g, dek, id := load(t)
	d, err := Derive(dek, id)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][32]byte{"frame": d.Frame, "pretrailer": d.PreTrailer, "manifest": d.Manifest, "object_id": d.ObjectID, "key_check": d.KeyCheck} {
		if hex.EncodeToString(got[:]) != g.Keys[name] {
			t.Errorf("%s key: got %x want %s", name, got, g.Keys[name])
		}
	}
	k, err := New(dek, id)
	if err != nil {
		t.Fatal(err)
	}
	if !k.CheckKey(unhex(t, g.Keys["key_check"])) {
		t.Fatal("key check")
	}
	other := bytes.Clone(dek)
	other[0] ^= 1
	k2, _ := New(other, id)
	if k2.CheckKey(unhex(t, g.Keys["key_check"])) {
		t.Fatal("a wrong DEK passed the key check")
	}
	if _, err := Derive(dek[:31], id); !errors.Is(err, wire.ErrInvalid) {
		t.Fatal("short DEK accepted")
	}
}

// §17.9: keyed object_id golden vectors; a guessed path cannot be
// confirmed without the key.
func TestKeyedObjectID(t *testing.T) {
	g, dek, id := load(t)
	k, _ := New(dek, id)
	for _, c := range g.ObjectIDs {
		got, err := k.ObjectID(c.Path, c.FileVer)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got[:]) != c.ObjectID {
			t.Errorf("%q v%d: %x want %s", c.Path, c.FileVer, got, c.ObjectID)
		}
		for _, hid := range []wire.HashID{wire.HashSHA256, wire.HashBLAKE3} {
			guess, _ := ident.ObjectID(hid, c.Path, c.FileVer)
			if guess == got {
				t.Fatalf("unkeyed object_id confirms %q", c.Path)
			}
		}
	}
}

// §17.9: exact nonce layouts and the encrypted-profile limits.
func TestNonces(t *testing.T) {
	g, _, _ := load(t)
	for _, c := range g.FrameNonces {
		n, err := FrameNonce(c.Gen, c.Blob, c.Ordinal)
		if err != nil || hex.EncodeToString(n[:]) != c.Nonce {
			t.Errorf("frame nonce %+v: %x %v", c, n, err)
		}
		if gg, b, o := SplitFrameNonce(n[:]); gg != c.Gen || b != c.Blob || o != c.Ordinal {
			t.Errorf("split %+v", c)
		}
	}
	for _, c := range g.ManifestNonces {
		n, err := ManifestNonce(c.Gen, c.Seq)
		if err != nil || hex.EncodeToString(n[:]) != c.Nonce {
			t.Errorf("manifest nonce %+v: %x %v", c, n, err)
		}
	}
	if _, err := FrameNonce(MaxGenerationID+1, 0, 0); !errors.Is(err, ErrNonceLimit) {
		t.Fatal("generation limit")
	}
	if _, err := FrameNonce(0, 0, MaxFrameOrdinal+1); !errors.Is(err, ErrNonceLimit) {
		t.Fatal("ordinal limit")
	}
	if _, err := ManifestNonce(MaxGenerationID+1, 1); !errors.Is(err, ErrNonceLimit) {
		t.Fatal("manifest generation limit")
	}
	// injective across blob ordinals, frame ordinals and generations
	seen := map[[12]byte]bool{}
	for gen := uint64(0); gen < 4; gen++ {
		for b := 0; b < 4; b++ {
			for o := uint64(0); o < 300; o++ {
				n, _ := FrameNonce(gen, uint8(b), o)
				if seen[n] {
					t.Fatalf("nonce reuse at %d/%d/%d", gen, b, o)
				}
				seen[n] = true
			}
		}
	}
}

// §17.9: tag, AAD and stored-nonce tampering are rejected; domains are
// separate.
func TestSealOpenTamper(t *testing.T) {
	_, dek, id := load(t)
	k, _ := New(dek, id)
	nonce, _ := FrameNonce(1, 2, 3)
	aad := []byte("aad")
	s := k.Seal(FrameDomain, nil, nonce, []byte("secret payload"), aad)
	if p, err := k.Open(FrameDomain, nil, s, aad); err != nil || string(p) != "secret payload" {
		t.Fatal(p, err)
	}
	for name, mut := range map[string]func([]byte) ([]byte, []byte){
		"tag":    func(b []byte) ([]byte, []byte) { b[len(b)-1] ^= 1; return b, aad },
		"cipher": func(b []byte) ([]byte, []byte) { b[13] ^= 1; return b, aad },
		"nonce":  func(b []byte) ([]byte, []byte) { b[0] ^= 1; return b, aad },
		"aad":    func(b []byte) ([]byte, []byte) { return b, []byte("aae") },
	} {
		b, a := mut(bytes.Clone(s))
		if _, err := k.Open(FrameDomain, nil, b, a); !errors.Is(err, ErrAuth) || !errors.Is(err, wire.ErrCorrupt) {
			t.Errorf("%s tampering: %v", name, err)
		}
	}
	if _, err := k.Open(PreTrailerDomain, nil, s, aad); !errors.Is(err, ErrAuth) {
		t.Fatal("frame ciphertext opened under the Pre-Trailer key")
	}
	if _, err := k.Open(FrameDomain, nil, s[:27], aad); !errors.Is(err, ErrAuth) {
		t.Fatal("short value")
	}
}
