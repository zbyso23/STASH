package recovery

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"stash/internal/archive"
	"stash/internal/vfs"
	"stash/internal/wire"
)

var rkey = bytes.Repeat([]byte{0xC3}, 32)

func encFixture(t *testing.T, c archive.Config) (*vfs.CrashFS, map[string][]byte) {
	t.Helper()
	fsys := vfs.NewCrashFS()
	c.Key = rkey
	if _, err := archive.Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	w, err := archive.OpenWriter(fsys, archive.Options{MaxExtent: 8192, Key: rkey})
	if err != nil {
		t.Fatal(err)
	}
	live := map[string][]byte{}
	for i, n := range []int{0, 10, 5000, 20000, 70000} {
		p := "obj/" + string(rune('a'+i))
		live[p] = data(i, n)
		if i%2 == 1 { // compressible
			live[p] = bytes.Repeat([]byte("stash-zstd "), n/11+1)[:n]
		}
		if _, err := w.Put(p, live[p]); err != nil {
			t.Fatal(err)
		}
	}
	// compaction: frames keep the nonces of generation 0
	if _, err := w.Compact(context.Background(), archive.CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Put("after", data(99, 12000)); err != nil {
		t.Fatal(err)
	}
	live["after"] = data(99, 12000)
	w.Close()
	return fsys, live
}

// §15.10/§11.7: keyed recovery of an encrypted, compressed, compacted
// archive decrypts every frame with its stored nonce; without the
// manifest it still finds and extracts everything; keyless recovery groups
// DATA extents by object_id and extracts nothing.
func TestEncryptedRecovery(t *testing.T) {
	for _, c := range []archive.Config{
		{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16, Codec: wire.CodecZstdDefault},
		{Mode: wire.ModeFixed, HashID: wire.HashBLAKE3, BlobCount: 3, MaxFrameQuanta: 4, Codec: wire.CodecZstdFast,
			ParityScheme: wire.ParityXOR, ParityK: 2, ParityM: 1},
	} {
		fsys, live := encFixture(t, c)
		for _, noManifest := range []bool{false, true} {
			rc, err := Scan(fsys, Options{Key: rkey, NoManifest: noManifest})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, v := range rc.DefaultSelection() {
				if d, ok := live[v.Path]; ok {
					if !bytes.Equal(extract(t, rc, v), d) {
						t.Fatalf("%s differs (noManifest %v)", v.Path, noManifest)
					}
					got[v.Path] = true
				}
			}
			if len(got) != len(live) || rc.Keyless {
				t.Fatalf("recovered %v of %d", got, len(live))
			}
			rc.Close()
		}
		rc, err := Scan(fsys, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !rc.Keyless || !errors.Is(rc.Manifest.Err, archive.ErrKeyRequired) {
			t.Fatalf("keyless report %+v", rc.Manifest)
		}
		opaque := 0
		for _, v := range rc.Versions {
			if !v.Opaque || v.Path != "" {
				t.Fatalf("keyless version names %q", v.Path)
			}
			opaque++
			if err := rc.Extract(v, &bytes.Buffer{}); !errors.Is(err, archive.ErrKeyRequired) {
				t.Fatalf("keyless extract: %v", err)
			}
		}
		if opaque == 0 && rc.OpaquePacked == 0 {
			t.Fatal("keyless scan found nothing")
		}
		rc.Close()
		// a wrong key is refused
		bad := bytes.Clone(rkey)
		bad[0] ^= 1
		if _, err := Scan(fsys, Options{Key: bad}); !errors.Is(err, archive.ErrWrongKey) {
			t.Fatalf("wrong key: %v", err)
		}
		// key.check lost with the root: the frames still authenticate
		fsys.Remove(archive.KeyCheckName)
		fsys.Remove(archive.RootName)
		rc, err = Scan(fsys, Options{Key: rkey})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, v := range rc.DefaultSelection() {
			if d, ok := live[v.Path]; ok && bytes.Equal(extract(t, rc, v), d) {
				n++
			}
		}
		if n != len(live) {
			t.Fatalf("without key.check: %d of %d", n, len(live))
		}
		rc.Close()
	}
}

// Raw recovery of extents whose logical length exceeds the frame's
// uncompressed capacity (§6.6.1), with and without the manifest.
func TestRecoverCompressedExtents(t *testing.T) {
	for _, key := range [][]byte{nil, rkey} {
		fsys := vfs.NewCrashFS()
		c := archive.Config{Mode: wire.ModeFixed, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 4,
			Codec: wire.CodecZstdDense, ParityScheme: wire.ParityRS, ParityK: 2, ParityM: 1, Key: key}
		if _, err := archive.Create(fsys, c); err != nil {
			t.Fatal(err)
		}
		w, err := archive.OpenWriter(fsys, archive.Options{Key: key})
		if err != nil {
			t.Fatal(err)
		}
		d := bytes.Repeat([]byte("recoverable compressed extent "), 40000)
		if _, err := w.Put("x", d); err != nil {
			t.Fatal(err)
		}
		v, _ := w.Stat("x")
		w.Close()
		if v.Loc[0].Length <= 16384-4096 {
			t.Fatalf("extent of %d bytes", v.Loc[0].Length)
		}
		for _, noManifest := range []bool{false, true} {
			rc, err := Scan(fsys, Options{Key: key, NoManifest: noManifest})
			if err != nil {
				t.Fatal(err)
			}
			sel := rc.DefaultSelection()
			if len(sel) != 1 || !bytes.Equal(extract(t, rc, sel[0]), d) {
				t.Fatalf("recovery (noManifest %v)", noManifest)
			}
			rc.Close()
		}
	}
}
