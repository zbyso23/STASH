package recovery

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path"
	"testing"

	"stash/internal/archive"
	"stash/internal/blob"
	"stash/internal/manifest"
	"stash/internal/vfs"
	"stash/internal/wire"
)

func data(seed, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(int64(seed))).Read(b)
	return b
}

func blobFile(b int) string { n, _ := blob.Name(uint8(b)); return path.Join(archive.GenDir(0), n) }

func damage(t testing.TB, fsys vfs.FS, name string, off int64, n int) {
	t.Helper()
	f, err := fsys.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, n)
	f.ReadAt(b, off)
	for i := range b {
		b[i] ^= 0x5A
	}
	f.WriteAt(b, off)
	f.Sync()
	f.Close()
}

type memWriterAt struct{ b []byte }

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if need := int(off) + len(p); need > len(m.b) {
		m.b = append(m.b, make([]byte, need-len(m.b))...)
	}
	return copy(m.b[off:], p), nil
}

// fixture: objects of several extents and small packed ones; a.bin is
// overwritten (v1 superseded), gone.bin deleted.
func fixture(t *testing.T, cfg archive.Config) (*vfs.CrashFS, map[string][]byte, map[string][]byte) {
	t.Helper()
	c := vfs.NewCrashFS()
	if _, err := archive.Create(c, cfg); err != nil {
		t.Fatal(err)
	}
	w, err := archive.OpenWriter(c, archive.Options{MaxExtent: 8192})
	if err != nil {
		t.Fatal(err)
	}
	live := map[string][]byte{}
	old := map[string][]byte{}
	for i, n := range []int{0, 10, 5000, 8192, 20000, 70000} {
		p := "obj/" + string(rune('a'+i))
		live[p] = data(i, n)
		if _, err := w.Put(p, live[p]); err != nil {
			t.Fatal(err)
		}
	}
	old["a.bin"] = data(50, 30000)
	w.Put("a.bin", old["a.bin"])
	live["a.bin"] = data(51, 9000)
	w.Put("a.bin", live["a.bin"])
	old["gone.bin"] = data(52, 100)
	w.Put("gone.bin", old["gone.bin"])
	if err := w.Delete("gone.bin"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return c, live, old
}

var plain = archive.Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 3, MaxFrameQuanta: 16}

func extract(t *testing.T, rc *Recovery, v *Version) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := rc.Extract(v, &b); err != nil {
		t.Fatalf("%s v%d: %v", v.Path, v.FileVer, err)
	}
	return b.Bytes()
}

func byPath(rc *Recovery) map[string][]*Version {
	m := map[string][]*Version{}
	for _, v := range rc.Versions {
		m[v.Path] = append(m[v.Path], v)
	}
	return m
}

func TestScanIntact(t *testing.T) {
	c, live, old := fixture(t, plain)
	rc, err := Scan(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if !rc.Authoritative || !rc.Manifest.Loaded || len(rc.Versions) != len(live)+len(old) {
		t.Fatalf("%+v %d versions", rc.Manifest, len(rc.Versions))
	}
	vs := byPath(rc)
	for p, d := range live {
		cur := vs[p][len(vs[p])-1]
		if !cur.Current || !cur.Committed || !cur.Complete || cur.Unverified || !bytes.Equal(extract(t, rc, cur), d) {
			t.Fatalf("%s: %+v", p, cur)
		}
	}
	if v := vs["a.bin"][0]; v.Current || !v.Committed || !bytes.Equal(extract(t, rc, v), old["a.bin"]) {
		t.Fatalf("superseded %+v", v)
	}
	if v := vs["gone.bin"][0]; v.Current || !v.Committed || !bytes.Equal(extract(t, rc, v), old["gone.bin"]) {
		t.Fatalf("deleted %+v", v)
	}
	if sel := rc.DefaultSelection(); len(sel) != len(live) {
		t.Fatalf("selection %d", len(sel))
	}
}

// Without a manifest every version is "not known to be committed" and the
// selection takes the highest file_ver per path, deleted ones included.
func TestScanWithoutManifest(t *testing.T) {
	c, live, _ := fixture(t, plain)
	c.Remove(path.Join(archive.GenDir(0), manifest.ManifestName))
	c.Remove(archive.RootName)
	rc, err := Scan(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if rc.Authoritative || rc.RootErr == nil || rc.Manifest.Loaded || rc.Manifest.Err == nil {
		t.Fatalf("labels %+v", rc.Report.Manifest)
	}
	for _, v := range rc.Versions {
		if v.Committed || v.Current || v.LengthKnown {
			t.Fatalf("%+v", v)
		}
	}
	sel := rc.DefaultSelection()
	if len(sel) != len(live)+1 {
		t.Fatalf("selection %d", len(sel))
	}
	for _, v := range sel {
		if d, ok := live[v.Path]; ok && !bytes.Equal(extract(t, rc, v), d) {
			t.Fatal(v.Path)
		}
	}
}

// A damaged DATA frame: the version with it has a gap; frames after the
// damage are resync candidates, trusted because the manifest references
// them, unverified when it is gone.
func TestScanDamageNoParity(t *testing.T) {
	c, live, _ := fixture(t, plain)
	r, _ := archive.OpenReader(c, nil)
	v, _ := r.Stat("obj/f") // 70000 bytes: 9 extents
	r.Close()
	l := v.Loc[3]
	var off int64 = -1
	br, _ := blob.Open(c, blobFile(int(l.Blob)), mustHeader(t, c), nil)
	br.Hop(func(f blob.HopFrame) error {
		if f.Trailer.HashPayload == l.Hash {
			off = f.Offset
		}
		return nil
	})
	br.Close()
	damage(t, c, blobFile(int(l.Blob)), off+100, 8)
	for _, withManifest := range []bool{true, false} {
		rc, err := Scan(c, Options{NoManifest: !withManifest})
		if err != nil {
			t.Fatal(err)
		}
		br := rc.Blobs[l.Blob]
		if len(br.Damaged) == 0 || br.Damaged[0].From != off {
			t.Fatalf("damaged %+v", br)
		}
		for _, v := range rc.Versions {
			if v.Path == "obj/f" {
				if v.Complete || len(v.Gaps) != 1 || v.Gaps[0] != (Range{l.Offset, l.Length}) && withManifest {
					t.Fatalf("damaged version %+v", v)
				}
				m := &memWriterAt{}
				missing, err := rc.ExtractAt(v, m)
				if err != nil || len(missing) != 1 || !bytes.Equal(m.b[:l.Offset], live["obj/f"][:l.Offset]) {
					t.Fatalf("partial %v %v", missing, err)
				}
				continue
			}
			resynced := false
			for _, e := range v.Extents {
				resynced = resynced || e.Source == Resynced
			}
			if resynced && v.Unverified == withManifest {
				t.Fatalf("manifest %v: %s unverified=%v", withManifest, v.Path, v.Unverified)
			}
			if d, ok := live[v.Path]; ok && v.Current && !bytes.Equal(extract(t, rc, v), d) {
				t.Fatal(v.Path)
			}
		}
		rc.Close()
	}
}

func mustHeader(t *testing.T, c vfs.FS) *wire.ArchiveHeader {
	h, err := archive.ReadHeader(c, archive.GenDir(0))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// With RS 3+2, a lost blob and a damaged one are rebuilt from parity.
func TestScanParityRebuild(t *testing.T) {
	cfg := plain
	cfg.BlobCount, cfg.ParityScheme, cfg.ParityK, cfg.ParityM = 5, wire.ParityRS, 3, 2
	for _, mode := range []wire.FrameSizeMode{wire.ModeVariable, wire.ModeFixed} {
		cfg.Mode = mode
		c, live, _ := fixture(t, cfg)
		c.Remove(blobFile(1))
		damage(t, c, blobFile(3), wire.FrameAreaStart+200, 64)
		rc, err := Scan(c, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if rc.Blobs[1].Err == nil || rc.Groups.RebuiltFrames == 0 || rc.Groups.Unrecoverable != 0 || rc.Groups.Conflicting != 0 {
			t.Fatalf("mode %v: %+v %+v", mode, rc.Blobs[1], rc.Groups)
		}
		got := 0
		for _, v := range rc.Versions {
			if d, ok := live[v.Path]; ok && v.Current {
				if !bytes.Equal(extract(t, rc, v), d) {
					t.Fatal(v.Path)
				}
				got++
			}
		}
		if got != len(live) {
			t.Fatalf("mode %v: %d of %d recovered", mode, got, len(live))
		}
		rc.Close()
	}
}

func TestSalvage(t *testing.T) {
	c, live, _ := fixture(t, plain)
	c.Remove(path.Join(archive.GenDir(0), manifest.ManifestName))
	rc, err := Scan(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	dst := vfs.NewCrashFS()
	res, err := rc.Salvage(context.Background(), dst, rc.DefaultSelection())
	if err != nil || res.Written != len(live)+1 || len(res.Failed) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	r, err := archive.OpenReader(dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for p, d := range live {
		if got, err := r.Get(p); err != nil || !bytes.Equal(got, d) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if r.Header().ParityScheme != plain.ParityScheme || r.Header().ArchiveID == mustHeader(t, c).ArchiveID {
		t.Fatal("salvage target parameters")
	}
}
