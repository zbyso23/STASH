package manifest

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"os"
	"testing"

	"stash/internal/blob"
	"stash/internal/frame"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// End to end: frames written and synced, committed through the journal,
// more frames written without commit, crash. The manifest's references
// decide the blob's torn tail: committed frames are kept, the rest is
// truncated; a damaged committed frame seals the blob.
func TestManifestDrivesBlobTornTail(t *testing.T) {
	h := hdr()
	ext := func(path string, ver, off uint64, n int, seed byte) (*frame.Spec, Loc) {
		p := bytes.Repeat([]byte{seed}, n)
		s := &frame.Spec{BlockType: wire.BlockData, Payload: p,
			Entries: []wire.Entry{{Path: path, Offset: off, Length: uint64(n), FileVer: ver}}}
		return s, Loc{Blob: 0, Hash: sha256.Sum256(p), Offset: off, Length: uint64(n)}
	}
	sealed := 0
	for seed := int64(0); seed < 100; seed++ {
		rng := rand.New(rand.NewSource(seed))
		c := newFS(t)
		c.MkdirAll("g/frames", 0o755)
		bn := "g/frames/blob-00.stash"
		if err := blob.Create(c, bn, h); err != nil {
			t.Fatal(err)
		}
		bw, _, err := blob.OpenWriter(c, bn, h, nil, blob.Committed{})
		if err != nil {
			t.Fatal(err)
		}
		j, _ := openJ(t, c)
		var locs []Loc
		var offs []int64
		for k := 0; k < 3; k++ {
			n := 4096
			if k == 2 {
				n = 1 + rng.Intn(5000)
			}
			s, l := ext("obj", 1, uint64(k)*4096, n, byte(k+1))
			off, _, err := bw.Append(s)
			if err != nil {
				t.Fatal(err)
			}
			locs, offs = append(locs, l), append(offs, off)
		}
		bw.Sync() // frames durable before the manifest (§10.4)
		j.Add("obj", 1, locs)
		j.Sync()
		// an interrupted second write: frames without commit
		for k := 0; k < 1+rng.Intn(3); k++ {
			s, _ := ext("other", 2, uint64(k)*4096, 4096, byte(10+k))
			bw.Append(s)
		}
		damageCommitted := rng.Intn(4) == 0
		after := c.Crash(vfs.CrashTear, rng)
		if damageCommitted {
			f, _ := after.OpenFile(bn, os.O_RDWR, 0)
			f.WriteAt([]byte{0xEE, 0xEE}, offs[1]+50)
			f.Sync()
			f.Close()
		}
		st, _, err := Load(after, "g", h, LoadOptions{TrackRefs: true})
		if err != nil {
			t.Fatal(err)
		}
		_, res, err := blob.OpenWriter(after, bn, h, nil, st.BlobCommitted(0, nil))
		if damageCommitted {
			if !blob.IsSealed(err) {
				t.Fatalf("seed %d: damaged committed frame not sealed: %v", seed, err)
			}
			sealed++
			continue
		}
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		end := offs[2] + int64(wire.FrameSize(1)) // third frame is one or two quanta
		if res.Scan.End < end-4096 || res.Scan.Frames < 3 {
			t.Fatalf("seed %d: committed frames lost: %+v", seed, res.Scan)
		}
	}
	if sealed == 0 {
		t.Fatal("no seed damaged a committed frame")
	}
}
