package archive

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"path"
	"testing"

	"stash/internal/vfs"
	"stash/internal/wire"
)

func cpFixture(t *testing.T) (*vfs.CrashFS, map[string][]byte) {
	fsys := vfs.NewCrashFS()
	mustCreate(t, fsys)
	w, err := OpenWriter(fsys, Options{MaxExtent: 8192, PackThreshold: -1})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{}
	for i := 0; i < 12; i++ {
		p := fmt.Sprintf("p%d", i)
		want[p] = data(i, 3000+i*1000)
		if _, err := w.Put(p, want[p]); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	return fsys, want
}

// A clean close records checkpoints; the next open walks frames below them
// without hashing and finds the same state (E1-23).
func TestCheckpointUsed(t *testing.T) {
	fsys, want := cpFixture(t)
	w := mustOpen(t, fsys)
	first := w.Health().Checkpointed
	if first < 12 || len(w.Health().Sealed) != 0 {
		t.Fatalf("health %+v", w.Health())
	}
	checkAll(t, w.Get, want)
	w.Put("more", data(99, 5000))
	w.Close()
	w = mustOpen(t, fsys)
	if w.Health().Checkpointed != first+1 {
		t.Fatalf("checkpoint not advanced: %+v", w.Health())
	}
	w.Close()
}

// Payload damage below a checkpoint is found on read, not at open: the
// blob stays writable and the object reports ErrMissingData.
func TestCheckpointPayloadDamage(t *testing.T) {
	fsys, want := cpFixture(t)
	damage(t, fsys, blobFile(0), wire.FrameAreaStart+40, 4) // first frame of blob 0, not its last
	w := mustOpen(t, fsys)
	if len(w.Health().Sealed) != 0 || w.Health().Checkpointed == 0 {
		t.Fatalf("health %+v", w.Health())
	}
	missing := 0
	for p, d := range want {
		got, err := w.Get(p)
		switch {
		case errors.Is(err, ErrMissingData):
			missing++
		case err != nil || !bytes.Equal(got, d):
			t.Fatalf("%s: %v", p, err)
		}
	}
	if missing != 1 {
		t.Fatalf("%d objects missing", missing)
	}
	w.Close()
	// VerifyAll ignores the checkpoint and seals the damaged blob at open
	w2, err := OpenWriter(fsys, Options{VerifyAll: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if _, ok := w2.Health().Sealed[0]; !ok || w2.Health().Checkpointed != 0 {
		t.Fatalf("VerifyAll: %+v", w2.Health())
	}
}

// A damaged tail below the checkpoint, a damaged checkpoint file, or one
// from another generation makes the open validate everything again.
func TestCheckpointRejected(t *testing.T) {
	fsys, _ := cpFixture(t)
	damage(t, fsys, blobFile(1), wire.FrameAreaStart+4096-60, 4) // tail of blob 1's first frame
	w := mustOpen(t, fsys)
	if _, ok := w.Health().Sealed[1]; !ok {
		t.Fatalf("damaged tail below the checkpoint not sealed: %+v", w.Health())
	}
	w.Close()

	fsys, _ = cpFixture(t)
	name := path.Join(GenDir(0), checkpointName)
	damage(t, fsys, name, 60, 1)
	w = mustOpen(t, fsys)
	if w.Health().Checkpointed != 0 {
		t.Fatal("damaged checkpoint file used")
	}
	w.Close() // writes a fresh one

	b, _ := vfs.ReadFile(fsys, name, 1<<20)
	b[40] ^= 1 // generation_id
	vfs.ReplaceFile(fsys, name, b)
	w = mustOpen(t, fsys)
	if w.Health().Checkpointed != 0 {
		t.Fatal("checkpoint of another generation used")
	}
	w.Close()
}

// Crashes after a clean close: every returned Put durable, nothing sealed,
// and the checkpoint still applies below the frames written since.
func TestCheckpointCrash(t *testing.T) {
	base, want := cpFixture(t)
	s := &snapFS{CrashFS: base, rng: rand.New(rand.NewSource(3))}
	w := mustOpen(t, s)
	type done struct {
		p  string
		d  []byte
		at int
	}
	var hist []done
	for i := 0; i < 10; i++ {
		p := fmt.Sprintf("n%d", i)
		d := data(500+i, 2000+i*3000)
		if _, err := w.Put(p, d); err != nil {
			t.Fatal(err)
		}
		hist = append(hist, done{p, d, s.count()})
	}
	w.Close()
	for k, snap := range s.snaps {
		w2, err := OpenWriter(snap, Options{MaxExtent: 8192})
		if err != nil {
			t.Fatalf("snapshot %d: %v", k, err)
		}
		if len(w2.Health().Sealed) != 0 || w2.Health().Checkpointed == 0 {
			t.Fatalf("snapshot %d: %+v", k, w2.Health())
		}
		checkAll(t, w2.Get, want)
		for _, h := range hist {
			if h.at <= k {
				if got, err := w2.Get(h.p); err != nil || !bytes.Equal(got, h.d) {
					t.Fatalf("snapshot %d: %s lost (%v)", k, h.p, err)
				}
			}
		}
		w2.Close()
	}
}
