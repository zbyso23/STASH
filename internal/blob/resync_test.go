package blob

import (
	"bytes"
	"testing"

	"stash/internal/frame"
	"stash/internal/wire"
)

func TestResyncIntact(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	c, offs := blobWith(t, h, build(t, h, spec(0, 100)), build(t, h, spec(1, 5000)), build(t, h, spec(2, 9)))
	r, _ := Open(c, "frames/blob-00.stash", h, nil)
	defer r.Close()
	res, err := r.Resync(0)
	if err != nil || len(res.Frames) != 3 || res.Candidates != 0 || len(res.Damaged) != 0 || res.Frames[2].Offset != offs[2] {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestResyncAfterDamage(t *testing.T) {
	for _, mode := range []wire.FrameSizeMode{wire.ModeVariable, wire.ModeFixed} {
		h := header(mode, 4)
		fs := [][]byte{build(t, h, spec(0, 100)), build(t, h, spec(1, 9000)), build(t, h, spec(2, 50)), build(t, h, spec(3, 50))}
		c, offs := blobWith(t, h, fs...)
		damage(t, c, offs[1]+3000)
		r, _ := Open(c, "frames/blob-00.stash", h, nil)
		res, err := r.Resync(0)
		r.Close()
		if err != nil || len(res.Frames) != 3 {
			t.Fatalf("mode %v: %v %+v", mode, err, res)
		}
		if res.Frames[0].Candidate || !res.Frames[1].Candidate || !res.Frames[2].Candidate || res.Candidates != 2 || res.Conflicts != 0 {
			t.Fatalf("mode %v: provenance %+v", mode, res.Frames)
		}
		if len(res.Damaged) != 1 || res.Damaged[0] != (Region{offs[1], offs[2]}) {
			t.Fatalf("mode %v: damaged %+v", mode, res.Damaged)
		}
	}
}

// A forged frame embedded in the payload of a frame found by probing is
// found too, and both are conflicts (§11.2.1).
func TestResyncForgedFrameConflict(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	inner := build(t, h, spec(7, 300))
	payload := append(bytes.Repeat([]byte{'p'}, wire.BaseQuantum-wire.FramePrefixSize), inner...)
	payload = append(payload, bytes.Repeat([]byte{'q'}, 700)...)
	outer := build(t, h, &frame.Spec{BlockType: wire.BlockData, Payload: payload,
		Entries: []wire.Entry{{Path: "evil", Length: uint64(len(payload)), FileVer: 1}}})
	c, offs := blobWith(t, h, build(t, h, spec(0, 10)), build(t, h, spec(1, 10)), outer)
	damage(t, c, offs[1]+20)
	r, _ := Open(c, "frames/blob-00.stash", h, nil)
	defer r.Close()
	res, err := r.Resync(0)
	if err != nil || len(res.Frames) != 3 || res.Conflicts != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	if res.Frames[1].Offset != offs[2] || res.Frames[2].Offset != offs[2]+wire.BaseQuantum || !res.Frames[1].Conflict || !res.Frames[2].Conflict {
		t.Fatalf("%+v", res.Frames)
	}
	// a normal scan of the intact blob never looks inside outer
	c2, _ := blobWith(t, h, build(t, h, spec(0, 10)), outer)
	r2, _ := Open(c2, "frames/blob-00.stash", h, nil)
	defer r2.Close()
	if res, _ := r2.Resync(0); len(res.Frames) != 2 || res.Conflicts != 0 {
		t.Fatalf("intact %+v", res)
	}
}

func TestResyncBudget(t *testing.T) {
	h := header(wire.ModeVariable, 8)
	var fs [][]byte
	for i := 0; i < 10; i++ {
		fs = append(fs, build(t, h, spec(i, 6000)))
	}
	c, offs := blobWith(t, h, fs...)
	damage(t, c, offs[0]+100)
	r, _ := Open(c, "frames/blob-00.stash", h, nil)
	defer r.Close()
	res, err := r.Resync(3 * 6000)
	if err != nil || len(res.Frames) != 3 || len(res.Unscanned) != 1 || res.Unscanned[0].From != offs[4] {
		t.Fatalf("%v %+v", err, res)
	}
	if last := res.Damaged[len(res.Damaged)-1]; last.To > res.Unscanned[0].From {
		t.Fatalf("unscanned reported as damaged %+v", res.Damaged)
	}
}
