package archive

import (
	"context"
	"testing"

	"stash/internal/vfs"
	"stash/internal/wire"
)

func TestVerify(t *testing.T) {
	ctx := context.Background()
	// clean archive with parity
	fsys := vfs.NewCrashFS()
	cfgRS := parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable)
	if _, err := Create(fsys, cfgRS); err != nil {
		t.Fatal(err)
	}
	want := writeObjects(t, fsys, 3)
	r, _ := OpenReader(fsys, nil)
	rep, err := r.Verify(ctx)
	r.Close()
	if err != nil || !rep.OK() || rep.Versions != len(want) || rep.Groups.Healthy != rep.Groups.Total || rep.Groups.Total == 0 {
		t.Fatalf("clean: %v %+v", err, rep)
	}
	// one damaged member per group: degraded, everything still read
	groups, _ := groupsOf(t, fsys)
	for _, ms := range groups {
		mem := ms[0]
		damage(t, fsys, blobFile(int(mem.blob)), mem.off+16, 3)
	}
	r, _ = OpenReader(fsys, nil)
	rep, err = r.Verify(ctx)
	r.Close()
	if err != nil || rep.OK() || len(rep.Failed) != 0 || rep.Groups.Degraded != len(groups) || rep.Groups.Healthy != 0 {
		t.Fatalf("damaged: %v %+v", err, rep.Groups)
	}
	damagedBlobs := 0
	for _, b := range rep.Blobs {
		if len(b.Damaged) > 0 {
			damagedBlobs++
		}
	}
	if damagedBlobs == 0 {
		t.Fatal("no damaged region reported")
	}

	// without parity damage is a failed path
	fsys = vfs.NewCrashFS()
	mustCreate(t, fsys)
	w := mustOpen(t, fsys)
	w.Put("x", data(1, 100000))
	w.Put("y", data(2, 100))
	v, _ := w.Stat("x")
	w.Close()
	rr, _ := OpenReader(fsys, nil)
	bv := rr.blobs[v.Loc[1].Blob]
	recs := bv.idx.Lookup(v.Loc[1].Hash)
	rr.Close()
	damage(t, fsys, blobFile(int(v.Loc[1].Blob)), int64(recs[0].PhysicalOffset)+16, 2)
	w = mustOpen(t, fsys)
	rep, err = w.Verify(ctx)
	w.Close()
	if err != nil || rep.OK() || rep.Failed["x"] == nil || len(rep.Failed) != 1 {
		t.Fatalf("no parity: %v %+v", err, rep)
	}
}
