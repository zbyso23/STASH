package alloc

import (
	"errors"
	"math/rand"
	"sync"
	"testing"

	"stash/internal/vfs"
	"stash/internal/wire"
)

func ident(kind wire.AllocKind) Identity {
	id := Identity{Kind: kind, ArchiveID: [32]byte{1, 2, 3}}
	if kind.PerGeneration() {
		id.GenerationID = 7
	}
	if kind == wire.AllocFrameOrdinal {
		id.Blob = 3
	}
	return id
}

func setup(t *testing.T, kind wire.AllocKind) (*vfs.CrashFS, string) {
	c := vfs.NewCrashFS()
	c.MkdirAll("alloc", 0o755)
	name := FileName(kind, 3)
	if err := Create(c, name, ident(kind)); err != nil {
		t.Fatal(err)
	}
	return c, name
}

func stored(t *testing.T, fsys vfs.FS, name string) uint64 {
	b, err := vfs.ReadFile(fsys, name, 64)
	if err != nil {
		t.Fatal(err)
	}
	s, err := wire.DecodeAllocState(b)
	if err != nil {
		t.Fatal(err)
	}
	return s.ReservedThrough
}

func TestReserveBeforeUse(t *testing.T) {
	for kind := wire.AllocGeneration; kind <= wire.AllocGroupID; kind++ {
		c, name := setup(t, kind)
		a, err := Open(c, name, ident(kind), 10)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 25; i++ {
			v, err := a.Next()
			if err != nil {
				t.Fatal(err)
			}
			if v != Start(kind)+uint64(i) {
				t.Fatalf("kind %d: value %d at step %d", kind, v, i)
			}
			// the value is below a durable reserved_through
			if r := stored(t, c.Crash(vfs.CrashDropUnsynced, nil), name); v >= r {
				t.Fatalf("kind %d: value %d handed out with durable reserved_through %d", kind, v, r)
			}
		}
		if a.ReservedThrough() != Start(kind)+30 {
			t.Fatalf("kind %d: reserved %d", kind, a.ReservedThrough())
		}
	}
}

func TestBlockBound(t *testing.T) {
	c, name := setup(t, wire.AllocGeneration)
	a, _ := Open(c, name, ident(wire.AllocGeneration), 1<<20)
	a.Next()
	if r := a.ReservedThrough(); r != 256 {
		t.Fatalf("kind 0 block must be capped at 2^8, reserved %d", r)
	}
}

// After any crash, a reopened allocator never hands out a value that was
// handed out before the crash.
func TestNoReuseAfterCrash(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		c, name := setup(t, wire.AllocFrameOrdinal)
		used := map[uint64]bool{}
		fs := vfs.FS(c)
		for round := 0; round < 4; round++ {
			a, err := Open(fs, name, ident(wire.AllocFrameOrdinal), uint64(1+rng.Intn(8)))
			if err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
			for i := 0; i < rng.Intn(30); i++ {
				v, err := a.Next()
				if err != nil {
					t.Fatal(err)
				}
				if used[v] {
					t.Fatalf("seed %d: value %d reused", seed, v)
				}
				used[v] = true
			}
			cc := fs.(*vfs.CrashFS)
			fs = cc.Crash(vfs.CrashTear, rng)
		}
	}
}

func TestIdentityChecks(t *testing.T) {
	c, name := setup(t, wire.AllocFrameOrdinal)
	good := ident(wire.AllocFrameOrdinal)
	for why, id := range map[string]Identity{
		"kind":       {Kind: wire.AllocManifestSeq, GenerationID: 7, ArchiveID: good.ArchiveID},
		"generation": {Kind: good.Kind, Blob: 3, GenerationID: 8, ArchiveID: good.ArchiveID},
		"blob":       {Kind: good.Kind, Blob: 4, GenerationID: 7, ArchiveID: good.ArchiveID},
		"archive":    {Kind: good.Kind, Blob: 3, GenerationID: 7},
	} {
		if _, err := Open(c, name, id, 0); !errors.Is(err, wire.ErrCorrupt) {
			t.Errorf("%s: %v", why, err)
		}
	}
	if _, err := Open(c, "alloc/missing.alloc", good, 0); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := Create(c, name, good); err == nil {
		t.Fatal("Create overwrote an allocator")
	}
}

func TestRollbackCheck(t *testing.T) {
	c, name := setup(t, wire.AllocFileVer)
	a, _ := Open(c, name, ident(wire.AllocFileVer), 0)
	if err := a.Check(0, false); err != nil {
		t.Fatal(err)
	}
	if err := a.Check(1, true); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("committed file_ver 1 with reserved_through 1: %v", err)
	}
	a.Next()
	if err := a.Check(1, true); err != nil {
		t.Fatal(err)
	}
}

func TestReinitAndExhaustion(t *testing.T) {
	c := vfs.NewCrashFS()
	c.MkdirAll("alloc", 0o755)
	id := ident(wire.AllocGeneration)
	id.Encrypted = true
	name := FileName(wire.AllocGeneration, 0)
	if err := Reinit(c, name, id, 5, true, nil); err == nil {
		t.Fatal("unlogged re-initialization accepted")
	}
	var log []string
	logf := func(s string) { log = append(log, s) }
	if err := Reinit(c, name, id, 5, true, logf); err != nil || len(log) != 1 {
		t.Fatal(err)
	}
	if r := stored(t, c, name); r != 5+1<<16 {
		t.Fatalf("reserved %d", r)
	}
	// near the 32-bit limit the addition saturates and the allocator fails closed
	Reinit(c, name, id, 1<<32-10, true, logf)
	if r := stored(t, c, name); r != 1<<32 {
		t.Fatalf("not saturated: %d", r)
	}
	a, err := Open(c, name, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Next(); !errors.Is(err, ErrExhausted) {
		t.Fatal(err)
	}
	// 65,536 re-initializations of the encrypted generation space fit (E1-2)
	if (1<<32)/(1<<16) < 65536 {
		t.Fatal("arithmetic")
	}
	// unencrypted: same max observed does not exhaust
	id.Encrypted = false
	Reinit(c, name, id, 1<<32-10, true, logf)
	a, _ = Open(c, name, id, 0)
	if v, err := a.Next(); err != nil || v != 1<<32-10+1<<16 {
		t.Fatal(v, err)
	}
	// nothing observed: counted from the first value
	gid := ident(wire.AllocGroupID)
	Reinit(c, FileName(wire.AllocGroupID, 0), gid, 0, false, logf)
	if r := stored(t, c, FileName(wire.AllocGroupID, 0)); r != 1+1<<16 {
		t.Fatal(r)
	}
}

func TestOnReserveFailureSkipsBlock(t *testing.T) {
	c, name := setup(t, wire.AllocManifestSeq)
	a, _ := Open(c, name, ident(wire.AllocManifestSeq), 4)
	fail := true
	a.OnReserve = func(wire.AllocKind, uint64) error {
		if fail {
			return errors.New("anchor down")
		}
		return nil
	}
	if _, err := a.Next(); err == nil {
		t.Fatal("value handed out without anchoring")
	}
	fail = false
	if v, err := a.Next(); err != nil || v != 5 {
		t.Fatalf("got %d %v; the unanchored block 1..4 must be skipped", v, err)
	}
}

func TestConcurrentUnique(t *testing.T) {
	c, name := setup(t, wire.AllocFileVer)
	a, _ := Open(c, name, ident(wire.AllocFileVer), 16)
	var mu sync.Mutex
	seen := map[uint64]bool{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				v, err := a.Next()
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				if seen[v] {
					t.Errorf("duplicate %d", v)
				}
				seen[v] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}
