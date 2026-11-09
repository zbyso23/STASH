package anchor

import (
	"context"
	"errors"
	"testing"

	"stash/internal/vfs"
	"stash/internal/wire"
)

func providers(t *testing.T) map[string]Anchor {
	return map[string]Anchor{"memory": NewMemory(), "file-crashfs": File{FS: vfs.NewCrashFS()}, "file-os": File{FS: vfs.OS{Root: t.TempDir()}}}
}

func TestProviders(t *testing.T) {
	ctx := context.Background()
	for name, a := range providers(t) {
		var id [32]byte
		id[0] = 7
		s0 := State{ArchiveID: id, RootDigest: RootDigest([]byte("root0"))}
		if _, err := a.Load(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: %v", name, err)
		}
		if err := a.Create(ctx, s0); err != nil {
			t.Fatal(name, err)
		}
		if err := a.Create(ctx, s0); !errors.Is(err, ErrExists) {
			t.Fatalf("%s: second create %v", name, err)
		}
		s1 := s0
		s1.ManifestLength, s1.ManifestDigest = 100, [32]byte{1}
		if err := a.Advance(ctx, s0, s1); err != nil {
			t.Fatal(name, err)
		}
		// replaying the old update is stale
		if err := a.Advance(ctx, s0, s1); !errors.Is(err, ErrStale) {
			t.Fatalf("%s: replay %v", name, err)
		}
		// going back is not an advance
		if err := a.Advance(ctx, s1, s0); !errors.Is(err, ErrNotNewer) {
			t.Fatalf("%s: backwards %v", name, err)
		}
		// non-consecutive generation switch
		s2 := State{ArchiveID: id, GenerationID: 300, RootDigest: RootDigest([]byte("root300"))}
		if err := a.Advance(ctx, s1, s2); err != nil {
			t.Fatal(name, err)
		}
		got, err := a.Load(ctx, id)
		if err != nil || !got.Equal(s2) {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
}

func TestNewer(t *testing.T) {
	var id [32]byte
	b := State{ArchiveID: id, GenerationID: 5, ManifestLength: 10, Reservations: []Reservation{{Kind: wire.AllocManifestSeq, ReservedThrough: 100}}}
	for i, c := range []struct {
		mod  func(*State)
		want bool
	}{
		{func(s *State) { s.GenerationID = 6; s.ManifestLength = 0 }, true},
		{func(s *State) { s.GenerationID = 4; s.ManifestLength = 99 }, false},
		{func(s *State) { s.ManifestLength = 11 }, true},
		{func(s *State) { s.ManifestLength = 9 }, false},
		{func(s *State) {}, false},
		{func(s *State) { s.Reservations = []Reservation{{Kind: wire.AllocManifestSeq, ReservedThrough: 200}} }, true},
		{func(s *State) { s.Reservations = []Reservation{{Kind: wire.AllocManifestSeq, ReservedThrough: 50}} }, false},
		{func(s *State) { s.ManifestDigest[0] = 1 }, false},
		{func(s *State) { s.ArchiveID[0] = 1; s.GenerationID = 9 }, false},
	} {
		n := b
		n.Reservations = append([]Reservation(nil), b.Reservations...)
		c.mod(&n)
		if Newer(b, n) != c.want {
			t.Fatalf("case %d", i)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	s := State{GenerationID: 9, ManifestLength: 77, Reservations: []Reservation{{Kind: 3, Blob: 2, ReservedThrough: 1 << 40}}}
	s.ArchiveID[5] = 9
	got, err := Decode(Encode(s))
	if err != nil || !got.Equal(s) {
		t.Fatal(err)
	}
	b := Encode(s)
	for i := range b {
		c := append([]byte(nil), b...)
		c[i] ^= 1
		if _, err := Decode(c); err == nil {
			t.Fatalf("bit flip at %d accepted", i)
		}
	}
}
