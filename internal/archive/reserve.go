package archive

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"

	"stash/internal/alloc"
	"stash/internal/anchor"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// HARDENED binding of reservations (§2.1.3.5): in an encrypted HARDENED
// archive the allocators whose values enter nonces or identify parity
// groups (kind 0 generation_id, and per generation kind 2 seq, kind 3
// frame ordinals, kind 4 group_id) hand out a new block only after the
// anchor includes its reserved_through.

// ErrAllocatorRollback reports local Allocator State below the anchored
// reservations: a security incident (§2.1.3.5).
var ErrAllocatorRollback = errors.New("allocator state below the anchored reservation (security incident)")

type boundAlloc struct {
	kind wire.AllocKind
	blob uint8
	name string // relative to the archive root
}

func boundAllocs(h *wire.ArchiveHeader) []boundAlloc {
	gen := GenDir(h.GenerationID)
	out := []boundAlloc{{wire.AllocGeneration, 0, alloc.FileName(wire.AllocGeneration, 0)},
		{wire.AllocManifestSeq, 0, path.Join(gen, alloc.FileName(wire.AllocManifestSeq, 0))}}
	for b := 0; b < int(h.BlobCount); b++ {
		out = append(out, boundAlloc{wire.AllocFrameOrdinal, uint8(b), path.Join(gen, alloc.FileName(wire.AllocFrameOrdinal, uint8(b)))})
	}
	if h.ParityScheme != wire.ParityNone {
		out = append(out, boundAlloc{wire.AllocGroupID, 0, path.Join(gen, alloc.FileName(wire.AllocGroupID, 0))})
	}
	return out
}

func sortReservations(rs []anchor.Reservation) {
	slices.SortFunc(rs, func(a, b anchor.Reservation) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return int(a.Blob) - int(b.Blob)
	})
}

// currentReservations reads reserved_through of every bound allocator of
// generation h from its file.
func currentReservations(fsys vfs.FS, h *wire.ArchiveHeader) ([]anchor.Reservation, error) {
	var out []anchor.Reservation
	for _, ba := range boundAllocs(h) {
		b, err := vfs.ReadFile(fsys, ba.name, wire.AllocStateSize+1)
		if err != nil {
			return nil, err
		}
		s, err := wire.DecodeAllocState(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ba.name, err)
		}
		out = append(out, anchor.Reservation{Kind: ba.kind, Blob: ba.blob, ReservedThrough: s.ReservedThrough})
	}
	sortReservations(out)
	return out, nil
}

// allocators returns the writer's bound allocators by (kind, blob).
func (w *Writer) allocators() map[[2]uint8]*alloc.Allocator {
	m := map[[2]uint8]*alloc.Allocator{{uint8(wire.AllocGeneration), 0}: w.genAlloc, {uint8(wire.AllocManifestSeq), 0}: w.seqAlloc}
	for b, a := range w.ordAlloc {
		m[[2]uint8{uint8(wire.AllocFrameOrdinal), uint8(b)}] = a
	}
	if w.groupAlloc != nil {
		m[[2]uint8{uint8(wire.AllocGroupID), 0}] = w.groupAlloc
	}
	return m
}

// reservations returns the writer's current bound reservations. It locks
// the allocators, so it must not run inside an OnReserve hook.
func (w *Writer) reservations() []anchor.Reservation {
	var out []anchor.Reservation
	for k, a := range w.allocators() {
		out = append(out, anchor.Reservation{Kind: wire.AllocKind(k[0]), Blob: k[1], ReservedThrough: a.ReservedThrough()})
	}
	sortReservations(out)
	return out
}

// bindReservations runs at the cold start of an encrypted HARDENED writer
// (§2.1.3.5): a local value below the anchored one is a rollback (fail
// closed unless acknowledged, then continue from the anchored value); a
// local value above it (a block made durable but not anchored before a
// crash) is anchored now. Afterwards every new block advances the anchor
// before it is used.
func (w *Writer) bindReservations(ctx context.Context) error {
	anchored := map[[2]uint8]uint64{}
	for _, r := range w.hard.anchored.Reservations {
		anchored[[2]uint8{uint8(r.Kind), r.Blob}] = r.ReservedThrough
	}
	for k, a := range w.allocators() {
		av, ok := anchored[k]
		if !ok || a.ReservedThrough() >= av {
			continue
		}
		if !w.opt.AcknowledgeAllocatorRollback {
			return fmt.Errorf("%w: kind %d blob %02X: local reserved_through %d, anchored %d", ErrAllocatorRollback, k[0], k[1], a.ReservedThrough(), av)
		}
		if err := a.RaiseTo(av); err != nil {
			return err
		}
	}
	return w.hookReservations(ctx)
}

// hookReservations records the current reservations, anchors them, and
// makes every bound allocator advance the anchor before it uses a new
// block.
func (w *Writer) hookReservations(ctx context.Context) error {
	hs := &w.hard
	cur := w.reservations()
	hs.mu.Lock()
	hs.resv = map[[2]uint8]uint64{}
	for _, r := range cur {
		hs.resv[[2]uint8{uint8(r.Kind), r.Blob}] = r.ReservedThrough
	}
	hs.mu.Unlock()
	for k, a := range w.allocators() {
		a.OnReserve = func(_ wire.AllocKind, r uint64) error { return w.advanceReservation(context.Background(), k, r) }
	}
	return w.advanceReservation(ctx, [2]uint8{}, 0)
}

// advanceReservation records reserved_through r for allocator key (r 0:
// nothing new) and advances the anchor to the recorded reservations when
// they differ from the anchored ones (a reservation advance: same
// generation and manifest length, §2.1.2). It never locks an allocator,
// so it may run inside OnReserve.
func (w *Writer) advanceReservation(ctx context.Context, key [2]uint8, r uint64) error {
	hs := &w.hard
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.failed != nil {
		return hs.failed
	}
	if r > hs.resv[key] {
		hs.resv[key] = r
	}
	next := hs.anchored
	next.Reservations = nil
	for k, v := range hs.resv {
		next.Reservations = append(next.Reservations, anchor.Reservation{Kind: wire.AllocKind(k[0]), Blob: k[1], ReservedThrough: v})
	}
	sortReservations(next.Reservations)
	if hs.anchored.Equal(next) {
		return nil
	}
	if err := hs.anchor.Advance(ctx, hs.anchored, next); err != nil {
		hs.failed = fmt.Errorf("%w: reservation advance: %v (reopen required)", ErrAnchorUnavailable, err)
		return hs.failed
	}
	hs.anchored = next
	return nil
}
