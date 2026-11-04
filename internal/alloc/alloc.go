// Package alloc implements Allocator State reservations (SPEC §2.1.3):
// identifiers are handed out only below a durably stored reserved_through,
// so no identifier that may have reached storage is ever reissued after a
// crash.
package alloc

import (
	"errors"
	"fmt"
	"math"
	"path"
	"sync"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// ErrExhausted reports a namespace whose values are used up (fail closed).
var ErrExhausted = errors.New("allocator namespace exhausted")

// ErrRolledBack reports reserved_through not above a value already present
// in committed state (§2.1.3.1): the file was rolled back or corrupted.
var ErrRolledBack = errors.New("allocator state rolled back")

// FileName returns the location of an allocator file: relative to the
// archive root for kinds 0 and 1, relative to the generation directory for
// kinds 2-4 (§2.1.3).
func FileName(kind wire.AllocKind, blob uint8) string {
	switch kind {
	case wire.AllocGeneration:
		return "alloc/generation.alloc"
	case wire.AllocFileVer:
		return "alloc/filever.alloc"
	case wire.AllocManifestSeq:
		return "alloc/manifest.alloc"
	case wire.AllocGroupID:
		return "alloc/groups.alloc"
	}
	return fmt.Sprintf("alloc/blob-%02X.alloc", blob)
}

// Limit returns the exclusive upper bound of values of a kind. Encrypted
// archives put generation_id (32 bits) and frame_ordinal (56 bits) into
// nonces (§15.5); group_id is a uint32. uint64 namespaces stop one short of
// 2^64 because reserved_through is itself a uint64.
func Limit(kind wire.AllocKind, encrypted bool) uint64 {
	switch {
	case kind == wire.AllocGroupID:
		return 1 << 32
	case kind == wire.AllocGeneration && encrypted:
		return 1 << 32
	case kind == wire.AllocFrameOrdinal && encrypted:
		return 1 << 56
	}
	return math.MaxUint64
}

// Start returns the first value of a kind: generation 0 and frame ordinal
// 0 exist; seq, file_ver and group_id start at 1 (seq 0 and group_id 0 are
// not valid identifiers).
func Start(kind wire.AllocKind) uint64 {
	if kind == wire.AllocGeneration || kind == wire.AllocFrameOrdinal {
		return 0
	}
	return 1
}

// Identity describes the allocator a file must belong to.
type Identity struct {
	Kind         wire.AllocKind
	Blob         uint8  // kind 3
	GenerationID uint64 // kinds 2-4
	ArchiveID    [32]byte
	Encrypted    bool
}

func (id Identity) state(reserved uint64) wire.AllocState {
	s := wire.AllocState{Kind: id.Kind, ReservedThrough: reserved, ArchiveID: id.ArchiveID}
	if id.Kind.PerGeneration() {
		s.GenerationID = id.GenerationID
	}
	if id.Kind == wire.AllocFrameOrdinal {
		s.BlobOrdinal = id.Blob
	}
	return s
}

// Allocator hands out values of one namespace. It is safe for concurrent
// use.
type Allocator struct {
	fsys  vfs.FS
	name  string
	id    Identity
	block uint64
	limit uint64

	// OnReserve, if set, runs after a new reserved_through is durable and
	// before any value of the new block is used; an error keeps the block
	// unusable. HARDENED encrypted archives advance the anchor here
	// (§2.1.3.5).
	OnReserve func(kind wire.AllocKind, reservedThrough uint64) error

	mu       sync.Mutex
	next     uint64
	reserved uint64 // durable reserved_through
}

func write(fsys vfs.FS, name string, s wire.AllocState) error {
	b, err := s.AppendBinary(nil)
	if err != nil {
		return err
	}
	return vfs.ReplaceFile(fsys, name, b)
}

// Create writes a new allocator file with reserved_through = Start(kind)
// (nothing handed out yet). It fails if the file exists.
func Create(fsys vfs.FS, name string, id Identity) error {
	if _, err := fsys.Stat(name); err == nil {
		return fmt.Errorf("%w: %s exists", wire.ErrInvalid, name)
	}
	return write(fsys, name, id.state(Start(id.Kind)))
}

// Open validates an allocator file against id (§2.1.3.3) and returns an
// allocator with next = reserved_through (§2.1.3.1 cold start). block is
// the reservation step, at most MAX_RESERVATION_BLOCK (0 = the maximum).
// A missing or invalid file is an error: it is never recreated from a scan.
func Open(fsys vfs.FS, name string, id Identity, block uint64) (*Allocator, error) {
	b, err := vfs.ReadFile(fsys, name, wire.AllocStateSize+1)
	if err != nil {
		return nil, err
	}
	s, err := wire.DecodeAllocState(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	want := id.state(s.ReservedThrough)
	if s != want {
		return nil, fmt.Errorf("%s: %w: allocator identity does not match its location", name, wire.ErrCorrupt)
	}
	maxBlock := id.Kind.MaxReservationBlock()
	if block == 0 || block > maxBlock {
		block = maxBlock
	}
	a := &Allocator{fsys: fsys, name: name, id: id, block: block, limit: Limit(id.Kind, id.Encrypted),
		next: s.ReservedThrough, reserved: s.ReservedThrough}
	if a.reserved > a.limit {
		return nil, fmt.Errorf("%s: %w: reserved_through %d beyond namespace limit", name, wire.ErrCorrupt, a.reserved)
	}
	if a.next < Start(id.Kind) {
		a.next = Start(id.Kind)
	}
	return a, nil
}

// ReservedThrough returns the durable reserved_through.
func (a *Allocator) ReservedThrough() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reserved
}

// Check enforces the cold-start rule: reserved_through must be greater than
// every value of the kind present in committed state (pass observed=false
// when there is none).
func (a *Allocator) Check(maxObserved uint64, observed bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if observed && a.reserved <= maxObserved {
		return fmt.Errorf("%s: %w: reserved_through %d, committed state holds %d", a.name, ErrRolledBack, a.reserved, maxObserved)
	}
	return nil
}

// Next hands out one value, first extending the reservation durably when
// the current block is used up.
func (a *Allocator) Next() (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next >= a.reserved {
		if err := a.extendLocked(); err != nil {
			return 0, err
		}
	}
	v := a.next
	a.next++
	return v, nil
}

func (a *Allocator) extendLocked() error {
	if a.reserved >= a.limit {
		return fmt.Errorf("%s: %w", a.name, ErrExhausted)
	}
	r := a.reserved + min(a.block, a.limit-a.reserved)
	if err := write(a.fsys, a.name, a.id.state(r)); err != nil {
		return err
	}
	if a.OnReserve != nil {
		if err := a.OnReserve(a.id.Kind, r); err != nil {
			// durable but not anchored: skip the block entirely, never
			// use it (skipping is always safe)
			a.next = r
			a.reserved = r
			return err
		}
	}
	a.reserved = r
	return nil
}

// Reinit is the conservative initialization of §2.1.3.4: an explicit,
// logged operation for a missing or corrupt file. maxObserved is the
// largest value of the kind observable on media (observed=false if none).
// reserved_through becomes maxObserved + SKIP, saturating at the namespace
// limit (the allocator is then exhausted and fails closed). logf receives
// the log line; it must not be nil.
func Reinit(fsys vfs.FS, name string, id Identity, maxObserved uint64, observed bool, logf func(string)) error {
	if logf == nil {
		return fmt.Errorf("%w: allocator re-initialization must be logged", wire.ErrInvalid)
	}
	limit := Limit(id.Kind, id.Encrypted)
	base := Start(id.Kind) // nothing observable: count from the first value
	if observed {
		base = maxObserved
	}
	r := limit
	if skip := id.Kind.ReinitSkip(); base < limit && limit-base > skip {
		r = base + skip
	}
	logf(fmt.Sprintf("alloc: re-initializing %s (kind %d) with reserved_through %d (max observed %d, present %v)", path.Clean(name), id.Kind, r, maxObserved, observed))
	return write(fsys, name, id.state(r))
}
