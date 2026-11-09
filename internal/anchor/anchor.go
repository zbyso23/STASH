// Package anchor is the external Generation Anchor of HARDENED policy
// (SPEC §2.1.2): monotonic compare-and-advance state per archive_id that
// lives outside the archive's storage, so rolling the archive back cannot
// roll the anchor back with it. It is not part of the wire format.
package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sync"
	"time"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// Errors. A provider wraps ErrUnavailable around every failure that is not
// a definite answer, so callers never mistake an outage for "no anchor".
var (
	ErrExists      = errors.New("generation anchor already exists for this archive")
	ErrNotFound    = errors.New("no generation anchor for this archive")
	ErrStale       = errors.New("stale generation anchor update (compare-and-advance failed)")
	ErrNotNewer    = errors.New("generation anchor update does not advance")
	ErrUnavailable = errors.New("generation anchor unavailable")
)

// Reservation is one bound allocator value (encrypted HARDENED archives,
// §2.1.3.5): kind 0 has blob 0 and generation 0.
type Reservation struct {
	Kind            wire.AllocKind
	Blob            uint8
	ReservedThrough uint64
}

// State is what the anchor stores (§2.1.2).
type State struct {
	ArchiveID      [32]byte
	GenerationID   uint64
	RootDigest     [32]byte // SHA-256 of the exact 64 root.current bytes
	ManifestLength uint64
	ManifestDigest [32]byte // SHA-256 of manifest.jsonl[0:ManifestLength]
	Reservations   []Reservation
}

// Equal compares two states completely.
func (s State) Equal(o State) bool {
	if s.ArchiveID != o.ArchiveID || s.GenerationID != o.GenerationID || s.RootDigest != o.RootDigest ||
		s.ManifestLength != o.ManifestLength || s.ManifestDigest != o.ManifestDigest || len(s.Reservations) != len(o.Reservations) {
		return false
	}
	for i := range s.Reservations {
		if s.Reservations[i] != o.Reservations[i] {
			return false
		}
	}
	return true
}

// Newer reports whether next is a valid advance from prev (§2.1.2):
// lexicographically greater (generation_id, manifest_length), or an equal
// pair with componentwise greater-or-equal reservations, at least one
// greater, and an unchanged manifest digest and root.
func Newer(prev, next State) bool {
	if next.ArchiveID != prev.ArchiveID {
		return false
	}
	if next.GenerationID != prev.GenerationID {
		return next.GenerationID > prev.GenerationID
	}
	if next.RootDigest != prev.RootDigest {
		return false
	}
	if next.ManifestLength != prev.ManifestLength {
		return next.ManifestLength > prev.ManifestLength
	}
	if next.ManifestDigest != prev.ManifestDigest {
		return false
	}
	pr := map[[2]uint8]uint64{}
	for _, r := range prev.Reservations {
		pr[[2]uint8{uint8(r.Kind), r.Blob}] = r.ReservedThrough
	}
	greater := false
	for _, r := range next.Reservations {
		p, ok := pr[[2]uint8{uint8(r.Kind), r.Blob}]
		if ok && r.ReservedThrough < p {
			return false
		}
		greater = greater || !ok || r.ReservedThrough > p
		delete(pr, [2]uint8{uint8(r.Kind), r.Blob})
	}
	return greater && len(pr) == 0
}

// Anchor is a Generation Anchor provider (§2.1.2). Implementations must be
// safe for concurrent use and durable before they return success.
type Anchor interface {
	// Create stores the first state of an archive; ErrExists if any exists.
	Create(ctx context.Context, initial State) error
	// Load returns the newest state; ErrNotFound if none exists.
	Load(ctx context.Context, archiveID [32]byte) (State, error)
	// Advance replaces prev by next atomically: ErrStale when the stored
	// state is not prev, ErrNotNewer when next does not advance it.
	Advance(ctx context.Context, prev, next State) error
}

// RootDigest returns SHA-256 of the exact root bytes.
func RootDigest(rootBytes []byte) [32]byte { return sha256.Sum256(rootBytes) }

// Encoding of a stored state (provider-private): magic, fields,
// reservation count and entries, CRC32C.
var magic = [8]byte{'S', 'T', 'A', 'N', 'C', 'H', 'O', 'R'}

// Encode returns the canonical bytes of s.
func Encode(s State) []byte {
	b := append([]byte{}, magic[:]...)
	b = append(b, s.ArchiveID[:]...)
	b = binary.LittleEndian.AppendUint64(b, s.GenerationID)
	b = append(b, s.RootDigest[:]...)
	b = binary.LittleEndian.AppendUint64(b, s.ManifestLength)
	b = append(b, s.ManifestDigest[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(s.Reservations)))
	for _, r := range s.Reservations {
		b = append(b, byte(r.Kind), r.Blob)
		b = binary.LittleEndian.AppendUint64(b, r.ReservedThrough)
	}
	return binary.LittleEndian.AppendUint32(b, wire.CRC32C(b))
}

const fixedLen = 8 + 32 + 8 + 32 + 8 + 32 + 4

// Decode parses Encode's output.
func Decode(b []byte) (State, error) {
	var s State
	if len(b) < fixedLen+4 || !bytes.Equal(b[:8], magic[:]) || binary.LittleEndian.Uint32(b[len(b)-4:]) != wire.CRC32C(b[:len(b)-4]) {
		return s, fmt.Errorf("%w: anchor state damaged", wire.ErrCorrupt)
	}
	p := b[8:]
	copy(s.ArchiveID[:], p)
	s.GenerationID = binary.LittleEndian.Uint64(p[32:])
	copy(s.RootDigest[:], p[40:])
	s.ManifestLength = binary.LittleEndian.Uint64(p[72:])
	copy(s.ManifestDigest[:], p[80:])
	n := binary.LittleEndian.Uint32(p[112:])
	if uint64(len(b)) != uint64(fixedLen)+uint64(n)*10+4 {
		return s, fmt.Errorf("%w: anchor state length", wire.ErrCorrupt)
	}
	p = p[116:]
	for i := uint32(0); i < n; i++ {
		s.Reservations = append(s.Reservations, Reservation{Kind: wire.AllocKind(p[0]), Blob: p[1], ReservedThrough: binary.LittleEndian.Uint64(p[2:])})
		p = p[10:]
	}
	return s, nil
}

// Memory is an in-process anchor for tests. Fail makes every call fail
// with ErrUnavailable; Set replaces the stored state (to simulate an
// anchor that was itself rolled back).
type Memory struct {
	mu       sync.Mutex
	states   map[[32]byte]State
	fail     bool
	Advances int // successful Advance calls
}

// NewMemory returns an empty in-memory anchor.
func NewMemory() *Memory { return &Memory{states: map[[32]byte]State{}} }

// SetUnavailable switches simulated outages on or off.
func (m *Memory) SetUnavailable(v bool) { m.mu.Lock(); m.fail = v; m.mu.Unlock() }

// Set stores s unconditionally (test helper).
func (m *Memory) Set(s State) { m.mu.Lock(); m.states[s.ArchiveID] = s; m.mu.Unlock() }

// Snapshot returns a copy of every stored state.
func (m *Memory) Snapshot() map[[32]byte]State {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[[32]byte]State{}
	for k, v := range m.states {
		out[k] = v
	}
	return out
}

// Restore replaces every stored state by a snapshot.
func (m *Memory) Restore(s map[[32]byte]State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states = map[[32]byte]State{}
	for k, v := range s {
		m.states[k] = v
	}
}

func (m *Memory) Create(_ context.Context, s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return ErrUnavailable
	}
	if _, ok := m.states[s.ArchiveID]; ok {
		return ErrExists
	}
	m.states[s.ArchiveID] = s
	return nil
}

func (m *Memory) Load(_ context.Context, id [32]byte) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return State{}, ErrUnavailable
	}
	s, ok := m.states[id]
	if !ok {
		return State{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) Advance(_ context.Context, prev, next State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return ErrUnavailable
	}
	cur, ok := m.states[prev.ArchiveID]
	if !ok {
		return ErrNotFound
	}
	if !cur.Equal(prev) {
		return ErrStale
	}
	if !Newer(cur, next) {
		return ErrNotNewer
	}
	m.states[next.ArchiveID] = next
	m.Advances++
	return nil
}

// File is a reference provider that keeps one file per archive,
// <hex archive_id>.anchor, in a directory of an FS that must lie in a
// trust domain the archive storage cannot roll back (another machine, a
// WORM or versioned store). Updates are atomic durable replacements under
// an exclusive lock, so concurrent writers serialize.
type File struct {
	FS vfs.FS
}

func (f File) name(id [32]byte) string { return hex.EncodeToString(id[:]) + ".anchor" }

func (f File) lock(ctx context.Context, id [32]byte) (func() error, error) {
	for {
		unlock, err := f.FS.Lock(path.Join(".", f.name(id)+".lock"))
		if err == nil {
			return unlock, nil
		}
		if !errors.Is(err, vfs.ErrLocked) {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (f File) read(id [32]byte) (State, error) {
	b, err := vfs.ReadFile(f.FS, f.name(id), 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, ErrNotFound
	}
	if err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	s, err := Decode(b)
	if err != nil {
		// a damaged anchor is an outage, never "no anchor"
		return State{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if s.ArchiveID != id {
		return State{}, fmt.Errorf("%w: anchor file names another archive", ErrUnavailable)
	}
	return s, nil
}

func (f File) Create(ctx context.Context, s State) error {
	unlock, err := f.lock(ctx, s.ArchiveID)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := f.read(s.ArchiveID); !errors.Is(err, ErrNotFound) {
		if err == nil {
			return ErrExists
		}
		return err
	}
	if err := vfs.ReplaceFile(f.FS, f.name(s.ArchiveID), Encode(s)); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (f File) Load(ctx context.Context, id [32]byte) (State, error) {
	unlock, err := f.lock(ctx, id)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	return f.read(id)
}

func (f File) Advance(ctx context.Context, prev, next State) error {
	unlock, err := f.lock(ctx, prev.ArchiveID)
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := f.read(prev.ArchiveID)
	if err != nil {
		return err
	}
	if !cur.Equal(prev) {
		return ErrStale
	}
	if !Newer(cur, next) {
		return ErrNotNewer
	}
	if err := vfs.ReplaceFile(f.FS, f.name(next.ArchiveID), Encode(next)); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}
