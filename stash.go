// Package stash is the public API of the STASH 2.0 R10 reference
// implementation (wire 0x0006, SPEC.md).
//
// Current scope: STANDARD security policy, unencrypted archives, STORE
// codec, VARIABLE and FIXED frame modes, optional XOR or Reed-Solomon
// parity with repair on read, small objects packed into shared frames,
// compaction with repair and regrouping, full verification, and raw
// recovery from blob files alone. HARDENED policy binds freshness to an
// external Generation Anchor (anti-rollback). One writer per
// archive (an exclusive lock on writer.lock); any number of readers.
//
//	err := stash.Create(dir, stash.CreateOptions{})
//	a, err := stash.Open(dir, stash.Options{})
//	defer a.Close()
//	ver, err := a.Put("photos/2026/a.jpg", data)
//	data, err := a.Get("photos/2026/a.jpg")
//
// Paths are relative, '/'-separated and are normalized to Unicode NFC
// (SPEC §6.4.5); a path that is not a clean relative path is rejected,
// never rewritten.
package stash

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"stash/internal/anchor"
	"stash/internal/archive"
	"stash/internal/canonpath"
	"stash/internal/manifest"
	"stash/internal/recovery"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Errors. Use errors.Is.
var (
	// ErrNotFound: the path has no current version.
	ErrNotFound = archive.ErrNotFound
	// ErrMissingData: committed data is damaged or missing (never zero-filled).
	ErrMissingData = archive.ErrMissingData
	// ErrLocked: another writer holds the archive.
	ErrLocked = vfs.ErrLocked
	// ErrPathBusy: another write to the same path is in progress.
	ErrPathBusy = archive.ErrPathBusy
	// ErrNoWritableBlob: every blob is sealed; compaction is needed.
	ErrNoWritableBlob = archive.ErrNoWritableBlob
	// ErrIncomplete: the archive's creation did not finish.
	ErrIncomplete = archive.ErrIncomplete
	// ErrCorrupt, ErrUnsupported, ErrInvalid and ErrResource classify
	// format and input errors.
	ErrCorrupt     = wire.ErrCorrupt
	ErrUnsupported = wire.ErrUnsupported
	ErrInvalid     = wire.ErrInvalid
	ErrResource    = wire.ErrResource
	// ErrRollback: HARDENED found rollback, stale storage or tampering
	// against the Generation Anchor (a security incident; nothing falls
	// back to older state).
	ErrRollback = archive.ErrRollback
	// ErrAnchorRequired: a HARDENED archive opened without its anchor, or
	// an anchor given for a STANDARD archive.
	ErrAnchorRequired = archive.ErrAnchorRequired
	// ErrAnchorUnavailable: the anchor cannot be reached; HARDENED does
	// not downgrade, the operation fails.
	ErrAnchorUnavailable = archive.ErrAnchorUnavailable
)

// FrameMode selects the physical frame geometry (SPEC §3).
type FrameMode int

const (
	// Variable frames use as many 4 KiB quanta as they need (default).
	Variable FrameMode = iota
	// Fixed frames are all MaxFrameSize, directly addressable.
	Fixed
)

// Hash selects the payload hash (SPEC §4).
type Hash int

const (
	// SHA256 is the BASELINE/SECURE hash (default).
	SHA256 Hash = iota
	// BLAKE3 is the FAST profile hash.
	BLAKE3
)

// ParityScheme selects erasure coding (SPEC §7).
type ParityScheme int

const (
	// NoParity: damaged data is reported, not repaired (default).
	NoParity ParityScheme = iota
	// XOR: one parity frame per group of up to K data frames; survives the
	// loss of one member.
	XOR
	// ReedSolomon: M parity frames per group of up to K data frames;
	// survives the loss of any M members.
	ReedSolomon
)

// Parity configures erasure coding. A group's members are spread over
// distinct blobs; to survive the loss of a whole blob, Blobs must be at
// least ceil((K+M)/M).
type Parity struct {
	Scheme ParityScheme
	// K data frames per group (1..255), M parity frames (XOR: 1);
	// K+M <= 256.
	K, M int
}

// CreateOptions are fixed for the archive's lifetime.
type CreateOptions struct {
	Mode FrameMode
	Hash Hash
	// Blobs is the number of blob files written in parallel (1..255,
	// default 4).
	Blobs int
	// MaxFrameSize in bytes, a multiple of 4096 from 8 KiB (default 4 MiB).
	MaxFrameSize int
	// Parity: none by default. Needs at least 2 blobs.
	Parity Parity
	// Anchor makes the archive HARDENED (SPEC §15A.2): its freshness is
	// bound to this external Generation Anchor, which must live where the
	// archive's storage cannot roll it back.
	Anchor Anchor
}

// Create creates a new archive in dir, which must be empty or absent.
func Create(dir string, o CreateOptions) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cfg := archive.Config{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 4, MaxFrameQuanta: 1024}
	if o.Mode == Fixed {
		cfg.Mode = wire.ModeFixed
	}
	if o.Hash == BLAKE3 {
		cfg.HashID = wire.HashBLAKE3
	}
	if o.Blobs != 0 {
		if o.Blobs < 1 || o.Blobs > 255 {
			return errors.Join(ErrInvalid, errors.New("stash: Blobs must be 1..255"))
		}
		cfg.BlobCount = uint8(o.Blobs)
	}
	if o.MaxFrameSize != 0 {
		if o.MaxFrameSize%4096 != 0 || o.MaxFrameSize < 8192 {
			return errors.Join(ErrInvalid, errors.New("stash: MaxFrameSize must be a multiple of 4096, at least 8192"))
		}
		cfg.MaxFrameQuanta = uint32(o.MaxFrameSize / 4096)
	}
	switch o.Parity.Scheme {
	case NoParity:
		if o.Parity.K != 0 || o.Parity.M != 0 {
			return errors.Join(ErrInvalid, errors.New("stash: Parity.K and M need a parity scheme"))
		}
	case XOR, ReedSolomon:
		k, m := o.Parity.K, o.Parity.M
		if o.Parity.Scheme == XOR && m == 0 {
			m = 1
		}
		if k < 1 || k > 255 || m < 1 || m > 255 || k+m > 256 || (o.Parity.Scheme == XOR && m != 1) {
			return errors.Join(ErrInvalid, errors.New("stash: parity needs 1 <= K, 1 <= M, K+M <= 256 (XOR: M = 1)"))
		}
		cfg.ParityScheme = wire.ParityXOR
		if o.Parity.Scheme == ReedSolomon {
			cfg.ParityScheme = wire.ParityRS
		}
		cfg.ParityK, cfg.ParityM = uint8(k), uint8(m)
	default:
		return errors.Join(ErrInvalid, errors.New("stash: unknown parity scheme"))
	}
	cfg.Anchor = o.Anchor
	_, err := archive.Create(vfs.OS{Root: dir}, cfg)
	return err
}

// Options configure Open.
type Options struct {
	// MaxExtent caps the bytes per frame of one object (default 4 MiB).
	MaxExtent int
	// PackThreshold: objects up to this size share PACKED frames with
	// the other small objects written at the same time (default 64 KiB;
	// negative disables packing).
	PackThreshold int
	// VerifyAll hashes every frame when opening, even data that was
	// verified before the last clean close (slower; payload damage is then
	// found at open instead of on read).
	VerifyAll bool
	// Anchor is required for a HARDENED archive and refused for a
	// STANDARD one; a HARDENED archive never opens without it.
	Anchor Anchor
	// AdoptUnanchored keeps manifest records written after the last anchor
	// advance (a crash in between) instead of discarding them. It is an
	// operator decision: their content is not authenticated.
	AdoptUnanchored bool
}

// Archive is an archive opened for writing. Its methods are safe for
// concurrent use; concurrent writes share fsyncs (group commit).
type Archive struct {
	w *archive.Writer
}

// Open opens the archive in dir for writing, taking the writer lock and
// running crash recovery (torn tails, open transactions, indexes).
func Open(dir string, o Options) (*Archive, error) {
	w, err := archive.OpenWriter(vfs.OS{Root: dir}, archive.Options{MaxExtent: o.MaxExtent, PackThreshold: o.PackThreshold, VerifyAll: o.VerifyAll,
		Anchor: o.Anchor, AdoptUnanchored: o.AdoptUnanchored})
	if err != nil {
		return nil, err
	}
	return &Archive{w: w}, nil
}

func normalize(p string) (string, error) {
	n, err := canonpath.Normalize(p)
	if err != nil {
		return "", errors.Join(ErrInvalid, err)
	}
	return n, nil
}

// Put stores data as the new version of path and returns once it is
// durable. It returns the version's file_ver.
func (a *Archive) Put(path string, data []byte) (uint64, error) {
	p, err := normalize(path)
	if err != nil {
		return 0, err
	}
	return a.w.Put(p, data)
}

// PutReader streams r into the new version of path with bounded memory.
// Cancelling ctx abandons the write before it commits.
func (a *Archive) PutReader(ctx context.Context, path string, r io.Reader) (uint64, error) {
	p, err := normalize(path)
	if err != nil {
		return 0, err
	}
	return a.w.PutReader(ctx, p, r)
}

// Get returns the whole current content of path.
func (a *Archive) Get(path string) ([]byte, error) {
	p, err := normalize(path)
	if err != nil {
		return nil, err
	}
	return a.w.Get(p)
}

// OpenObject returns a lazy reader (io.ReaderAt, io.Reader, io.Seeker) of
// the current version of path. Close it to release its buffer.
func (a *Archive) OpenObject(path string) (*Object, error) {
	p, err := normalize(path)
	if err != nil {
		return nil, err
	}
	return a.w.Open(p)
}

// Delete removes path (its current version) durably.
func (a *Archive) Delete(path string) error {
	p, err := normalize(path)
	if err != nil {
		return err
	}
	return a.w.Delete(p)
}

// Stat describes the current version of path.
func (a *Archive) Stat(path string) (Info, error) {
	p, err := normalize(path)
	if err != nil {
		return Info{}, err
	}
	v, err := a.w.Stat(p)
	if err != nil {
		return Info{}, err
	}
	return info(p, v), nil
}

// List returns every live path in bytewise order.
func (a *Archive) List() []string { return a.w.List() }

// Health reports what crash recovery found when the archive was opened.
func (a *Archive) Health() Health { return a.w.Health() }

// Repairs counts reads that needed hop-and-read past damage or parity
// reconstruction since the archive was opened.
func (a *Archive) Repairs() RepairStats { return a.w.Repairs() }

// Close persists indexes and releases the writer lock. Every completed Put
// and Delete is already durable.
func (a *Archive) Close() error { return a.w.Close() }

// Compact copies the live versions into a new generation (SPEC §13): dead
// data is dropped, frames damaged or lost are rebuilt from parity, parity
// groups with dead members are regrouped and partly dead PACKED frames
// repacked; sealed blobs become writable again. Writes continue during
// the copy and wait only during the final merge and switch. Unless
// KeepOld is set, generations nothing uses any more are removed
// afterwards. A committed extent that cannot be found or rebuilt makes
// Compact fail with ErrMissingData and leaves the archive unchanged.
func (a *Archive) Compact(ctx context.Context, o CompactOptions) (CompactResult, error) {
	return a.w.Compact(ctx, o)
}

// GC removes old generations (replaced by compaction or left by an
// interrupted one) that no pinned reader and no open Object still uses.
func (a *Archive) GC() ([]uint64, error) { return a.w.GC() }

// Verify reads and checks the whole archive: every blob scanned frame by
// frame, every live version read completely, every parity group checked
// against recomputed parity. Writes wait while it runs.
func (a *Archive) Verify(ctx context.Context) (*VerifyReport, error) { return a.w.Verify(ctx) }

// CompactOptions configure Compact.
type CompactOptions = archive.CompactOptions

// CompactResult describes a compaction.
type CompactResult = archive.CompactResult

// VerifyReport is the result of Verify; OK() says whether nothing is
// damaged, missing or degraded.
type VerifyReport = archive.VerifyReport

// Object is a lazily read object version.
type Object = archive.Object

// Health is the report of crash recovery.
type Health = archive.Health

// RepairStats counts repaired reads.
type RepairStats = archive.RepairStats

// Info describes one object version.
type Info struct {
	Path    string
	Size    int64
	FileVer uint64
	Extents int
}

func info(p string, v *manifest.Version) Info {
	return Info{Path: p, Size: int64(v.Length), FileVer: v.FileVer, Extents: len(v.Loc)}
}

// Reader is a read-only snapshot of an archive; it takes no lock.
type Reader struct {
	r *archive.Reader
}

// ReadOptions configure OpenReadOnlyWith.
type ReadOptions struct {
	// NoPin skips the reader pin (for read-only media): a compaction may
	// then remove the generation while the snapshot is open.
	NoPin bool
	// PinTTL is the pin lifetime between background renewals (default 10
	// minutes); a crashed reader's pin expires after it.
	PinTTL time.Duration
	// Anchor is required for a HARDENED archive: the snapshot is the
	// anchored state, never bytes written after the last anchor advance.
	Anchor Anchor
}

// OpenReadOnly opens a snapshot of the archive in dir for reading. It pins
// the snapshot's generation (a file under pins/) so compaction keeps it
// until Close (SPEC §13.1.1).
func OpenReadOnly(dir string) (*Reader, error) { return OpenReadOnlyWith(dir, ReadOptions{}) }

// OpenReadOnlyWith is OpenReadOnly with options.
func OpenReadOnlyWith(dir string, o ReadOptions) (*Reader, error) {
	r, err := archive.OpenReaderWith(vfs.OS{Root: dir}, archive.ReaderOptions{Pin: !o.NoPin, PinTTL: o.PinTTL, Anchor: o.Anchor})
	if err != nil {
		return nil, err
	}
	return &Reader{r: r}, nil
}

// Verify checks the snapshot completely (see Archive.Verify).
func (r *Reader) Verify(ctx context.Context) (*VerifyReport, error) { return r.r.Verify(ctx) }

// Get returns the whole content of path in the snapshot.
func (r *Reader) Get(path string) ([]byte, error) {
	p, err := normalize(path)
	if err != nil {
		return nil, err
	}
	return r.r.Get(p)
}

// OpenObject returns a lazy reader of path in the snapshot.
func (r *Reader) OpenObject(path string) (*Object, error) {
	p, err := normalize(path)
	if err != nil {
		return nil, err
	}
	return r.r.Open(p)
}

// Stat describes path in the snapshot.
func (r *Reader) Stat(path string) (Info, error) {
	p, err := normalize(path)
	if err != nil {
		return Info{}, err
	}
	v, err := r.r.Stat(p)
	if err != nil {
		return Info{}, err
	}
	return info(p, v), nil
}

// List returns every live path of the snapshot.
func (r *Reader) List() []string { return r.r.List() }

// Unavailable lists blob files that could not be opened (missing or with a
// damaged header); with parity their data is rebuilt on read.
func (r *Reader) Unavailable() map[uint8]error { return r.r.Unavailable() }

// Repairs counts reads that needed hop-and-read or parity.
func (r *Reader) Repairs() RepairStats { return r.r.Repairs() }

// Close releases the files.
func (r *Reader) Close() error { return r.r.Close() }

// RecoverOptions configure Recover.
type RecoverOptions struct {
	// Generation selects a generation by id; nil takes the one
	// root.current names, or the newest one when the root is unusable.
	Generation *uint64
	// NoManifest ignores the manifest (labels then say nothing is known
	// to be committed).
	NoManifest bool
	// ResyncBudget bounds the bytes hashed per blob while resynchronizing
	// after damage (default four times the blob size).
	ResyncBudget int64
}

// Recovery is a raw recovery scan (SPEC §11): object versions rebuilt from
// the blob files alone, labeled with what a surviving manifest says.
type Recovery = recovery.Recovery

// RecoveredVersion is one version found by Recover.
type RecoveredVersion = recovery.Version

// SalvageResult describes Recovery.Salvage.
type SalvageResult = recovery.SalvageResult

// Recover scans the archive in dir without the writer lock and without
// trusting its manifest or indexes: frames are validated one by one,
// damaged regions are skipped by resynchronization, and lost frames are
// rebuilt from parity. It writes nothing. The result lists every version
// found, including deleted and superseded ones (raw recovery cannot know
// the live state), with gaps, provenance and manifest labels. Extract
// reads one version; Salvage writes a selection into a new archive.
func Recover(dir string, o RecoverOptions) (*Recovery, error) {
	return recovery.Scan(vfs.OS{Root: dir}, recovery.Options{Generation: o.Generation, NoManifest: o.NoManifest, Budget: o.ResyncBudget})
}

// Salvage creates a new archive in dir (empty or absent) with the
// recovered archive's parameters and writes the given versions into it
// (rc.DefaultSelection() picks the current versions, or the newest
// complete version per path when the manifest is gone).
func Salvage(ctx context.Context, rc *Recovery, dir string, versions []*RecoveredVersion) (SalvageResult, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return SalvageResult{}, err
	}
	return rc.Salvage(ctx, vfs.OS{Root: dir}, versions)
}

// Anchor is a Generation Anchor provider (SPEC §2.1.2): monotonic
// compare-and-advance state per archive, kept outside the archive's
// storage. Implement it over a trusted service, or use NewFileAnchor.
type Anchor = anchor.Anchor

// AnchorState is what an anchor stores.
type AnchorState = anchor.State

// NewFileAnchor returns the reference anchor: one file per archive in dir,
// replaced atomically under a lock. dir must be on storage that is not
// rolled back together with the archive (another host, a versioned or
// WORM store), or the anchor protects nothing.
func NewFileAnchor(dir string) (Anchor, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return anchor.File{FS: vfs.OS{Root: dir}}, nil
}

// NewMemoryAnchor returns an in-process anchor (tests only: it is lost
// with the process).
func NewMemoryAnchor() *anchor.Memory { return anchor.NewMemory() }

// Enroll switches an existing STANDARD archive to HARDENED (SPEC
// §2.1.2.1): the archive is verified completely, the anchor's first state
// is created from it, and a local policy marker is written. operator and
// log are required; keep the logged record outside the archive. No
// archive wire byte changes.
func Enroll(ctx context.Context, dir string, a Anchor, operator string, log func(string)) (AnchorState, error) {
	return archive.Enroll(ctx, vfs.OS{Root: dir}, a, archive.EnrollOptions{Operator: operator, Log: log})
}

// LeaveHardened returns an archive to STANDARD (an explicit operator
// action; the anchor's state is left for the operator to retire).
func LeaveHardened(dir, operator string, log func(string)) error {
	return archive.LeaveHardened(vfs.OS{Root: dir}, operator, log)
}

// AuthorizeAnchorTransition is the operator's recovery flow for a
// root.current that names a newer generation than the anchor (SPEC
// §13.6.1): that generation is verified completely and the anchor is
// advanced to it.
func AuthorizeAnchorTransition(ctx context.Context, dir string, a Anchor, operator string, log func(string)) error {
	return archive.AuthorizeAnchorTransition(ctx, vfs.OS{Root: dir}, a, operator, log)
}
