// Package stash is the public API of the STASH 2.0 R11 reference
// implementation (wire 0x0006, SPEC.md).
//
// Scope: the BASELINE, SECURE and FAST profiles (SPEC §5.2): SHA-256 or
// BLAKE3 hashes, STORE or Zstandard compression, optional AES-256-GCM
// encryption with a caller-held archive key; VARIABLE and FIXED frame
// modes, optional XOR or Reed-Solomon parity with repair on read, small
// objects packed into shared frames, compaction with repair and
// regrouping, full verification, and raw recovery from blob files alone
// (keyless or with the key). STANDARD or HARDENED policy; HARDENED binds
// freshness to an external Generation Anchor (anti-rollback). One writer
// per archive (an exclusive lock on writer.lock); any number of readers.
//
//	err := stash.Create(dir, stash.CreateOptions{Profile: stash.Fast})
//	a, err := stash.Open(dir, stash.Options{})
//	defer a.Close()
//	ver, err := a.Put("photos/2026/a.jpg", data)
//	data, err := a.Get("photos/2026/a.jpg")
//
// Paths are relative, '/'-separated and are normalized to Unicode NFC
// (SPEC §6.4.5); a path that is not a clean relative path is rejected,
// never rewritten.
//
// The command stash (cmd/stash) exposes the same operations on the
// command line; package stash/fusefs mounts an archive read-only.
package stash

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"stash/internal/anchor"
	"stash/internal/archive"
	"stash/internal/canonpath"
	"stash/internal/manifest"
	"stash/internal/recovery"
	"stash/internal/seal"
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
	// ErrUnrecoverable: the path's version was given up by an Emergency
	// Pruning (the error is an *UnrecoverableError). It matches
	// ErrMissingData, never ErrNotFound, so a loss is not mistaken for a
	// deletion. A Put restores the path; a Delete acknowledges the loss.
	ErrUnrecoverable = archive.ErrUnrecoverable
	// ErrPruneRefused: an Emergency Pruning without the required
	// authorization, or whose losses differ from the confirmed count.
	ErrPruneRefused = archive.ErrPruneRefused
	// ErrKeyRequired: an encrypted archive opened without its key.
	ErrKeyRequired = archive.ErrKeyRequired
	// ErrWrongKey: the key does not match the archive (key.check).
	ErrWrongKey = archive.ErrWrongKey
	// ErrAllocatorRollback: an encrypted HARDENED archive's allocator
	// files are below the anchored reservations (a security incident;
	// Options.AcknowledgeAllocatorRollback continues after review).
	ErrAllocatorRollback = archive.ErrAllocatorRollback
)

// KeySize is the size of an archive key (the archive DEK, SPEC §15.1).
const KeySize = seal.KeySize

// NewKey returns a new random archive key. Keep it (wrapped by your KMS
// or key-encryption key) outside the archive: the archive never stores
// it, and without it the encrypted content is lost.
func NewKey() ([]byte, error) { return seal.NewKey() }

// Profile is a named combination of hash, compression and encryption
// (SPEC §5.2).
type Profile int

const (
	// Custom uses CreateOptions.Hash, Compression and Key as given
	// (default; with zero values this is BASELINE).
	Custom Profile = iota
	// Baseline: SHA-256, STORE, no encryption.
	Baseline
	// Secure: SHA-256, STORE, AES-256-GCM; CreateOptions.Key is required.
	Secure
	// Fast: BLAKE3, ZSTD_FAST (STORE where compression does not help), no
	// encryption.
	Fast
)

// Compression selects the archive codec (SPEC §5).
type Compression int

const (
	// Store keeps data uncompressed (default).
	Store Compression = iota
	// ZstdFast is Zstandard level 1.
	ZstdFast
	// ZstdDefault is Zstandard level 3.
	ZstdDefault
	// ZstdDense is Zstandard level 9 (the encoder's closest setting).
	ZstdDense
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
	// Profile sets Hash, Compression and encryption together; with a
	// profile other than Custom, Hash and Compression must be zero.
	Profile Profile
	// Compression is the codec for every frame it makes smaller.
	Compression Compression
	// Key (KeySize bytes, see NewKey) encrypts the archive with
	// AES-256-GCM (SPEC §15). The same key is needed to open it.
	Key []byte
}

// Create creates a new archive in dir, which must be empty or absent.
func Create(dir string, o CreateOptions) error {
	switch o.Profile {
	case Custom:
	case Baseline, Secure, Fast:
		if o.Hash != SHA256 || o.Compression != Store {
			return errors.Join(ErrInvalid, errors.New("stash: a profile fixes Hash and Compression"))
		}
		if (o.Profile == Secure) != (o.Key != nil) {
			return errors.Join(ErrInvalid, errors.New("stash: the Secure profile needs a Key, Baseline and Fast take none"))
		}
		if o.Profile == Fast {
			o.Hash, o.Compression = BLAKE3, ZstdFast
		}
	default:
		return errors.Join(ErrInvalid, errors.New("stash: unknown profile"))
	}
	if o.Compression < Store || o.Compression > ZstdDense {
		return errors.Join(ErrInvalid, errors.New("stash: unknown compression"))
	}
	if o.Key != nil && len(o.Key) != KeySize {
		return errors.Join(ErrInvalid, errors.New("stash: Key must be 32 bytes"))
	}
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
	cfg.Codec = wire.CodecID(o.Compression)
	cfg.Key = o.Key
	_, err := archive.Create(vfs.OS{Root: dir}, cfg)
	return err
}

// Options configure Open.
type Options struct {
	// MaxExtent caps the logical bytes per frame of one object (default
	// 4 MiB; never more than the archive's maximum frame size).
	MaxExtent int
	// UncompressedExtents makes a compressing archive put no more logical
	// bytes into a frame than it would hold uncompressed. By default a
	// frame holds as many bytes as compress into it, up to the maximum
	// frame size (SPEC §6.6.1).
	UncompressedExtents bool
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
	// Key opens an encrypted archive.
	Key []byte
	// AcknowledgeAllocatorRollback continues an encrypted HARDENED archive
	// after ErrAllocatorRollback was reviewed, from the anchored values.
	AcknowledgeAllocatorRollback bool
	// Policy is the expected security policy. With an Anchor, HARDENED is
	// expected whatever the storage says.
	Policy Policy
	// MemoryLimit bounds the memory for archive-scale working state: the
	// index page cache, in-memory index deltas, spills and validation
	// sorts (default 1 GiB). Data beyond it goes to the scratch/ directory
	// of the archive, which is removed when the writer opens and closes.
	// A limit below MinMemoryLimit is ErrInvalid.
	MemoryLimit int64
}

// MinMemoryLimit is the smallest MemoryLimit Open, OpenReadOnlyWith and
// Recover accept (0 selects the 1 GiB default). The engine works below it
// (its tests run at 8 MiB), but everything gets slower without a gain
// worth having.
const MinMemoryLimit = 128 << 20

func checkMemory(n int64) error {
	if n != 0 && n < MinMemoryLimit {
		return fmt.Errorf("%w: memory limit %d MiB is below the minimum of %d MiB", ErrInvalid, n>>20, MinMemoryLimit>>20)
	}
	return nil
}

// Policy is the security policy an opener expects (SPEC §15A.2). It must
// come from configuration the archive's storage cannot change: the local
// HARDENED marker lives on that storage and only guards against mistakes.
type Policy = archive.Policy

const (
	// PolicyAuto (default) follows the local marker when no Anchor is
	// configured; an adversary controlling the storage can delete the
	// marker. Configure PolicyHardened (or an Anchor) where HARDENED
	// guarantees matter.
	PolicyAuto = archive.PolicyAuto
	// PolicyStandard requires a STANDARD archive.
	PolicyStandard = archive.PolicyStandard
	// PolicyHardened requires a HARDENED archive and its Anchor; a
	// missing marker is then ErrRollback.
	PolicyHardened = archive.PolicyHardened
)

// Archive is an archive opened for writing. Its methods are safe for
// concurrent use; concurrent writes share fsyncs (group commit).
type Archive struct {
	w *archive.Writer
}

// Open opens the archive in dir for writing, taking the writer lock and
// running crash recovery (torn tails, open transactions, indexes).
func Open(dir string, o Options) (*Archive, error) {
	if err := checkMemory(o.MemoryLimit); err != nil {
		return nil, err
	}
	w, err := archive.OpenWriter(vfs.OS{Root: dir}, archive.Options{MaxExtent: o.MaxExtent, UncompressedExtents: o.UncompressedExtents, PackThreshold: o.PackThreshold, VerifyAll: o.VerifyAll,
		Anchor: o.Anchor, AdoptUnanchored: o.AdoptUnanchored, Key: o.Key, AcknowledgeAllocatorRollback: o.AcknowledgeAllocatorRollback, Policy: o.Policy,
		MemoryLimit: o.MemoryLimit})
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

// List returns every live path in bytewise order. It holds them all in
// memory; use Walk for archive-scale listings.
func (a *Archive) List() ([]string, error) { return a.w.List() }

// Walk calls fn for every live path that starts with prefix, in bytewise
// order from the first path >= start ("" for the beginning), until fn
// returns false. Memory does not depend on the number of paths; the walk
// sees the state as it was when it began.
func (a *Archive) Walk(prefix, start string, fn func(Info) bool) error {
	return a.w.Walk(prefix, start, func(p string, v *manifest.Version) bool { return fn(info(p, v)) })
}

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
// Compact fail with a *GCBlockedError (matching ErrMissingData) and leaves
// the archive unchanged; CompactOptions.EmergencyPrune then lets the
// operator give those versions up explicitly (SPEC §13.9).
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

// EmergencyPrune authorizes a GC-blocked compaction to give up what can
// be neither found nor rebuilt (SPEC §13.9): the operator, a reason, and
// ExpectLostExtents equal to GCBlockedError.Extents of the failing
// compaction. The versions concerned become UNRECOVERABLE and leave the
// live state; a durable EMERGENCY_PRUNE record (health/, sealed in an
// encrypted archive) is written before anything is switched or deleted.
type EmergencyPrune = archive.EmergencyPrune

// UnrecoverableError names a version an Emergency Pruning gave up.
type UnrecoverableError = archive.UnrecoverableError

// GCBlockedError is the error of a compaction that found committed
// extents it can neither find nor rebuild.
type GCBlockedError = archive.GCBlockedError

// PruneReport, PruneRecord and PruneDetail describe Emergency Prunings.
type (
	PruneReport = archive.PruneReport
	PruneRecord = archive.PruneRecord
	PruneDetail = archive.PruneDetail
)

// PruneRecords lists the archive's EMERGENCY_PRUNE records and any
// health metadata this implementation does not understand (another
// implementation's: parity protection is then unknown until Verify).
func (a *Archive) PruneRecords() ([]PruneRecord, []string, error) { return a.w.PruneRecords() }

// Unrecoverable streams the paths whose version an Emergency Pruning gave
// up and that were neither written nor deleted since, until fn returns
// false.
func (a *Archive) Unrecoverable(fn func(UnrecoverableError) bool) error { return a.w.Unrecoverable(fn) }

// PruneDetails streams the lost extents, UNRECOVERABLE versions and
// affected parity groups of a record.
func (a *Archive) PruneDetails(record string, fn func(PruneDetail) error) error {
	return a.w.PruneDetails(record, fn)
}

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
	// minutes, at least 3 seconds); a crashed reader's pin expires after it.
	PinTTL time.Duration
	// Anchor is required for a HARDENED archive: the snapshot is the
	// anchored state, never bytes written after the last anchor advance.
	Anchor Anchor
	// Key opens an encrypted archive.
	Key []byte
	// Policy is the expected security policy (see Options.Policy).
	Policy Policy
	// MemoryLimit bounds the reader's archive-scale working state (see
	// Options.MemoryLimit; at least MinMemoryLimit).
	MemoryLimit int64
	// TempDir holds the reader's private scratch space, used only when an
	// index must be rebuilt or caught up beyond memory; "" means
	// os.TempDir(). A reader never writes into the archive.
	TempDir string
}

// OpenReadOnly opens a snapshot of the archive in dir for reading. It pins
// the snapshot's generation (a file under pins/) so compaction keeps it
// until Close (SPEC §13.1.1).
func OpenReadOnly(dir string) (*Reader, error) { return OpenReadOnlyWith(dir, ReadOptions{}) }

// OpenReadOnlyWith is OpenReadOnly with options.
func OpenReadOnlyWith(dir string, o ReadOptions) (*Reader, error) {
	if err := checkMemory(o.MemoryLimit); err != nil {
		return nil, err
	}
	r, err := archive.OpenReaderWith(vfs.OS{Root: dir}, archive.ReaderOptions{Pin: !o.NoPin, PinTTL: o.PinTTL, Anchor: o.Anchor, Key: o.Key, Policy: o.Policy,
		MemoryLimit: o.MemoryLimit, TempDir: o.TempDir})
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

// List returns every live path of the snapshot (all in memory; see Walk).
func (r *Reader) List() ([]string, error) { return r.r.List() }

// Walk calls fn for every live path of the snapshot that starts with
// prefix, in bytewise order from the first path >= start, until fn
// returns false (see Archive.Walk).
func (r *Reader) Walk(prefix, start string, fn func(Info) bool) error {
	return r.r.Walk(prefix, start, func(p string, v *manifest.Version) bool { return fn(info(p, v)) })
}

// PruneRecords lists the archive's EMERGENCY_PRUNE records (see
// Archive.PruneRecords).
func (r *Reader) PruneRecords() ([]PruneRecord, []string, error) { return r.r.PruneRecords() }

// Unrecoverable streams the snapshot's UNRECOVERABLE paths.
func (r *Reader) Unrecoverable(fn func(UnrecoverableError) bool) error { return r.r.Unrecoverable(fn) }

// PruneDetails streams the details of a record.
func (r *Reader) PruneDetails(record string, fn func(PruneDetail) error) error {
	return r.r.PruneDetails(record, fn)
}

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
	// Key recovers an encrypted archive's content. Without it the scan is
	// keyless: frames, parity and opaque object_id groups are checked and
	// reported, nothing can be extracted (SPEC §15.10).
	Key []byte
	// WorkDir is where the scan keeps its working tables, outside the
	// archive (recovery never writes there). A private directory is
	// created below it and removed by Close. Empty: os.TempDir(). When it
	// cannot be used, Recover fails with ErrRecoveryWorkDir.
	WorkDir string
	// MemoryLimit bounds the scan's memory (0: 1 GiB; at least
	// MinMemoryLimit); what does not fit
	// spills to WorkDir.
	MemoryLimit int64
}

// ErrRecoveryWorkDir reports an unusable RecoverOptions.WorkDir.
var ErrRecoveryWorkDir = recovery.ErrWorkDir

// RecoverySelection streams recovered versions (Recovery.All,
// Recovery.Default, or SelectVersions of a list).
type RecoverySelection = recovery.Selection

// SelectVersions is a selection of the given versions.
func SelectVersions(vs ...*RecoveredVersion) RecoverySelection { return recovery.Select(vs...) }

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
	if err := checkMemory(o.MemoryLimit); err != nil {
		return nil, err
	}
	return recovery.Scan(vfs.OS{Root: dir}, recovery.Options{Generation: o.Generation, NoManifest: o.NoManifest, Budget: o.ResyncBudget, Key: o.Key,
		WorkDir: o.WorkDir, MemoryLimit: o.MemoryLimit})
}

// Salvage creates a new archive in dir (empty or absent) with the
// recovered archive's parameters and writes the selected versions into it
// (rc.Default() selects the current versions, or the newest complete
// version per path when the manifest is gone; SelectVersions a list).
func Salvage(ctx context.Context, rc *Recovery, dir string, sel RecoverySelection) (SalvageResult, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return SalvageResult{}, err
	}
	return rc.Salvage(ctx, vfs.OS{Root: dir}, sel)
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
	return EnrollWithKey(ctx, dir, a, nil, operator, log)
}

// EnrollWithKey is Enroll for an encrypted archive; the anchor also binds
// its allocator reservations (SPEC §2.1.3.5).
func EnrollWithKey(ctx context.Context, dir string, a Anchor, key []byte, operator string, log func(string)) (AnchorState, error) {
	return archive.Enroll(ctx, vfs.OS{Root: dir}, a, archive.EnrollOptions{Operator: operator, Log: log, Key: key})
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
	return AuthorizeAnchorTransitionWithKey(ctx, dir, a, nil, operator, log)
}

// AuthorizeAnchorTransitionWithKey is AuthorizeAnchorTransition for an
// encrypted archive.
func AuthorizeAnchorTransitionWithKey(ctx context.Context, dir string, a Anchor, key []byte, operator string, log func(string)) error {
	return archive.AuthorizeAnchorTransition(ctx, vfs.OS{Root: dir}, a, operator, log, key)
}

// ArchiveInfo describes an archive's fixed parameters and state as stored
// in its plaintext root and header; reading it needs no key and no lock.
type ArchiveInfo struct {
	ArchiveID    [32]byte
	Generation   uint64   // the generation root.current names
	Generations  []uint64 // generation directories present
	Mode         FrameMode
	Hash         Hash
	Compression  Compression
	Encrypted    bool
	Hardened     bool
	Blobs        int
	MaxFrameSize int
	Parity       Parity
}

// Describe reads the archive parameters of dir.
func Describe(dir string) (ArchiveInfo, error) {
	fsys := vfs.OS{Root: dir}
	root, err := archive.ReadRoot(fsys)
	if err != nil {
		return ArchiveInfo{}, err
	}
	h, err := archive.ReadHeader(fsys, archive.GenDir(root.GenerationID))
	if err != nil {
		return ArchiveInfo{}, err
	}
	gens, err := archive.Generations(fsys)
	if err != nil {
		return ArchiveInfo{}, err
	}
	in := ArchiveInfo{ArchiveID: h.ArchiveID, Generation: root.GenerationID, Generations: gens,
		Compression: Compression(h.CodecID), Encrypted: h.Encrypted(), Blobs: int(h.BlobCount), MaxFrameSize: int(h.MaxFrameSize())}
	if h.Mode == wire.ModeFixed {
		in.Mode = Fixed
	}
	if h.HashID == wire.HashBLAKE3 {
		in.Hash = BLAKE3
	}
	switch h.ParityScheme {
	case wire.ParityXOR:
		in.Parity = Parity{Scheme: XOR, K: int(h.ParityK), M: int(h.ParityM)}
	case wire.ParityRS:
		in.Parity = Parity{Scheme: ReedSolomon, K: int(h.ParityK), M: int(h.ParityM)}
	}
	if _, err := os.Stat(filepath.Join(dir, archive.PolicyName)); err == nil {
		in.Hardened = true
	}
	return in, nil
}
