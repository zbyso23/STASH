package archive

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"sync"

	"stash/internal/anchor"
	"stash/internal/bufpool"
	"stash/internal/manifest"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// HARDENED policy (§2.1.2, §10.4.1, §11.8, §13.6.1, §15A.2). The policy is
// not a wire identifier: an archive is HARDENED because an anchor exists
// for it and because this implementation keeps a local marker file,
// PolicyName, so that an opener without an anchor fails instead of
// silently downgrading to STANDARD. Leaving HARDENED is an explicit
// operator action (LeaveHardened).

// PolicyName is the implementation-defined marker of a HARDENED archive
// (outside the normative names; other readers ignore it).
const PolicyName = "policy.hardened"

var policyMagic = [8]byte{'S', 'T', 'P', 'O', 'L', 'I', 'C', 'Y'}

// ErrRollback reports rollback, stale storage or tampering detected
// against the Generation Anchor: a security incident; nothing falls back.
var ErrRollback = errors.New("rollback or tampering detected against the generation anchor")

// ErrAnchorRequired reports a HARDENED archive opened without an anchor,
// or an anchor given for an archive that is not HARDENED.
var ErrAnchorRequired = errors.New("generation anchor policy mismatch")

// ErrAnchorUnavailable reports an anchor that cannot be reached; HARDENED
// never downgrades because of it.
var ErrAnchorUnavailable = anchor.ErrUnavailable

func encodePolicy(id [32]byte) []byte {
	b := append(append([]byte{}, policyMagic[:]...), id[:]...)
	return binary.LittleEndian.AppendUint32(b, wire.CRC32C(b))
}

// isHardened reports whether the marker exists. A damaged marker counts
// as present: the opener then needs the anchor, which decides.
func isHardened(fsys vfs.FS) (bool, error) {
	_, err := fsys.Stat(PolicyName)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func writePolicy(fsys vfs.FS, id [32]byte) error {
	return vfs.ReplaceFile(fsys, PolicyName, encodePolicy(id))
}

// rootBytes returns the exact root.current bytes for a generation.
func rootBytes(gen uint64, id [32]byte) []byte {
	r := wire.Root{GenerationID: gen, ArchiveID: id}
	return r.AppendBinary(nil)
}

// manifestHash hashes manifest.jsonl[0:n] of gen and returns the running
// hash (to continue with appended bytes) and the file size.
func manifestHash(fsys vfs.FS, gen string, n int64) (hash.Hash, int64, error) {
	f, err := fsys.OpenFile(path.Join(gen, manifest.ManifestName), os.O_RDONLY, 0)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	size, err := f.Size()
	if err != nil {
		return nil, 0, err
	}
	h := sha256.New()
	if n > size {
		return h, size, nil
	}
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, n)); err != nil {
		return nil, 0, err
	}
	return h, size, nil
}

func sum(h hash.Hash) [32]byte {
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// cloneHash copies a running SHA-256 state.
func cloneHash(h hash.Hash) hash.Hash {
	st, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
	c := sha256.New()
	c.(encoding.BinaryUnmarshaler).UnmarshalBinary(st)
	return c
}

// archiveIDOf finds the archive_id when root.current may be missing: from
// the root, else from the newest generation's header.
func archiveIDOf(fsys vfs.FS) ([32]byte, error) {
	if r, err := readRoot(fsys); err == nil {
		return r.ArchiveID, nil
	}
	gens, err := generations(fsys)
	if err != nil || len(gens) == 0 {
		return [32]byte{}, fmt.Errorf("no archive found (%v)", err)
	}
	h, err := ReadHeader(fsys, GenDir(slices.Max(gens)))
	if err != nil {
		return [32]byte{}, err
	}
	return h.ArchiveID, nil
}

func loadAnchor(ctx context.Context, a anchor.Anchor, id [32]byte) (anchor.State, error) {
	st, err := a.Load(ctx, id)
	if errors.Is(err, anchor.ErrNotFound) {
		return st, fmt.Errorf("%w: no anchor for a HARDENED archive (deleted, or the wrong provider): %v", ErrRollback, err)
	}
	if err != nil {
		return st, fmt.Errorf("%w: %v", ErrAnchorUnavailable, err)
	}
	return st, nil
}

// Policy is the security policy an opener expects, from configuration the
// archive's storage cannot change (§15A.2). The local marker PolicyName
// lives on that storage, so whoever controls it can delete it: it only
// guards against opening a HARDENED archive by mistake, never as the sole
// authority.
type Policy int

const (
	// PolicyAuto follows the local marker when no anchor is configured.
	// It does not protect against an adversary who controls the storage:
	// a deleted marker opens the archive as STANDARD. Deployments that
	// need HARDENED guarantees configure PolicyHardened or an anchor.
	PolicyAuto Policy = iota
	// PolicyStandard: the archive must be STANDARD (no marker).
	PolicyStandard
	// PolicyHardened: the archive must be HARDENED; an anchor is required
	// and a missing marker is a security incident.
	PolicyHardened
)

// checkPolicy enforces "never silently downgrade" and "no anti-rollback
// without an anchor" (§15A.2). A configured anchor is trusted
// configuration: it makes the opener expect HARDENED whatever the storage
// says. A missing marker while the anchor holds state for the archive
// means the marker was removed (ErrRollback); a marker without a
// configured anchor fails closed.
func checkPolicy(ctx context.Context, fsys vfs.FS, a anchor.Anchor, pol Policy) error {
	if pol < PolicyAuto || pol > PolicyHardened {
		return fmt.Errorf("%w: unknown policy %d", wire.ErrInvalid, pol)
	}
	if pol == PolicyStandard && a != nil {
		return fmt.Errorf("%w: an anchor was given with policy STANDARD", ErrAnchorRequired)
	}
	if pol == PolicyHardened && a == nil {
		return fmt.Errorf("%w: policy HARDENED needs the archive's generation anchor (§15A.2)", ErrAnchorRequired)
	}
	hard, err := isHardened(fsys)
	if err != nil {
		return err
	}
	switch {
	case hard && a == nil:
		return fmt.Errorf("%w: the archive is HARDENED; open it with its generation anchor (leaving HARDENED is an explicit operator action)", ErrAnchorRequired)
	case !hard && a != nil:
		id, err := archiveIDOf(fsys)
		if err != nil {
			return fmt.Errorf("%w: a generation anchor is configured but the policy marker is missing and the archive cannot be identified: %v", ErrRollback, err)
		}
		if _, err := a.Load(ctx, id); errors.Is(err, anchor.ErrNotFound) {
			return fmt.Errorf("%w: the archive is STANDARD; enroll it first", ErrAnchorRequired)
		} else if err != nil {
			return fmt.Errorf("%w: %v", ErrAnchorUnavailable, err)
		}
		return fmt.Errorf("%w: the anchor holds state for this archive but the policy marker %s is missing: removed by tampering, an interrupted enrollment, or HARDENED was left (then open without the anchor)", ErrRollback, PolicyName)
	}
	return nil
}

// resolveHardened is steps 1-7 of §11.8 for an opener: the anchored
// generation, its root and manifest prefix. With repair (a writer) a
// missing or older local root is reconstructed after the anchored
// generation verifies completely (§2.1.2.1); a reader only checks that it
// could be and reads the anchored generation.
func resolveHardened(ctx context.Context, fsys vfs.FS, a anchor.Anchor, pool *bufpool.Pool, repair bool, dek []byte) (wire.Root, anchor.State, error) {
	id, err := archiveIDOf(fsys)
	if err != nil {
		return wire.Root{}, anchor.State{}, err
	}
	st, err := loadAnchor(ctx, a, id)
	if err != nil {
		if _, rerr := readRoot(fsys); errors.Is(err, ErrRollback) && errors.Is(rerr, ErrIncomplete) {
			return wire.Root{}, st, ErrIncomplete // crash before the anchor was created
		}
		return wire.Root{}, st, err
	}
	want := wire.Root{GenerationID: st.GenerationID, ArchiveID: id}
	local, rootErr := readRoot(fsys)
	switch {
	case rootErr == nil && local.GenerationID == st.GenerationID:
		b, err := vfs.ReadFile(fsys, RootName, wire.RootSize+1)
		if err != nil {
			return want, st, err
		}
		if anchor.RootDigest(b) != st.RootDigest {
			return want, st, fmt.Errorf("%w: root.current digest differs from the anchored root_digest", ErrRollback)
		}
		if err := checkManifestPrefix(fsys, GenDir(st.GenerationID), st); err != nil {
			return want, st, err
		}
		return want, st, nil
	case rootErr == nil && local.GenerationID > st.GenerationID:
		return want, st, fmt.Errorf("%w: root.current names generation %d, the anchor %d; local storage may not advance trust (§13.6.1)",
			ErrRollback, local.GenerationID, st.GenerationID)
	case rootErr != nil && !errors.Is(rootErr, fs.ErrNotExist) && !errors.Is(rootErr, ErrIncomplete) && !wire.IsFormatError(rootErr):
		return want, st, rootErr
	}
	// root missing, damaged or older: the anchored generation must be
	// present and verify completely (§2.1.2.1, §13.6.1)
	rb := rootBytes(st.GenerationID, id)
	if anchor.RootDigest(rb) != st.RootDigest {
		return want, st, fmt.Errorf("%w: rebuilt root bytes do not match the anchored root_digest", ErrRollback)
	}
	if err := verifyAnchored(ctx, fsys, pool, want, st, dek); err != nil {
		return want, st, fmt.Errorf("%w: anchored generation %d is missing or does not verify: %v", ErrRollback, st.GenerationID, err)
	}
	if repair {
		if err := vfs.ReplaceFile(fsys, RootName, rb); err != nil {
			return want, st, err
		}
	}
	return want, st, nil
}

// checkManifestPrefix requires manifest.jsonl to hold the anchored prefix
// (§10.4.1).
func checkManifestPrefix(fsys vfs.FS, gen string, st anchor.State) error {
	h, size, err := manifestHash(fsys, gen, int64(st.ManifestLength))
	if err != nil {
		return fmt.Errorf("%w: manifest: %v", ErrRollback, err)
	}
	if size < int64(st.ManifestLength) {
		return fmt.Errorf("%w: manifest is %d bytes, the anchor covers %d", ErrRollback, size, st.ManifestLength)
	}
	if sum(h) != st.ManifestDigest {
		return fmt.Errorf("%w: manifest prefix digest differs from the anchor", ErrRollback)
	}
	return nil
}

// verifyAnchored verifies a generation completely against the anchor.
func verifyAnchored(ctx context.Context, fsys vfs.FS, pool *bufpool.Pool, root wire.Root, st anchor.State, dek []byte) error {
	if err := checkManifestPrefix(fsys, GenDir(root.GenerationID), st); err != nil {
		return err
	}
	r, err := openReaderAt(fsys, pool, root, int64(st.ManifestLength), true, dek)
	if err != nil {
		return err
	}
	defer r.Close()
	rep, err := r.Verify(ctx)
	if err != nil {
		return err
	}
	if !rep.OK() {
		return fmt.Errorf("verification found damage (%d failed paths, groups %+v)", len(rep.Failed), rep.Groups)
	}
	return nil
}

// hardenedState is the writer's anchor bookkeeping.
type hardenedState struct {
	anchor   anchor.Anchor
	anchored anchor.State
	mh       hash.Hash // SHA-256 over manifest.jsonl[0:mhLen]
	mhLen    int64
	// failed poisons the writer after an anchor error: the commit's state
	// is unknown, so nothing more is reported durable until a reopen.
	failed error
	// mu serializes anchor advances (commits, reservations, switch); resv
	// holds the bound reservations of an encrypted archive (§2.1.3.5).
	mu   sync.Mutex
	resv map[[2]uint8]uint64
}

// prepareManifest checks the anchored prefix and handles unanchored bytes
// before the journal opens (§10.4.1): truncated by default, kept for
// adoption with adopt.
func (w *Writer) prepareManifest(gen string, adopt bool) error {
	st := w.hard.anchored
	if err := checkManifestPrefix(w.fsys, gen, st); err != nil {
		return err
	}
	h, size, err := manifestHash(w.fsys, gen, int64(st.ManifestLength))
	if err != nil {
		return err
	}
	w.hard.mh, w.hard.mhLen = h, int64(st.ManifestLength)
	if size > int64(st.ManifestLength) && !adopt {
		f, err := w.fsys.OpenFile(path.Join(gen, manifest.ManifestName), os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Truncate(int64(st.ManifestLength)); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		w.health.UnanchoredBytes = size - int64(st.ManifestLength)
	} else if size > int64(st.ManifestLength) {
		w.health.AdoptedBytes = size - int64(st.ManifestLength)
	}
	return nil
}

// advanceCommit hashes the manifest bytes appended since the last advance
// and advances the anchor to them (§10.4.1 commit advance).
func (w *Writer) advanceCommit(ctx context.Context) error {
	hs := &w.hard
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.failed != nil {
		return hs.failed
	}
	end := w.journal.End()
	if end == hs.mhLen {
		return nil
	}
	f, err := w.fsys.OpenFile(path.Join(w.gen, manifest.ManifestName), os.O_RDONLY, 0)
	if err != nil {
		hs.failed = err
		return err
	}
	h := cloneHash(hs.mh)
	_, err = io.Copy(h, io.NewSectionReader(f, hs.mhLen, end-hs.mhLen))
	f.Close()
	if err != nil {
		hs.failed = err
		return err
	}
	next := hs.anchored
	next.ManifestLength, next.ManifestDigest = uint64(end), sum(h)
	if err := hs.anchor.Advance(ctx, hs.anchored, next); err != nil {
		hs.failed = fmt.Errorf("%w: commit advance: %v (reopen required)", ErrAnchorUnavailable, err)
		if errors.Is(err, anchor.ErrStale) || errors.Is(err, anchor.ErrNotNewer) {
			hs.failed = fmt.Errorf("%w: commit advance rejected: %v (another writer, or a replayed anchor)", ErrRollback, err)
		}
		return hs.failed
	}
	hs.anchored, hs.mh, hs.mhLen = next, h, end
	return nil
}

// advanceSwitch is steps 6-9 of §13.6.1 for a compaction to generation
// id whose manifest is complete and durable.
func (w *Writer) advanceSwitch(ctx context.Context, d *Writer, id uint64) error {
	hs := &w.hard
	var resv []anchor.Reservation
	if w.h.Encrypted() {
		// §2.1.3.5: the destination's kind 2-4 values and kind 0
		resv = d.reservations()
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.failed != nil {
		return hs.failed
	}
	end := d.journal.End()
	h, _, err := manifestHash(w.fsys, d.gen, end)
	if err != nil {
		return err
	}
	next := anchor.State{ArchiveID: w.h.ArchiveID, GenerationID: id, RootDigest: anchor.RootDigest(rootBytes(id, w.h.ArchiveID)),
		ManifestLength: uint64(end), ManifestDigest: sum(h), Reservations: resv}
	if err := hs.anchor.Advance(ctx, hs.anchored, next); err != nil {
		hs.failed = fmt.Errorf("%w: switch advance: %v (reopen required)", ErrAnchorUnavailable, err)
		return hs.failed
	}
	hs.anchored, hs.mh, hs.mhLen = next, h, end
	return nil
}

// EnrollOptions configure Enroll.
type EnrollOptions struct {
	Pool *bufpool.Pool
	// Log receives the enrollment record (time, operator, state); the
	// caller keeps it outside the archive (§2.1.2.1). Required.
	Log func(string)
	// Operator identifies who enrolls.
	Operator string
	// Key is the DEK of an encrypted archive.
	Key []byte
}

// Enroll switches an existing STANDARD archive to HARDENED (§2.1.2.1):
// trust on first use after a full verification of the current generation,
// then the anchor's initial state, then the local policy marker. No archive
// wire byte changes.
func Enroll(ctx context.Context, fsys vfs.FS, a anchor.Anchor, opt EnrollOptions) (anchor.State, error) {
	if opt.Log == nil || opt.Operator == "" {
		return anchor.State{}, fmt.Errorf("%w: enrollment needs an operator and a log", wire.ErrInvalid)
	}
	w, err := OpenWriter(fsys, Options{Pool: opt.Pool, VerifyAll: true, Key: opt.Key})
	if err != nil {
		return anchor.State{}, err
	}
	defer w.Close()
	rep, err := w.Verify(ctx)
	if err != nil {
		return anchor.State{}, err
	}
	if !rep.OK() {
		return anchor.State{}, fmt.Errorf("%w: the archive does not verify; repair (compact) it before enrolling", wire.ErrCorrupt)
	}
	w.genMu.Lock()
	defer w.genMu.Unlock()
	end := w.journal.End()
	h, _, err := manifestHash(fsys, w.gen, end)
	if err != nil {
		return anchor.State{}, err
	}
	rb, err := vfs.ReadFile(fsys, RootName, wire.RootSize+1)
	if err != nil {
		return anchor.State{}, err
	}
	st := anchor.State{ArchiveID: w.h.ArchiveID, GenerationID: w.h.GenerationID, RootDigest: anchor.RootDigest(rb),
		ManifestLength: uint64(end), ManifestDigest: sum(h)}
	if w.h.Encrypted() {
		st.Reservations = w.reservations() // §2.1.3.5
	}
	if err := a.Create(ctx, st); err != nil {
		return st, err
	}
	if err := writePolicy(fsys, st.ArchiveID); err != nil {
		return st, err
	}
	opt.Log(fmt.Sprintf("stash: HARDENED enrollment of archive %x by %q: generation %d, manifest %d bytes, digest %x",
		st.ArchiveID, opt.Operator, st.GenerationID, st.ManifestLength, st.ManifestDigest))
	return st, nil
}

// LeaveHardened removes the local HARDENED marker (an explicit operator
// action, §2.1.2.1). The anchor itself is left to the operator.
func LeaveHardened(fsys vfs.FS, operator string, log func(string)) error {
	if log == nil || operator == "" {
		return fmt.Errorf("%w: leaving HARDENED needs an operator and a log", wire.ErrInvalid)
	}
	unlock, err := fsys.Lock(LockName)
	if err != nil {
		return err
	}
	defer unlock()
	if err := fsys.Remove(PolicyName); err != nil {
		return err
	}
	if err := fsys.SyncDir("."); err != nil {
		return err
	}
	log(fmt.Sprintf("stash: archive left HARDENED policy by %q", operator))
	return nil
}

// AuthorizeAnchorTransition is the authorized recovery flow of §13.6.1 for
// root.current naming a generation beyond the anchor: the local generation
// is verified completely and the anchor advanced to it. Only an operator
// who knows why the anchor lags may run it.
func AuthorizeAnchorTransition(ctx context.Context, fsys vfs.FS, a anchor.Anchor, operator string, log func(string), dek []byte) error {
	if log == nil || operator == "" {
		return fmt.Errorf("%w: needs an operator and a log", wire.ErrInvalid)
	}
	unlock, err := fsys.Lock(LockName)
	if err != nil {
		return err
	}
	defer unlock()
	root, err := readRoot(fsys)
	if err != nil {
		return err
	}
	prev, err := loadAnchor(ctx, a, root.ArchiveID)
	if err != nil {
		return err
	}
	if root.GenerationID <= prev.GenerationID {
		return fmt.Errorf("%w: root.current does not lead the anchor", wire.ErrInvalid)
	}
	gen := GenDir(root.GenerationID)
	fi, err := fsys.Stat(path.Join(gen, manifest.ManifestName))
	if err != nil {
		return err
	}
	size := fi.Size()
	mh, _, err := manifestHash(fsys, gen, size)
	if err != nil {
		return err
	}
	next := anchor.State{ArchiveID: root.ArchiveID, GenerationID: root.GenerationID,
		RootDigest: anchor.RootDigest(rootBytes(root.GenerationID, root.ArchiveID)), ManifestLength: uint64(size), ManifestDigest: sum(mh)}
	if h, err := readHeader(fsys, gen, root); err != nil {
		return err
	} else if h.Encrypted() {
		if next.Reservations, err = currentReservations(fsys, h); err != nil {
			return err
		}
	}
	if err := verifyAnchored(ctx, fsys, nil, root, next, dek); err != nil {
		return fmt.Errorf("%w: local generation %d does not verify: %v", ErrRollback, root.GenerationID, err)
	}
	if err := a.Advance(ctx, prev, next); err != nil {
		return err
	}
	log(fmt.Sprintf("stash: anchor of archive %x advanced by %q from generation %d to local generation %d",
		root.ArchiveID, operator, prev.GenerationID, root.GenerationID))
	return nil
}
