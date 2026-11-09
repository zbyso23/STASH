package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sync"
	"sync/atomic"

	"stash/internal/alloc"
	"stash/internal/anchor"
	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/index"
	"stash/internal/manifest"
	"stash/internal/parity"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// ErrNoWritableBlob reports that every blob of the generation is SEALED
// (§10.4.2): writes fail until compaction.
var ErrNoWritableBlob = errors.New("no writable blob (all sealed)")

// ErrPathBusy reports a concurrent write to the same path (§10.2.1).
var ErrPathBusy = manifest.ErrPathBusy

// Options configures OpenWriter.
type Options struct {
	Pool *bufpool.Pool
	// MaxExtent caps the logical bytes per DATA frame (default 4 MiB, never
	// more than the frame can hold).
	MaxExtent int
	// PackThreshold: objects up to this size are packed into shared
	// PACKED frames by the group commit (§8). 0 means
	// DefaultPackThreshold, negative disables packing.
	PackThreshold int
	// VerifyAll makes the open hash every frame even below a verified
	// checkpoint of a clean close (E1-23), so payload damage seals its blob
	// at open instead of being reported on read.
	VerifyAll bool
	Limits    manifest.Limits
	// Anchor is the Generation Anchor of a HARDENED archive (§2.1.2); it
	// is required for a HARDENED archive and refused for a STANDARD one.
	Anchor anchor.Anchor
	// AdoptUnanchored keeps manifest records beyond the anchored length
	// (a crash between the manifest fsync and the commit advance) and
	// anchors them, instead of truncating them (§10.4.1). It is an
	// operator-authorized recovery action: unencrypted records are not
	// authenticated.
	AdoptUnanchored bool
	// Key is the 32-byte archive DEK of an encrypted archive (§15.1).
	Key []byte
	// AcknowledgeAllocatorRollback continues an encrypted HARDENED archive
	// whose local Allocator State is below the anchored reservations from
	// the anchored values (§2.1.3.5): an operator decision after the
	// security incident was reported.
	AcknowledgeAllocatorRollback bool
}

// Health reports conditions found when opening (§13.9).
type Health struct {
	// Sealed lists blobs that may not be appended to in this generation,
	// with the reason.
	Sealed map[uint8]error
	// TornManifestBytes and TornBlobBytes count truncated torn tails.
	TornManifestBytes int64
	TornBlobBytes     map[uint8]int64
	// AbortedOnStart lists transactions closed by the cold start.
	AbortedOnStart []manifest.TxID
	// RebuiltIndexes lists blobs whose index was rebuilt by scan.
	RebuiltIndexes []uint8
	// Checkpointed counts frames below verified checkpoints whose payload
	// hashes were not recomputed at open (E1-23).
	Checkpointed int
	// UnanchoredBytes counts manifest bytes beyond the anchored length
	// that were truncated (HARDENED, §10.4.1); AdoptedBytes those adopted.
	UnanchoredBytes, AdoptedBytes int64
	// ParityWarning is set when the writable blobs cannot hold a parity
	// group so that losing one whole blob is survivable (§7.4).
	ParityWarning string
}

// Writer is the single writer of an archive (§12.1). Put, Delete and Get
// are safe for concurrent use; writes to different blobs proceed in
// parallel, commits go through one manifest stream.
type Writer struct {
	*view
	// genMu: every operation holds it shared; compaction holds it
	// exclusively while it freezes, merges and switches generations
	// (§13.5).
	genMu sync.RWMutex
	// retired are views of earlier generations still used by open
	// Objects; their files close when the last Object closes, or in Close.
	retiredMu sync.Mutex
	retired   []*view
	compactMu sync.Mutex
	fsys      vfs.FS // shadows view.fsys (the same FS), usable before a view exists
	unlock    func() error
	journal   *manifest.Journal
	opt       Options

	genAlloc, verAlloc, seqAlloc *alloc.Allocator
	groupAlloc                   *alloc.Allocator // nil without parity
	code                         *parity.Code     // full-size code; nil without parity
	ordAlloc                     []*alloc.Allocator
	writers                      []*blob.Writer // nil: sealed

	stateMu sync.RWMutex // journal state vs. readers
	gc      groupCommit
	busyMu  sync.Mutex
	busy    map[string]bool
	rr      atomic.Uint32
	health  Health
	opened  bool // OpenWriter completed
	hard    hardenedState
	keys    *seal.Keys // encrypted archive
}

// OpenWriter takes the writer lock and opens the current generation for
// writing, applying every cold-start rule: allocator validation and
// rollback checks (§2.1.3), manifest torn tail and ADD_ABORT of open
// transactions (§10.3.1, §10.4.2), blob torn tails decided by manifest
// references or SEALED (§10.4.2), and index validation or rebuild (§10.5).
func OpenWriter(fsys vfs.FS, opt Options) (w *Writer, err error) {
	if opt.Pool == nil {
		opt.Pool = bufpool.Default
	}
	if opt.MaxExtent <= 0 {
		opt.MaxExtent = 4 << 20
	}
	unlock, err := fsys.Lock(LockName)
	if err != nil {
		return nil, err
	}
	w = &Writer{unlock: unlock, opt: opt, busy: map[string]bool{}, fsys: fsys,
		health: Health{Sealed: map[uint8]error{}, TornBlobBytes: map[uint8]int64{}}}
	opened := w
	defer func() {
		if err != nil {
			opened.Close()
			w = nil
		}
	}()
	if err := checkPolicy(fsys, opt.Anchor); err != nil {
		return nil, err
	}
	if opt.Anchor != nil {
		// §11.8: may complete an interrupted switch or creation
		_, st, err := resolveHardened(context.Background(), fsys, opt.Anchor, opt.Pool, true, opt.Key)
		if err != nil {
			return nil, err
		}
		w.hard = hardenedState{anchor: opt.Anchor, anchored: st}
	}
	root, err := readRoot(fsys)
	if err != nil {
		return nil, err
	}
	gen := GenDir(root.GenerationID)
	h, err := readHeader(fsys, gen, root)
	if err != nil {
		return nil, err
	}
	if w.keys, err = archiveKeys(fsys, h, opt.Key); err != nil {
		return nil, err
	}
	// archive-wide allocators
	ga := alloc.Identity{Kind: wire.AllocGeneration, ArchiveID: h.ArchiveID, Encrypted: h.Encrypted()}
	if w.genAlloc, err = alloc.Open(fsys, alloc.FileName(wire.AllocGeneration, 0), ga, 0); err != nil {
		return nil, err
	}
	gens, err := generations(fsys)
	if err != nil {
		return nil, err
	}
	maxGen := root.GenerationID
	for _, g := range gens {
		maxGen = max(maxGen, g)
	}
	if err := w.genAlloc.Check(maxGen, true); err != nil {
		return nil, err
	}
	fa := alloc.Identity{Kind: wire.AllocFileVer, ArchiveID: h.ArchiveID}
	if w.verAlloc, err = alloc.Open(fsys, alloc.FileName(wire.AllocFileVer, 0), fa, 0); err != nil {
		return nil, err
	}
	if err := w.openGeneration(gen, h); err != nil {
		return nil, err
	}
	w.opened = true
	return w, nil
}

// openGeneration opens generation gen for writing with every cold-start
// rule (see OpenWriter). The archive-wide allocators must be open.
func (w *Writer) openGeneration(gen string, h *wire.ArchiveHeader) (err error) {
	fsys, opt := w.fsys, w.opt
	if h.ParityScheme != wire.ParityNone {
		if w.code, err = parity.New(h.ParityScheme, int(h.ParityK), int(h.ParityM)); err != nil {
			return err
		}
	}
	w.view = &view{fsys: fsys, gen: gen, h: h, pool: opt.Pool, k: w.keys}
	if h.Encrypted() && h.GenerationID > seal.MaxGenerationID {
		return fmt.Errorf("%w: generation %d", seal.ErrNonceLimit, h.GenerationID)
	}
	per := func(kind wire.AllocKind, b uint8) (*alloc.Allocator, error) {
		return alloc.Open(fsys, path.Join(gen, alloc.FileName(kind, b)),
			alloc.Identity{Kind: kind, Blob: b, GenerationID: h.GenerationID, ArchiveID: h.ArchiveID, Encrypted: h.Encrypted()}, 0)
	}
	if w.seqAlloc, err = per(wire.AllocManifestSeq, 0); err != nil {
		return err
	}
	if w.code != nil {
		if w.groupAlloc, err = per(wire.AllocGroupID, 0); err != nil {
			return err
		}
	}
	w.ordAlloc = make([]*alloc.Allocator, h.BlobCount)
	for b := 0; b < int(h.BlobCount); b++ {
		if w.ordAlloc[b], err = per(wire.AllocFrameOrdinal, uint8(b)); err != nil {
			return err
		}
	}
	if w.hard.anchor != nil && h.Encrypted() {
		// §2.1.3.5: before any value is handed out (cold-start ADD_ABORTs
		// take seq values)
		if err := w.bindReservations(context.Background()); err != nil {
			return err
		}
	}

	if w.hard.anchor != nil {
		if err := w.prepareManifest(gen, opt.AdoptUnanchored); err != nil {
			return err
		}
	}
	// manifest: torn tail, allocator checks against the fold, cold-start aborts
	j, st, res, err := manifest.OpenJournal(fsys, gen, h, manifest.LoadOptions{
		Limits:    opt.Limits,
		Crypto:    manifestCrypto(h, w.keys),
		SeqSource: w.seqAlloc.Next,
		BeforeAppend: func(st *manifest.State) error {
			if err := w.verAlloc.Check(st.MaxFileVer(), st.MaxFileVer() > 0); err != nil {
				return err
			}
			return w.seqAlloc.Check(st.LastSeq(), st.Records() > 0)
		},
	})
	if err != nil {
		return err
	}
	w.journal = j
	if w.hard.anchor != nil {
		// cold-start ADD_ABORTs and adopted records are anchored now
		if err := w.advanceCommit(context.Background()); err != nil {
			return err
		}
	}
	w.health.TornManifestBytes = res.Load.Torn
	w.health.AbortedOnStart = res.Aborted

	// blobs: torn tails decided by the manifest's references
	w.writers = make([]*blob.Writer, h.BlobCount)
	truncated := make([]bool, h.BlobCount)
	var maxGroup uint32
	var groupRef func(uint32) bool
	tailHold := false
	if w.code != nil {
		refd, incomplete, err := w.groupCensus(st)
		if err != nil {
			return err
		}
		groupRef = func(g uint32) bool { return refd[g] }
		tailHold = incomplete
	}
	// blobs are scanned in parallel; results are merged in ordinal order
	type blobOpen struct {
		bw  *blob.Writer
		br  blob.OpenResult
		err error
	}
	opens := make([]blobOpen, h.BlobCount)
	var cps []blob.Checkpoint
	if !opt.VerifyAll {
		cps = readCheckpoints(fsys, gen, h)
	}
	var wg sync.WaitGroup
	for b := 0; b < int(h.BlobCount); b++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// unencrypted: the frame-ordinal check is skipped (§2.1.3.1)
			name, _ := blob.Name(uint8(b))
			committed := st.BlobCommitted(uint8(b), groupRef)
			committed.TailMayHoldCommitted = tailHold
			if cps != nil {
				committed.Verified = cps[b]
			}
			bw, br, err := blob.OpenWriterKeyed(fsys, path.Join(gen, name), h, opt.Pool, committed, w.keys, uint8(b))
			opens[b] = blobOpen{bw, br, err}
		}()
	}
	wg.Wait()
	var openErr error
	for b, o := range opens {
		maxGroup = max(maxGroup, o.br.MaxGroupID)
		switch {
		case blob.IsSealed(o.err):
			w.health.Sealed[uint8(b)] = o.err
		case o.err != nil && w.code != nil && errors.Is(o.err, fs.ErrNotExist):
			// a lost blob file: parity stands in for its frames, writes go
			// to the other blobs, compaction rebuilds it (§7.3.1)
			w.health.Sealed[uint8(b)] = fmt.Errorf("%w: blob file missing: %v", blob.ErrSealed, o.err)
		case o.err != nil:
			if openErr == nil {
				openErr = fmt.Errorf("blob %02X: %w", b, o.err)
			}
		case h.Encrypted() && o.err == nil && w.ordAlloc[b].Check(o.br.MaxNonceOrdinal, o.br.HasNonce) != nil:
			// §2.1.3.1: a stored nonce of this namespace at or above
			// reserved_through means the allocator was rolled back
			o.bw.Close()
			if openErr == nil {
				openErr = fmt.Errorf("blob %02X: %w", b, w.ordAlloc[b].Check(o.br.MaxNonceOrdinal, o.br.HasNonce))
			}
		default:
			w.health.Checkpointed += o.br.Checkpointed
			w.writers[b] = o.bw // closed by Close on failure
			if o.br.Truncated > 0 {
				w.health.TornBlobBytes[uint8(b)] = o.br.Truncated
				truncated[b] = true
			}
		}
	}
	if openErr != nil {
		return openErr
	}
	if w.groupAlloc != nil {
		// group_id cold-start check over every frame found (§2.1.3.1, §7)
		if err := w.groupAlloc.Check(uint64(maxGroup), maxGroup > 0); err != nil {
			return err
		}
		writable := 0
		for _, bw := range w.writers {
			if bw != nil {
				writable++
			}
		}
		n, m := int(h.ParityK)+int(h.ParityM), int(h.ParityM)
		if need := (n + m - 1) / m; writable < need {
			w.health.ParityWarning = fmt.Sprintf("%d writable blobs cannot place a group of %d+%d so that one lost blob is survivable (needs %d, §7.4)",
				writable, h.ParityK, h.ParityM, need)
		}
	}
	// indexes: a truncated blob gets a fresh index (stale records could
	// otherwise collide with frames appended at the same offsets)
	for b, t := range truncated {
		if t {
			iname, _ := index.Name(uint8(b))
			fsys.Remove(path.Join(gen, iname))
		}
	}
	stats, err := w.openBlobs(true, w.code != nil)
	if err != nil {
		return err
	}
	for b, s := range stats {
		if s.Rebuilt {
			w.health.RebuiltIndexes = append(w.health.RebuiltIndexes, uint8(b))
		}
	}
	return nil
}

// groupCensus hops every blob once (Prefix and tail only) and returns,
// for the torn-tail rules of §10.4.2, the parity groups that a loc
// references through one of their DATA members, and whether such a
// committed group lacks a member that no blob holds (E1-22). Members are
// counted by intact tail; a member whose payload is damaged is useless for
// reconstruction already, so truncating it loses nothing.
func (w *Writer) groupCensus(st *manifest.State) (referenced map[uint32]bool, incomplete bool, err error) {
	referenced = map[uint32]bool{}
	type info struct {
		k, m uint8
		idx  map[uint8]bool
	}
	groups := map[uint32]*info{}
	for b := 0; b < int(w.h.BlobCount); b++ {
		refs := st.BlobCommitted(uint8(b), nil).Refs
		name, _ := blob.Name(uint8(b))
		r, err := blob.OpenKeyed(w.fsys, path.Join(w.gen, name), w.h, w.pool, w.keys)
		if errors.Is(err, fs.ErrNotExist) {
			continue // lost blob: OpenWriter decides
		}
		if err != nil {
			return nil, false, fmt.Errorf("blob %02X: %w", b, err)
		}
		err = r.Hop(func(f blob.HopFrame) error {
			g := f.Trailer.GroupID
			if g == 0 {
				return nil
			}
			gi := groups[g]
			if gi == nil {
				gi = &info{k: f.Trailer.GroupK, m: f.Trailer.GroupM, idx: map[uint8]bool{}}
				groups[g] = gi
			}
			gi.idx[f.Trailer.GroupIndex] = true
			for _, e := range f.Entries {
				off := e.Offset
				if f.Trailer.BlockType == wire.BlockPacked {
					off = 0
				}
				if _, ok := refs[blob.FrameKey{Hash: f.Trailer.HashPayload, Path: e.Path, FileVer: e.FileVer, Offset: off}]; ok {
					referenced[g] = true
				}
			}
			return nil
		})
		r.Close()
		if err != nil {
			return nil, false, err
		}
	}
	for g := range referenced {
		gi := groups[g]
		if len(gi.idx) < int(gi.k)+int(gi.m) {
			incomplete = true
		}
	}
	return referenced, incomplete, nil
}

// Header returns the archive header.
func (w *Writer) Header() *wire.ArchiveHeader {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	return w.h
}

// Health returns what the cold start found.
func (w *Writer) Health() Health {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	return w.health
}

// maxPayload is the largest DATA payload for path in one frame.
func (w *Writer) maxExtent(p string) int {
	pt := 4 + 2 + len(p) + 24 + 4 // entry list + outer CRC
	n := int(w.h.MaxFrameSize()) - wire.FrameOverhead - pt
	if w.h.Encrypted() {
		n -= 2 * wire.AEADOverhead // payload and Pre-Trailer (§6.4.3, §15.3)
	}
	if w.code != nil {
		n -= wire.MinParityPadding // §7.2
	}
	n = n / wire.BaseQuantum * wire.BaseQuantum
	return min(n, w.opt.MaxExtent/wire.BaseQuantum*wire.BaseQuantum)
}

func (w *Writer) pickBlob() (int, error) {
	n := len(w.writers)
	start := int(w.rr.Add(1))
	for i := 0; i < n; i++ {
		b := (start + i) % n
		if w.writers[b] != nil {
			return b, nil
		}
	}
	return 0, ErrNoWritableBlob
}

func (w *Writer) claim(p string) error {
	w.busyMu.Lock()
	defer w.busyMu.Unlock()
	if w.busy[p] {
		return fmt.Errorf("%w: %s", ErrPathBusy, p)
	}
	w.busy[p] = true
	return nil
}

func (w *Writer) release(p string) {
	w.busyMu.Lock()
	delete(w.busy, p)
	w.busyMu.Unlock()
}

// Put writes data as a new version of p and commits it durably (§9.5,
// §10.4). It returns the new file_ver. See PutReader for streaming input.
func (w *Writer) Put(p string, data []byte) (uint64, error) {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	chunk, err := w.prepare(p)
	if err != nil {
		return 0, err
	}
	defer w.release(p)
	if len(data) <= w.packMax(p) {
		return w.putPacked(p, data)
	}
	src := func(off int) ([]byte, func(), error) {
		if off >= len(data) && !(off == 0 && len(data) == 0) {
			return nil, nil, errDone
		}
		return data[off:min(off+chunk, len(data))], nil, nil
	}
	return w.writeAndCommit(context.Background(), p, src)
}

// prepare validates p, claims it and returns the extent size.
func (w *Writer) prepare(p string) (int, error) {
	if err := checkPath(p); err != nil {
		return 0, err
	}
	chunk := w.maxExtent(p)
	if chunk <= 0 {
		return 0, fmt.Errorf("%w: path too long for one frame", wire.ErrInvalid)
	}
	if err := w.claim(p); err != nil {
		return 0, err
	}
	return chunk, nil
}

// Delete commits removal of the current version of p.
func (w *Writer) Delete(p string) error {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	if err := w.claim(p); err != nil {
		return err
	}
	defer w.release(p)
	return w.commit(&commitReq{del: true, path: p})
}

// Get returns the content of the current version of p.
func (w *Writer) Get(p string) ([]byte, error) {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	w.stateMu.RLock()
	v, ok := w.journal.State().Lookup(p)
	w.stateMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p)
	}
	return w.read(p, v)
}

// Open returns a lazy reader of the current version of p. The object stays
// readable after later writes to p (versions are immutable, §9.5) until
// compaction, which does not exist yet.
func (w *Writer) Open(p string) (*Object, error) {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	w.stateMu.RLock()
	v, ok := w.journal.State().Lookup(p)
	w.stateMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p)
	}
	return w.object(p, v), nil
}

// Stat returns the current version of p.
func (w *Writer) Stat(p string) (*manifest.Version, error) {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	w.stateMu.RLock()
	defer w.stateMu.RUnlock()
	v, ok := w.journal.State().Lookup(p)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p)
	}
	return v, nil
}

// PutReader streams r into a new version of p: chunks are read into pooled
// buffers and written as frames in parallel; memory use is bounded by the
// number of workers times the extent size. Cancelling ctx stops the write
// before the commit (frames written so far stay unreferenced).
func (w *Writer) PutReader(ctx context.Context, p string, r io.Reader) (uint64, error) {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	chunk, err := w.prepare(p)
	if err != nil {
		return 0, err
	}
	defer w.release(p)
	// the first chunk decides between a PACKED object and extents
	first := w.pool.Get(chunk)
	n, err := io.ReadFull(r, first)
	eof := err == io.EOF || err == io.ErrUnexpectedEOF
	if err != nil && !eof {
		w.pool.Put(first)
		return 0, err
	}
	if eof && n <= w.packMax(p) {
		defer w.pool.Put(first)
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return w.putPacked(p, first[:n])
	}
	pre := first[:n]
	src := func(off int) ([]byte, func(), error) {
		if pre != nil {
			b := pre
			pre = nil
			return b, func() { w.pool.Put(first) }, nil
		}
		if eof {
			return nil, nil, errDone
		}
		buf := w.pool.Get(chunk)
		n, err := io.ReadFull(r, buf)
		switch {
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			eof = true
			if n == 0 && off > 0 {
				w.pool.Put(buf)
				return nil, nil, errDone
			}
		case err != nil:
			w.pool.Put(buf)
			return nil, nil, err
		}
		return buf[:n], func() { w.pool.Put(buf) }, nil
	}
	return w.writeAndCommit(ctx, p, src)
}

// putPacked commits a small object; the group commit leader packs it
// with the other small objects of its batch (§8).
func (w *Writer) putPacked(p string, data []byte) (uint64, error) {
	ver, err := w.verAlloc.Next()
	if err != nil {
		return 0, err
	}
	if err := w.commitPacked(&commitReq{path: p, fileVer: ver, pack: true, small: data}); err != nil {
		return 0, err
	}
	return ver, nil
}

// List returns the live paths.
func (w *Writer) List() []string {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	w.stateMu.RLock()
	defer w.stateMu.RUnlock()
	return w.journal.State().Paths()
}

// Close persists the indexes, closes files and releases the writer lock.
// It does not commit anything: every Put is already durable.
func (w *Writer) Close() error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	if w.opened {
		keep(w.writeCheckpoints())
	}
	var blobs []*blobView
	if w.view != nil {
		blobs = w.blobs
	}
	for b, bv := range blobs {
		if bv == nil {
			continue
		}
		if w.writers != nil && w.writers[b] != nil {
			iname, _ := index.Name(uint8(b))
			bv.mu.Lock()
			keep(bv.idx.Write(w.fsys, path.Join(w.gen, iname)))
			bv.mu.Unlock()
		}
	}
	if w.view != nil {
		w.close()
	}
	w.retiredMu.Lock()
	for _, v := range w.retired {
		v.close()
	}
	w.retired = nil
	w.retiredMu.Unlock()
	for _, bw := range w.writers {
		if bw != nil {
			keep(bw.Close())
		}
	}
	if w.journal != nil {
		keep(w.journal.Close())
	}
	if w.unlock != nil {
		keep(w.unlock())
		w.unlock = nil
	}
	return first
}
