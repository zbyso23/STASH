package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"stash/internal/anchor"
	"time"

	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/canonpath"
	"stash/internal/index"
	"stash/internal/kvtab"
	"stash/internal/manifest"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// ErrNotFound reports a path with no current version.
var ErrNotFound = errors.New("path not found")

// ErrMissingData reports a committed extent whose frame cannot be found
// or validated (§9.4: surfaced, never zero-filled).
var ErrMissingData = errors.New("committed data missing or damaged")

// blobView is the read side of one blob: a reader and its index.
type blobView struct {
	r   *blob.Reader
	mu  sync.Mutex   // guards defective and serializes index rewrites
	idx *index.Index // safe for concurrent use
	// defective is set when a lookup needed the fallback scan (§10.5.1).
	defective bool
}

// view is the read path shared by Reader and Writer.
type view struct {
	fsys  vfs.FS
	gen   string
	h     *wire.ArchiveHeader
	k     *seal.Keys // encrypted archive
	pool  *bufpool.Pool
	env   *index.Env   // memory budget, page cache, scratch space
	kv    kvtab.Config // tables of the repair directory and of compaction
	blobs []*blobView  // nil entry: blob unavailable
	// hints holds locator hints of extents whose frame_hash is shared
	// (the manifest state of the generation; nil: none)
	hints    hintStore
	learning sync.Map // learnKey → chan struct{}: a group being learned
	// hinted and learned count reads through a hint and groups learned
	hinted, learned atomic.Uint64
	// unavailable records why a blob could not be opened (readers of a
	// parity archive continue without it, §7.4).
	unavailable map[uint8]error
	repairs
	// lost holds the generation's UNRECOVERABLE markers (lost.go)
	lost *lostSet

	// users counts open Objects; a retired view (an earlier generation
	// after compaction) closes its files when the last one closes.
	users     atomic.Int64
	retiredV  atomic.Bool
	closeOnce sync.Once
}

// retire marks the view as belonging to a replaced generation.
func (v *view) retire() {
	v.retiredV.Store(true)
	if v.users.Load() == 0 {
		v.close()
	}
}

// inUse reports whether a retired view still has open Objects.
func (v *view) inUse() bool { return v.users.Load() > 0 }

// openBlobs opens every blob and its index. With tolerate, a blob that
// cannot be opened is recorded as unavailable instead of failing (only
// useful when parity can stand in for it).
func (v *view) openBlobs(writeIndexes, tolerate bool) (statuses []index.Status, err error) {
	v.blobs = make([]*blobView, v.h.BlobCount)
	v.unavailable = map[uint8]error{}
	statuses = make([]index.Status, v.h.BlobCount)
	errs := make([]error, len(v.blobs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for b := range v.blobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name, _ := blob.Name(uint8(b))
			r, err := blob.OpenKeyed(v.fsys, path.Join(v.gen, name), v.h, v.pool, v.k)
			if err != nil {
				if tolerate && !errors.Is(err, wire.ErrUnsupported) {
					mu.Lock()
					v.unavailable[uint8(b)] = err
					mu.Unlock()
					return
				}
				errs[b] = fmt.Errorf("blob %02X: %w", b, err)
				return
			}
			iname, _ := index.Name(uint8(b))
			x, st, err := index.Open(v.env, v.fsys, path.Join(v.gen, iname), r, v.h, uint8(b), v.pool)
			if err != nil {
				r.Close()
				errs[b] = fmt.Errorf("index %02X: %w", b, err)
				return
			}
			if writeIndexes && (st.Rebuilt || st.CaughtUp > 0) {
				if err := x.Write(v.fsys, path.Join(v.gen, iname)); err != nil {
					x.Close()
					r.Close()
					errs[b] = err
					return
				}
			}
			statuses[b] = st
			v.blobs[b] = &blobView{r: r, idx: x}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return statuses, nil
}

func (v *view) close() {
	v.closeOnce.Do(func() {
		v.lost.close()
		v.fdir.close()
		for _, b := range v.blobs {
			if b != nil {
				b.idx.Close()
				b.r.Close()
			}
		}
	})
}

// fetch finds the frame of one extent (§9.1): through the index
// (candidates validated, fallback scan), carrying exactly this object's
// path, file_ver and placement. The Ref must be released.
func (v *view) fetch(p string, ver *manifest.Version, l manifest.Loc) (*blob.Ref, error) {
	if int(l.Blob) >= len(v.blobs) {
		return nil, fmt.Errorf("%w: blob %02X out of range", ErrMissingData, l.Blob)
	}
	accept := func(ref *blob.Ref) bool {
		if ref.Trailer.HashPayload != l.Hash {
			return false
		}
		_, ok := packedEntry(ref, p, ver.FileVer, l)
		return ok
	}
	if bv := v.blobs[l.Blob]; bv != nil {
		ref, err := v.fetchHinted(bv, p, ver, l, accept)
		if ref == nil && err == nil {
			// another reader is learning this group: wait for its hints
			if ch, ok := v.learning.Load(learnKey{l.Blob, l.Hash}); ok {
				<-ch.(chan struct{})
				ref, err = v.fetchHinted(bv, p, ver, l, accept)
			}
		}
		if ref != nil || err != nil {
			if err != nil {
				return nil, err
			}
			if err := ref.Decode(); err != nil {
				ref.Release()
				return nil, fmt.Errorf("%w: %s v%d extent at %d: %v", ErrMissingData, p, ver.FileVer, l.Offset, err)
			}
			slicePacked(ref, p, ver.FileVer, l)
			return ref, nil
		}
		// the index is safe for concurrent lookups: no blob lock across I/O
		rejected := false
		accept := func(ref *blob.Ref) bool {
			ok := accept(ref)
			rejected = rejected || !ok
			return ok
		}
		ref, how, err := bv.idx.Find(bv.r, l.Hash, accept)
		if rejected && how == index.ViaIndex && err == nil {
			v.learn(l.Blob, bv, l.Hash, p, ver.FileVer, l.Offset)
		}
		if how == index.ViaScan {
			bv.mu.Lock()
			bv.defective = true
			bv.mu.Unlock()
		}
		if err != nil {
			return nil, err
		}
		if how != index.NotFound {
			if err := ref.Decode(); err != nil {
				ref.Release()
				return nil, fmt.Errorf("%w: %s v%d extent at %d: %v", ErrMissingData, p, ver.FileVer, l.Offset, err)
			}
			slicePacked(ref, p, ver.FileVer, l)
			return ref, nil
		}
		bv.mu.Lock()
		bv.defective = true
		bv.mu.Unlock()
	}
	// damaged or unavailable: hop-and-read, then parity (§7.3, §11)
	ref, err := v.recover(p, ver, l, accept)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, fmt.Errorf("%w: %s v%d extent at %d (blob %02X)", ErrMissingData, p, ver.FileVer, l.Offset, l.Blob)
	}
	if err := ref.Decode(); err != nil {
		ref.Release()
		return nil, fmt.Errorf("%w: %s v%d extent at %d: %v", ErrMissingData, p, ver.FileVer, l.Offset, err)
	}
	slicePacked(ref, p, ver.FileVer, l)
	return ref, nil
}

// hintStore keeps locator hints (manifest.State).
type hintStore interface {
	Hint(path string, fileVer, offset uint64) (uint8, uint64, bool, error)
	SetHint(path string, fileVer, offset uint64, blob uint8, phys uint64) error
}

// fetchHinted reads an extent through its locator hint: one index check
// and one frame read instead of a walk over every frame sharing its hash.
// A missing, stale or unreadable hint is a miss (nil, nil), never an
// error: hints are not authoritative.
func (v *view) fetchHinted(bv *blobView, p string, ver *manifest.Version, l manifest.Loc, accept func(*blob.Ref) bool) (*blob.Ref, error) {
	if v.hints == nil {
		return nil, nil
	}
	b, phys, ok, err := v.hints.Hint(p, ver.FileVer, l.Offset)
	if err != nil || !ok || b != l.Blob {
		return nil, nil
	}
	ref, err := bv.idx.FindAt(bv.r, l.Hash, phys, accept)
	if ref != nil {
		v.hinted.Add(1)
	}
	return ref, err
}

// learn records a hint for every extent stored in a frame with this hash,
// read by Prefix and tail only. It runs when Find had to reject a
// candidate, so a group of payload-identical frames is read once, not once
// per object (a read that missed while another learned the group skips
// it). Failures only mean fewer hints.
func (v *view) learn(b uint8, bv *blobView, hash [wire.HashSize]byte, p string, fileVer, offset uint64) {
	if v.hints == nil {
		return
	}
	k := learnKey{b, hash}
	done := make(chan struct{})
	if _, busy := v.learning.LoadOrStore(k, done); busy {
		return
	}
	if _, _, ok, _ := v.hints.Hint(p, fileVer, offset); ok {
		// learned by a concurrent read since this one missed
		v.learning.Delete(k)
		close(done)
		return
	}
	defer func() {
		v.learning.Delete(k)
		close(done)
	}()
	v.learned.Add(1)
	bv.idx.EachCandidate(hash, func(rec wire.IndexRecord) bool {
		hf, ok, err := bv.r.TailAt(int64(rec.PhysicalOffset))
		if err != nil {
			return false
		}
		if !ok || hf.Trailer.HashPayload != hash {
			return true
		}
		for _, e := range hf.Entries {
			if v.hints.SetHint(e.Path, e.FileVer, e.Offset, b, rec.PhysicalOffset) != nil {
				return false
			}
		}
		return true
	})
}

type learnKey struct {
	blob uint8
	hash [wire.HashSize]byte
}

// packedEntry finds the payload range of extent l of (p, fileVer) in a
// frame: the single entry of a DATA frame, or the one entry of a PACKED
// frame with this path and file_ver (§9.1, offset 0, whole object).
func packedEntry(ref *blob.Ref, p string, fileVer uint64, l manifest.Loc) (wire.Entry, bool) {
	switch ref.Trailer.BlockType {
	case wire.BlockData:
		if len(ref.Entries) == 1 {
			e := ref.Entries[0]
			return e, e.Path == p && e.FileVer == fileVer && e.Offset == l.Offset && e.Length == l.Length
		}
	case wire.BlockPacked:
		if l.Offset != 0 {
			return wire.Entry{}, false
		}
		// entries are sorted by path and paths are unique (§8)
		i, found := slices.BinarySearchFunc(ref.Entries, p, func(e wire.Entry, p string) int { return strings.Compare(e.Path, p) })
		if found {
			e := ref.Entries[i]
			return e, e.FileVer == fileVer && e.Length == l.Length
		}
	}
	return wire.Entry{}, false
}

// slicePacked narrows a PACKED Ref's Payload to the object's bytes.
func slicePacked(ref *blob.Ref, p string, fileVer uint64, l manifest.Loc) {
	if ref.Trailer.BlockType == wire.BlockPacked {
		e, _ := packedEntry(ref, p, fileVer, l)
		ref.Payload = ref.Payload[e.Offset : e.Offset+e.Length]
	}
}

// read assembles a whole version (§9.2: order by logical_offset only).
// Extents are fetched and verified in parallel.
func (v *view) read(p string, ver *manifest.Version) ([]byte, error) {
	out := make([]byte, ver.Length)
	one := func(l manifest.Loc) error {
		ref, err := v.fetch(p, ver, l)
		if err != nil {
			return err
		}
		copy(out[l.Offset:], ref.Payload)
		ref.Release()
		return nil
	}
	workers := min(runtime.GOMAXPROCS(0), len(ver.Loc))
	if workers <= 1 {
		for _, l := range ver.Loc {
			if err := one(l); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	next := make(chan manifest.Loc)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			var first error
			for l := range next {
				if first == nil {
					first = one(l)
				}
			}
			errs <- first
		}()
	}
	for _, l := range ver.Loc {
		next <- l
	}
	close(next)
	var first error
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return nil, first
	}
	return out, nil
}

// Object reads one version lazily, frame by frame. It implements
// io.ReaderAt, io.Reader and io.Seeker; ReadAt is safe for concurrent use.
type Object struct {
	*io.SectionReader
	v    *view
	path string
	ver  *manifest.Version

	mu     sync.Mutex
	cur    *blob.Ref // last frame read (sequential reads hit it)
	at     int       // its extent index
	ahead  *prefetch // the next extent, fetched in the background
	closed bool
}

// prefetch is a background fetch of extent i.
type prefetch struct {
	i   int
	ch  chan fetched
	got *fetched
}

type fetched struct {
	ref *blob.Ref
	err error
}

func (f *prefetch) wait() fetched {
	if f.got == nil {
		r := <-f.ch
		f.got = &r
	}
	return *f.got
}

// drop releases a prefetch that will not be used.
func (f *prefetch) drop() {
	if r := f.wait(); r.ref != nil {
		r.ref.Release()
	}
}

// load returns extent i: the prefetched one when it matches, and starts
// fetching i+1 so sequential reads overlap I/O and hashing. o.mu is held.
func (o *Object) load(i int) (*blob.Ref, error) {
	var r fetched
	if o.ahead != nil && o.ahead.i == i {
		r = o.ahead.wait()
		o.ahead = nil
	} else {
		if o.ahead != nil {
			o.ahead.drop()
			o.ahead = nil
		}
		r.ref, r.err = o.v.fetch(o.path, o.ver, o.ver.Loc[i])
	}
	if r.err == nil && i+1 < len(o.ver.Loc) {
		f := &prefetch{i: i + 1, ch: make(chan fetched, 1)}
		l := o.ver.Loc[i+1]
		go func() {
			ref, err := o.v.fetch(o.path, o.ver, l)
			f.ch <- fetched{ref, err}
		}()
		o.ahead = f
	}
	return r.ref, r.err
}

func (v *view) object(p string, ver *manifest.Version) *Object {
	v.users.Add(1)
	o := &Object{v: v, path: p, ver: ver, at: -1}
	o.SectionReader = io.NewSectionReader(objectAt{o}, 0, int64(ver.Length))
	return o
}

// FileVer returns the version's file_ver.
func (o *Object) FileVer() uint64 { return o.ver.FileVer }

type objectAt struct{ o *Object }

func (a objectAt) ReadAt(b []byte, off int64) (int, error) {
	o := a.o
	if off < 0 {
		return 0, fmt.Errorf("%w: negative offset", wire.ErrInvalid)
	}
	n := 0
	for n < len(b) {
		pos := uint64(off) + uint64(n)
		if pos >= o.ver.Length {
			return n, io.EOF
		}
		// extents are sorted and contiguous: binary search by offset
		i := sort.Search(len(o.ver.Loc), func(i int) bool { return o.ver.Loc[i].Offset > pos }) - 1
		l := o.ver.Loc[i]
		o.mu.Lock()
		if o.at != i {
			if o.cur != nil {
				o.cur.Release()
				o.cur = nil
			}
			ref, err := o.load(i)
			if err != nil {
				o.at = -1
				o.mu.Unlock()
				return n, err
			}
			o.cur, o.at = ref, i
		}
		n += copy(b[n:], o.cur.Payload[pos-l.Offset:])
		o.mu.Unlock()
	}
	return n, nil
}

// Close releases the cached frame buffer.
func (o *Object) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cur != nil {
		o.cur.Release()
		o.cur, o.at = nil, -1
	}
	if o.ahead != nil {
		o.ahead.drop()
		o.ahead = nil
	}
	if !o.closed {
		o.closed = true
		if o.v.users.Add(-1) == 0 && o.v.retiredV.Load() {
			o.v.close()
		}
	}
	return nil
}

func checkPath(p string) error {
	if err := canonpath.Validate(p); err != nil {
		return fmt.Errorf("%w: %v", wire.ErrInvalid, err)
	}
	return nil
}

// Reader is a read-only snapshot of the current generation (§10.4.1
// reader snapshot). It takes no lock and never writes.
type Reader struct {
	view
	st       *manifest.State
	pin      *Pin
	memClose func() // releases the page cache and the scratch directory
	stEnv    *manifest.Env
}

// OpenReader opens the archive in fsys for reading, without a pin: a
// compaction's GC may remove the generation while it is read (on POSIX
// filesystems the open blob files stay readable).
func OpenReader(fsys vfs.FS, pool *bufpool.Pool) (*Reader, error) {
	root, err := readRoot(fsys)
	if err != nil {
		return nil, err
	}
	return openReaderAt(fsys, pool, root, 0, false, nil, memOpts{})
}

// ReaderOptions configure OpenReaderWith.
type ReaderOptions struct {
	Pool *bufpool.Pool
	// Pin registers a reader pin (§13.1.1) with PinTTL (0: default).
	Pin    bool
	PinTTL time.Duration
	// Anchor is required for a HARDENED archive (§11.8): the snapshot is
	// the anchored generation and manifest prefix; unanchored bytes are
	// never applied.
	Anchor anchor.Anchor
	// Key is the DEK of an encrypted archive.
	Key []byte
	// Policy is the expected security policy (§15A.2).
	Policy Policy
	// MemoryLimit bounds the archive-scale working state (index pages,
	// spills, validation sorts); 0 means 1 GiB.
	MemoryLimit int64
	// TempDir holds the reader's private scratch space, created only when
	// an index must spill (a rebuild or a large lag); "" is os.TempDir().
	// A reader never writes into the archive.
	TempDir string
}

// OpenReaderWith opens a read-only snapshot with options.
func OpenReaderWith(fsys vfs.FS, o ReaderOptions) (*Reader, error) {
	mo := memOpts{limit: o.MemoryLimit, tempDir: o.TempDir}
	if err := checkPolicy(context.Background(), fsys, o.Anchor, o.Policy); err != nil {
		return nil, err
	}
	if o.Anchor == nil {
		if o.Pin {
			return openReaderPinned(fsys, o.Pool, o.PinTTL, o.Key, mo)
		}
		root, err := readRoot(fsys)
		if err != nil {
			return nil, err
		}
		return openReaderAt(fsys, o.Pool, root, 0, false, o.Key, mo)
	}
	ctx := context.Background()
	root, st, err := resolveHardened(ctx, fsys, o.Anchor, o.Pool, false, o.Key)
	if err != nil {
		return nil, err
	}
	var pin *Pin
	if o.Pin {
		if pin, err = pinGeneration(fsys, root.GenerationID, o.PinTTL); err != nil {
			return nil, err
		}
		// re-check: a switch may have happened before the pin existed
		if again, err := loadAnchor(ctx, o.Anchor, root.ArchiveID); err != nil || again.GenerationID != st.GenerationID {
			pin.Release()
			if err == nil {
				err = fmt.Errorf("generation changed while pinning; retry")
			}
			return nil, err
		}
	}
	r, err := openReaderAt(fsys, o.Pool, root, int64(st.ManifestLength), true, o.Key, mo)
	if err != nil {
		pin.Release()
		return nil, err
	}
	r.pin = pin
	return r, nil
}

// OpenReaderPinned opens the archive for reading and pins the generation
// first (§13.1.1), so GC keeps it until Close. ttl <= 0 selects
// DefaultPinTTL; the pin is renewed in the background.
func OpenReaderPinned(fsys vfs.FS, pool *bufpool.Pool, ttl time.Duration) (*Reader, error) {
	return openReaderPinned(fsys, pool, ttl, nil, memOpts{})
}

func openReaderPinned(fsys vfs.FS, pool *bufpool.Pool, ttl time.Duration, dek []byte, mo memOpts) (*Reader, error) {
	for try := 0; ; try++ {
		root, err := readRoot(fsys)
		if err != nil {
			return nil, err
		}
		pin, err := pinGeneration(fsys, root.GenerationID, ttl)
		if err != nil {
			return nil, err
		}
		// the pin counts only if the generation was still current once
		// it existed: GC never removes the current generation
		again, err := readRoot(fsys)
		if err != nil || again.GenerationID != root.GenerationID {
			pin.Release()
			if err != nil {
				return nil, err
			}
			if try < 8 {
				continue
			}
			return nil, fmt.Errorf("generation keeps changing while pinning")
		}
		r, err := openReaderAt(fsys, pool, root, 0, false, dek, mo)
		if err != nil {
			pin.Release()
			return nil, err
		}
		r.pin = pin
		return r, nil
	}
}

// openReaderAt opens generation root.GenerationID; with limited, only
// manifest.jsonl[0:limit] is applied (a HARDENED reader snapshot, §10.4.1).
func openReaderAt(fsys vfs.FS, pool *bufpool.Pool, root wire.Root, limit int64, limited bool, dek []byte, mo memOpts) (*Reader, error) {
	if pool == nil {
		pool = bufpool.Default
	}
	gen := GenDir(root.GenerationID)
	h, err := readHeader(fsys, gen, root)
	if err != nil {
		return nil, err
	}
	k, err := archiveKeys(fsys, h, dek)
	if err != nil {
		return nil, err
	}
	env, envClose := readerEnv(mo.limit, mo.tempDir)
	senv, senvClose := stateEnv(env)
	cleanup := func() { senvClose(); envClose() }
	var st *manifest.State
	if limited && limit == 0 {
		st = manifest.NewState(h, manifest.DefaultLimits)
	} else {
		st, _, err = manifest.Load(fsys, gen, h, manifest.LoadOptions{Limit: limit, Crypto: manifestCrypto(h, k), Env: senv})
		if err != nil {
			cleanup()
			return nil, err
		}
	}
	r := &Reader{view: view{fsys: fsys, gen: gen, h: h, pool: pool, k: k, env: env, kv: senv.Table(), hints: st}, st: st, memClose: cleanup, stEnv: senv}
	if r.lost, err = openLostSet(fsys, k, root.GenerationID, false, r.kv); err != nil {
		st.Close()
		cleanup()
		return nil, err
	}
	if _, err := r.openBlobs(false, h.ParityScheme != wire.ParityNone); err != nil {
		r.close()
		st.Close()
		cleanup()
		return nil, err
	}
	return r, nil
}

// Unavailable lists the blobs that could not be opened, with the reason;
// their data is read through parity.
func (r *Reader) Unavailable() map[uint8]error { return r.unavailable }

// Header returns the archive header.
func (r *Reader) Header() *wire.ArchiveHeader { return r.h }

// List returns the live paths in bytewise order (all of them in memory;
// see Walk).
func (r *Reader) List() ([]string, error) { return r.st.Paths() }

// Walk calls fn for the live paths with prefix, in bytewise order from the
// first path >= start, until fn returns false. Memory does not depend on
// the number of paths.
func (r *Reader) Walk(prefix, start string, fn func(string, *manifest.Version) bool) error {
	return r.st.Walk(prefix, start, fn)
}

// Stat returns the current version of a path.
func (r *Reader) Stat(p string) (*manifest.Version, error) {
	v, ok, err := r.st.Lookup(p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, r.notFound(p)
	}
	return v, nil
}

// Get returns the content of the current version of p.
func (r *Reader) Get(p string) ([]byte, error) {
	v, err := r.Stat(p)
	if err != nil {
		return nil, err
	}
	return r.read(p, v)
}

// Open returns a lazy reader of the current version of p.
func (r *Reader) Open(p string) (*Object, error) {
	v, err := r.Stat(p)
	if err != nil {
		return nil, err
	}
	return r.object(p, v), nil
}

// Generation returns the generation the snapshot reads.
func (r *Reader) Generation() uint64 { return r.h.GenerationID }

// Close releases the files and the pin.
func (r *Reader) Close() error {
	r.close()
	if r.st != nil {
		r.st.Close()
	}
	if r.memClose != nil {
		r.memClose()
	}
	return r.pin.Release()
}

// notFound is the error of a path without a live version: an
// UNRECOVERABLE marker if one stands (never mistaken for a deletion),
// ErrNotFound otherwise.
func (v *view) notFound(p string) error {
	u, err := v.lost.lookup(p)
	if err != nil {
		return err
	}
	if u != nil {
		return u
	}
	return fmt.Errorf("%w: %s", ErrNotFound, p)
}
