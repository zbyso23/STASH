package archive

import (
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/canonpath"
	"stash/internal/index"
	"stash/internal/manifest"
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
	mu  sync.Mutex // guards idx
	idx *index.Index
	// defective is set when a lookup needed the fallback scan (§10.5.1).
	defective bool
}

// view is the read path shared by Reader and Writer.
type view struct {
	fsys  vfs.FS
	gen   string
	h     *wire.ArchiveHeader
	pool  *bufpool.Pool
	blobs []*blobView // nil entry: blob unavailable
	// unavailable records why a blob could not be opened (readers of a
	// parity archive continue without it, §7.4).
	unavailable map[uint8]error
	repairs
}

// openBlobs opens every blob and its index. With tolerate, a blob that
// cannot be opened is recorded as unavailable instead of failing (only
// useful when parity can stand in for it).
func (v *view) openBlobs(writeIndexes, tolerate bool) (statuses []index.Status, err error) {
	v.blobs = make([]*blobView, v.h.BlobCount)
	v.unavailable = map[uint8]error{}
	statuses = make([]index.Status, v.h.BlobCount)
	for b := range v.blobs {
		name, _ := blob.Name(uint8(b))
		r, err := blob.Open(v.fsys, path.Join(v.gen, name), v.h, v.pool)
		if err != nil {
			if tolerate && !errors.Is(err, wire.ErrUnsupported) {
				v.unavailable[uint8(b)] = err
				continue
			}
			return nil, fmt.Errorf("blob %02X: %w", b, err)
		}
		iname, _ := index.Name(uint8(b))
		x, st, err := index.Open(v.fsys, path.Join(v.gen, iname), r, v.h, uint8(b), v.pool)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("index %02X: %w", b, err)
		}
		if writeIndexes && (st.Rebuilt || st.CaughtUp > 0) {
			if err := x.Write(v.fsys, path.Join(v.gen, iname)); err != nil {
				r.Close()
				return nil, err
			}
		}
		statuses[b] = st
		v.blobs[b] = &blobView{r: r, idx: x}
	}
	return statuses, nil
}

func (v *view) close() {
	for _, b := range v.blobs {
		if b != nil {
			b.r.Close()
		}
	}
}

// fetch finds the frame of one extent (§9.1): through the index
// (candidates validated, fallback scan), carrying exactly this object's
// path, file_ver and placement. The Ref must be released.
func (v *view) fetch(p string, ver *manifest.Version, l manifest.Loc) (*blob.Ref, error) {
	if int(l.Blob) >= len(v.blobs) {
		return nil, fmt.Errorf("%w: blob %02X out of range", ErrMissingData, l.Blob)
	}
	accept := func(ref *blob.Ref) bool {
		if ref.Trailer.HashPayload != l.Hash || ref.Trailer.CodecID != wire.CodecStore {
			return false
		}
		_, ok := packedEntry(ref, p, ver.FileVer, l)
		return ok
	}
	if bv := v.blobs[l.Blob]; bv != nil {
		bv.mu.Lock()
		ref, how, err := bv.idx.Find(bv.r, l.Hash, accept)
		if how == index.ViaScan {
			bv.defective = true
		}
		bv.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if how != index.NotFound {
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
	slicePacked(ref, p, ver.FileVer, l)
	return ref, nil
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
func (v *view) read(p string, ver *manifest.Version) ([]byte, error) {
	out := make([]byte, ver.Length)
	for _, l := range ver.Loc {
		ref, err := v.fetch(p, ver, l)
		if err != nil {
			return nil, err
		}
		copy(out[l.Offset:], ref.Payload)
		ref.Release()
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

	mu  sync.Mutex
	cur *blob.Ref // last frame read (sequential reads hit it)
	at  int       // its extent index
}

func (v *view) object(p string, ver *manifest.Version) *Object {
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
			ref, err := o.v.fetch(o.path, o.ver, l)
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
	st *manifest.State
}

// OpenReader opens the archive in fsys for reading.
func OpenReader(fsys vfs.FS, pool *bufpool.Pool) (*Reader, error) {
	if pool == nil {
		pool = bufpool.Default
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
	st, _, err := manifest.Load(fsys, gen, h, manifest.LoadOptions{})
	if err != nil {
		return nil, err
	}
	r := &Reader{view: view{fsys: fsys, gen: gen, h: h, pool: pool}, st: st}
	if _, err := r.openBlobs(false, h.ParityScheme != wire.ParityNone); err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}

// Unavailable lists the blobs that could not be opened, with the reason;
// their data is read through parity.
func (r *Reader) Unavailable() map[uint8]error { return r.unavailable }

// Header returns the archive header.
func (r *Reader) Header() *wire.ArchiveHeader { return r.h }

// List returns the live paths in bytewise order.
func (r *Reader) List() []string { return r.st.Paths() }

// Stat returns the current version of a path.
func (r *Reader) Stat(p string) (*manifest.Version, error) {
	v, ok := r.st.Lookup(p)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p)
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

// Close releases the files.
func (r *Reader) Close() error {
	r.close()
	return nil
}
