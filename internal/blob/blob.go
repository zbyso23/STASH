// Package blob reads and appends frames of one blob file (SPEC §2.4, §3,
// §10.4, §10.4.2, §11.1-§11.3, §12.2).
//
// A blob is the 64-byte Archive Header followed by frames on the frame grid
// 0x40 + j*4096. Reading uses positional I/O through a pooled read-ahead
// window; appending serializes only the allocation of the next offset, so
// several goroutines can build and write frames of one blob in parallel.
package blob

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"stash/internal/bufpool"
	"stash/internal/compress"
	"stash/internal/frame"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// ErrSealed reports a blob that may no longer be truncated or appended to in
// this generation (§10.4.2).
var ErrSealed = errors.New("blob sealed")

// ErrPoisoned reports a writer that saw a write or sync failure. Its state
// on disk is unknown; the blob must be reopened, which re-runs torn-tail
// handling.
var ErrPoisoned = errors.New("blob writer failed earlier; reopen required")

// Name returns the normative blob file name below a generation directory.
func Name(ordinal uint8) (string, error) {
	if ordinal == 0xFF {
		return "", fmt.Errorf("%w: blob ordinal 0xFF", wire.ErrInvalid)
	}
	return fmt.Sprintf("frames/blob-%02X.stash", ordinal), nil
}

// Create creates a new, empty blob and makes it durable: header written,
// file synced, directory entry synced. It fails if the file exists.
func Create(fsys vfs.FS, name string, h *wire.ArchiveHeader) error {
	hb, err := h.AppendBinary(nil)
	if err != nil {
		return err
	}
	f, err := fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(hb, 0); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsys.SyncDir(path.Dir(name))
}

// checkHeader reads the blob header and requires it to describe the same
// archive and generation as want (§11.1).
func checkHeader(f vfs.File, want *wire.ArchiveHeader) error {
	var b [wire.ArchiveHeaderSize]byte
	if _, err := f.ReadAt(b[:], 0); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: blob shorter than its header", wire.ErrCorrupt)
		}
		return err
	}
	h, err := wire.DecodeArchiveHeader(b[:])
	if err != nil {
		return err
	}
	if h != *want {
		return fmt.Errorf("%w: blob header differs from the generation's archive header", wire.ErrCorrupt)
	}
	return nil
}

// Reader gives read access to the frames of one blob. It is safe for
// concurrent use.
type Reader struct {
	f    vfs.File
	h    *wire.ArchiveHeader
	k    *seal.Keys
	pool *bufpool.Pool
}

// Open opens a blob for reading and validates its header. Frames of an
// encrypted archive are parsed keyless (Pre-Trailers stay opaque).
func Open(fsys vfs.FS, name string, h *wire.ArchiveHeader, pool *bufpool.Pool) (*Reader, error) {
	return OpenKeyed(fsys, name, h, pool, nil)
}

// OpenKeyed is Open with the keys of an encrypted archive: Pre-Trailers
// are authenticated and decrypted by every read, and Ref.Decode can
// decrypt payloads.
func OpenKeyed(fsys vfs.FS, name string, h *wire.ArchiveHeader, pool *bufpool.Pool, k *seal.Keys) (*Reader, error) {
	f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	if err := checkHeader(f, h); err != nil {
		f.Close()
		return nil, err
	}
	if pool == nil {
		pool = bufpool.Default
	}
	return &Reader{f: f, h: h, k: k, pool: pool}, nil
}

// Keys returns the keys the reader was opened with (nil: keyless).
func (r *Reader) Keys() *seal.Keys { return r.k }

// Close closes the file.
func (r *Reader) Close() error { return r.f.Close() }

// Size returns the current blob size.
func (r *Reader) Size() (int64, error) { return r.f.Size() }

// Ref is a parsed frame whose Payload and PreTrailer alias a pooled buffer.
// Release returns the buffer; the Frame must not be used afterwards.
type Ref struct {
	*frame.Frame
	Offset int64
	buf    []byte
	pool   *bufpool.Pool
	h      *wire.ArchiveHeader
	k      *seal.Keys
	// decoded: Payload holds the logical bytes (Decode ran); extra are
	// pooled buffers holding them.
	decoded bool
	extra   [2][]byte
}

// Release returns the frame buffer to the pool. It is idempotent.
func (r *Ref) Release() {
	if r.buf != nil {
		r.pool.Put(r.buf)
		r.buf = nil
		r.Frame = nil
	}
	for i, b := range r.extra {
		if b != nil {
			r.pool.Put(b)
			r.extra[i] = nil
		}
	}
}

// Plain returns the payload plaintext of a DATA/PACKED frame: decrypted
// when the archive is encrypted, still compressed when codec_id is not
// STORE. It is valid until Release and must be called before Decode.
func (r *Ref) Plain() ([]byte, error) {
	if r.decoded {
		return nil, fmt.Errorf("%w: Plain after Decode", wire.ErrInvalid)
	}
	if !r.h.Encrypted() || r.Trailer.BlockType == wire.BlockParity {
		return r.Payload, nil
	}
	if r.extra[0] == nil {
		r.extra[0] = r.pool.Get(len(r.Payload))
		p, err := frame.OpenPayload(r.Frame, r.h, r.k, r.Bytes(), r.extra[0][:0])
		if err != nil {
			r.pool.Put(r.extra[0])
			r.extra[0] = nil
			return nil, err
		}
		r.extra[0] = p
	}
	return r.extra[0], nil
}

// Decode replaces Payload by the frame's logical bytes (§5.1): the payload
// is decrypted (encrypted archives) and decompressed with the validated
// logical length as the exact ceiling. For a plaintext STORE frame it does
// nothing. It is idempotent.
func (r *Ref) Decode() error {
	if r.decoded || r.Trailer.BlockType == wire.BlockParity {
		return nil
	}
	plain, err := r.Plain()
	if err != nil {
		return err
	}
	want, ok := r.LogicalLength()
	if !ok {
		return fmt.Errorf("%w: encrypted PACKED frame needs the keys", wire.ErrInvalid)
	}
	if r.Trailer.CodecID == wire.CodecStore {
		if uint64(len(plain)) != want {
			return fmt.Errorf("%w: STORE payload %d bytes, logical %d", wire.ErrCorrupt, len(plain), want)
		}
		r.Payload, r.decoded = plain, true
		return nil
	}
	if want > r.h.MaxFrameSize() {
		return fmt.Errorf("%w: logical length %d > MAX_FRAME_SIZE", wire.ErrCorrupt, want)
	}
	if err := compress.CheckFrame(plain, want, r.h.MaxFrameSize()); err != nil {
		return err // before the decompression buffer is allocated (§5.1.1)
	}
	b := r.pool.Get(int(want))
	out, err := compress.Decode(r.Trailer.CodecID, plain, want, r.h.MaxFrameSize(), b[:0])
	if err != nil {
		r.pool.Put(b)
		return err
	}
	r.extra[1] = out
	r.Payload, r.decoded = out, true
	return nil
}

// Bytes returns the frame's encoded bytes (valid until Release).
func (r *Ref) Bytes() []byte {
	return r.buf[:wire.FrameSize(r.Prefix.FrameQuanta)]
}

// NewRef validates a complete frame held in buf (taken from pool, and
// owned by the Ref afterwards) and wraps it as a Ref with offset -1, for
// frames that were rebuilt rather than read (§7.3).
func NewRef(buf []byte, h *wire.ArchiveHeader, pool *bufpool.Pool, k *seal.Keys) (*Ref, error) {
	fr, err := frame.ParseKeyed(buf, h, k)
	if err != nil {
		return nil, err
	}
	return &Ref{Frame: fr, Offset: -1, buf: buf, pool: pool, h: h, k: k}, nil
}

// ReadFrame reads and fully validates the frame at off (on the frame grid).
// The read size comes from a validated prefix and is bounded by the file
// size, so a corrupt prefix cannot force a large allocation.
func (r *Reader) ReadFrame(off int64) (*Ref, error) {
	size, err := r.f.Size()
	if err != nil {
		return nil, err
	}
	fsz, err := frameSizeAt(r.f, r.h, off, size)
	if err != nil {
		return nil, err
	}
	buf := r.pool.Get(int(fsz))
	if _, err := r.f.ReadAt(buf, off); err != nil {
		r.pool.Put(buf)
		return nil, err
	}
	fr, err := frame.ParseKeyed(buf, r.h, r.k)
	if err != nil {
		r.pool.Put(buf)
		return nil, err
	}
	return &Ref{Frame: fr, Offset: off, buf: buf, pool: r.pool, h: r.h, k: r.k}, nil
}

func frameSizeAt(f vfs.File, h *wire.ArchiveHeader, off, size int64) (int64, error) {
	if off < wire.FrameAreaStart || !wire.OnFrameGrid(uint64(off)) {
		return 0, fmt.Errorf("%w: offset %d is not on the frame grid", wire.ErrInvalid, off)
	}
	var pb [wire.FramePrefixSize]byte
	if off+wire.FramePrefixSize > size {
		return 0, fmt.Errorf("%w: no frame prefix at %d", wire.ErrCorrupt, off)
	}
	if _, err := f.ReadAt(pb[:], off); err != nil {
		return 0, err
	}
	p, err := wire.DecodeFramePrefix(pb[:], h)
	if err != nil {
		return 0, err
	}
	fsz := int64(wire.FrameSize(p.FrameQuanta))
	if off+fsz > size {
		return 0, fmt.Errorf("%w: frame at %d extends past end of blob", wire.ErrCorrupt, off)
	}
	return fsz, nil
}
