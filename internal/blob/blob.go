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
	"stash/internal/frame"
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
	pool *bufpool.Pool
}

// Open opens a blob for reading and validates its header.
func Open(fsys vfs.FS, name string, h *wire.ArchiveHeader, pool *bufpool.Pool) (*Reader, error) {
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
	return &Reader{f: f, h: h, pool: pool}, nil
}

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
}

// Release returns the frame buffer to the pool. It is idempotent.
func (r *Ref) Release() {
	if r.buf != nil {
		r.pool.Put(r.buf)
		r.buf = nil
		r.Frame = nil
	}
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
	fr, err := frame.Parse(buf, r.h)
	if err != nil {
		r.pool.Put(buf)
		return nil, err
	}
	return &Ref{Frame: fr, Offset: off, buf: buf, pool: r.pool}, nil
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
