package manifest

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"

	"crypto/sha256"

	"github.com/zeebo/blake3"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// ManifestName is the main journal of a generation directory.
const ManifestName = "manifest.jsonl"

// MaxLinkedManifests is MAX_LINKED_MANIFESTS.
const MaxLinkedManifests = 65535

// lineReader yields LF-terminated lines of a file with bounded memory.
type lineReader struct {
	f     vfs.File
	limit int64 // bytes of the file to read
	off   int64 // file offset of buf[start]
	buf   []byte
	start int
	n     int
	eof   bool
}

func newLineReader(f vfs.File, limit int64) *lineReader {
	return &lineReader{f: f, limit: limit, buf: make([]byte, 64<<10)}
}

// errTooLong reports an LF-terminated line over MaxLineBytes.
var errTooLong = errors.New("line too long")

// next returns the next line (without LF) and its start offset. At the end
// it returns io.EOF, with tail > 0 when unterminated bytes remain (a torn
// tail). The returned line is valid until the next call.
func (lr *lineReader) next() (line []byte, at int64, tail int64, err error) {
	scanned := 0 // bytes of the current line already checked for LF
	discarding := false
	var discarded int64
	for {
		if i := bytes.IndexByte(lr.buf[lr.start+scanned:lr.n], '\n'); i >= 0 {
			end := lr.start + scanned + i
			line, at = lr.buf[lr.start:end], lr.off
			lr.off += int64(end - lr.start + 1)
			lr.start = end + 1
			if discarding {
				return nil, at - discarded, 0, errTooLong
			}
			if len(line) > MaxLineBytes {
				return nil, at, 0, errTooLong
			}
			return line, at, 0, nil
		}
		scanned = lr.n - lr.start
		if lr.eof {
			return nil, lr.off - discarded, discarded + int64(lr.n-lr.start), io.EOF
		}
		// make room: compact, grow up to MaxLineBytes+1, or start discarding
		if lr.start > 0 {
			copy(lr.buf, lr.buf[lr.start:lr.n])
			lr.n -= lr.start
			lr.start = 0
		}
		if lr.n == len(lr.buf) {
			if len(lr.buf) <= MaxLineBytes {
				lr.buf = append(lr.buf, make([]byte, len(lr.buf))...)
			} else {
				// longer than any valid line: keep scanning for LF without
				// buffering (an LF makes it corrupt, EOF makes it torn)
				discarding = true
				discarded += int64(lr.n)
				lr.off += int64(lr.n)
				lr.n, scanned = 0, 0
			}
		}
		pos := lr.off + int64(lr.n)
		want := min(int64(len(lr.buf)-lr.n), lr.limit-pos)
		if want <= 0 {
			lr.eof = true
			continue
		}
		m, err := lr.f.ReadAt(lr.buf[lr.n:lr.n+int(want)], pos)
		lr.n += m
		if err == io.EOF || (err == nil && m == 0) {
			lr.eof = true
		} else if err != nil {
			return nil, 0, 0, err
		}
	}
}

// LoadOptions configures Load.
type LoadOptions struct {
	// Limit is the reader snapshot length of manifest.jsonl (§10.4.1); 0
	// means the whole file.
	Limit  int64
	Limits Limits
	// TrackRefs records loc references for State.BlobCommitted (writers).
	TrackRefs bool
}

// LoadInfo describes the main journal after Load.
type LoadInfo struct {
	// ValidEnd is the end of the last line kept; a writer truncates the
	// file to it before appending (§10.4.2).
	ValidEnd int64
	// Torn is the number of bytes in the torn tail (0 if none).
	Torn int64
	// TornReason says why the tail is torn ("unterminated", "NUL").
	TornReason string
	// Linked counts linked manifests merged.
	Linked int
}

type cursor struct {
	file   int
	name   string
	f      vfs.File
	lr     *lineReader
	rec    *Record
	last   uint64 // last seq of this file
	main   bool
	torn   *LoadInfo
	minSeq uint64 // records must be greater (LINK seq for linked files)
}

func (c *cursor) corrupt(at int64, format string, args ...any) error {
	return &wire.Error{Struct: "Manifest", Class: wire.ErrCorrupt, Detail: fmt.Sprintf("%s offset %d: ", c.name, at) + fmt.Sprintf(format, args...)}
}

// advance reads the next record into c.rec (nil at the end).
func (c *cursor) advance(encrypted bool) error {
	c.rec = nil
	line, at, tail, err := c.lr.next()
	switch {
	case err == io.EOF:
		if tail > 0 {
			if !c.main {
				return c.corrupt(at, "linked manifest ends without LF")
			}
			c.torn.ValidEnd, c.torn.Torn, c.torn.TornReason = at, tail, "unterminated"
		} else if c.main {
			c.torn.ValidEnd = at
		}
		return nil
	case err == errTooLong:
		return c.corrupt(at, "line exceeds MAX_MANIFEST_LINE_BYTES")
	case err != nil:
		return err
	}
	if c.main && bytes.IndexByte(line, 0) >= 0 {
		// A writer never emits NUL (JSON escapes it); NUL bytes are pages
		// of an append that never reached storage (§10.4.2).
		size, _ := c.f.Size()
		c.torn.ValidEnd, c.torn.Torn, c.torn.TornReason = at, min(size, c.lr.limit)-at, "NUL"
		return nil
	}
	r, err := DecodeLine(line, encrypted)
	if err != nil {
		return fmt.Errorf("%s offset %d: %w", c.name, at, err)
	}
	if r.Seq <= c.last || r.Seq <= c.minSeq {
		return c.corrupt(at, "seq %d not increasing in file", r.Seq)
	}
	c.last = r.Seq
	c.rec = r
	return nil
}

type cursorHeap []*cursor

func (h cursorHeap) Len() int           { return len(h) }
func (h cursorHeap) Less(i, j int) bool { return h[i].rec.Seq < h[j].rec.Seq }
func (h cursorHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *cursorHeap) Push(x any)        { *h = append(*h, x.(*cursor)) }
func (h *cursorHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// Load folds the manifest graph of the generation directory genDir
// (manifest.jsonl plus linked submanifests, merged by seq) into a State.
// A torn tail of manifest.jsonl is ignored and reported in LoadInfo; every
// other violation fails closed.
func Load(fsys vfs.FS, genDir string, h *wire.ArchiveHeader, opt LoadOptions) (*State, LoadInfo, error) {
	return LoadWith(fsys, genDir, h, opt, nil)
}

// LoadWith is Load with a callback invoked for every record after it was
// applied (for tests and tools).
func LoadWith(fsys vfs.FS, genDir string, h *wire.ArchiveHeader, opt LoadOptions, each func(*Record, int)) (*State, LoadInfo, error) {
	var info LoadInfo
	st := NewState(h, opt.Limits)
	if opt.TrackRefs {
		st.TrackRefs()
	}
	enc := h.Encrypted()
	mf, err := fsys.OpenFile(path.Join(genDir, ManifestName), os.O_RDONLY, 0)
	if err != nil {
		return nil, info, err
	}
	defer mf.Close()
	size, err := mf.Size()
	if err != nil {
		return nil, info, err
	}
	limit := size
	if opt.Limit > 0 {
		if opt.Limit > size {
			return nil, info, &wire.Error{Struct: "Manifest", Class: wire.ErrCorrupt, Detail: fmt.Sprintf("manifest is %d bytes, snapshot needs %d", size, opt.Limit)}
		}
		limit = opt.Limit
	}
	main := &cursor{file: 0, name: ManifestName, f: mf, lr: newLineReader(mf, limit), main: true, torn: &info}
	if err := main.advance(enc); err != nil {
		return nil, info, err
	}
	hp := &cursorHeap{}
	if main.rec != nil {
		heap.Push(hp, main)
	}
	linked := map[string]bool{}
	var closers []vfs.File
	defer func() {
		for _, f := range closers {
			f.Close()
		}
	}()
	for hp.Len() > 0 {
		c := (*hp)[0]
		r := c.rec
		if err := st.Apply(r, c.file); err != nil {
			return nil, info, fmt.Errorf("%s: %w", c.name, err)
		}
		if each != nil {
			each(r, c.file)
		}
		if r.Op == OpLinkManifest {
			if linked[r.Path] {
				return nil, info, c.corrupt(0, "%s linked twice", r.Path)
			}
			if len(linked) >= MaxLinkedManifests {
				return nil, info, &wire.Error{Struct: "Manifest", Class: wire.ErrResource, Detail: "more than MAX_LINKED_MANIFESTS"}
			}
			linked[r.Path] = true
			lc, err := openLinked(fsys, genDir, h, r, len(linked))
			if err != nil {
				return nil, info, err
			}
			closers = append(closers, lc.f)
			if err := lc.advance(enc); err != nil {
				return nil, info, err
			}
			if lc.rec != nil {
				heap.Push(hp, lc)
			}
			info.Linked++
		}
		if err := c.advance(enc); err != nil {
			return nil, info, err
		}
		if c.rec == nil {
			heap.Pop(hp)
		} else {
			heap.Fix(hp, 0)
		}
	}
	return st, info, nil
}

func newHash(id wire.HashID) hash.Hash {
	if id == wire.HashBLAKE3 {
		return blake3.New()
	}
	return sha256.New()
}

// openLinked verifies a linked manifest's digest and line count over its
// exact bytes (§10.6), then returns a cursor over its records.
func openLinked(fsys vfs.FS, genDir string, h *wire.ArchiveHeader, link *Record, n int) (*cursor, error) {
	name := path.Join(genDir, link.Path)
	f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("linked manifest %s: %w", link.Path, err)
	}
	size, err := f.Size()
	if err != nil {
		f.Close()
		return nil, err
	}
	hs := newHash(h.HashID)
	var lines uint64
	buf := make([]byte, 64<<10)
	for off := int64(0); off < size; {
		m, err := f.ReadAt(buf[:min(int64(len(buf)), size-off)], off)
		if m == 0 && err != nil {
			f.Close()
			return nil, err
		}
		hs.Write(buf[:m])
		lines += uint64(bytes.Count(buf[:m], []byte{'\n'}))
		off += int64(m)
	}
	bad := func(format string, args ...any) error {
		f.Close()
		return &wire.Error{Struct: "Manifest", Field: "LINK_MANIFEST", Class: wire.ErrCorrupt, Detail: link.Path + ": " + fmt.Sprintf(format, args...)}
	}
	if [32]byte(hs.Sum(nil)) != link.Hash {
		return nil, bad("digest mismatch")
	}
	if lines != link.Lines {
		return nil, bad("%d lines, LINK_MANIFEST says %d", lines, link.Lines)
	}
	return &cursor{file: n, name: link.Path, f: f, lr: newLineReader(f, size), minSeq: link.Seq}, nil
}
