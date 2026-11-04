// Package archive ties the pieces into an archive directory (SPEC §2.1):
// creation, the single writer, allocators, generation layout, and a first
// end-to-end Put/Get over plaintext DATA frames.
package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// Names of the normative layout (§2.1).
const (
	RootName = "root.current"
	LockName = "writer.lock"
)

// ErrIncomplete reports an archive directory whose creation did not finish
// (generation data exists but no root.current). A STANDARD archive in this
// state was never handed to anyone; delete the directory and create again.
var ErrIncomplete = errors.New("archive creation did not complete (no root.current)")

// GenDir returns generation-XXXXXXXXXXXXXXXX (16 uppercase hex digits).
func GenDir(id uint64) string { return fmt.Sprintf("generation-%016X", id) }

// ParseGenDir parses a generation directory name in its exact form; any
// other spelling is not a generation (§2.1).
func ParseGenDir(name string) (uint64, bool) {
	const p = "generation-"
	if len(name) != len(p)+16 || name[:len(p)] != p {
		return 0, false
	}
	for _, c := range name[len(p):] {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(name[len(p):], 16, 64)
	return v, err == nil
}

// generations lists the generation ids present as directories.
func generations(fsys vfs.FS) ([]uint64, error) {
	ents, err := fsys.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range ents {
		if id, ok := ParseGenDir(e.Name()); ok && e.IsDir() {
			out = append(out, id)
		}
	}
	return out, nil
}

func readRoot(fsys vfs.FS) (wire.Root, error) {
	b, err := vfs.ReadFile(fsys, RootName, wire.RootSize+1)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if gens, _ := generations(fsys); len(gens) > 0 {
				return wire.Root{}, ErrIncomplete
			}
		}
		return wire.Root{}, err
	}
	return wire.DecodeRoot(b)
}

// readHeader reads the Archive Header from blob 00 of a generation and
// checks it against the root (§11.1). Every blob is checked again when it
// is opened.
func readHeader(fsys vfs.FS, gen string, root wire.Root) (*wire.ArchiveHeader, error) {
	f, err := fsys.OpenFile(path.Join(gen, "frames/blob-00.stash"), 0, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hb [wire.ArchiveHeaderSize]byte
	if _, err := f.ReadAt(hb[:], 0); err != nil {
		return nil, fmt.Errorf("blob 00 header: %w", err)
	}
	h, err := wire.DecodeArchiveHeader(hb[:])
	if err != nil {
		return nil, err
	}
	if h.GenerationID != root.GenerationID || h.ArchiveID != root.ArchiveID {
		return nil, fmt.Errorf("%w: blob header does not match root.current", wire.ErrCorrupt)
	}
	return &h, nil
}
