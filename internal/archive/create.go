package archive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path"

	"stash/internal/alloc"
	"stash/internal/anchor"
	"stash/internal/blob"
	"stash/internal/manifest"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Config selects the archive parameters fixed at creation (§2.2).
type Config struct {
	Mode           wire.FrameSizeMode
	HashID         wire.HashID
	BlobCount      uint8
	MaxFrameQuanta uint32
	// Parity scheme and code (§7); zero values mean no parity.
	ParityScheme     wire.ParityScheme
	ParityK, ParityM uint8
	// Anchor creates a HARDENED archive (§2.1.2.1): generation 0 durable,
	// the policy marker, the anchor's initial state, then root.current.
	Anchor anchor.Anchor
}

// Create creates a new STANDARD archive in an empty directory (§2.1,
// §2.1.2.1 without the anchor step): archive_id from a CSPRNG, generation 0
// written completely and durably (allocators, blobs, empty manifest), and
// root.current last. A crash before the root write leaves ErrIncomplete,
// never a partially valid archive.
func Create(fsys vfs.FS, cfg Config) (*wire.ArchiveHeader, error) {
	if _, err := fsys.Stat(RootName); err == nil {
		return nil, fmt.Errorf("%w: archive already exists", fs.ErrExist)
	}
	if ents, err := fsys.ReadDir("."); err == nil {
		for _, e := range ents {
			if e.Name() != LockName {
				return nil, fmt.Errorf("%w: directory not empty (%s)", fs.ErrExist, e.Name())
			}
		}
	}
	h := &wire.ArchiveHeader{Mode: cfg.Mode, HashID: cfg.HashID, CodecID: wire.CodecStore,
		ParityScheme: cfg.ParityScheme, ParityK: cfg.ParityK, ParityM: cfg.ParityM, BlobCount: cfg.BlobCount, MaxFrameQuanta: cfg.MaxFrameQuanta}
	if h.MaxFrameQuanta < 2 {
		return nil, fmt.Errorf("%w: a writer must not create max_frame_quanta < 2 (§3.1)", wire.ErrInvalid)
	}
	if _, err := rand.Read(h.ArchiveID[:]); err != nil {
		return nil, err
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	if err := fsys.MkdirAll("alloc", 0o755); err != nil {
		return nil, err
	}
	gid := alloc.Identity{Kind: wire.AllocGeneration, ArchiveID: h.ArchiveID}
	if err := alloc.Create(fsys, alloc.FileName(wire.AllocGeneration, 0), gid); err != nil {
		return nil, err
	}
	ga, err := alloc.Open(fsys, alloc.FileName(wire.AllocGeneration, 0), gid, 0)
	if err != nil {
		return nil, err
	}
	if h.GenerationID, err = ga.Next(); err != nil {
		return nil, err
	}
	if h.GenerationID != 0 {
		return nil, fmt.Errorf("%w: first generation is %d", wire.ErrInvalid, h.GenerationID)
	}
	if err := alloc.Create(fsys, alloc.FileName(wire.AllocFileVer, 0), alloc.Identity{Kind: wire.AllocFileVer, ArchiveID: h.ArchiveID}); err != nil {
		return nil, err
	}
	if err := createGeneration(fsys, h); err != nil {
		return nil, err
	}
	if err := fsys.SyncDir("."); err != nil {
		return nil, err
	}
	root := wire.Root{GenerationID: h.GenerationID, ArchiveID: h.ArchiveID}
	rb := root.AppendBinary(nil)
	if cfg.Anchor != nil {
		if err := writePolicy(fsys, h.ArchiveID); err != nil {
			return nil, err
		}
		empty := sha256.Sum256(nil)
		st := anchor.State{ArchiveID: h.ArchiveID, GenerationID: h.GenerationID, RootDigest: anchor.RootDigest(rb), ManifestDigest: empty}
		if err := cfg.Anchor.Create(context.Background(), st); err != nil {
			return nil, err
		}
	}
	if err := vfs.ReplaceFile(fsys, RootName, rb); err != nil {
		return nil, err
	}
	return h, nil
}

// createGeneration writes an empty generation durably: per-generation
// allocators, blobs with headers, an empty manifest.
func createGeneration(fsys vfs.FS, h *wire.ArchiveHeader) error {
	gen := GenDir(h.GenerationID)
	for _, d := range []string{"alloc", "frames", "index", "submanifests"} {
		if err := fsys.MkdirAll(path.Join(gen, d), 0o755); err != nil {
			return err
		}
	}
	per := func(kind wire.AllocKind, b uint8) error {
		return alloc.Create(fsys, path.Join(gen, alloc.FileName(kind, b)),
			alloc.Identity{Kind: kind, Blob: b, GenerationID: h.GenerationID, ArchiveID: h.ArchiveID, Encrypted: h.Encrypted()})
	}
	if err := per(wire.AllocManifestSeq, 0); err != nil {
		return err
	}
	if h.ParityScheme != wire.ParityNone {
		if err := per(wire.AllocGroupID, 0); err != nil {
			return err
		}
	}
	for b := 0; b < int(h.BlobCount); b++ {
		if err := per(wire.AllocFrameOrdinal, uint8(b)); err != nil {
			return err
		}
		name, _ := blob.Name(uint8(b))
		if err := blob.Create(fsys, path.Join(gen, name), h); err != nil {
			return err
		}
	}
	mf, err := fsys.OpenFile(path.Join(gen, manifest.ManifestName), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if err := mf.Sync(); err != nil {
		mf.Close()
		return err
	}
	mf.Close()
	for _, d := range []string{gen, path.Join(gen, "alloc"), path.Join(gen, "frames"), path.Join(gen, "index"), path.Join(gen, "submanifests")} {
		if err := fsys.SyncDir(d); err != nil {
			return err
		}
	}
	return nil
}
