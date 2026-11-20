package recovery

import (
	"context"
	"fmt"
	"io"

	"stash/internal/archive"
	"stash/internal/blob"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// payloadOf reads the extent's frame again, validates it completely and
// returns the extent's bytes (copied).
func (rc *Recovery) payloadOf(v *Version, e Extent) ([]byte, error) {
	if v.Opaque {
		return nil, fmt.Errorf("%w: keyless recovery cannot decrypt", archive.ErrKeyRequired)
	}
	var ref *blob.Ref
	if e.FrameOffset >= 0 {
		var err error
		if ref, err = rc.readers[e.Blob].ReadFrame(e.FrameOffset); err != nil {
			return nil, err
		}
	} else {
		rebuilt, err := rc.rebuild(e.group)
		if err != nil {
			return nil, err
		}
		buf := rebuilt[e.index]
		if buf == nil {
			return nil, fmt.Errorf("%w: group %d member %d no longer rebuilds", archive.ErrMissingData, e.group, e.index)
		}
		if ref, err = blob.NewRef(append([]byte(nil), buf...), rc.h, rc.pool, rc.k); err != nil {
			return nil, err
		}
	}
	defer ref.Release()
	fr := ref.Frame
	if fr.Trailer.HashPayload != e.hash {
		return nil, fmt.Errorf("%w: frame changed since the scan", wire.ErrCorrupt)
	}
	entries := fr.Entries
	if err := ref.Decode(); err != nil { // decrypt, decompress (§5.1, §11.7)
		return nil, err
	}
	for _, en := range entries {
		if en.Path != v.Path || en.FileVer != v.FileVer {
			continue
		}
		switch fr.Trailer.BlockType {
		case wire.BlockPacked:
			return append([]byte(nil), ref.Payload[en.Offset:en.Offset+en.Length]...), nil
		case wire.BlockData:
			if en.Offset == e.Offset {
				return append([]byte(nil), ref.Payload...), nil
			}
		}
	}
	return nil, fmt.Errorf("%w: entry not in frame", wire.ErrCorrupt)
}

// Extract writes a complete version to w in logical order.
func (rc *Recovery) Extract(v *Version, w io.Writer) error {
	if !v.Complete {
		return fmt.Errorf("%w: %s v%d", ErrIncompleteVersion, v.Path, v.FileVer)
	}
	for _, e := range v.Extents {
		b, err := rc.payloadOf(v, e)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// ExtractAt writes every recoverable extent of v at its logical offset and
// returns the ranges it could not write (gaps and extents that failed to
// read). Missing ranges are left untouched, never zero-filled.
func (rc *Recovery) ExtractAt(v *Version, w io.WriterAt) ([]Range, error) {
	missing := append([]Range(nil), v.Gaps...)
	for _, e := range v.Extents {
		b, err := rc.payloadOf(v, e)
		if err != nil {
			missing = append(missing, Range{e.Offset, e.Length})
			continue
		}
		if _, err := w.WriteAt(b, int64(e.Offset)); err != nil {
			return missing, err
		}
	}
	return missing, nil
}

// Default selects what Salvage writes by default: when the whole manifest
// loaded, the current versions; otherwise, per path, the complete version
// with the highest file_ver (which may have been deleted or superseded;
// raw recovery cannot know, §11.2.2). It streams like All.
func (rc *Recovery) Default() Selection {
	all := rc.All()
	if rc.Manifest.Loaded {
		return func(fn func(*Version) bool) error {
			return all(func(v *Version) bool { return !(v.Current && v.Complete) || fn(v) })
		}
	}
	return func(fn func(*Version) bool) error {
		var best *Version // of the current path; versions arrive by file_ver
		more := true
		err := all(func(v *Version) bool {
			if best != nil && best.Path != v.Path {
				if more = fn(best); !more {
					return false
				}
				best = nil
			}
			if v.Complete {
				best = v
			}
			return true
		})
		if err == nil && more && best != nil {
			fn(best)
		}
		return err
	}
}

// SalvageResult describes a salvage.
type SalvageResult struct {
	Written int
	Bytes   int64
	// Failed lists the first maxFailedListed failures; FailedCount counts all.
	Failed      map[string]error
	FailedCount int
}

const maxFailedListed = 1000

// Salvage creates a new archive in dst with the source's parameters and
// writes the given versions into it as new versions of their paths.
func (rc *Recovery) Salvage(ctx context.Context, dst vfs.FS, sel Selection) (SalvageResult, error) {
	res := SalvageResult{Failed: map[string]error{}}
	if rc.Keyless {
		return res, fmt.Errorf("%w: salvage of an encrypted archive", archive.ErrKeyRequired)
	}
	cfg := archive.Config{Mode: rc.h.Mode, HashID: rc.h.HashID, BlobCount: rc.h.BlobCount, MaxFrameQuanta: rc.h.MaxFrameQuanta,
		ParityScheme: rc.h.ParityScheme, ParityK: rc.h.ParityK, ParityM: rc.h.ParityM, Codec: rc.h.CodecID, Key: rc.key}
	if _, err := archive.Create(dst, cfg); err != nil {
		return res, err
	}
	w, err := archive.OpenWriter(dst, archive.Options{Pool: rc.pool, Key: rc.key})
	if err != nil {
		return res, err
	}
	defer func() {
		if w != nil {
			w.Close()
		}
	}()
	var cerr error
	if err := sel(func(v *Version) bool {
		if cerr = ctx.Err(); cerr != nil {
			return false
		}
		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(rc.Extract(v, pw)) }()
		_, err := w.PutReader(ctx, v.Path, pr)
		pr.CloseWithError(err)
		if err != nil {
			if len(res.Failed) < maxFailedListed {
				res.Failed[v.Path] = err
			}
			res.FailedCount++
			return true
		}
		res.Written++
		res.Bytes += int64(v.End)
		return true
	}); err != nil {
		return res, err
	}
	if cerr != nil {
		return res, cerr
	}
	err = w.Close()
	w = nil
	return res, err
}
