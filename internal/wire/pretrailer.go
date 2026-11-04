package wire

import (
	"encoding/binary"

	"stash/internal/canonpath"
)

// Entry is one Pre-Trailer entry (§6.4.2). For DATA, Offset and Length are
// logical_offset/logical_length; for PACKED they are inner_offset/inner_length.
type Entry struct {
	Path    string
	Offset  uint64
	Length  uint64
	FileVer uint64
}

// AppendEntries appends the plaintext entry list (entry_count and entries)
// without the outer CRC. The same bytes are the AEAD plaintext of an
// encrypted Pre-Trailer (§6.4.3). Paths must already be canonical.
func AppendEntries(dst []byte, entries []Entry) ([]byte, error) {
	if len(entries) > MaxPackedEntries {
		return dst, errf(ErrInvalid, "PreTrailer", "entry_count", "%d", len(entries))
	}
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(entries)))
	for i := range entries {
		e := &entries[i]
		if err := canonpath.Validate(e.Path); err != nil {
			return dst, errf(ErrInvalid, "PreTrailer", "path", "%v", err)
		}
		var err error
		if dst, err = AppendPathLen(dst, len(e.Path)); err != nil {
			return dst, err
		}
		dst = append(dst, e.Path...)
		dst = binary.LittleEndian.AppendUint64(dst, e.Offset)
		dst = binary.LittleEndian.AppendUint64(dst, e.Length)
		dst = binary.LittleEndian.AppendUint64(dst, e.FileVer)
	}
	return dst, nil
}

// DecodeEntries parses exactly one entry list occupying all of b. The number
// of entries is bounded both by MAX_PACKED_ENTRIES and by the input length
// before anything is allocated (§16.1).
func DecodeEntries(b []byte) ([]Entry, error) {
	const st = "PreTrailer"
	if len(b) < 4 {
		return nil, errf(ErrCorrupt, st, "entry_count", "truncated")
	}
	n := binary.LittleEndian.Uint32(b)
	if n > MaxPackedEntries {
		return nil, errf(ErrCorrupt, st, "entry_count", "%d > %d", n, MaxPackedEntries)
	}
	const minEntry = 1 + 1 + 24
	if uint64(n)*minEntry > uint64(len(b)-4) {
		return nil, errf(ErrCorrupt, st, "entry_count", "%d entries cannot fit in %d bytes", n, len(b)-4)
	}
	entries := make([]Entry, 0, n)
	p := b[4:]
	for i := uint32(0); i < n; i++ {
		l, used, err := DecodePathLen(p)
		if err != nil {
			return nil, err
		}
		p = p[used:]
		if len(p) < l+24 {
			return nil, errf(ErrCorrupt, st, "entry", "entry %d truncated", i)
		}
		path := string(p[:l])
		if err := canonpath.Validate(path); err != nil {
			return nil, errf(ErrCorrupt, st, "path", "entry %d: %v", i, err)
		}
		p = p[l:]
		entries = append(entries, Entry{
			Path:    path,
			Offset:  binary.LittleEndian.Uint64(p[0:8]),
			Length:  binary.LittleEndian.Uint64(p[8:16]),
			FileVer: binary.LittleEndian.Uint64(p[16:24]),
		})
		p = p[24:]
	}
	if len(p) != 0 {
		return nil, errf(ErrCorrupt, st, "entry", "%d trailing bytes", len(p))
	}
	return entries, nil
}
