package wire

import "encoding/binary"

// FramePrefix is the 16-byte prefix of every frame (§6.1). Flags are always
// zero in wire 0x0006, so only FrameQuanta is carried.
type FramePrefix struct {
	FrameQuanta uint32
}

// prefixCRC is CRC32C(magic || frame_quanta || flags), skipping the CRC field.
func prefixCRC(b []byte) uint32 { return CRC32C(b[0:8], b[12:16]) }

// AppendBinary appends the 16 prefix bytes.
func (p FramePrefix) AppendBinary(dst []byte) ([]byte, error) {
	if p.FrameQuanta == 0 || p.FrameQuanta > MaxMaxFrameQuanta {
		return dst, errf(ErrInvalid, "FramePrefix", "frame_quanta", "%d", p.FrameQuanta)
	}
	var b [FramePrefixSize]byte
	copy(b[0:4], MagicFramePrefix[:])
	binary.LittleEndian.PutUint32(b[4:8], p.FrameQuanta)
	binary.LittleEndian.PutUint32(b[8:12], prefixCRC(b[:]))
	return append(dst, b[:]...), nil
}

// DecodeFramePrefix validates magic, CRC, flags and the quanta bound against
// the archive header before any frame-sized allocation (§6.1, §11.2).
func DecodeFramePrefix(b []byte, h *ArchiveHeader) (FramePrefix, error) {
	const st = "FramePrefix"
	if len(b) < FramePrefixSize {
		return FramePrefix{}, errf(ErrCorrupt, st, "", "truncated: %d bytes", len(b))
	}
	if [4]byte(b[0:4]) != MagicFramePrefix {
		return FramePrefix{}, errf(ErrCorrupt, st, "magic", "%x", b[0:4])
	}
	if got, want := binary.LittleEndian.Uint32(b[8:12]), prefixCRC(b); got != want {
		return FramePrefix{}, errf(ErrCorrupt, st, "prefix_crc32c", "got %08x want %08x", got, want)
	}
	if f := binary.LittleEndian.Uint32(b[12:16]); f != 0 {
		return FramePrefix{}, errf(ErrCorrupt, st, "flags", "0x%08x", f)
	}
	q := binary.LittleEndian.Uint32(b[4:8])
	if err := CheckFrameQuanta(q, h); err != nil {
		return FramePrefix{}, err
	}
	return FramePrefix{FrameQuanta: q}, nil
}

// CheckFrameQuanta enforces 1 <= q <= max_frame_quanta and the FIXED rule.
func CheckFrameQuanta(q uint32, h *ArchiveHeader) error {
	const st = "Frame"
	if q == 0 || q > h.MaxFrameQuanta {
		return errf(ErrCorrupt, st, "frame_quanta", "%d outside 1..%d", q, h.MaxFrameQuanta)
	}
	if h.Mode == ModeFixed && q != h.MaxFrameQuanta {
		return errf(ErrCorrupt, st, "frame_quanta", "FIXED frame has %d quanta, want %d", q, h.MaxFrameQuanta)
	}
	return nil
}
