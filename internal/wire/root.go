package wire

import "encoding/binary"

// Root is root.current (§2.1.1). Every byte is determined by these fields.
type Root struct {
	GenerationID uint64
	ArchiveID    [ArchiveIDSize]byte
}

// AppendBinary appends the exact 64 root bytes.
func (r *Root) AppendBinary(dst []byte) []byte {
	var b [RootSize]byte
	copy(b[0:8], MagicRoot[:])
	binary.LittleEndian.PutUint16(b[8:10], Version)
	binary.LittleEndian.PutUint16(b[10:12], RootSize)
	binary.LittleEndian.PutUint64(b[12:20], r.GenerationID)
	copy(b[20:52], r.ArchiveID[:])
	// flags b[52:56] zero, crc b[56:60], reserved b[60:64] zero
	binary.LittleEndian.PutUint32(b[56:60], crcWithZeroField(b[:], 56))
	return append(dst, b[:]...)
}

// DecodeRoot parses and validates exactly 64 bytes.
func DecodeRoot(b []byte) (Root, error) {
	const st = "Root"
	if len(b) != RootSize {
		return Root{}, errf(ErrCorrupt, st, "", "size %d", len(b))
	}
	if [8]byte(b[0:8]) != MagicRoot {
		return Root{}, errf(ErrCorrupt, st, "magic", "%x", b[0:8])
	}
	if got, want := binary.LittleEndian.Uint32(b[56:60]), crcWithZeroField(b, 56); got != want {
		return Root{}, errf(ErrCorrupt, st, "root_crc32c", "got %08x want %08x", got, want)
	}
	if v := binary.LittleEndian.Uint16(b[8:10]); v != Version {
		return Root{}, errf(ErrUnsupported, st, "version", "0x%04x", v)
	}
	if s := binary.LittleEndian.Uint16(b[10:12]); s != RootSize {
		return Root{}, errf(ErrCorrupt, st, "root_size", "%d", s)
	}
	if !allZero(b[52:56]) {
		return Root{}, errf(ErrCorrupt, st, "flags", "%x", b[52:56])
	}
	if !allZero(b[60:64]) {
		return Root{}, errf(ErrCorrupt, st, "reserved", "%x", b[60:64])
	}
	return Root{GenerationID: binary.LittleEndian.Uint64(b[12:20]), ArchiveID: [32]byte(b[20:52])}, nil
}
