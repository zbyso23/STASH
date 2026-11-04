package wire

import "encoding/binary"

// ArchiveHeader is the 64-byte header at offset 0 of every blob (§2.2).
type ArchiveHeader struct {
	Mode           FrameSizeMode
	HashID         HashID
	CodecID        CodecID // archive default
	ParityScheme   ParityScheme
	ParityK        uint8
	ParityM        uint8
	BlobCount      uint8
	Flags          uint8
	MaxFrameQuanta uint32
	GenerationID   uint64
	ArchiveID      [ArchiveIDSize]byte
}

// Encrypted reports the ENCRYPTED flag.
func (h *ArchiveHeader) Encrypted() bool { return h.Flags&HeaderFlagEncrypted != 0 }

// MaxFrameSize returns MAX_FRAME_SIZE in bytes (fits uint64 for every valid value).
func (h *ArchiveHeader) MaxFrameSize() uint64 { return uint64(h.MaxFrameQuanta) * BaseQuantum }

// Validate checks every rule of §2.2, §2.3, §3.1 and the header invariants of §7.
func (h *ArchiveHeader) Validate() error {
	const st = "ArchiveHeader"
	if !h.Mode.Valid() {
		return errf(ErrUnsupported, st, "frame_size_mode", "0x%02x", uint8(h.Mode))
	}
	if !h.HashID.Valid() {
		return errf(ErrUnsupported, st, "hash_id", "0x%02x", uint8(h.HashID))
	}
	if !h.CodecID.Valid() {
		return errf(ErrUnsupported, st, "codec_id", "0x%02x", uint8(h.CodecID))
	}
	if h.BlobCount == 0 {
		return errf(ErrCorrupt, st, "blob_count", "0")
	}
	if h.Flags&^HeaderFlagEncrypted != 0 {
		return errf(ErrCorrupt, st, "flags", "reserved bits 0x%02x", h.Flags)
	}
	if h.MaxFrameQuanta == 0 || h.MaxFrameQuanta > MaxMaxFrameQuanta {
		return errf(ErrCorrupt, st, "max_frame_quanta", "%d", h.MaxFrameQuanta)
	}
	return validateParityHeader(h.ParityScheme, h.ParityK, h.ParityM, h.BlobCount)
}

func validateParityHeader(p ParityScheme, k, m, blobs uint8) error {
	const st = "ArchiveHeader"
	switch p {
	case ParityNone:
		if k != 0 || m != 0 {
			return errf(ErrCorrupt, st, "parity_k", "NONE requires k=m=0, got k=%d m=%d", k, m)
		}
		return nil
	case ParityXOR:
		if k == 0 || m != 1 {
			return errf(ErrCorrupt, st, "parity_k", "XOR requires k>0 m=1, got k=%d m=%d", k, m)
		}
	case ParityRS:
		if k == 0 || m == 0 {
			return errf(ErrCorrupt, st, "parity_k", "RS requires k>0 m>0, got k=%d m=%d", k, m)
		}
	default:
		return errf(ErrUnsupported, st, "parity_scheme", "0x%02x", uint8(p))
	}
	if blobs < 2 {
		return errf(ErrCorrupt, st, "blob_count", "active parity requires >= 2 blobs, got %d", blobs)
	}
	if int(k)+int(m) > MaxParityShards {
		return errf(ErrCorrupt, st, "parity_m", "k+m=%d > 256", int(k)+int(m))
	}
	return nil
}

// AppendBinary appends the 64-byte encoding. It refuses invalid headers.
func (h *ArchiveHeader) AppendBinary(dst []byte) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return dst, err
	}
	var b [ArchiveHeaderSize]byte
	copy(b[0:4], MagicArchiveHeader[:])
	binary.LittleEndian.PutUint16(b[4:6], Version)
	b[6] = uint8(h.Mode)
	b[7] = uint8(h.HashID)
	b[8] = uint8(h.CodecID)
	b[9] = uint8(h.ParityScheme)
	b[10] = h.ParityK
	b[11] = h.ParityM
	b[12] = h.BlobCount
	b[13] = h.Flags
	binary.LittleEndian.PutUint16(b[14:16], ArchiveHeaderSize)
	binary.LittleEndian.PutUint32(b[16:20], h.MaxFrameQuanta)
	binary.LittleEndian.PutUint64(b[20:28], h.GenerationID)
	// b[28:32] reserved zero
	copy(b[32:64], h.ArchiveID[:])
	return append(dst, b[:]...), nil
}

// DecodeArchiveHeader parses and validates a header. b must hold at least 64
// bytes; only the first 64 are read.
func DecodeArchiveHeader(b []byte) (ArchiveHeader, error) {
	const st = "ArchiveHeader"
	var h ArchiveHeader
	if len(b) < 6 {
		return h, errf(ErrCorrupt, st, "", "truncated: %d bytes", len(b))
	}
	if [4]byte(b[0:4]) != MagicArchiveHeader {
		return h, errf(ErrCorrupt, st, "magic", "%x", b[0:4])
	}
	v := binary.LittleEndian.Uint16(b[4:6])
	if isLegacyVersion(v) {
		return h, errf(ErrLegacyVersion, st, "version", "0x%04x", v)
	}
	if v != Version {
		return h, errf(ErrUnsupported, st, "version", "0x%04x", v)
	}
	if len(b) < ArchiveHeaderSize {
		return h, errf(ErrCorrupt, st, "", "truncated: %d bytes", len(b))
	}
	if hs := binary.LittleEndian.Uint16(b[14:16]); hs != ArchiveHeaderSize {
		return h, errf(ErrCorrupt, st, "header_size", "%d", hs)
	}
	if !allZero(b[28:32]) {
		return h, errf(ErrCorrupt, st, "reserved", "%x", b[28:32])
	}
	h = ArchiveHeader{
		Mode:           FrameSizeMode(b[6]),
		HashID:         HashID(b[7]),
		CodecID:        CodecID(b[8]),
		ParityScheme:   ParityScheme(b[9]),
		ParityK:        b[10],
		ParityM:        b[11],
		BlobCount:      b[12],
		Flags:          b[13],
		MaxFrameQuanta: binary.LittleEndian.Uint32(b[16:20]),
		GenerationID:   binary.LittleEndian.Uint64(b[20:28]),
		ArchiveID:      [32]byte(b[32:64]),
	}
	if err := h.Validate(); err != nil {
		return ArchiveHeader{}, err
	}
	return h, nil
}

// SameArchive reports whether two headers agree on every immutable archive
// field (§2.2). GenerationID is not compared.
func (h *ArchiveHeader) SameArchive(o *ArchiveHeader) bool {
	a, b := *h, *o
	a.GenerationID, b.GenerationID = 0, 0
	return a == b
}
