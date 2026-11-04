package wire

import "encoding/binary"

// AllocState is a 64-byte Allocator State file (§2.1.3).
type AllocState struct {
	Kind            AllocKind
	BlobOrdinal     uint8  // kind 3 only
	GenerationID    uint64 // kinds 2, 3, 4 only
	ReservedThrough uint64
	ArchiveID       [ArchiveIDSize]byte
}

// Validate checks the kind and zero-field rules.
func (a *AllocState) Validate() error {
	const st = "AllocState"
	if !a.Kind.Valid() {
		return errf(ErrUnsupported, st, "kind", "%d", a.Kind)
	}
	if a.Kind == AllocFrameOrdinal {
		if a.BlobOrdinal > MaxBlobOrdinal {
			return errf(ErrCorrupt, st, "blob_ordinal", "0x%02x", a.BlobOrdinal)
		}
	} else if a.BlobOrdinal != 0 {
		return errf(ErrCorrupt, st, "blob_ordinal", "must be zero for kind %d", a.Kind)
	}
	if !a.Kind.PerGeneration() && a.GenerationID != 0 {
		return errf(ErrCorrupt, st, "generation_id", "must be zero for kind %d", a.Kind)
	}
	return nil
}

// AppendBinary appends the 64 bytes.
func (a *AllocState) AppendBinary(dst []byte) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return dst, err
	}
	var b [AllocStateSize]byte
	copy(b[0:8], MagicAllocState[:])
	binary.LittleEndian.PutUint16(b[8:10], Version)
	b[10] = uint8(a.Kind)
	b[11] = a.BlobOrdinal
	binary.LittleEndian.PutUint64(b[16:24], a.GenerationID)
	binary.LittleEndian.PutUint64(b[24:32], a.ReservedThrough)
	copy(b[32:64], a.ArchiveID[:])
	binary.LittleEndian.PutUint32(b[12:16], crcWithZeroField(b[:], 12))
	return append(dst, b[:]...), nil
}

// DecodeAllocState parses and validates exactly 64 bytes (§2.1.3.3). Matching
// archive_id, generation and blob ordinal against the file location is the
// caller's job.
func DecodeAllocState(b []byte) (AllocState, error) {
	const st = "AllocState"
	if len(b) != AllocStateSize {
		return AllocState{}, errf(ErrCorrupt, st, "", "size %d", len(b))
	}
	if [8]byte(b[0:8]) != MagicAllocState {
		return AllocState{}, errf(ErrCorrupt, st, "magic", "%x", b[0:8])
	}
	if got, want := binary.LittleEndian.Uint32(b[12:16]), crcWithZeroField(b, 12); got != want {
		return AllocState{}, errf(ErrCorrupt, st, "alloc_crc32c", "got %08x want %08x", got, want)
	}
	if v := binary.LittleEndian.Uint16(b[8:10]); v != Version {
		return AllocState{}, errf(ErrUnsupported, st, "version", "0x%04x", v)
	}
	a := AllocState{
		Kind:            AllocKind(b[10]),
		BlobOrdinal:     b[11],
		GenerationID:    binary.LittleEndian.Uint64(b[16:24]),
		ReservedThrough: binary.LittleEndian.Uint64(b[24:32]),
		ArchiveID:       [32]byte(b[32:64]),
	}
	if err := a.Validate(); err != nil {
		return AllocState{}, err
	}
	return a, nil
}
