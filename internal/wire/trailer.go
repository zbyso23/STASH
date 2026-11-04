package wire

import "encoding/binary"

// MasterTrailer is the 96-byte trailer at the end of every frame (§6.2).
// Flags and reserved bytes are always zero in wire 0x0006.
type MasterTrailer struct {
	HashID        HashID
	CodecID       CodecID
	BlockType     BlockType
	GroupID       uint32
	GroupIndex    uint8
	GroupK        uint8
	GroupM        uint8
	DataLen       uint32
	FrameQuanta   uint32
	ObjectID      [ObjectIDSize]byte
	LogicalOffset uint64
	LogicalLength uint64
	FrameOrdinal  uint64
	HashPayload   [HashSize]byte
}

// AppendBinary appends the 96 trailer bytes. Only identifiers are checked
// here; ValidateTrailer checks the semantic rules.
func (t *MasterTrailer) AppendBinary(dst []byte) ([]byte, error) {
	const st = "MasterTrailer"
	if !t.HashID.Valid() {
		return dst, errf(ErrInvalid, st, "hash_id", "0x%02x", uint8(t.HashID))
	}
	if !t.CodecID.Valid() {
		return dst, errf(ErrInvalid, st, "codec_id", "0x%02x", uint8(t.CodecID))
	}
	if !t.BlockType.Valid() {
		return dst, errf(ErrInvalid, st, "block_type", "%d", uint8(t.BlockType))
	}
	var b [MasterTrailerSize]byte
	copy(b[0:4], MagicMasterTrailer[:])
	b[4] = uint8(t.HashID)
	b[5] = uint8(t.CodecID)
	b[6] = uint8(t.BlockType)
	// b[7] flags zero
	binary.LittleEndian.PutUint32(b[8:12], t.GroupID)
	b[12] = t.GroupIndex
	b[13] = t.GroupK
	b[14] = t.GroupM
	// b[15] reserved zero
	binary.LittleEndian.PutUint32(b[16:20], t.DataLen)
	binary.LittleEndian.PutUint32(b[20:24], t.FrameQuanta)
	copy(b[24:40], t.ObjectID[:])
	binary.LittleEndian.PutUint64(b[40:48], t.LogicalOffset)
	binary.LittleEndian.PutUint64(b[48:56], t.LogicalLength)
	binary.LittleEndian.PutUint64(b[56:64], t.FrameOrdinal)
	copy(b[64:96], t.HashPayload[:])
	return append(dst, b[:]...), nil
}

// DecodeMasterTrailer parses 96 bytes and rejects reserved identifiers and
// non-zero flag/reserved bytes. The caller MUST have verified the outer
// Pre-Trailer CRC (§6.4.3) before trusting the result.
func DecodeMasterTrailer(b []byte) (MasterTrailer, error) {
	const st = "MasterTrailer"
	if len(b) != MasterTrailerSize {
		return MasterTrailer{}, errf(ErrCorrupt, st, "", "size %d", len(b))
	}
	if [4]byte(b[0:4]) != MagicMasterTrailer {
		return MasterTrailer{}, errf(ErrCorrupt, st, "magic", "%x", b[0:4])
	}
	if !HashID(b[4]).Valid() {
		return MasterTrailer{}, errf(ErrUnsupported, st, "hash_id", "0x%02x", b[4])
	}
	if !CodecID(b[5]).Valid() {
		return MasterTrailer{}, errf(ErrUnsupported, st, "codec_id", "0x%02x", b[5])
	}
	if !BlockType(b[6]).Valid() {
		return MasterTrailer{}, errf(ErrCorrupt, st, "block_type", "%d", b[6])
	}
	if b[7] != 0 {
		return MasterTrailer{}, errf(ErrCorrupt, st, "flags", "0x%02x", b[7])
	}
	if b[15] != 0 {
		return MasterTrailer{}, errf(ErrCorrupt, st, "reserved", "0x%02x", b[15])
	}
	return MasterTrailer{
		HashID:        HashID(b[4]),
		CodecID:       CodecID(b[5]),
		BlockType:     BlockType(b[6]),
		GroupID:       binary.LittleEndian.Uint32(b[8:12]),
		GroupIndex:    b[12],
		GroupK:        b[13],
		GroupM:        b[14],
		DataLen:       binary.LittleEndian.Uint32(b[16:20]),
		FrameQuanta:   binary.LittleEndian.Uint32(b[20:24]),
		ObjectID:      [16]byte(b[24:40]),
		LogicalOffset: binary.LittleEndian.Uint64(b[40:48]),
		LogicalLength: binary.LittleEndian.Uint64(b[48:56]),
		FrameOrdinal:  binary.LittleEndian.Uint64(b[56:64]),
		HashPayload:   [32]byte(b[64:96]),
	}, nil
}

// ValidateTrailer checks the trailer against its archive header and the
// already validated prefix: §2.3 hash agreement, §6.2 block-type rules,
// §6.6 placement, §6.6.1 ceiling, §6.6.2 STORE length for DATA, §7 parity
// invariants, §7.1 parity shard length. Pre-Trailer-dependent rules (PACKED
// length, exact payload budget) are checked when the Pre-Trailer is parsed.
func ValidateTrailer(t *MasterTrailer, h *ArchiveHeader, p FramePrefix) error {
	const st = "MasterTrailer"
	if t.HashID != h.HashID {
		return errf(ErrCorrupt, st, "hash_id", "trailer 0x%02x, header 0x%02x", uint8(t.HashID), uint8(h.HashID))
	}
	if t.FrameQuanta != p.FrameQuanta {
		return errf(ErrCorrupt, st, "frame_quanta", "trailer %d, prefix %d", t.FrameQuanta, p.FrameQuanta)
	}
	frameSize := uint64(p.FrameQuanta) * BaseQuantum
	if uint64(t.DataLen) > frameSize-FrameOverhead-MinParityPreTrailerLen {
		return errf(ErrCorrupt, st, "data_len", "%d exceeds frame budget %d", t.DataLen, frameSize-FrameOverhead-MinParityPreTrailerLen)
	}
	var zeroID [ObjectIDSize]byte
	switch t.BlockType {
	case BlockData:
		if t.ObjectID == zeroID {
			return errf(ErrCorrupt, st, "object_id", "zero for DATA")
		}
		if t.LogicalOffset%BaseQuantum != 0 {
			return errf(ErrCorrupt, st, "logical_offset", "%d not 4096-aligned", t.LogicalOffset)
		}
		if t.LogicalLength > h.MaxFrameSize() {
			return errf(ErrCorrupt, st, "logical_length", "%d > MAX_FRAME_SIZE %d", t.LogicalLength, h.MaxFrameSize())
		}
		if t.CodecID == CodecStore {
			want := t.LogicalLength
			if h.Encrypted() {
				want += AEADOverhead
			}
			if uint64(t.DataLen) != want {
				return errf(ErrCorrupt, st, "data_len", "STORE DATA has %d, want %d", t.DataLen, want)
			}
		}
	case BlockPacked, BlockParity:
		if t.ObjectID != zeroID || t.LogicalOffset != 0 || t.LogicalLength != 0 {
			return errf(ErrCorrupt, st, "object_id", "placement fields must be zero for block type %d", t.BlockType)
		}
	}
	if t.BlockType == BlockParity {
		if t.CodecID != CodecStore {
			return errf(ErrCorrupt, st, "codec_id", "PARITY must be STORE")
		}
		if uint64(t.DataLen) != frameSize-ParityShardOverhead {
			return errf(ErrCorrupt, st, "data_len", "PARITY shard %d, want %d", t.DataLen, frameSize-ParityShardOverhead)
		}
		if t.GroupID == 0 {
			return errf(ErrCorrupt, st, "group_id", "PARITY frame outside a group")
		}
	}
	return validateGroup(t, h)
}

func validateGroup(t *MasterTrailer, h *ArchiveHeader) error {
	const st = "MasterTrailer"
	if t.GroupID == 0 {
		if t.GroupIndex != 0 || t.GroupK != 0 || t.GroupM != 0 {
			return errf(ErrCorrupt, st, "group_index", "group fields must be zero when group_id is 0")
		}
		return nil
	}
	if h.ParityScheme == ParityNone {
		return errf(ErrCorrupt, st, "group_id", "%d in an archive without parity", t.GroupID)
	}
	if t.GroupK < 1 || t.GroupK > h.ParityK {
		return errf(ErrCorrupt, st, "group_k", "%d outside 1..%d", t.GroupK, h.ParityK)
	}
	if t.GroupM != h.ParityM {
		return errf(ErrCorrupt, st, "group_m", "%d, header %d", t.GroupM, h.ParityM)
	}
	if int(t.GroupIndex) >= int(t.GroupK)+int(t.GroupM) {
		return errf(ErrCorrupt, st, "group_index", "%d >= k+m %d", t.GroupIndex, int(t.GroupK)+int(t.GroupM))
	}
	isParity := t.BlockType == BlockParity
	if isParity != (t.GroupIndex >= t.GroupK) {
		return errf(ErrCorrupt, st, "group_index", "%d does not match block type %d (k=%d)", t.GroupIndex, t.BlockType, t.GroupK)
	}
	return nil
}
