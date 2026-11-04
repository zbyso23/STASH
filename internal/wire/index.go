package wire

import "encoding/binary"

// IndexHeader is the 64-byte physical index header (§10.5).
type IndexHeader struct {
	GenerationID uint64
	ArchiveID    [ArchiveIDSize]byte
	BlobOrdinal  uint8
	HashID       HashID
	RecordCount  uint64
}

// AppendBinary appends the 64 header bytes.
func (x *IndexHeader) AppendBinary(dst []byte) ([]byte, error) {
	if !x.HashID.Valid() {
		return dst, errf(ErrInvalid, "IndexHeader", "hash_id", "0x%02x", uint8(x.HashID))
	}
	if x.BlobOrdinal > MaxBlobOrdinal {
		return dst, errf(ErrInvalid, "IndexHeader", "blob_ordinal", "0x%02x", x.BlobOrdinal)
	}
	var b [IndexHeaderSize]byte
	copy(b[0:8], MagicIndex[:])
	binary.LittleEndian.PutUint16(b[8:10], Version)
	binary.LittleEndian.PutUint16(b[10:12], IndexHeaderSize)
	binary.LittleEndian.PutUint64(b[12:20], x.GenerationID)
	copy(b[20:52], x.ArchiveID[:])
	b[52] = x.BlobOrdinal
	b[53] = uint8(x.HashID)
	binary.LittleEndian.PutUint16(b[54:56], IndexRecordSize)
	binary.LittleEndian.PutUint64(b[56:64], x.RecordCount)
	return append(dst, b[:]...), nil
}

// DecodeIndexHeader parses 64 bytes. Identity matching against the blob and
// the file-size check (§10.5.1) are the caller's job.
func DecodeIndexHeader(b []byte) (IndexHeader, error) {
	const st = "IndexHeader"
	if len(b) != IndexHeaderSize {
		return IndexHeader{}, errf(ErrCorrupt, st, "", "size %d", len(b))
	}
	if [8]byte(b[0:8]) != MagicIndex {
		return IndexHeader{}, errf(ErrCorrupt, st, "magic", "%x", b[0:8])
	}
	if v := binary.LittleEndian.Uint16(b[8:10]); v != Version {
		return IndexHeader{}, errf(ErrUnsupported, st, "version", "0x%04x", v)
	}
	if s := binary.LittleEndian.Uint16(b[10:12]); s != IndexHeaderSize {
		return IndexHeader{}, errf(ErrCorrupt, st, "header_size", "%d", s)
	}
	if s := binary.LittleEndian.Uint16(b[54:56]); s != IndexRecordSize {
		return IndexHeader{}, errf(ErrCorrupt, st, "record_size", "%d", s)
	}
	if b[52] > MaxBlobOrdinal {
		return IndexHeader{}, errf(ErrCorrupt, st, "blob_ordinal", "0x%02x", b[52])
	}
	if !HashID(b[53]).Valid() {
		return IndexHeader{}, errf(ErrCorrupt, st, "hash_id", "0x%02x", b[53])
	}
	return IndexHeader{
		GenerationID: binary.LittleEndian.Uint64(b[12:20]),
		ArchiveID:    [32]byte(b[20:52]),
		BlobOrdinal:  b[52],
		HashID:       HashID(b[53]),
		RecordCount:  binary.LittleEndian.Uint64(b[56:64]),
	}, nil
}

// IndexRecord is one 64-byte index record (§10.5).
type IndexRecord struct {
	FrameHash      [HashSize]byte
	PhysicalOffset uint64
	FrameQuanta    uint32
	BlockType      BlockType
	FrameOrdinal   uint64
}

// AppendBinary appends the 64 record bytes.
func (r *IndexRecord) AppendBinary(dst []byte) ([]byte, error) {
	if !r.BlockType.Valid() {
		return dst, errf(ErrInvalid, "IndexRecord", "block_type", "%d", r.BlockType)
	}
	var b [IndexRecordSize]byte
	copy(b[0:32], r.FrameHash[:])
	binary.LittleEndian.PutUint64(b[32:40], r.PhysicalOffset)
	binary.LittleEndian.PutUint32(b[40:44], r.FrameQuanta)
	b[44] = uint8(r.BlockType)
	binary.LittleEndian.PutUint64(b[48:56], r.FrameOrdinal)
	return append(dst, b[:]...), nil
}

// DecodeIndexRecord parses one record and checks block type, reserved bytes,
// frame-grid placement and the quanta bound against the header (§10.5.1).
// The blob-size bound and sort order are checked by the index reader.
func DecodeIndexRecord(b []byte, h *ArchiveHeader) (IndexRecord, error) {
	const st = "IndexRecord"
	if len(b) != IndexRecordSize {
		return IndexRecord{}, errf(ErrCorrupt, st, "", "size %d", len(b))
	}
	if !BlockType(b[44]).Valid() {
		return IndexRecord{}, errf(ErrCorrupt, st, "block_type", "%d", b[44])
	}
	if !allZero(b[45:48]) || !allZero(b[56:64]) {
		return IndexRecord{}, errf(ErrCorrupt, st, "reserved", "non-zero")
	}
	r := IndexRecord{
		FrameHash:      [32]byte(b[0:32]),
		PhysicalOffset: binary.LittleEndian.Uint64(b[32:40]),
		FrameQuanta:    binary.LittleEndian.Uint32(b[40:44]),
		BlockType:      BlockType(b[44]),
		FrameOrdinal:   binary.LittleEndian.Uint64(b[48:56]),
	}
	if !OnFrameGrid(r.PhysicalOffset) {
		return IndexRecord{}, errf(ErrCorrupt, st, "physical_offset", "%d not on frame grid", r.PhysicalOffset)
	}
	if err := CheckFrameQuanta(r.FrameQuanta, h); err != nil {
		return IndexRecord{}, err
	}
	return r, nil
}
