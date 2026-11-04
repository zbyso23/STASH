// Package frame builds and parses complete physical frames (SPEC §6) on top
// of the fixed-size codecs in internal/wire.
//
// This milestone covers plaintext frames of every block type in both
// geometry modes. Encrypted DATA/PACKED frames are parsed structurally
// (keyless, §15.10): the Pre-Trailer stays opaque. Encryption and payload
// decompression arrive in later milestones.
package frame

import (
	"encoding/binary"
	"fmt"
	"slices"

	"stash/internal/canonpath"
	"stash/internal/checked"
	"stash/internal/ident"
	"stash/internal/wire"
)

// Spec describes a plaintext frame to build.
type Spec struct {
	BlockType wire.BlockType
	Codec     wire.CodecID
	// Payload is the exact stored payload representation (already
	// compressed when Codec is not STORE).
	Payload []byte
	// Entries: DATA exactly 1 (offset/length are logical_offset/length);
	// PACKED 1..65535 sorted by path; PARITY none.
	Entries []wire.Entry
	// Parity group membership; zero GroupID means no group.
	GroupID    uint32
	GroupIndex uint8
	GroupK     uint8
	GroupM     uint8
	// FrameOrdinal comes from the namespace allocator (§12.2).
	FrameOrdinal uint64
	// FrameQuanta: 0 selects the smallest size in VARIABLE mode; FIXED
	// always uses max_frame_quanta.
	FrameQuanta uint32
}

// Frame is a parsed and validated frame.
type Frame struct {
	Prefix  wire.FramePrefix
	Trailer wire.MasterTrailer
	Payload []byte // aliases the input
	// Entries is nil for encrypted DATA/PACKED frames, whose Pre-Trailer
	// is opaque without the key.
	Entries []wire.Entry
	// PreTrailer is the stored body including the outer CRC (aliases input).
	PreTrailer []byte
	// PackedLength is packed_logical_length for plaintext PACKED frames.
	PackedLength uint64
}

func errf(class error, field, format string, args ...any) error {
	return &wire.Error{Struct: "Frame", Field: field, Class: class, Detail: fmt.Sprintf(format, args...)}
}

// RequiredQuanta returns the smallest frame_quanta that holds the payload and
// Pre-Trailer, reserving the 112-byte parity padding when the frame belongs
// to a parity group (§6.3, §7.2).
func RequiredQuanta(dataLen, preTrailerLen uint64, parity bool) (uint32, error) {
	pad := uint64(0)
	if parity {
		pad = wire.MinParityPadding
	}
	need, err := checked.Sum64(wire.FrameOverhead, dataLen, preTrailerLen, pad)
	if err != nil {
		return 0, err
	}
	q := (need + wire.BaseQuantum - 1) / wire.BaseQuantum
	if q > wire.MaxMaxFrameQuanta {
		return 0, errf(wire.ErrResource, "frame_quanta", "%d bytes need %d quanta", need, q)
	}
	return uint32(q), nil
}

// Build encodes a complete plaintext frame into a new slice.
func Build(h *wire.ArchiveHeader, s *Spec) ([]byte, error) { return AppendFrame(nil, h, s) }

// AppendFrame appends a complete plaintext frame to dst and returns the
// extended slice. With enough capacity in dst (for example a pooled buffer
// of FrameSize bytes) it performs no heap allocation for DATA and PARITY
// frames. Every byte of the frame is written explicitly, including zero
// padding, so a reused buffer never leaks old content. On error dst is
// returned with its original length.
//
// The archive must be unencrypted; encrypted frames are built by the
// crypto layer.
func AppendFrame(dst []byte, h *wire.ArchiveHeader, s *Spec) ([]byte, error) {
	if h.Encrypted() {
		return dst, errf(wire.ErrInvalid, "", "encrypted frames are built by the crypto layer")
	}
	if err := checkEntriesForBuild(h, s); err != nil {
		return dst, err
	}
	start := len(dst)
	// The entry list is encoded in place at the end of dst first; once the
	// layout is known it is moved to its final position.
	out, err := wire.AppendEntries(dst, s.Entries)
	if err != nil {
		return dst[:start], err
	}
	bodyLen := uint64(len(out) - start)
	ptLen := bodyLen + 4
	q, err := chooseQuanta(h, s, ptLen)
	if err != nil {
		return dst[:start], err
	}
	if uint64(len(s.Payload)) > 0xFFFFFFFF {
		return dst[:start], errf(wire.ErrInvalid, "data_len", "payload too large")
	}
	t := wire.MasterTrailer{
		HashID: h.HashID, CodecID: s.Codec, BlockType: s.BlockType,
		GroupID: s.GroupID, GroupIndex: s.GroupIndex, GroupK: s.GroupK, GroupM: s.GroupM,
		DataLen: uint32(len(s.Payload)), FrameQuanta: q, FrameOrdinal: s.FrameOrdinal,
	}
	if s.BlockType == wire.BlockData {
		e := s.Entries[0]
		t.LogicalOffset, t.LogicalLength = e.Offset, e.Length
		if t.ObjectID, err = ident.ObjectID(h.HashID, e.Path, e.FileVer); err != nil {
			return dst[:start], err
		}
	}
	if t.HashPayload, err = ident.Hash(h.HashID, s.Payload); err != nil {
		return dst[:start], err
	}
	p := wire.FramePrefix{FrameQuanta: q}
	if err := wire.ValidateTrailer(&t, h, p); err != nil {
		return dst[:start], err
	}
	lay, err := wire.ComputeLayout(q, uint64(len(s.Payload)), ptLen)
	if err != nil {
		return dst[:start], err
	}
	fsz := int(lay.FrameSize)
	out = slices.Grow(out, start+fsz-len(out))[:start+fsz]
	f := out[start:]
	// body: currently at f[0:bodyLen], moves to PreTrailerStart (>= 16 +
	// bodyLen is not guaranteed, so copy handles the overlap).
	copy(f[lay.PreTrailerStart:lay.PreTrailerStart+bodyLen], f[:bodyLen])
	pb, err := p.AppendBinary(f[:0])
	if err != nil || len(pb) != wire.FramePrefixSize {
		return dst[:start], errf(wire.ErrInvalid, "", "prefix encode: %v", err)
	}
	copy(f[lay.PayloadStart:lay.PayloadEnd], s.Payload)
	clear(f[lay.PayloadEnd:lay.PreTrailerStart])
	tb, err := t.AppendBinary(f[lay.TrailerStart:lay.TrailerStart])
	if err != nil || len(tb) != wire.MasterTrailerSize {
		return dst[:start], errf(wire.ErrInvalid, "", "trailer encode: %v", err)
	}
	body := f[lay.PreTrailerStart : lay.PreTrailerStart+bodyLen]
	crcAt := lay.PreTrailerStart + bodyLen
	binary.LittleEndian.PutUint32(f[crcAt:], wire.OuterCRC(body, uint32(ptLen), tb))
	binary.LittleEndian.PutUint32(f[lay.TrailerStart-4:], uint32(ptLen))
	return out, nil
}

// chooseQuanta picks frame_quanta for a frame (§6.3, §7.1).
func chooseQuanta(h *wire.ArchiveHeader, s *Spec, ptLen uint64) (uint32, error) {
	q := s.FrameQuanta
	if h.Mode == wire.ModeFixed {
		if q != 0 && q != h.MaxFrameQuanta {
			return 0, errf(wire.ErrInvalid, "frame_quanta", "FIXED archive needs %d", h.MaxFrameQuanta)
		}
		q = h.MaxFrameQuanta
	}
	if s.BlockType == wire.BlockParity {
		// PARITY payload length defines the frame size exactly (§7.1).
		pq, err := RequiredQuanta(uint64(len(s.Payload)), ptLen, false)
		if err != nil {
			return 0, err
		}
		if q == 0 {
			q = pq
		}
		if uint64(len(s.Payload)) != wire.ParityShardLen(q) {
			return 0, errf(wire.ErrInvalid, "payload", "parity shard %d bytes, frame of %d quanta needs %d", len(s.Payload), q, wire.ParityShardLen(q))
		}
	}
	minQ, err := RequiredQuanta(uint64(len(s.Payload)), ptLen, s.GroupID != 0 && s.BlockType != wire.BlockParity)
	if err != nil {
		return 0, err
	}
	if q == 0 {
		q = minQ
	}
	if q < minQ || q > h.MaxFrameQuanta {
		return 0, errf(wire.ErrInvalid, "frame_quanta", "%d outside %d..%d", q, minQ, h.MaxFrameQuanta)
	}
	return q, nil
}

func checkEntriesForBuild(h *wire.ArchiveHeader, s *Spec) error {
	switch s.BlockType {
	case wire.BlockData:
		if len(s.Entries) != 1 {
			return errf(wire.ErrInvalid, "entries", "DATA needs exactly 1 entry, got %d", len(s.Entries))
		}
	case wire.BlockPacked:
		if _, err := checkPacked(s.Entries, h.MaxFrameSize()); err != nil {
			return err
		}
	case wire.BlockParity:
		if len(s.Entries) != 0 {
			return errf(wire.ErrInvalid, "entries", "PARITY has no entries")
		}
	default:
		return errf(wire.ErrInvalid, "block_type", "%d", s.BlockType)
	}
	return nil
}

// checkPacked validates PACKED entries (§8) and returns
// packed_logical_length.
func checkPacked(es []wire.Entry, maxFrame uint64) (uint64, error) {
	if len(es) < 1 || len(es) > wire.MaxPackedEntries {
		return 0, errf(wire.ErrCorrupt, "entries", "PACKED entry_count %d", len(es))
	}
	var end uint64
	for i, e := range es {
		if i > 0 && canonpath.Compare(es[i-1].Path, e.Path) >= 0 {
			return 0, errf(wire.ErrCorrupt, "entries", "PACKED paths not strictly sorted at entry %d", i)
		}
		if e.Offset != end {
			return 0, errf(wire.ErrCorrupt, "entries", "PACKED entry %d at %d, want dense offset %d", i, e.Offset, end)
		}
		var err error
		if end, err = checked.Add64(end, e.Length); err != nil {
			return 0, errf(wire.ErrCorrupt, "entries", "PACKED length overflow")
		}
	}
	if end > maxFrame {
		return 0, errf(wire.ErrCorrupt, "entries", "packed_logical_length %d > MAX_FRAME_SIZE %d", end, maxFrame)
	}
	return end, nil
}

// Parse validates a complete frame (§6, §11.2 steps 1-8) and returns its
// parts. frame must be exactly the frame's bytes; the caller sizes the read
// from a prefix validated with wire.DecodeFramePrefix.
func Parse(frame []byte, h *wire.ArchiveHeader) (*Frame, error) {
	p, err := wire.DecodeFramePrefix(frame, h)
	if err != nil {
		return nil, err
	}
	if uint64(len(frame)) != wire.FrameSize(p.FrameQuanta) {
		return nil, errf(wire.ErrCorrupt, "", "have %d bytes, prefix says %d", len(frame), wire.FrameSize(p.FrameQuanta))
	}
	tail, err := wire.DecodeFrameTail(frame)
	if err != nil {
		return nil, err
	}
	t := tail.Trailer
	if err := wire.ValidateTrailer(&t, h, p); err != nil {
		return nil, err
	}
	lay, err := wire.ComputeLayout(p.FrameQuanta, uint64(t.DataLen), uint64(len(tail.Body)))
	if err != nil {
		return nil, err
	}
	f := &Frame{Prefix: p, Trailer: t, PreTrailer: tail.Body, Payload: frame[lay.PayloadStart:lay.PayloadEnd]}
	for _, x := range frame[lay.PayloadEnd:lay.PreTrailerStart] {
		if x != 0 {
			return nil, errf(wire.ErrCorrupt, "padding", "non-zero padding")
		}
	}
	sum, err := ident.Hash(h.HashID, f.Payload)
	if err != nil {
		return nil, err
	}
	if sum != t.HashPayload {
		return nil, errf(wire.ErrCorrupt, "hash_payload", "mismatch")
	}
	if t.BlockType == wire.BlockParity {
		if len(tail.Body) != wire.MinParityPreTrailerLen || lay.PaddingLen != 0 {
			return nil, errf(wire.ErrCorrupt, "pre_trailer_len", "PARITY needs the 8-byte zero-entry Pre-Trailer and no padding")
		}
	}
	if h.Encrypted() && t.BlockType != wire.BlockParity {
		// nonce || ciphertext || tag || crc; plaintext holds at least entry_count.
		if len(tail.Body) < wire.AEADOverhead+4+4 {
			return nil, errf(wire.ErrCorrupt, "pre_trailer_len", "encrypted Pre-Trailer too short")
		}
		if t.BlockType == wire.BlockPacked && t.CodecID == wire.CodecStore && t.DataLen < wire.AEADOverhead {
			return nil, errf(wire.ErrCorrupt, "data_len", "encrypted STORE payload shorter than AEAD overhead")
		}
		return f, nil
	}
	es, err := wire.DecodeEntries(tail.Body[:len(tail.Body)-4])
	if err != nil {
		return nil, err
	}
	f.Entries = es
	switch t.BlockType {
	case wire.BlockParity:
		if len(es) != 0 {
			return nil, errf(wire.ErrCorrupt, "entry_count", "PARITY must have 0 entries")
		}
	case wire.BlockData:
		if len(es) != 1 {
			return nil, errf(wire.ErrCorrupt, "entry_count", "DATA must have 1 entry, got %d", len(es))
		}
		e := es[0]
		if e.Offset != t.LogicalOffset || e.Length != t.LogicalLength {
			return nil, errf(wire.ErrCorrupt, "entry", "Pre-Trailer placement differs from Master Trailer")
		}
		id, err := ident.ObjectID(h.HashID, e.Path, e.FileVer)
		if err != nil {
			return nil, err
		}
		if id != t.ObjectID {
			return nil, errf(wire.ErrCorrupt, "object_id", "does not match path and file_ver")
		}
	case wire.BlockPacked:
		n, err := checkPacked(es, h.MaxFrameSize())
		if err != nil {
			return nil, err
		}
		if t.CodecID == wire.CodecStore && uint64(t.DataLen) != n {
			return nil, errf(wire.ErrCorrupt, "data_len", "STORE PACKED has %d, want %d", t.DataLen, n)
		}
		f.PackedLength = n
	}
	return f, nil
}
