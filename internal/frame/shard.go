package frame

import (
	"encoding/binary"
	"slices"

	"stash/internal/wire"
)

// AppendRecoveryShard appends the canonical recovery shard (§7.2) of an
// encoded DATA or PACKED frame to dst:
//
//	uint32_le(recovery_image_len) || recovery_image || zeros
//
// with recovery_image = payload || stored Pre-Trailer || pre_trailer_len ||
// Master Trailer, PARITY_SHARD_LEN(S) bytes in total. The frame's tail must
// be intact (outer CRC); the payload is taken as stored. A frame with less
// than 112 bytes of zero padding cannot be a parity member and is refused.
func AppendRecoveryShard(dst, fr []byte) ([]byte, error) {
	tail, err := wire.DecodeFrameTail(fr)
	if err != nil {
		return dst, err
	}
	t := &tail.Trailer
	if t.BlockType == wire.BlockParity {
		return dst, errf(wire.ErrInvalid, "block_type", "PARITY frames have no recovery shard")
	}
	S := uint64(len(fr))
	ptl := uint64(len(tail.Body))
	lay, err := wire.ComputeLayout(uint32(S/wire.BaseQuantum), uint64(t.DataLen), ptl)
	if err != nil {
		return dst, err
	}
	if lay.PaddingLen < wire.MinParityPadding {
		return dst, errf(wire.ErrInvalid, "zero_padding", "%d bytes, a parity member needs %d", lay.PaddingLen, wire.MinParityPadding)
	}
	shardLen := int(S - wire.ParityShardOverhead)
	imageLen := int(S - wire.FramePrefixSize - lay.PaddingLen)
	start := len(dst)
	out := slices.Grow(dst, shardLen)[:start+shardLen]
	s := out[start:]
	binary.LittleEndian.PutUint32(s, uint32(imageLen))
	n := 4 + copy(s[4:], fr[lay.PayloadStart:lay.PayloadEnd])
	n += copy(s[n:], fr[lay.PreTrailerStart:])
	clear(s[n:])
	return out, nil
}

// AppendFromRecoveryShard rebuilds a complete frame of q quanta from a
// canonical recovery shard (§7.3 steps 1-5): the recovered payload and
// stored tail are placed at their canonical positions, the Prefix is
// regenerated and the padding is zero. The result is NOT validated; the
// caller must run Parse (step 6) before trusting it.
func AppendFromRecoveryShard(dst, shard []byte, q uint32) ([]byte, error) {
	S := wire.FrameSize(q)
	if q == 0 || uint64(len(shard)) != wire.ParityShardLen(q) {
		return dst, errf(wire.ErrCorrupt, "shard", "%d bytes for a frame of %d quanta", len(shard), q)
	}
	imageLen := uint64(binary.LittleEndian.Uint32(shard))
	if imageLen < wire.MasterTrailerSize+wire.PreTrailerLenSize+wire.MinParityPreTrailerLen || 4+imageLen > uint64(len(shard)) {
		return dst, errf(wire.ErrCorrupt, "recovery_image_len", "%d outside the shard", imageLen)
	}
	for _, b := range shard[4+imageLen:] {
		if b != 0 {
			return dst, errf(wire.ErrCorrupt, "shard", "non-zero bytes after the recovery image")
		}
	}
	image := shard[4 : 4+imageLen]
	trailer := image[imageLen-wire.MasterTrailerSize:]
	ptl := uint64(binary.LittleEndian.Uint32(image[imageLen-wire.MasterTrailerSize-wire.PreTrailerLenSize:]))
	dataLen := uint64(binary.LittleEndian.Uint32(trailer[0x10:]))
	tailLen := ptl + wire.PreTrailerLenSize + wire.MasterTrailerSize
	if tailLen > imageLen || imageLen-tailLen != dataLen {
		return dst, errf(wire.ErrCorrupt, "recovery_image_len", "image %d, data_len %d, pre_trailer_len %d", imageLen, dataLen, ptl)
	}
	start := len(dst)
	out := slices.Grow(dst, int(S))[:start+int(S)]
	f := out[start:]
	if _, err := (wire.FramePrefix{FrameQuanta: q}).AppendBinary(f[:0]); err != nil {
		return dst, err
	}
	copy(f[wire.FramePrefixSize:], image[:dataLen])
	clear(f[wire.FramePrefixSize+dataLen : S-tailLen])
	copy(f[S-tailLen:], image[dataLen:])
	return out, nil
}
