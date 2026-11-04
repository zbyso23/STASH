package wire

import (
	"stash/internal/checked"
)

// FrameSize returns frame_quanta * 4096 (always fits uint64).
func FrameSize(q uint32) uint64 { return uint64(q) * BaseQuantum }

// OnFrameGrid reports whether off is FRAME_AREA_START + j*4096 (§3.1.1).
func OnFrameGrid(off uint64) bool {
	return off >= FrameAreaStart && (off-FrameAreaStart)%BaseQuantum == 0
}

// FixedSlotOffset returns 0x40 + n*MAX_FRAME_SIZE (§3.3) with overflow checks.
func FixedSlotOffset(n uint64, h *ArchiveHeader) (uint64, error) {
	m, err := checked.Mul64(n, h.MaxFrameSize())
	if err != nil {
		return 0, errf(ErrResource, "Geometry", "slot", "slot %d overflows", n)
	}
	off, err := checked.Add64(m, FrameAreaStart)
	if err != nil {
		return 0, errf(ErrResource, "Geometry", "slot", "slot %d overflows", n)
	}
	return off, nil
}

// FrameEnd returns off + frame size, checking that the frame lies inside a
// blob of blobSize bytes.
func FrameEnd(off uint64, q uint32, blobSize uint64) (uint64, error) {
	if !OnFrameGrid(off) {
		return 0, errf(ErrCorrupt, "Geometry", "offset", "%d not on frame grid", off)
	}
	end, err := checked.RangeEnd(off, FrameSize(q), blobSize)
	if err != nil {
		return 0, errf(ErrCorrupt, "Geometry", "frame_end", "frame at %d with %d quanta exceeds blob size %d", off, q, blobSize)
	}
	return end, nil
}

// Layout is the byte layout of one frame, computed from validated fields
// (§6, §6.3). Offsets are relative to the frame start.
type Layout struct {
	FrameSize       uint64
	PayloadStart    uint64 // always 16
	PayloadEnd      uint64
	PaddingLen      uint64
	PreTrailerStart uint64
	PreTrailerLen   uint64
	TrailerStart    uint64
}

// ComputeLayout checks the exact budget equation of §6.3 and rejects overlap
// between payload and Pre-Trailer.
func ComputeLayout(q uint32, dataLen, preTrailerLen uint64) (Layout, error) {
	const st = "Geometry"
	fs := FrameSize(q)
	used, err := checked.Sum64(FrameOverhead, dataLen, preTrailerLen)
	if err != nil || used > fs {
		return Layout{}, errf(ErrCorrupt, st, "budget", "data_len %d + pre_trailer_len %d + 116 exceed frame size %d", dataLen, preTrailerLen, fs)
	}
	trailerStart := fs - MasterTrailerSize
	ptStart := trailerStart - PreTrailerLenSize - preTrailerLen
	payloadEnd := FramePrefixSize + dataLen
	return Layout{
		FrameSize:       fs,
		PayloadStart:    FramePrefixSize,
		PayloadEnd:      payloadEnd,
		PaddingLen:      ptStart - payloadEnd,
		PreTrailerStart: ptStart,
		PreTrailerLen:   preTrailerLen,
		TrailerStart:    trailerStart,
	}, nil
}

// ParityShardLen returns PARITY_SHARD_LEN(S) = S - 124 (§7.1).
func ParityShardLen(q uint32) uint64 { return FrameSize(q) - ParityShardOverhead }
