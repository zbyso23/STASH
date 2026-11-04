package wire

import "encoding/binary"

// OuterCRC computes the outer Pre-Trailer CRC32C (§6.4.3) over the stored
// Pre-Trailer body without its final four CRC bytes, the uint32
// pre_trailer_len, and the complete 96-byte Master Trailer.
func OuterCRC(bodyWithoutCRC []byte, preTrailerLen uint32, trailer []byte) uint32 {
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], preTrailerLen)
	return CRC32C(bodyWithoutCRC, l[:], trailer)
}

// FrameTail is the tail of a frame: stored Pre-Trailer body, its length and
// the Master Trailer, after the outer CRC has been verified.
type FrameTail struct {
	Body    []byte // stored body including the outer CRC (aliases the input)
	Trailer MasterTrailer
}

// DecodeFrameTail reverse-parses a complete frame (§6.4.3 steps 1-5): it
// locates the trailer and pre_trailer_len, checks bounds with checked
// arithmetic, verifies the outer CRC binding the body, length and every
// trailer byte, and only then decodes the trailer. frame must be exactly
// frame_size bytes of a frame whose prefix was already validated.
func DecodeFrameTail(frame []byte) (FrameTail, error) {
	const st = "PreTrailer"
	n := uint64(len(frame))
	if n < BaseQuantum || n%BaseQuantum != 0 {
		return FrameTail{}, errf(ErrCorrupt, st, "", "frame size %d", n)
	}
	trailer := frame[n-MasterTrailerSize:]
	ptl := uint64(binary.LittleEndian.Uint32(frame[n-MasterTrailerSize-PreTrailerLenSize:]))
	if ptl < 8 || ptl > n-FrameOverhead {
		return FrameTail{}, errf(ErrCorrupt, st, "pre_trailer_len", "%d outside 8..%d", ptl, n-FrameOverhead)
	}
	start := n - MasterTrailerSize - PreTrailerLenSize - ptl
	body := frame[start : n-MasterTrailerSize-PreTrailerLenSize]
	stored := binary.LittleEndian.Uint32(body[len(body)-4:])
	if got := OuterCRC(body[:len(body)-4], uint32(ptl), trailer); got != stored {
		return FrameTail{}, errf(ErrCorrupt, st, "outer_crc32c", "got %08x stored %08x", got, stored)
	}
	t, err := DecodeMasterTrailer(trailer)
	if err != nil {
		return FrameTail{}, err
	}
	if _, err := ComputeLayout(uint32(n/BaseQuantum), uint64(t.DataLen), ptl); err != nil {
		return FrameTail{}, err
	}
	return FrameTail{Body: body, Trailer: t}, nil
}
