// Package compress implements the codec profiles of SPEC §5: STORE and
// Zstandard at the ZSTD_FAST/DEFAULT/DENSE strengths, with the strict
// decoder rules of §5.1 and §5.1.1. The encoder is
// github.com/klauspost/compress/zstd; frames are single-segment (so
// Frame_Content_Size is always present) without a content checksum
// (hash_payload already covers the stored bytes).
package compress

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"

	"stash/internal/wire"
)

// Level is the zstd level of a codec profile (§5).
func Level(c wire.CodecID) int {
	switch c {
	case wire.CodecZstdFast:
		return 1
	case wire.CodecZstdDefault:
		return 3
	case wire.CodecZstdDense:
		return 9
	}
	return 0
}

var (
	encMu    sync.Mutex
	encoders = map[wire.CodecID]*zstd.Encoder{}
	decOnce  sync.Once
	decoder  *zstd.Decoder
	decErr   error
)

func encoder(c wire.CodecID) (*zstd.Encoder, error) {
	encMu.Lock()
	defer encMu.Unlock()
	if e := encoders[c]; e != nil {
		return e, nil
	}
	// level 9 has no exact klauspost equivalent: EncoderLevelFromZstd picks
	// the closest documented setting (§5.1)
	e, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(Level(c))),
		zstd.WithEncoderCRC(false),
		zstd.WithSingleSegment(true),
		zstd.WithZeroFrames(true),
		zstd.WithLowerEncoderMem(false))
	if err != nil {
		return nil, err
	}
	encoders[c] = e
	return e, nil
}

func dec() (*zstd.Decoder, error) {
	decOnce.Do(func() {
		decoder, decErr = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(0),
			zstd.WithDecoderMaxMemory(wire.MaxMaxFrameQuanta*wire.BaseQuantum),
			zstd.WithDecodeAllCapLimit(true),
			zstd.IgnoreChecksum(false))
	})
	return decoder, decErr
}

// Encode returns the stored payload of logical under codec c and the codec
// actually used: STORE when c is STORE, when logical is empty, or when the
// compressed form would not be smaller (§5.2 FAST rule). With STORE the
// result aliases logical. dst is appended to for compressed output.
func Encode(c wire.CodecID, logical, dst []byte) (wire.CodecID, []byte, error) {
	if c == wire.CodecStore || len(logical) == 0 {
		return wire.CodecStore, logical, nil
	}
	if !c.Valid() {
		return 0, nil, fmt.Errorf("%w: codec_id 0x%02x", wire.ErrInvalid, uint8(c))
	}
	e, err := encoder(c)
	if err != nil {
		return 0, nil, err
	}
	out := e.EncodeAll(logical, dst[len(dst):len(dst)])
	if len(out) >= len(logical) {
		return wire.CodecStore, logical, nil
	}
	if err := CheckFrame(out, uint64(len(logical)), uint64(len(logical))); err != nil {
		// never emit a payload our own reader rejects
		return wire.CodecStore, logical, nil
	}
	return c, append(dst, out...), nil
}

// FrameInfo is what CheckFrame read from a Zstandard frame header.
type FrameInfo struct {
	ContentSize uint64
	WindowSize  uint64
	Checksum    bool
}

func corrupt(format string, args ...any) error {
	return &wire.Error{Struct: "Zstd", Class: wire.ErrCorrupt, Detail: fmt.Sprintf(format, args...)}
}

// CheckFrame enforces §5.1.1 from the headers alone, before anything is
// allocated: src is exactly one Zstandard frame (no skippable frames, no
// trailing bytes, walked block by block), Frame_Content_Size is present and
// equals expected, Window_Size <= maxWindow, and no dictionary is used.
func CheckFrame(src []byte, expected, maxWindow uint64) error {
	_, err := Inspect(src, expected, maxWindow)
	return err
}

// Inspect is CheckFrame returning the header fields.
func Inspect(src []byte, expected, maxWindow uint64) (FrameInfo, error) {
	var fi FrameInfo
	if len(src) < 4+1 {
		return fi, corrupt("payload of %d bytes is not a Zstandard frame", len(src))
	}
	magic := binary.LittleEndian.Uint32(src)
	if magic&0xFFFFFFF0 == 0x184D2A50 {
		return fi, corrupt("skippable frame")
	}
	if magic != 0xFD2FB528 {
		return fi, corrupt("bad magic %08x", magic)
	}
	fhd := src[4]
	fcsFlag, single, reserved, checksum, didFlag := fhd>>6, fhd&0x20 != 0, fhd&0x08 != 0, fhd&0x04 != 0, fhd&0x03
	if reserved {
		return fi, corrupt("reserved frame header bit set")
	}
	fi.Checksum = checksum
	p := 5
	need := func(n int) error {
		if len(src) < p+n {
			return corrupt("truncated frame header")
		}
		return nil
	}
	if !single {
		if err := need(1); err != nil {
			return fi, err
		}
		wd := src[p]
		p++
		exp, mant := uint64(wd>>3), uint64(wd&7)
		base := uint64(1) << (10 + exp)
		fi.WindowSize = base + base/8*mant
	}
	didSize := [4]int{0, 1, 2, 4}[didFlag]
	if err := need(didSize); err != nil {
		return fi, err
	}
	var did uint64
	for i := 0; i < didSize; i++ {
		did |= uint64(src[p+i]) << (8 * i)
	}
	p += didSize
	if did != 0 {
		return fi, corrupt("dictionary id %d", did)
	}
	fcsSize := [4]int{0, 2, 4, 8}[fcsFlag]
	if fcsFlag == 0 && single {
		fcsSize = 1
	}
	if fcsSize == 0 {
		return fi, corrupt("Frame_Content_Size absent")
	}
	if err := need(fcsSize); err != nil {
		return fi, err
	}
	var fcs uint64
	for i := 0; i < fcsSize; i++ {
		fcs |= uint64(src[p+i]) << (8 * i)
	}
	if fcsSize == 2 {
		fcs += 256
	}
	p += fcsSize
	fi.ContentSize = fcs
	if single {
		fi.WindowSize = fcs
	}
	if fcs != expected {
		return fi, corrupt("Frame_Content_Size %d, expected %d", fcs, expected)
	}
	if fi.WindowSize > maxWindow {
		return fi, corrupt("Window_Size %d exceeds %d", fi.WindowSize, maxWindow)
	}
	blockMax := min(fi.WindowSize, 128<<10)
	for {
		if err := need(3); err != nil {
			return fi, corrupt("truncated block header")
		}
		bh := uint32(src[p]) | uint32(src[p+1])<<8 | uint32(src[p+2])<<16
		p += 3
		last, typ, size := bh&1 != 0, (bh>>1)&3, int(bh>>3)
		switch typ {
		case 0, 2: // raw, compressed
			if uint64(size) > blockMax {
				return fi, corrupt("block of %d bytes exceeds %d", size, blockMax)
			}
		case 1: // RLE: one byte of content
			if uint64(size) > blockMax {
				return fi, corrupt("RLE block of %d bytes exceeds %d", size, blockMax)
			}
			size = 1
		case 3:
			return fi, corrupt("reserved block type")
		}
		if len(src)-p < size {
			return fi, corrupt("truncated block")
		}
		p += size
		if last {
			break
		}
	}
	if checksum {
		p += 4
	}
	if p != len(src) {
		if p > len(src) {
			return fi, corrupt("truncated content checksum")
		}
		return fi, corrupt("%d bytes after the Zstandard frame", len(src)-p)
	}
	return fi, nil
}

// Decode decodes a stored payload of codec c whose logical length is
// expected (validated <= maxFrame by the caller, §6.6.1), appending to dst.
// STORE returns src itself after checking its length.
func Decode(c wire.CodecID, src []byte, expected, maxFrame uint64, dst []byte) ([]byte, error) {
	switch c {
	case wire.CodecStore:
		if uint64(len(src)) != expected {
			return nil, corrupt("STORE payload %d bytes, expected %d", len(src), expected)
		}
		return src, nil
	case wire.CodecZstdFast, wire.CodecZstdDefault, wire.CodecZstdDense:
	default:
		return nil, &wire.Error{Struct: "Zstd", Field: "codec_id", Class: wire.ErrUnsupported, Detail: fmt.Sprintf("0x%02x", uint8(c))}
	}
	if expected > maxFrame {
		return nil, corrupt("logical length %d exceeds MAX_FRAME_SIZE %d", expected, maxFrame)
	}
	if err := CheckFrame(src, expected, maxFrame); err != nil {
		return nil, err
	}
	d, err := dec()
	if err != nil {
		return nil, err
	}
	start := len(dst)
	if uint64(cap(dst)-start) < expected {
		nd := make([]byte, start, start+int(expected))
		copy(nd, dst)
		dst = nd
	}
	// cap limit: the decoder never writes more than expected bytes
	out, err := d.DecodeAll(src, dst[:start:start+int(expected)])
	if err != nil {
		return nil, corrupt("decode: %v", err)
	}
	if uint64(len(out)-start) != expected {
		return nil, corrupt("decoded %d bytes, expected %d", len(out)-start, expected)
	}
	return out, nil
}
