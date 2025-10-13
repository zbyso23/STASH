package stash

import (
    "bytes"
    "compress/gzip"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
)

// Frame encoding constants. See README.md for detailed specification.
const (
    // Magic is the two-byte sync word that begins every frame.
    Magic = "SF"
    // Version identifies the frame format version.
    Version uint8 = 1
    // CodecStore indicates the payload is stored uncompressed.
    CodecStore uint8 = 0
    // CodecGzip is an additional codec ID we introduce for gzip compression.
    // This is not part of the original specification but useful for demonstration.
    CodecGzip uint8 = 5
)

// FrameObject represents a single object entry in a frame's object table.
// Offset is relative to the uncompressed payload.
// Size is the uncompressed size of this object.
// Hash is the SHA-256 hash of the uncompressed object, encoded in hex.
type FrameObject struct {
    Name   string `json:"name"`
    Offset uint64 `json:"offset"`
    Size   uint64 `json:"size"`
    Hash   string `json:"hash"`
}

// FrameMetadata carries the decoded contents of a frame.
// Data holds the full uncompressed payload for the frame.
// Objects contains metadata about each object within the frame.
// Hash is the SHA-256 digest of the frame (excluding the final 32-byte hash), encoded in hex.
type FrameMetadata struct {
    Codec            uint8
    Flags            uint32
    UncompressedSize uint64
    CompressedSize   uint64
    Timestamp        uint64
    FrameID          uint64
    ObjectTableOff   uint64
    Objects          []FrameObject
    Data             []byte
    Hash             string
}

// CreateFrame builds a binary STASH frame from the provided data and metadata.
// Each frame contains exactly one object. The returned slice contains the full
// frame (header, compressed payload, object table, and trailing hash). The
// returned hash is the SHA-256 digest of the frame (excluding the trailing
// hash bytes).
func CreateFrame(frameID uint64, codecID uint8, data []byte, objectName string, ts int64) ([]byte, string, error) {
    // Compute hash of the raw data (object hash)
    objHashBytes := sha256.Sum256(data)
    objHash := hex.EncodeToString(objHashBytes[:])
    uncompressedSize := uint64(len(data))

    // Compress payload according to codec
    var compBuf bytes.Buffer
    switch codecID {
    case CodecStore:
        // store uncompressed
        if _, err := compBuf.Write(data); err != nil {
            return nil, "", fmt.Errorf("failed to write store data: %w", err)
        }
    case CodecGzip:
        gw := gzip.NewWriter(&compBuf)
        if _, err := gw.Write(data); err != nil {
            return nil, "", fmt.Errorf("failed to write gzip data: %w", err)
        }
        if err := gw.Close(); err != nil {
            return nil, "", fmt.Errorf("failed to close gzip writer: %w", err)
        }
    default:
        return nil, "", fmt.Errorf("unsupported codec ID %d", codecID)
    }
    compressedPayload := compBuf.Bytes()
    compressedSize := uint64(len(compressedPayload))

    // Build header (fixed 0x30 bytes)
    header := make([]byte, 0x30)
    // Magic (2 bytes)
    copy(header[0:2], []byte(Magic))
    // Version (1 byte)
    header[2] = byte(Version)
    // Codec ID (1 byte)
    header[3] = byte(codecID)
    // Flags (4 bytes, little-endian)
    binary.LittleEndian.PutUint32(header[4:8], 0)
    // Uncompressed size (8 bytes)
    binary.LittleEndian.PutUint64(header[8:16], uncompressedSize)
    // Compressed size (8 bytes)
    binary.LittleEndian.PutUint64(header[16:24], compressedSize)
    // Timestamp (8 bytes)
    binary.LittleEndian.PutUint64(header[24:32], uint64(ts))
    // Frame ID (8 bytes)
    binary.LittleEndian.PutUint64(header[32:40], frameID)
    // Object table offset (8 bytes) — temporarily zero; will fill below
    binary.LittleEndian.PutUint64(header[40:48], 0)

    // Build object table (JSON array with a single entry)
    objects := []FrameObject{{
        Name:   objectName,
        Offset: 0,
        Size:   uncompressedSize,
        Hash:   objHash,
    }}
    objTableBytes, err := json.Marshal(objects)
    if err != nil {
        return nil, "", fmt.Errorf("failed to marshal object table: %w", err)
    }

    // Compute object table offset: header length + compressed payload length
    objectTableOffset := uint64(len(header) + len(compressedPayload))
    // Write the offset into the header
    binary.LittleEndian.PutUint64(header[40:48], objectTableOffset)

    // Assemble frame without hash
    frameWithoutHash := make([]byte, 0, len(header)+len(compressedPayload)+len(objTableBytes))
    frameWithoutHash = append(frameWithoutHash, header...)
    frameWithoutHash = append(frameWithoutHash, compressedPayload...)
    frameWithoutHash = append(frameWithoutHash, objTableBytes...)

    // Compute frame hash (covers everything except the hash itself)
    frameHash := sha256.Sum256(frameWithoutHash)
    frameHashHex := hex.EncodeToString(frameHash[:])

    // Append the raw hash bytes to produce final frame
    fullFrame := append(frameWithoutHash, frameHash[:]...)
    return fullFrame, frameHashHex, nil
}

// ParseFrame reads a binary STASH frame and returns the decoded metadata and data.
// It verifies the magic, version and the trailing frame hash. If verification
// succeeds, the returned FrameMetadata contains the uncompressed payload and
// object descriptions. If the codec is unsupported or the integrity check fails,
// an error is returned.
func ParseFrame(frameBytes []byte) (*FrameMetadata, error) {
    // Minimum length is header (0x30) + 32-byte hash
    if len(frameBytes) < 0x30+32 {
        return nil, fmt.Errorf("frame too short")
    }
    totalLen := len(frameBytes)
    // Verify frame hash
    payloadPart := frameBytes[:totalLen-32]
    expectedHash := frameBytes[totalLen-32:]
    calcHash := sha256.Sum256(payloadPart)
    if !bytes.Equal(calcHash[:], expectedHash) {
        return nil, fmt.Errorf("frame hash mismatch")
    }
    // Verify magic
    if string(frameBytes[0:2]) != Magic {
        return nil, fmt.Errorf("invalid magic")
    }
    version := frameBytes[2]
    if version != byte(Version) {
        return nil, fmt.Errorf("unsupported version %d", version)
    }
    codec := frameBytes[3]
    flags := binary.LittleEndian.Uint32(frameBytes[4:8])
    uncompressedSize := binary.LittleEndian.Uint64(frameBytes[8:16])
    compressedSize := binary.LittleEndian.Uint64(frameBytes[16:24])
    timestamp := binary.LittleEndian.Uint64(frameBytes[24:32])
    frameID := binary.LittleEndian.Uint64(frameBytes[32:40])
    objectTableOff := binary.LittleEndian.Uint64(frameBytes[40:48])
    // Ensure sizes are within bounds
    if objectTableOff > uint64(totalLen-32) {
        return nil, fmt.Errorf("object table offset out of bounds")
    }
    if 0x30+compressedSize > objectTableOff {
        return nil, fmt.Errorf("compressed payload exceeds object table")
    }
    compPayload := frameBytes[0x30 : 0x30+compressedSize]
    objBytes := frameBytes[objectTableOff : totalLen-32]

    // Decompress payload
    var uncompressed []byte
    switch codec {
    case CodecStore:
        uncompressed = make([]byte, len(compPayload))
        copy(uncompressed, compPayload)
    case CodecGzip:
        // gzip
        r, err := gzip.NewReader(bytes.NewReader(compPayload))
        if err != nil {
            return nil, fmt.Errorf("failed to create gzip reader: %w", err)
        }
        defer r.Close()
        uncompressed, err = io.ReadAll(r)
        if err != nil {
            return nil, fmt.Errorf("failed to decompress gzip: %w", err)
        }
    default:
        return nil, fmt.Errorf("unsupported codec ID %d", codec)
    }
    if uint64(len(uncompressed)) != uncompressedSize {
        return nil, fmt.Errorf("uncompressed size mismatch: expected %d, got %d", uncompressedSize, len(uncompressed))
    }
    // Parse object table
    var objects []FrameObject
    if err := json.Unmarshal(objBytes, &objects); err != nil {
        return nil, fmt.Errorf("failed to parse object table: %w", err)
    }
    // Build result
    fm := &FrameMetadata{
        Codec:            codec,
        Flags:            flags,
        UncompressedSize: uncompressedSize,
        CompressedSize:   compressedSize,
        Timestamp:        timestamp,
        FrameID:          frameID,
        ObjectTableOff:   objectTableOff,
        Objects:          objects,
        Data:             uncompressed,
        Hash:             hex.EncodeToString(calcHash[:]),
    }
    return fm, nil
}