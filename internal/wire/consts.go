package wire

// Wire version and fixed sizes (§2.2, §6, §16.2).
const (
	Version = 0x0006

	ArchiveHeaderSize = 64
	FrameAreaStart    = 0x40
	BaseQuantum       = 4096
	FramePrefixSize   = 16
	MasterTrailerSize = 96
	PreTrailerLenSize = 4
	RootSize          = 64
	AllocStateSize    = 64
	IndexHeaderSize   = 64
	IndexRecordSize   = 64

	// FrameOverhead is Prefix + pre_trailer_len + Master Trailer (§6.3).
	FrameOverhead = FramePrefixSize + PreTrailerLenSize + MasterTrailerSize // 116

	// MinParityPreTrailerLen is the zero-entry plaintext Pre-Trailer (§7.1).
	MinParityPreTrailerLen = 8
	// ParityShardOverhead is S - PARITY_SHARD_LEN(S) (§7.1).
	ParityShardOverhead = FrameOverhead + MinParityPreTrailerLen // 124
	// MinParityPadding is the zero padding a parity-protected frame needs (§7.2).
	MinParityPadding = 112

	MaxMaxFrameQuanta = 0x00100000 // 4 GiB frames
	MaxBlobCount      = 255
	MaxBlobOrdinal    = 0xFE
	MaxPackedEntries  = 65535
	MaxPathLen        = 4096
	MaxParityShards   = 256

	MaxManifestLineBytes = 1 << 20
	MaxOpenTransactions  = 1024
	MaxLinkedManifests   = 65535

	// Encrypted-profile nonce limits (§15.5).
	MaxEncryptedGenerationID = 0xFFFFFFFF
	MaxEncryptedFrameOrdinal = 0x00FFFFFFFFFFFFFF

	AEADNonceSize = 12
	AEADTagSize   = 16
	AEADOverhead  = AEADNonceSize + AEADTagSize // 28
	HashSize      = 32
	ObjectIDSize  = 16
	ArchiveIDSize = 32
)

// Magic values.
var (
	MagicArchiveHeader = [4]byte{'S', 'T', 'S', 'H'}
	MagicMasterTrailer = [4]byte{'S', 'T', 'S', 'H'}
	MagicFramePrefix   = [4]byte{'S', 'T', 'F', 'R'}
	MagicRoot          = [8]byte{'S', 'T', 'R', 'O', 'O', 'T', '8', 0}
	MagicAllocState    = [8]byte{'S', 'T', 'A', 'L', 'L', 'O', 'C', 0}
	MagicIndex         = [8]byte{'S', 'T', 'I', 'D', 'X', '8', 0, 0}
)

// FrameSizeMode (§3).
type FrameSizeMode uint8

const (
	ModeVariable FrameSizeMode = 0x00
	ModeFixed    FrameSizeMode = 0x01
)

func (m FrameSizeMode) Valid() bool { return m == ModeVariable || m == ModeFixed }

// HashID (§4).
type HashID uint8

const (
	HashBLAKE3 HashID = 0x01
	HashSHA256 HashID = 0x02
)

func (h HashID) Valid() bool { return h == HashBLAKE3 || h == HashSHA256 }

// CodecID (§5).
type CodecID uint8

const (
	CodecStore       CodecID = 0x00
	CodecZstdFast    CodecID = 0x01
	CodecZstdDefault CodecID = 0x02
	CodecZstdDense   CodecID = 0x03
)

func (c CodecID) Valid() bool { return c <= CodecZstdDense }

// ParityScheme (§7).
type ParityScheme uint8

const (
	ParityNone ParityScheme = 0x00
	ParityXOR  ParityScheme = 0x01
	ParityRS   ParityScheme = 0x02
)

func (p ParityScheme) Valid() bool { return p <= ParityRS }

// BlockType (§6.2).
type BlockType uint8

const (
	BlockData   BlockType = 0
	BlockParity BlockType = 1
	BlockPacked BlockType = 2
)

func (b BlockType) Valid() bool { return b <= BlockPacked }

// Archive Header flags (§2.2).
const HeaderFlagEncrypted uint8 = 0x01

// AllocKind (§2.1.3).
type AllocKind uint8

const (
	AllocGeneration   AllocKind = 0
	AllocFileVer      AllocKind = 1
	AllocManifestSeq  AllocKind = 2
	AllocFrameOrdinal AllocKind = 3
	AllocGroupID      AllocKind = 4
)

func (k AllocKind) Valid() bool { return k <= AllocGroupID }

// PerGeneration reports whether the allocator belongs to one generation.
func (k AllocKind) PerGeneration() bool {
	return k == AllocManifestSeq || k == AllocFrameOrdinal || k == AllocGroupID
}

// MaxReservationBlock returns the largest single extension of reserved_through
// (§2.1.3.1).
func (k AllocKind) MaxReservationBlock() uint64 {
	if k == AllocGeneration || k == AllocGroupID {
		return 1 << 8
	}
	return 1 << 16
}

// ReinitSkip returns SKIP of the conservative initialization (§2.1.3.4).
func (k AllocKind) ReinitSkip() uint64 {
	if k == AllocGeneration || k == AllocGroupID {
		return 1 << 16
	}
	return 1 << 32
}

// legacyVersions are recognized and refused without parsing (§14).
func isLegacyVersion(v uint16) bool { return v >= 0x0002 && v <= 0x0005 }
