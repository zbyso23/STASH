package stash

import "context"

type GenerationID uint64

type BlobOrdinal uint8

type ObjectID [16]byte

type FrameHash [32]byte

type FrameSizeMode uint8

const (
	FrameSizeVariable FrameSizeMode = iota
	FrameSizeFixed
)

type HashAlgorithm uint8

const (
	HashBLAKE3 HashAlgorithm = 0x01
	HashSHA256 HashAlgorithm = 0x02
	HashSHA3   HashAlgorithm = 0x03
)

type Codec uint8

const (
	CodecStore  Codec = 0x00
	CodecLZ4    Codec = 0x01
	CodecZstd   Codec = 0x02
	CodecLZMA   Codec = 0x03
	CodecBrotli Codec = 0x04
)

type ParityScheme uint8

const (
	ParityNone        ParityScheme = 0x00
	ParityXOR         ParityScheme = 0x01
	ParityReedSolomon ParityScheme = 0x02
	ParityLRC         ParityScheme = 0x03
)

type CreateOptions struct {
	FrameSizeMode FrameSizeMode
	MaxFrameSize  uint64

	Hash  HashAlgorithm
	Codec Codec

	BlobCount uint8

	Parity ParityOptions

	Encryption EncryptionOptions
}

type ParityOptions struct {
	Scheme ParityScheme
	K      uint8
	M      uint8
}

type EncryptionOptions struct {
	Enabled bool

	KeyProvider KeyProvider
}

type KeyProvider interface {
	ArchiveKey(
		ctx context.Context,
		archiveID [32]byte,
	) ([]byte, error)
}

type RootRef struct {
	Generation GenerationID
}
