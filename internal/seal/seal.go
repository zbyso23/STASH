// Package seal is the encryption profile of SPEC §15: the archive DEK,
// the four HKDF-SHA-256 domain keys, AES-256-GCM in the stored form
// nonce || ciphertext || tag, the numeric nonces of §15.5 and the frame and
// manifest AAD of §15.4 and §15.8.3. It also derives the key-check value
// of the key.check file (E1-25), which is not wire format.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"stash/internal/ident"
	"stash/internal/wire"
)

// KeySize is the archive DEK size.
const KeySize = 32

// HKDF info strings (§15.2; exact ASCII, no NUL) and the key-check info.
const (
	InfoFrame      = "STASH-FRAME-AEAD-R8"
	InfoPreTrailer = "STASH-PRETRAILER-AEAD-R8"
	InfoManifest   = "STASH-MANIFEST-AEAD-R8"
	InfoObjectID   = "STASH-OBJECT-ID-KEY-R10"
	InfoKeyCheck   = "STASH-KEY-CHECK-R10"
)

// Errors.
var (
	// ErrAuth reports an AEAD authentication failure: wrong key, or the
	// ciphertext, tag, nonce or AAD was modified.
	ErrAuth = errors.New("authentication failed")
	// ErrNonceLimit reports a value outside the encrypted-profile nonce
	// namespace (§15.5); no encryption is attempted.
	ErrNonceLimit = errors.New("encrypted-profile nonce limit exceeded")
)

// Encrypted-profile limits (§15.5).
const (
	MaxGenerationID = 0xFFFFFFFF
	MaxFrameOrdinal = 0x00FFFFFFFFFFFFFF
)

// NewKey returns a fresh random archive DEK.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Derived holds the raw derived keys (for golden vectors and tests).
type Derived struct {
	Frame, PreTrailer, Manifest, ObjectID, KeyCheck [32]byte
}

// Derive computes every HKDF-SHA-256 output with IKM = dek and
// salt = archive_id.
func Derive(dek []byte, archiveID [32]byte) (Derived, error) {
	var d Derived
	if len(dek) != KeySize {
		return d, fmt.Errorf("%w: archive DEK must be %d bytes, got %d", wire.ErrInvalid, KeySize, len(dek))
	}
	for _, x := range []struct {
		out  *[32]byte
		info string
	}{{&d.Frame, InfoFrame}, {&d.PreTrailer, InfoPreTrailer}, {&d.Manifest, InfoManifest}, {&d.ObjectID, InfoObjectID}, {&d.KeyCheck, InfoKeyCheck}} {
		k, err := hkdf.Key(sha256.New, dek, archiveID[:], x.info, 32)
		if err != nil {
			return d, err
		}
		copy(x.out[:], k)
	}
	return d, nil
}

// Keys is the key schedule of one encrypted archive. It is safe for
// concurrent use.
type Keys struct {
	ArchiveID          [32]byte
	frame, pt, man     cipher.AEAD
	objectID, keyCheck [32]byte
}

func gcm(k [32]byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b) // 12-byte nonce, 16-byte tag
}

// New derives the key schedule of the archive archiveID from dek.
func New(dek []byte, archiveID [32]byte) (*Keys, error) {
	d, err := Derive(dek, archiveID)
	if err != nil {
		return nil, err
	}
	k := &Keys{ArchiveID: archiveID, objectID: d.ObjectID, keyCheck: d.KeyCheck}
	if k.frame, err = gcm(d.Frame); err != nil {
		return nil, err
	}
	if k.pt, err = gcm(d.PreTrailer); err != nil {
		return nil, err
	}
	if k.man, err = gcm(d.Manifest); err != nil {
		return nil, err
	}
	return k, nil
}

// KeyCheck is the value stored in key.check (E1-25).
func (k *Keys) KeyCheck() [32]byte { return k.keyCheck }

// CheckKey compares a stored key-check value in constant time.
func (k *Keys) CheckKey(stored []byte) bool { return hmac.Equal(stored, k.keyCheck[:]) }

// ObjectID is the keyed object_id of §6.5.
func (k *Keys) ObjectID(path string, fileVer uint64) ([16]byte, error) {
	return ident.KeyedObjectID(k.objectID[:], path, fileVer)
}

// FrameNonce is the payload and Pre-Trailer nonce of §15.5.1/§15.5.2:
// uint32_le(generation_id) || uint8(blob_ordinal) || uint56_le(frame_ordinal).
func FrameNonce(gen uint64, blob uint8, ordinal uint64) ([12]byte, error) {
	var n [12]byte
	if gen > MaxGenerationID || ordinal > MaxFrameOrdinal {
		return n, fmt.Errorf("%w: generation_id %d, frame_ordinal %d", ErrNonceLimit, gen, ordinal)
	}
	binary.LittleEndian.PutUint32(n[0:4], uint32(gen))
	n[4] = blob
	var o [8]byte
	binary.LittleEndian.PutUint64(o[:], ordinal)
	copy(n[5:12], o[:7])
	return n, nil
}

// SplitFrameNonce inverts FrameNonce.
func SplitFrameNonce(n []byte) (gen uint64, blob uint8, ordinal uint64) {
	var o [8]byte
	copy(o[:7], n[5:12])
	return uint64(binary.LittleEndian.Uint32(n[0:4])), n[4], binary.LittleEndian.Uint64(o[:])
}

// ManifestNonce is uint32_le(generation_id) || uint64_le(seq) (§15.5.3).
func ManifestNonce(gen, seq uint64) ([12]byte, error) {
	var n [12]byte
	if gen > MaxGenerationID {
		return n, fmt.Errorf("%w: generation_id %d", ErrNonceLimit, gen)
	}
	binary.LittleEndian.PutUint32(n[0:4], uint32(gen))
	binary.LittleEndian.PutUint64(n[4:12], seq)
	return n, nil
}

// FrameAADSize is the length of the canonical frame AAD.
const FrameAADSize = 32 + 2 + 1 + 4 + 4 + 4 + 64

// FrameAAD appends the canonical frame AAD of §15.4. trailer64 is
// master_trailer_bytes[0x00:0x40].
func FrameAAD(dst []byte, h *wire.ArchiveHeader, frameQuanta uint32, trailer64 []byte) []byte {
	dst = append(dst, h.ArchiveID[:]...)
	dst = binary.LittleEndian.AppendUint16(dst, wire.Version)
	dst = append(dst, h.Flags)
	dst = append(dst, wire.MagicFramePrefix[:]...)
	dst = binary.LittleEndian.AppendUint32(dst, frameQuanta)
	dst = binary.LittleEndian.AppendUint32(dst, 0) // frame_prefix_flags
	return append(dst, trailer64[:64]...)
}

// ManifestAAD appends the manifest AAD of §15.8.3 (op includes _ENC).
func ManifestAAD(dst []byte, archiveID [32]byte, gen, seq uint64, op string) []byte {
	dst = append(dst, archiveID[:]...)
	dst = binary.LittleEndian.AppendUint16(dst, wire.Version)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(gen))
	dst = binary.LittleEndian.AppendUint64(dst, seq)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(op)))
	return append(dst, op...)
}

// Domain selects one of the three AEAD keys.
type Domain int

const (
	FrameDomain Domain = iota
	PreTrailerDomain
	ManifestDomain
)

func (k *Keys) aead(d Domain) cipher.AEAD {
	switch d {
	case FrameDomain:
		return k.frame
	case PreTrailerDomain:
		return k.pt
	}
	return k.man
}

// Seal appends nonce || ciphertext || tag to dst. dst must not overlap
// plain unless they start at the same position after the nonce.
func (k *Keys) Seal(d Domain, dst []byte, nonce [12]byte, plain, aad []byte) []byte {
	dst = append(dst, nonce[:]...)
	return k.aead(d).Seal(dst, nonce[:], plain, aad)
}

// Open authenticates and decrypts a stored nonce || ciphertext || tag and
// appends the plaintext to dst. The stored nonce is authoritative (§15.10).
func (k *Keys) Open(d Domain, dst, stored, aad []byte) ([]byte, error) {
	if len(stored) < wire.AEADOverhead {
		return dst, fmt.Errorf("%w: %w: sealed value of %d bytes", wire.ErrCorrupt, ErrAuth, len(stored))
	}
	out, err := k.aead(d).Open(dst, stored[:12], stored[12:], aad)
	if err != nil {
		return dst, fmt.Errorf("%w: %w", wire.ErrCorrupt, ErrAuth)
	}
	return out, nil
}
