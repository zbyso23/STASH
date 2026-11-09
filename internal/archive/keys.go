package archive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"

	"stash/internal/manifest"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// KeyCheckName is the key-check file of an encrypted archive (E1-25):
// implementation-defined state outside the wire format, like the policy
// marker. It holds magic "STKEYCK1", the 32-byte key-check value
// HKDF-SHA-256(DEK, archive_id, "STASH-KEY-CHECK-R10") and a CRC32C, so a
// wrong DEK is refused before anything is read or written, even in an
// archive whose manifest is still empty.
const KeyCheckName = "key.check"

var keyCheckMagic = [8]byte{'S', 'T', 'K', 'E', 'Y', 'C', 'K', '1'}

// ErrKeyRequired reports an encrypted archive opened without its DEK.
var ErrKeyRequired = errors.New("encrypted archive: the archive DEK is required")

// ErrWrongKey reports a DEK that does not match the archive's key check.
var ErrWrongKey = errors.New("wrong archive DEK (key check failed)")

func encodeKeyCheck(k *seal.Keys) []byte {
	v := k.KeyCheck()
	b := append(append([]byte{}, keyCheckMagic[:]...), v[:]...)
	return binary.LittleEndian.AppendUint32(b, wire.CRC32C(b))
}

func writeKeyCheck(fsys vfs.FS, k *seal.Keys) error {
	return vfs.ReplaceFile(fsys, KeyCheckName, encodeKeyCheck(k))
}

// archiveKeys returns the key schedule for an archive with header h: nil
// for an unencrypted archive (a DEK is then refused), otherwise the keys
// derived from dek after the key check (§15.1, E1-25).
func archiveKeys(fsys vfs.FS, h *wire.ArchiveHeader, dek []byte) (*seal.Keys, error) {
	if !h.Encrypted() {
		if dek != nil {
			return nil, fmt.Errorf("%w: a DEK was given for an unencrypted archive", wire.ErrInvalid)
		}
		return nil, nil
	}
	if dek == nil {
		return nil, ErrKeyRequired
	}
	k, err := seal.New(dek, h.ArchiveID)
	if err != nil {
		return nil, err
	}
	b, err := vfs.ReadFile(fsys, KeyCheckName, 64)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s missing; the DEK cannot be checked", wire.ErrCorrupt, KeyCheckName)
	}
	if err != nil {
		return nil, err
	}
	if len(b) != 44 || [8]byte(b[:8]) != keyCheckMagic || binary.LittleEndian.Uint32(b[40:]) != wire.CRC32C(b[:40]) {
		return nil, fmt.Errorf("%w: %s damaged", wire.ErrCorrupt, KeyCheckName)
	}
	if !k.CheckKey(b[8:40]) {
		return nil, ErrWrongKey
	}
	return k, nil
}

// manifestCrypto is the manifest sealing context of generation h.
func manifestCrypto(h *wire.ArchiveHeader, k *seal.Keys) *manifest.Crypto {
	if k == nil {
		return nil
	}
	return &manifest.Crypto{Keys: k, GenerationID: h.GenerationID}
}

// RecoveryKeys derives the keys for raw recovery (§11.7): like the normal
// open, but a missing key.check file is tolerated (it may be lost with the
// rest of the archive root); the frames authenticate every byte anyway.
func RecoveryKeys(fsys vfs.FS, h *wire.ArchiveHeader, dek []byte) (*seal.Keys, error) {
	if dek == nil {
		return nil, nil // keyless (§15.10)
	}
	if !h.Encrypted() {
		return archiveKeys(fsys, h, dek)
	}
	if _, err := fsys.Stat(KeyCheckName); errors.Is(err, fs.ErrNotExist) {
		return seal.New(dek, h.ArchiveID)
	}
	return archiveKeys(fsys, h, dek)
}
