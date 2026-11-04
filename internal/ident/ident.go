// Package ident computes payload hashes (SPEC §4) and object identifiers
// (§6.5).
package ident

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/zeebo/blake3"

	"stash/internal/wire"
)

// ObjectIDDomain prefixes every object_id message (§6.5).
const ObjectIDDomain = "STASH-OBJECT-ID-V2"

// Hash returns the archive hash of b (BLAKE3 or SHA-256, 32 bytes).
func Hash(id wire.HashID, b []byte) ([32]byte, error) {
	switch id {
	case wire.HashSHA256:
		return sha256.Sum256(b), nil
	case wire.HashBLAKE3:
		return blake3.Sum256(b), nil
	}
	return [32]byte{}, fmt.Errorf("stash: unsupported hash_id 0x%02x", uint8(id))
}

func objectIDMessage(path string, fileVer uint64) []byte {
	msg := make([]byte, 0, len(ObjectIDDomain)+len(path)+8)
	msg = append(msg, ObjectIDDomain...)
	msg = append(msg, path...)
	return binary.LittleEndian.AppendUint64(msg, fileVer)
}

// ObjectID returns object_id for an unencrypted archive:
// first 16 bytes of HASH(hash_id, msg).
func ObjectID(id wire.HashID, canonicalPath string, fileVer uint64) ([16]byte, error) {
	h, err := Hash(id, objectIDMessage(canonicalPath, fileVer))
	if err != nil {
		return [16]byte{}, err
	}
	return [16]byte(h[:16]), nil
}

// KeyedObjectID returns object_id for an encrypted archive:
// first 16 bytes of HMAC-SHA-256(objectid_key, msg), whatever the hash_id.
func KeyedObjectID(objectIDKey []byte, canonicalPath string, fileVer uint64) ([16]byte, error) {
	if len(objectIDKey) != 32 {
		return [16]byte{}, fmt.Errorf("stash: objectid_key must be 32 bytes, got %d", len(objectIDKey))
	}
	m := hmac.New(sha256.New, objectIDKey)
	m.Write(objectIDMessage(canonicalPath, fileVer))
	return [16]byte(m.Sum(nil)[:16]), nil
}
