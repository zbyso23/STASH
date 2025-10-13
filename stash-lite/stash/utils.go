package stash

import (
    "crypto/sha256"
    "encoding/hex"
)

// HashSHA256Hex computes the SHA-256 hash of the provided byte slice and returns
// the result as a lowercase hexadecimal string. This helper avoids repeated
// boilerplate throughout the codebase.
func HashSHA256Hex(data []byte) string {
    sum := sha256.Sum256(data)
    return hex.EncodeToString(sum[:])
}