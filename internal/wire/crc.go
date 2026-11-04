package wire

import "hash/crc32"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// CRC32C returns the Castagnoli CRC of the concatenation of parts.
func CRC32C(parts ...[]byte) uint32 {
	var c uint32
	for _, p := range parts {
		c = crc32.Update(c, castagnoli, p)
	}
	return c
}

// crcWithZeroField computes CRC32C over b with b[off:off+4] treated as zero.
func crcWithZeroField(b []byte, off int) uint32 {
	var zero [4]byte
	return CRC32C(b[:off], zero[:], b[off+4:])
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
