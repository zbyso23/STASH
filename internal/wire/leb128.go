package wire

// AppendPathLen appends canonical unsigned LEB128 for a path length
// (§6.4.1). n must be 1..4096.
func AppendPathLen(dst []byte, n int) ([]byte, error) {
	if n < 1 || n > MaxPathLen {
		return dst, errf(ErrInvalid, "LEB128", "path_len", "%d", n)
	}
	if n < 0x80 {
		return append(dst, byte(n)), nil
	}
	return append(dst, byte(n&0x7f)|0x80, byte(n>>7)), nil
}

// DecodePathLen decodes a canonical LEB128 path length of at most two bytes
// with value 1..4096. It returns the value and the number of bytes read.
func DecodePathLen(b []byte) (int, int, error) {
	const st = "LEB128"
	if len(b) == 0 {
		return 0, 0, errf(ErrCorrupt, st, "path_len", "truncated")
	}
	b0 := b[0]
	if b0&0x80 == 0 {
		if b0 == 0 {
			return 0, 0, errf(ErrCorrupt, st, "path_len", "zero")
		}
		return int(b0), 1, nil
	}
	if len(b) < 2 {
		return 0, 0, errf(ErrCorrupt, st, "path_len", "truncated")
	}
	b1 := b[1]
	if b1&0x80 != 0 {
		return 0, 0, errf(ErrCorrupt, st, "path_len", "more than two bytes")
	}
	if b1 == 0 {
		return 0, 0, errf(ErrCorrupt, st, "path_len", "non-canonical encoding")
	}
	n := int(b0&0x7f) | int(b1)<<7
	if n > MaxPathLen {
		return 0, 0, errf(ErrCorrupt, st, "path_len", "%d > 4096", n)
	}
	return n, 2, nil
}
