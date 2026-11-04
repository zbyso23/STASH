package manifest

import (
	"bytes"
	"sync"
)

// decodeCanonical is the fast path of DecodeLine for plaintext lines in
// the canonical writer form (§10.1.1: fixed key order, no whitespace, no
// escapes in strings). It parses directly into a Record without building a
// JSON tree and then proves the result by re-encoding it: only when
// AppendLine reproduces the line byte for byte is the record returned.
// Anything else (non-canonical but valid input, escapes, other ops, errors)
// returns ok == false and DecodeLine takes the strict generic path, so the
// fast path can never accept a line the generic path would reject or decode
// differently.
func decodeCanonical(line []byte) (r *Record, ok bool) {
	c := cscan{b: line}
	r = &Record{}
	c.lit(`{"seq":`)
	r.Seq = c.dec()
	c.lit(`,"op":"`)
	switch {
	case c.try(`ADD","path":`):
		r.Op = OpAdd
		r.Path = c.str()
		c.lit(`,"file_ver":`)
		r.FileVer = c.dec()
		c.lit(`,"loc":`)
		r.Loc = c.locs()
	case c.try(`DEL","path":`):
		r.Op = OpDel
		r.Path = c.str()
		c.lit(`,"file_ver":`)
		r.FileVer = c.dec()
	case c.try(`ADD_EXTENT","tx_id":`):
		r.Op = OpAddExtent
		r.TxID = c.tx()
		c.lit(`,"extent_sequence":`)
		r.ExtentSequence = uint32(c.int(1<<32 - 1))
		c.lit(`,"loc":`)
		r.Loc = c.locs()
	case c.try(`ADD_BEGIN","tx_id":`):
		r.Op = OpAddBegin
		r.TxID = c.tx()
		c.lit(`,"path":`)
		r.Path = c.str()
		c.lit(`,"file_ver":`)
		r.FileVer = c.dec()
	case c.try(`ADD_COMMIT","tx_id":`):
		r.Op = OpAddCommit
		r.TxID = c.tx()
		c.lit(`,"extent_record_count":`)
		r.ExtentRecordCount = uint32(c.int(1<<32 - 1))
		c.lit(`,"extent_count":`)
		r.ExtentCount = uint32(c.int(1<<32 - 1))
	case c.try(`ADD_ABORT","tx_id":`):
		r.Op = OpAddAbort
		r.TxID = c.tx()
	default:
		return nil, false
	}
	if c.try(`,"ts":`) {
		r.HasTS, r.TS = true, c.dec()
	}
	c.lit(`}`)
	if c.bad || c.p != len(line) {
		return nil, false
	}
	buf := encPool.Get().(*[]byte)
	enc, err := AppendLine((*buf)[:0], r)
	same := err == nil && len(enc) == len(line)+1 && bytes.Equal(enc[:len(line)], line)
	*buf = enc[:0]
	encPool.Put(buf)
	if !same {
		return nil, false
	}
	return r, true
}

var encPool = sync.Pool{New: func() any { b := make([]byte, 0, 4096); return &b }}

// cscan scans the canonical form; any deviation sets bad.
type cscan struct {
	b   []byte
	p   int
	bad bool
}

func (c *cscan) try(s string) bool {
	if !c.bad && len(c.b)-c.p >= len(s) && string(c.b[c.p:c.p+len(s)]) == s {
		c.p += len(s)
		return true
	}
	return false
}

func (c *cscan) lit(s string) {
	if !c.try(s) {
		c.bad = true
	}
}

// digits parses 0|[1-9][0-9]* at most 20 digits; the round trip rejects
// overflow and non-canonical forms.
func (c *cscan) digits() uint64 {
	start := c.p
	var n uint64
	for c.p < len(c.b) && c.b[c.p] >= '0' && c.b[c.p] <= '9' && c.p-start < 20 {
		n = n*10 + uint64(c.b[c.p]-'0')
		c.p++
	}
	if c.p == start {
		c.bad = true
	}
	return n
}

func (c *cscan) dec() uint64 {
	c.lit(`"`)
	n := c.digits()
	c.lit(`"`)
	return n
}

func (c *cscan) int(max uint64) uint64 {
	n := c.digits()
	if n > max {
		c.bad = true
	}
	return n
}

// str reads a string without escapes or control characters.
func (c *cscan) str() string {
	c.lit(`"`)
	if c.bad {
		return ""
	}
	start := c.p
	for c.p < len(c.b) {
		switch b := c.b[c.p]; {
		case b == '"':
			s := string(c.b[start:c.p])
			c.p++
			return s
		case b == '\\' || b < 0x20:
			c.bad = true
			return ""
		}
		c.p++
	}
	c.bad = true
	return ""
}

func (c *cscan) hexInto(dst []byte) {
	if c.bad || len(c.b)-c.p < 2*len(dst) {
		c.bad = true
		return
	}
	for i := range dst {
		hi, ok1 := unhexLower(c.b[c.p])
		lo, ok2 := unhexLower(c.b[c.p+1])
		if !ok1 || !ok2 {
			c.bad = true
			return
		}
		dst[i] = hi<<4 | lo
		c.p += 2
	}
}

func unhexLower(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	}
	return 0, false
}

func (c *cscan) tx() (t TxID) {
	c.lit(`"`)
	c.hexInto(t[:])
	c.lit(`"`)
	return t
}

func (c *cscan) locs() []Loc {
	c.lit(`[`)
	n := 1 + bytes.Count(c.b[c.p:], []byte(`],[`))
	out := make([]Loc, 0, n)
	for !c.bad {
		var l Loc
		c.lit(`[`)
		l.Blob = uint8(c.int(0xFF))
		c.lit(`,"`)
		c.hexInto(l.Hash[:])
		c.lit(`",`)
		l.Offset = c.dec()
		c.lit(`,`)
		l.Length = c.dec()
		c.lit(`]`)
		out = append(out, l)
		if !c.try(`,`) {
			break
		}
	}
	c.lit(`]`)
	return out
}
