package manifest

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"stash/internal/canonpath"
	"stash/internal/wire"
)

// AppendLine appends the canonical writer form of r (§10.1.1) followed by
// LF. It validates r first, so a writer can never emit a record a reader
// rejects for its form; graph rules (seq order, transactions, versions) are
// checked by State.
func AppendLine(dst []byte, r *Record) ([]byte, error) {
	if err := r.validate(); err != nil {
		return dst, err
	}
	start := len(dst)
	b := append(dst, `{"seq":`...)
	b = appendDec(b, r.Seq)
	b = append(b, `,"op":"`...)
	b = append(b, r.Op.String()...)
	b = append(b, '"')
	b = appendFields(b, r)
	b = append(b, '}')
	if n := len(b) - start; n > MaxLineBytes {
		return dst, &wire.Error{Struct: "Manifest", Class: wire.ErrInvalid, Detail: fmt.Sprintf("record of %d bytes exceeds MAX_MANIFEST_LINE_BYTES", n)}
	}
	return append(b, '\n'), nil
}

// appendFields appends ,"field":value for every field of r after seq and
// op, in canonical order, ts last.
func appendFields(b []byte, r *Record) []byte {
	switch r.Op {
	case OpAdd:
		b = appendStrField(b, "path", r.Path)
		b = appendDecField(b, "file_ver", r.FileVer)
		b = appendLocs(b, r.Loc)
	case OpDel:
		b = appendStrField(b, "path", r.Path)
		b = appendDecField(b, "file_ver", r.FileVer)
	case OpAddBegin:
		b = appendStrField(b, "tx_id", r.TxID.String())
		b = appendStrField(b, "path", r.Path)
		b = appendDecField(b, "file_ver", r.FileVer)
	case OpAddExtent:
		b = appendStrField(b, "tx_id", r.TxID.String())
		b = appendIntField(b, "extent_sequence", uint64(r.ExtentSequence))
		b = appendLocs(b, r.Loc)
	case OpAddCommit:
		b = appendStrField(b, "tx_id", r.TxID.String())
		b = appendIntField(b, "extent_record_count", uint64(r.ExtentRecordCount))
		b = appendIntField(b, "extent_count", uint64(r.ExtentCount))
	case OpAddAbort:
		b = appendStrField(b, "tx_id", r.TxID.String())
	case OpLinkManifest:
		b = appendStrField(b, "path", r.Path)
		b = appendIntField(b, "hash_id", uint64(r.HashID))
		b = appendStrField(b, "hash", hex.EncodeToString(r.Hash[:]))
		b = appendDecField(b, "lines", r.Lines)
	case OpParityGroup:
		b = appendIntField(b, "group_id", uint64(r.GroupID))
		b = append(b, `,"members":[`...)
		for i, m := range r.Members {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, '[')
			b = strconv.AppendUint(b, uint64(m.Blob), 10)
			b = append(b, `,"`...)
			b = hex.AppendEncode(b, m.Hash[:])
			b = append(b, `",`...)
			b = strconv.AppendUint(b, uint64(m.GroupIndex), 10)
			b = append(b, ']')
		}
		b = append(b, ']')
	}
	if r.HasTS {
		b = appendDecField(b, "ts", r.TS)
	}
	return b
}

func appendDec(b []byte, v uint64) []byte {
	b = append(b, '"')
	b = strconv.AppendUint(b, v, 10)
	return append(b, '"')
}

func appendDecField(b []byte, k string, v uint64) []byte {
	b = append(b, ',', '"')
	b = append(b, k...)
	b = append(b, '"', ':')
	return appendDec(b, v)
}

func appendIntField(b []byte, k string, v uint64) []byte {
	b = append(b, ',', '"')
	b = append(b, k...)
	b = append(b, '"', ':')
	return strconv.AppendUint(b, v, 10)
}

func appendStrField(b []byte, k, v string) []byte {
	b = append(b, ',', '"')
	b = append(b, k...)
	b = append(b, '"', ':')
	return appendString(b, v)
}

// appendString escapes only '"', '\' and U+0000..U+001F (lowercase hex);
// everything else, including '/', is raw UTF-8 (§10.1.1).
func appendString(b []byte, s string) []byte {
	const hexd = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&15])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

func appendLocs(b []byte, locs []Loc) []byte {
	b = append(b, `,"loc":[`...)
	for i, l := range locs {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '[')
		b = strconv.AppendUint(b, uint64(l.Blob), 10)
		b = append(b, `,"`...)
		b = hex.AppendEncode(b, l.Hash[:])
		b = append(b, `",`...)
		b = appendDec(b, l.Offset)
		b = append(b, ',')
		b = appendDec(b, l.Length)
		b = append(b, ']')
	}
	return append(b, ']')
}

// validate checks what the line form requires.
func (r *Record) validate() error {
	bad := func(format string, args ...any) error {
		return &wire.Error{Struct: "Manifest", Class: wire.ErrInvalid, Detail: r.Op.String() + ": " + fmt.Sprintf(format, args...)}
	}
	if _, ok := opNames[r.Op]; !ok {
		return bad("unknown op")
	}
	switch r.Op {
	case OpAdd, OpDel, OpAddBegin, OpLinkManifest:
		if err := canonpath.Validate(r.Path); err != nil {
			return bad("%v", err)
		}
	}
	switch r.Op {
	case OpAdd, OpAddExtent:
		if len(r.Loc) == 0 {
			return bad("empty loc")
		}
		for _, l := range r.Loc {
			if l.Blob > wire.MaxBlobOrdinal {
				return bad("blob ordinal 0x%02X", l.Blob)
			}
		}
	case OpLinkManifest:
		if !strings.HasPrefix(r.Path, SubmanifestDir) || len(r.Path) == len(SubmanifestDir) {
			return bad("linked manifest %q is not beneath %s", r.Path, SubmanifestDir)
		}
	case OpParityGroup:
		if len(r.Members) == 0 {
			return bad("no members")
		}
		for _, m := range r.Members {
			if m.Blob > wire.MaxBlobOrdinal {
				return bad("blob ordinal 0x%02X", m.Blob)
			}
		}
	}
	return nil
}
