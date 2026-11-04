// Package manifest implements the manifest journal (SPEC §10): strict JSON
// records, the canonical writer form, journal files with torn-tail
// handling, the LINK_MANIFEST graph merged by seq, the live-state fold, and
// an appending writer.
package manifest

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"stash/internal/canonpath"
	"stash/internal/wire"
)

// MaxLineBytes is MAX_MANIFEST_LINE_BYTES, excluding the LF (§10.1).
const MaxLineBytes = 1 << 20

// Op is a manifest operation.
type Op uint8

const (
	OpAdd Op = iota + 1
	OpDel
	OpAddBegin
	OpAddExtent
	OpAddCommit
	OpAddAbort
	OpLinkManifest
	OpParityGroup
)

var opNames = map[Op]string{
	OpAdd: "ADD", OpDel: "DEL", OpAddBegin: "ADD_BEGIN", OpAddExtent: "ADD_EXTENT",
	OpAddCommit: "ADD_COMMIT", OpAddAbort: "ADD_ABORT", OpLinkManifest: "LINK_MANIFEST",
	OpParityGroup: "PARITY_GROUP",
}

var opByName = func() map[string]Op {
	m := map[string]Op{}
	for k, v := range opNames {
		m[v] = k
	}
	return m
}()

var encOps = map[string]bool{
	"ADD_ENC": true, "DEL_ENC": true, "ADD_BEGIN_ENC": true, "ADD_EXTENT_ENC": true,
	"ADD_COMMIT_ENC": true, "ADD_ABORT_ENC": true, "LINK_MANIFEST_ENC": true,
}

func (o Op) String() string {
	if s, ok := opNames[o]; ok {
		return s
	}
	return fmt.Sprintf("Op(%d)", uint8(o))
}

// fieldOrder lists the fields of each op in canonical order (§10.1.2);
// "ts" may follow.
var fieldOrder = map[Op][]string{
	OpAdd:          {"seq", "op", "path", "file_ver", "loc"},
	OpDel:          {"seq", "op", "path", "file_ver"},
	OpAddBegin:     {"seq", "op", "tx_id", "path", "file_ver"},
	OpAddExtent:    {"seq", "op", "tx_id", "extent_sequence", "loc"},
	OpAddCommit:    {"seq", "op", "tx_id", "extent_record_count", "extent_count"},
	OpAddAbort:     {"seq", "op", "tx_id"},
	OpLinkManifest: {"seq", "op", "path", "hash_id", "hash", "lines"},
	OpParityGroup:  {"seq", "op", "group_id", "members"},
}

// TxID is a transaction id (16 random bytes).
type TxID [16]byte

func (t TxID) String() string { return hex.EncodeToString(t[:]) }

// Loc is one location tuple [blob_ordinal, frame_hash, logical_offset,
// logical_length] (§9.1).
type Loc struct {
	Blob   uint8
	Hash   [32]byte
	Offset uint64
	Length uint64
}

// Member is one PARITY_GROUP member [blob_ordinal, frame_hash, group_index].
type Member struct {
	Blob       uint8
	Hash       [32]byte
	GroupIndex uint8
}

// Record is one decoded manifest record. Only the fields of its Op are
// meaningful.
type Record struct {
	Seq   uint64
	Op    Op
	HasTS bool
	TS    uint64

	Path    string // ADD, DEL, ADD_BEGIN, LINK_MANIFEST
	FileVer uint64 // ADD, DEL, ADD_BEGIN
	Loc     []Loc  // ADD, ADD_EXTENT

	TxID              TxID   // ADD_BEGIN, ADD_EXTENT, ADD_COMMIT, ADD_ABORT
	ExtentSequence    uint32 // ADD_EXTENT
	ExtentRecordCount uint32 // ADD_COMMIT
	ExtentCount       uint32 // ADD_COMMIT

	HashID uint8    // LINK_MANIFEST
	Hash   [32]byte // LINK_MANIFEST
	Lines  uint64   // LINK_MANIFEST

	GroupID uint32   // PARITY_GROUP
	Members []Member // PARITY_GROUP
}

// SubmanifestDir is the directory linked manifests live in (§10.6).
const SubmanifestDir = "submanifests/"

// DecodeLine parses and schema-checks one manifest line (without LF).
// encrypted selects the record form required by §10.1.2.
func DecodeLine(line []byte, encrypted bool) (*Record, error) {
	if len(line) > MaxLineBytes {
		return nil, corrupt("line of %d bytes exceeds MAX_MANIFEST_LINE_BYTES", len(line))
	}
	v, err := parseJSON(line)
	if err != nil {
		return nil, err
	}
	if v.kind != kObject {
		return nil, corrupt("top-level value is %v, not an object", v.kind)
	}
	var opName string
	for _, m := range v.obj {
		if m.key == "op" {
			if m.val.kind != kString {
				return nil, corrupt("op is not a string")
			}
			opName = m.val.s
		}
	}
	if opName == "" {
		return nil, corrupt("missing op")
	}
	op, ok := opByName[opName]
	switch {
	case encOps[opName] && !encrypted:
		return nil, corrupt("%s record in an unencrypted archive", opName)
	case encOps[opName]:
		return nil, &wire.Error{Struct: "Manifest", Field: "op", Class: wire.ErrUnsupported, Detail: opName + " needs the encryption layer (not implemented yet)"}
	case !ok:
		return nil, &wire.Error{Struct: "Manifest", Field: "op", Class: wire.ErrUnsupported, Detail: fmt.Sprintf("unknown op %q", opName)}
	case encrypted:
		return nil, corrupt("plaintext %s record in an encrypted archive", opName)
	}
	fields := map[string]value{}
	allowed := map[string]bool{"ts": true}
	for _, f := range fieldOrder[op] {
		allowed[f] = true
	}
	for _, m := range v.obj {
		if !allowed[m.key] {
			return nil, corrupt("%s: unknown key %q", op, m.key)
		}
		fields[m.key] = m.val
	}
	for _, f := range fieldOrder[op] {
		if _, ok := fields[f]; !ok {
			return nil, corrupt("%s: missing %q", op, f)
		}
	}
	d := decoder{f: fields, op: op}
	r := &Record{Op: op, Seq: d.dec("seq")}
	if _, ok := fields["ts"]; ok {
		r.HasTS, r.TS = true, d.dec("ts")
	}
	switch op {
	case OpAdd:
		r.Path, r.FileVer, r.Loc = d.path("path"), d.dec("file_ver"), d.locs("loc")
	case OpDel:
		r.Path, r.FileVer = d.path("path"), d.dec("file_ver")
	case OpAddBegin:
		r.TxID, r.Path, r.FileVer = d.tx("tx_id"), d.path("path"), d.dec("file_ver")
	case OpAddExtent:
		r.TxID, r.ExtentSequence, r.Loc = d.tx("tx_id"), uint32(d.int("extent_sequence", 1<<32-1)), d.locs("loc")
	case OpAddCommit:
		r.TxID = d.tx("tx_id")
		r.ExtentRecordCount = uint32(d.int("extent_record_count", 1<<32-1))
		r.ExtentCount = uint32(d.int("extent_count", 1<<32-1))
	case OpAddAbort:
		r.TxID = d.tx("tx_id")
	case OpLinkManifest:
		r.Path, r.HashID, r.Hash, r.Lines = d.path("path"), uint8(d.int("hash_id", 255)), d.hash(fields["hash"], "hash"), d.dec("lines")
		if d.err == nil && (!strings.HasPrefix(r.Path, SubmanifestDir) || len(r.Path) == len(SubmanifestDir)) {
			d.fail("path", "linked manifest %q is not beneath %s", r.Path, SubmanifestDir)
		}
	case OpParityGroup:
		r.GroupID = uint32(d.int("group_id", 1<<32-1))
		r.Members = d.members("members")
	}
	if d.err != nil {
		return nil, d.err
	}
	return r, nil
}

type decoder struct {
	f   map[string]value
	op  Op
	err error
}

func (d *decoder) fail(field, format string, args ...any) {
	if d.err == nil {
		d.err = &wire.Error{Struct: "Manifest", Field: field, Class: wire.ErrCorrupt, Detail: d.op.String() + ": " + fmt.Sprintf(format, args...)}
	}
}

// parseDecimal checks the uint64 decimal-string form 0|[1-9][0-9]*.
func parseDecimal(s string) (uint64, bool) {
	if s == "" || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func (d *decoder) decV(v value, field string) uint64 {
	if v.kind != kString {
		d.fail(field, "must be a decimal string, got %v", v.kind)
		return 0
	}
	n, ok := parseDecimal(v.s)
	if !ok {
		d.fail(field, "invalid decimal string %q", v.s)
	}
	return n
}

func (d *decoder) dec(field string) uint64 { return d.decV(d.f[field], field) }

// intV checks a JSON integer without sign, fraction or exponent, <= max.
func (d *decoder) intV(v value, field string, max uint64) uint64 {
	if v.kind != kNumber {
		d.fail(field, "must be a JSON integer, got %v", v.kind)
		return 0
	}
	n, ok := parseDecimal(v.s)
	if !ok || n > max {
		d.fail(field, "invalid integer %s (range 0..%d)", v.s, max)
	}
	return n
}

func (d *decoder) int(field string, max uint64) uint64 { return d.intV(d.f[field], field, max) }

func (d *decoder) path(field string) string {
	v := d.f[field]
	if v.kind != kString {
		d.fail(field, "must be a string")
		return ""
	}
	if err := canonpath.Validate(v.s); err != nil {
		d.fail(field, "%v", err)
	}
	return v.s
}

func lowerHex(s string, n int) ([]byte, bool) {
	if len(s) != 2*n {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

func (d *decoder) hash(v value, field string) [32]byte {
	if v.kind != kString {
		d.fail(field, "must be a string")
		return [32]byte{}
	}
	b, ok := lowerHex(v.s, 32)
	if !ok {
		d.fail(field, "must be 64 lowercase hex digits")
		return [32]byte{}
	}
	return [32]byte(b)
}

func (d *decoder) tx(field string) TxID {
	v := d.f[field]
	if v.kind != kString {
		d.fail(field, "must be a string")
		return TxID{}
	}
	b, ok := lowerHex(v.s, 16)
	if !ok {
		d.fail(field, "must be 32 lowercase hex digits")
		return TxID{}
	}
	return TxID(b)
}

func (d *decoder) locs(field string) []Loc {
	v := d.f[field]
	if v.kind != kArray || len(v.arr) == 0 {
		d.fail(field, "must be a non-empty array")
		return nil
	}
	out := make([]Loc, 0, len(v.arr))
	for _, e := range v.arr {
		if e.kind != kArray || len(e.arr) != 4 {
			d.fail(field, "element must be [blob_ordinal, frame_hash, logical_offset, logical_length]")
			return nil
		}
		out = append(out, Loc{
			Blob:   uint8(d.intV(e.arr[0], field, wire.MaxBlobOrdinal)),
			Hash:   d.hash(e.arr[1], field),
			Offset: d.decV(e.arr[2], field),
			Length: d.decV(e.arr[3], field),
		})
		if d.err != nil {
			return nil
		}
	}
	return out
}

func (d *decoder) members(field string) []Member {
	v := d.f[field]
	if v.kind != kArray || len(v.arr) == 0 {
		d.fail(field, "must be a non-empty array")
		return nil
	}
	out := make([]Member, 0, len(v.arr))
	for _, e := range v.arr {
		if e.kind != kArray || len(e.arr) != 3 {
			d.fail(field, "element must be [blob_ordinal, frame_hash, group_index]")
			return nil
		}
		out = append(out, Member{
			Blob:       uint8(d.intV(e.arr[0], field, wire.MaxBlobOrdinal)),
			Hash:       d.hash(e.arr[1], field),
			GroupIndex: uint8(d.intV(e.arr[2], field, 255)),
		})
		if d.err != nil {
			return nil
		}
	}
	return out
}
