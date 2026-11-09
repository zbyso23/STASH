package manifest

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"stash/internal/seal"
	"stash/internal/wire"
)

// Encrypted manifest records (§15.8): every line of an encrypted archive is
// an envelope {"seq":"N","op":"<OP>_ENC","enc":"<base64>"} whose plaintext
// is the record without seq and op plus "prev", the chain value.

// Crypto is the manifest sealing context of one generation.
type Crypto struct {
	Keys         *seal.Keys
	GenerationID uint64
}

// ChainStart is prev of the first line of a manifest file (§15.8.2):
// SHA-256(archive_id || relative path).
func ChainStart(archiveID [32]byte, relPath string) [32]byte {
	h := sha256.New()
	h.Write(archiveID[:])
	h.Write([]byte(relPath))
	return [32]byte(h.Sum(nil))
}

// LineHash is the chain value a line passes on: SHA-256 of its exact
// bytes without LF.
func LineHash(line []byte) [32]byte { return sha256.Sum256(line) }

// envelopeOverhead is the stored line without the base64 text, for the
// widest seq and op.
var envelopeOverhead = len(`{"seq":"18446744073709551615","op":"LINK_MANIFEST_ENC","enc":""}`)

// MaxEnvelopePlain is the largest envelope plaintext whose stored line fits
// MAX_MANIFEST_LINE_BYTES for any seq and op.
var MaxEnvelopePlain = (MaxLineBytes-envelopeOverhead)/4*3 - wire.AEADOverhead

// AppendPlain appends the canonical envelope plaintext of r (§10.1.1): the
// op's fields in listed order, then prev.
func AppendPlain(dst []byte, r *Record, prev [32]byte) ([]byte, error) {
	if err := r.validate(); err != nil {
		return dst, err
	}
	if r.Op == OpParityGroup {
		return dst, &wire.Error{Struct: "Manifest", Class: wire.ErrInvalid, Detail: "PARITY_GROUP must not be emitted in an encrypted archive"}
	}
	start := len(dst)
	b := appendFields(dst, r)
	b[start] = '{' // replaces the leading comma
	b = append(b, `,"prev":"`...)
	b = appendHex(b, prev[:])
	return append(b, `"}`...), nil
}

func appendHex(b, x []byte) []byte {
	const digits = "0123456789abcdef"
	for _, c := range x {
		b = append(b, digits[c>>4], digits[c&15])
	}
	return b
}

// AppendEnvelope appends the stored envelope line of r (with LF). r.Seq
// must be set; prev is the chain value of the previous line of the file.
func AppendEnvelope(dst []byte, r *Record, c *Crypto, prev [32]byte) ([]byte, error) {
	var stack [1024]byte
	plain, err := AppendPlain(stack[:0], r, prev)
	if err != nil {
		return dst, err
	}
	nonce, err := seal.ManifestNonce(c.GenerationID, r.Seq)
	if err != nil {
		return dst, err
	}
	op := r.Op.String() + "_ENC"
	aad := seal.ManifestAAD(nil, c.Keys.ArchiveID, c.GenerationID, r.Seq, op)
	sealed := c.Keys.Seal(seal.ManifestDomain, nil, nonce, plain, aad)
	start := len(dst)
	b := append(dst, `{"seq":`...)
	b = appendDec(b, r.Seq)
	b = append(b, `,"op":"`...)
	b = append(b, op...)
	b = append(b, `","enc":"`...)
	b = base64.StdEncoding.AppendEncode(b, sealed)
	b = append(b, `"}`...)
	if n := len(b) - start; n > MaxLineBytes {
		return dst, &wire.Error{Struct: "Manifest", Class: wire.ErrInvalid, Detail: fmt.Sprintf("envelope of %d bytes exceeds MAX_MANIFEST_LINE_BYTES", n)}
	}
	return append(b, '\n'), nil
}

// EnvelopeLen returns the stored line length (without LF) of an envelope
// whose plaintext has n bytes and whose seq has the widest encoding.
func EnvelopeLen(op Op, n int) int {
	return len(`{"seq":"18446744073709551615","op":"_ENC","enc":""}`) + len(op.String()) + base64.StdEncoding.EncodedLen(n+wire.AEADOverhead)
}

// DecodeEnvelope parses, authenticates and decrypts one envelope line
// (without LF) of generation c.GenerationID whose expected chain value is
// prev (§15.8): exact envelope keys, canonical base64, nonce equal to
// manifest_nonce(generation_id, seq) checked before decryption, AAD, then
// the plaintext record with its prev verified.
func DecodeEnvelope(line []byte, c *Crypto, prev [32]byte) (*Record, error) {
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
	f := map[string]value{}
	for _, m := range v.obj {
		switch m.key {
		case "seq", "op", "enc":
			f[m.key] = m.val
		default:
			if m.key == "path" || m.key == "file_ver" || m.key == "loc" || m.key == "tx_id" {
				return nil, corrupt("plaintext record in an encrypted archive")
			}
			return nil, corrupt("envelope: unknown key %q", m.key)
		}
	}
	opv, ok := f["op"]
	if !ok || opv.kind != kString {
		return nil, corrupt("envelope: missing op")
	}
	if !encOps[opv.s] {
		if _, plain := opByName[opv.s]; plain {
			return nil, corrupt("plaintext %s record in an encrypted archive", opv.s)
		}
		return nil, &wire.Error{Struct: "Manifest", Field: "op", Class: wire.ErrUnsupported, Detail: fmt.Sprintf("unknown op %q", opv.s)}
	}
	op := opByName[opv.s[:len(opv.s)-4]]
	if len(f) != 3 {
		return nil, corrupt("%s: envelope needs exactly seq, op, enc", opv.s)
	}
	d := decoder{f: f, op: op}
	seq := d.dec("seq")
	if d.err != nil {
		return nil, d.err
	}
	encv := f["enc"]
	if encv.kind != kString {
		return nil, corrupt("%s: enc is not a string", opv.s)
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(encv.s)
	if err != nil || base64.StdEncoding.EncodeToString(sealed) != encv.s {
		return nil, corrupt("%s: enc is not canonical base64", opv.s)
	}
	if len(sealed) < wire.AEADOverhead {
		return nil, corrupt("%s: enc shorter than nonce and tag", opv.s)
	}
	nonce, err := seal.ManifestNonce(c.GenerationID, seq)
	if err != nil {
		return nil, err
	}
	if [12]byte(sealed[:12]) != nonce {
		return nil, corrupt("%s seq %d: nonce does not match (generation_id, seq)", opv.s, seq)
	}
	aad := seal.ManifestAAD(nil, c.Keys.ArchiveID, c.GenerationID, seq, opv.s)
	plain, err := c.Keys.Open(seal.ManifestDomain, nil, sealed, aad)
	if err != nil {
		return nil, &wire.Error{Struct: "Manifest", Field: "enc", Class: wire.ErrCorrupt, Detail: fmt.Sprintf("%s seq %d: %v", opv.s, seq, err)}
	}
	pv, err := parseJSON(plain)
	if err != nil {
		return nil, err
	}
	if pv.kind != kObject {
		return nil, corrupt("%s: plaintext is not an object", opv.s)
	}
	r, got, err := recordFrom(pv.obj, op, true)
	if err != nil {
		return nil, err
	}
	if got != prev {
		return nil, corrupt("%s seq %d: manifest chain broken (prev mismatch)", opv.s, seq)
	}
	r.Seq = seq
	return r, nil
}
