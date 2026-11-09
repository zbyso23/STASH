package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

type envGolden struct {
	DEK       string `json:"dek"`
	ArchiveID string `json:"archive_id"`
	Manifest  struct {
		GenerationID uint64 `json:"generation_id"`
		ChainStart   string `json:"chain_start"`
		LastPrev     string `json:"last_prev"`
		Lines        []struct {
			Seq             uint64
			Op, Plain, Line string
		}
	}
}

func loadEnv(t *testing.T) (envGolden, *Crypto) {
	t.Helper()
	b, err := os.ReadFile("../seal/testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g envGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	dek, _ := hex.DecodeString(g.DEK)
	id, _ := hex.DecodeString(g.ArchiveID)
	k, err := seal.New(dek, [32]byte(id))
	if err != nil {
		t.Fatal(err)
	}
	return g, &Crypto{Keys: k, GenerationID: g.Manifest.GenerationID}
}

func goldenRecords() []*Record {
	h1, h2 := sha256.Sum256([]byte("one")), sha256.Sum256([]byte("two"))
	tx, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	tx2, _ := hex.DecodeString("ffeeddccbbaa99887766554433221100")
	p := "photos/čtení \"q\".jpg"
	return []*Record{
		{Seq: 3, Op: OpAdd, Path: p, FileVer: 5, Loc: []Loc{{Blob: 1, Hash: h1, Length: 4096}}},
		{Seq: 4, Op: OpAddBegin, TxID: TxID(tx), Path: "big", FileVer: 6},
		{Seq: 9, Op: OpAddExtent, TxID: TxID(tx), Loc: []Loc{{Blob: 0, Hash: h1, Length: 4096}, {Blob: 2, Hash: h2, Offset: 4096, Length: 10}}},
		{Seq: 10, Op: OpAddCommit, TxID: TxID(tx), ExtentRecordCount: 1, ExtentCount: 2},
		{Seq: 11, Op: OpDel, Path: p, FileVer: 5},
		{Seq: 12, Op: OpAddAbort, TxID: TxID(tx2)},
	}
}

// §17.1/§15.8: envelopes from the independent generator are reproduced
// byte for byte (canonical plaintext, numeric nonce), decode with the
// chain, and the chain value continues across lines.
func TestEnvelopeGolden(t *testing.T) {
	g, c := loadEnv(t)
	prev := ChainStart(c.Keys.ArchiveID, ManifestName)
	if hex.EncodeToString(prev[:]) != g.Manifest.ChainStart {
		t.Fatal("chain start")
	}
	for i, r := range goldenRecords() {
		want := g.Manifest.Lines[i]
		plain, err := AppendPlain(nil, r, prev)
		if err != nil || string(plain) != want.Plain {
			t.Fatalf("%s plaintext:\n got %s\nwant %s (%v)", want.Op, plain, want.Plain, err)
		}
		line, err := AppendEnvelope(nil, r, c, prev)
		if err != nil || string(line) != want.Line+"\n" {
			t.Fatalf("%s envelope differs (%v)", want.Op, err)
		}
		got, err := DecodeEnvelope([]byte(want.Line), c, prev)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := AppendLine(nil, got)
		orig, _ := AppendLine(nil, r)
		if !bytes.Equal(again, orig) {
			t.Fatalf("decoded record differs: %s", again)
		}
		prev = LineHash([]byte(want.Line))
	}
	if hex.EncodeToString(prev[:]) != g.Manifest.LastPrev {
		t.Fatal("last chain value")
	}
}

// §17.9: the chain detects deletion, insertion, reordering and cross-file
// moves; nonce mismatch is rejected before decryption; plaintext records,
// extra keys and non-canonical base64 are rejected.
func TestEnvelopeRejects(t *testing.T) {
	g, c := loadEnv(t)
	lines := make([][]byte, len(g.Manifest.Lines))
	for i, l := range g.Manifest.Lines {
		lines[i] = []byte(l.Line)
	}
	decodeAll := func(ls [][]byte, file string) error {
		prev := ChainStart(c.Keys.ArchiveID, file)
		for _, l := range ls {
			if _, err := DecodeEnvelope(l, c, prev); err != nil {
				return err
			}
			prev = LineHash(l)
		}
		return nil
	}
	if err := decodeAll(lines, ManifestName); err != nil {
		t.Fatal(err)
	}
	cases := map[string][][]byte{
		"deletion":       {lines[0], lines[2], lines[3]},
		"insertion":      {lines[0], lines[1], lines[1], lines[2]},
		"reorder":        {lines[1], lines[0]},
		"truncated head": {lines[1]},
	}
	for name, ls := range cases {
		if err := decodeAll(ls, ManifestName); !errors.Is(err, wire.ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := decodeAll(lines, SubmanifestDir+"x.jsonl"); !errors.Is(err, wire.ErrCorrupt) {
		t.Error("cross-file move")
	}
	start := ChainStart(c.Keys.ArchiveID, ManifestName)
	mod := func(f func(string) string) []byte { return []byte(f(string(lines[0]))) }
	bad := map[string][]byte{
		"seq changed (nonce)": mod(func(s string) string { return strings.Replace(s, `"seq":"3"`, `"seq":"4"`, 1) }),
		"op changed (AAD)":    mod(func(s string) string { return strings.Replace(s, `"op":"ADD_ENC"`, `"op":"DEL_ENC"`, 1) }),
		"extra key":           mod(func(s string) string { return strings.Replace(s, `{"seq"`, `{"ts":"1","seq"`, 1) }),
		"plaintext":           []byte(`{"seq":"3","op":"DEL","path":"a","file_ver":"1"}`),
		"padding stripped":    mod(func(s string) string { return strings.Replace(s, `="}`, `"}`, 1) }),
		"wrong generation":    nil,
	}
	for name, l := range bad {
		cc := c
		if l == nil {
			cc = &Crypto{Keys: c.Keys, GenerationID: c.GenerationID + 1}
			l = lines[0]
		}
		if _, err := DecodeEnvelope(l, cc, start); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the nonce check happens before decryption: a nonce mismatch is
	// reported as such, not as an authentication failure
	_, err := DecodeEnvelope(bad["seq changed (nonce)"], c, start)
	if err == nil || !strings.Contains(err.Error(), "nonce does not match") {
		t.Errorf("nonce mismatch: %v", err)
	}
	if _, err := AppendEnvelope(nil, &Record{Seq: 1, Op: OpParityGroup, GroupID: 1, Members: []Member{{}}}, c, start); err == nil {
		t.Error("PARITY_GROUP emitted in an encrypted archive")
	}
}

func encHdr(c *Crypto) *wire.ArchiveHeader {
	h := hdr()
	h.Flags = wire.HeaderFlagEncrypted
	h.ArchiveID = c.Keys.ArchiveID
	h.GenerationID = c.GenerationID
	return h
}

// The journal writes envelopes, continues the chain across reopen and
// torn-tail truncation, splits large versions into transactions that fit,
// and a plaintext line appended to an encrypted manifest fails the load.
func TestEncryptedJournal(t *testing.T) {
	_, c := loadEnv(t)
	fsys := newFS(t)
	h := encHdr(c)
	seq := uint64(0)
	next := func() (uint64, error) { seq += 3; return seq, nil }
	open := func() (*Journal, *State) {
		j, st, _, err := OpenJournal(fsys, "g", h, LoadOptions{Crypto: c, SeqSource: next})
		if err != nil {
			t.Fatal(err)
		}
		return j, st
	}
	if _, _, _, err := OpenJournal(fsys, "g", h, LoadOptions{Crypto: c}); err == nil {
		t.Fatal("encrypted journal without a seq allocator")
	}
	if _, _, err := Load(fsys, "g", h, LoadOptions{}); err == nil {
		t.Fatal("encrypted manifest loaded without keys")
	}
	j, _ := open()
	if err := j.Add("a", 1, loc1(1, 100)); err != nil {
		t.Fatal(err)
	}
	big := locN(2, 15000, 5) // several ADD_EXTENT envelopes
	if err := j.Add("big", 2, big); err != nil {
		t.Fatal(err)
	}
	j.Sync()
	j.Close()
	for _, l := range strings.Split(strings.TrimSuffix(readManifest(t, fsys), "\n"), "\n") {
		if len(l) > MaxLineBytes || !strings.Contains(l, `_ENC","enc":"`) {
			t.Fatalf("bad line of %d bytes", len(l))
		}
	}
	j, st := open()
	if v, ok := st.Lookup("big"); !ok || len(v.Loc) != len(big) {
		t.Fatal("big")
	}
	if err := j.Del("a", 1); err != nil {
		t.Fatal(err)
	}
	j.Sync()
	j.Close()
	// a torn tail is cut and the chain continues from the last kept line
	f, _ := fsys.OpenFile("g/"+ManifestName, os.O_RDWR, 0)
	sz, _ := f.Size()
	f.WriteAt([]byte(`{"seq":"99","op":"ADD_E`), sz)
	f.Close()
	j, st = open()
	if _, ok := st.Lookup("a"); ok {
		t.Fatal("deleted path live")
	}
	if err := j.Add("c", 3, loc1(3, 7)); err != nil {
		t.Fatal(err)
	}
	j.Sync()
	j.Close()
	_, st = open()
	if _, ok := st.Lookup("c"); !ok {
		t.Fatal("record after torn tail")
	}
	// a plaintext record inserted into an encrypted manifest
	f, _ = fsys.OpenFile("g/"+ManifestName, os.O_RDWR, 0)
	sz, _ = f.Size()
	f.WriteAt([]byte("{\"seq\":\"999\",\"op\":\"DEL\",\"path\":\"c\",\"file_ver\":\"3\"}\n"), sz)
	f.Close()
	if _, _, err := Load(fsys, "g", h, LoadOptions{Crypto: c}); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatalf("plaintext record accepted: %v", err)
	}
	_ = vfs.ErrLocked
}
