package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"testing"

	"stash/internal/wire"
)

type goldenFile struct {
	Records []struct {
		Record map[string]json.RawMessage `json:"record"`
		Line   string                     `json:"line"`
	} `json:"records"`
	Accept []struct {
		Line      string `json:"line"`
		Canonical string `json:"canonical"`
	} `json:"accept"`
	Reject []struct {
		Why string `json:"why"`
		Hex string `json:"hex"`
	} `json:"reject"`
}

func loadGolden(t testing.TB) goldenFile {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// recordFromGolden builds a Record from the generator's structured input.
func recordFromGolden(t *testing.T, m map[string]json.RawMessage) *Record {
	num := func(k string) uint64 {
		var n json.Number
		d := json.NewDecoder(bytes.NewReader(m[k]))
		d.UseNumber()
		if err := d.Decode(&n); err != nil {
			t.Fatal(k, err)
		}
		v, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil {
			t.Fatal(k, err)
		}
		return v
	}
	str := func(k string) string {
		var s string
		json.Unmarshal(m[k], &s)
		return s
	}
	h32 := func(s string) [32]byte { b, _ := hex.DecodeString(s); return [32]byte(b) }
	r := &Record{Op: opByName[str("op")], Seq: num("seq")}
	if _, ok := m["ts"]; ok {
		r.HasTS, r.TS = true, num("ts")
	}
	if _, ok := m["path"]; ok {
		r.Path = str("path")
	}
	if _, ok := m["file_ver"]; ok {
		r.FileVer = num("file_ver")
	}
	if _, ok := m["tx_id"]; ok {
		b, _ := hex.DecodeString(str("tx_id"))
		r.TxID = TxID(b)
	}
	for k, dst := range map[string]*uint32{"extent_sequence": &r.ExtentSequence, "extent_record_count": &r.ExtentRecordCount, "extent_count": &r.ExtentCount, "group_id": &r.GroupID} {
		if _, ok := m[k]; ok {
			*dst = uint32(num(k))
		}
	}
	if _, ok := m["hash_id"]; ok {
		r.HashID, r.Hash, r.Lines = uint8(num("hash_id")), h32(str("hash")), num("lines")
	}
	if raw, ok := m["loc"]; ok {
		var l [][4]json.RawMessage
		json.Unmarshal(raw, &l)
		for _, e := range l {
			r.Loc = append(r.Loc, Loc{Blob: uint8(rawU(t, e[0])), Hash: h32(rawS(e[1])), Offset: rawU(t, e[2]), Length: rawU(t, e[3])})
		}
	}
	if raw, ok := m["members"]; ok {
		var l [][3]json.RawMessage
		json.Unmarshal(raw, &l)
		for _, e := range l {
			r.Members = append(r.Members, Member{Blob: uint8(rawU(t, e[0])), Hash: h32(rawS(e[1])), GroupIndex: uint8(rawU(t, e[2]))})
		}
	}
	return r
}

func rawU(t *testing.T, m json.RawMessage) uint64 {
	v, err := strconv.ParseUint(string(m), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func rawS(m json.RawMessage) string {
	var s string
	json.Unmarshal(m, &s)
	return s
}

func TestGoldenCanonicalEncoding(t *testing.T) {
	g := loadGolden(t)
	for _, c := range g.Records {
		r := recordFromGolden(t, c.Record)
		got, err := AppendLine(nil, r)
		if err != nil {
			t.Fatalf("%s: %v", c.Line, err)
		}
		if string(got) != c.Line+"\n" {
			t.Fatalf("encoder\n got %s\nwant %s", got, c.Line)
		}
		back, err := DecodeLine([]byte(c.Line), false)
		if err != nil {
			t.Fatalf("decode %s: %v", c.Line, err)
		}
		if !reflect.DeepEqual(back, r) {
			t.Fatalf("decode differs:\n got %+v\nwant %+v", back, r)
		}
	}
}

func TestGoldenAcceptReject(t *testing.T) {
	g := loadGolden(t)
	for _, c := range g.Accept {
		r, err := DecodeLine([]byte(c.Line), false)
		if err != nil {
			t.Fatalf("valid line rejected: %s: %v", c.Line, err)
		}
		got, _ := AppendLine(nil, r)
		if string(got) != c.Canonical+"\n" {
			t.Fatalf("re-encoding\n got %s\nwant %s", got, c.Canonical)
		}
	}
	for _, c := range g.Reject {
		line, _ := hex.DecodeString(c.Hex)
		_, err := DecodeLine(line, false)
		if err == nil {
			t.Errorf("%s: accepted %q", c.Why, line)
			continue
		}
		if !errors.Is(err, wire.ErrCorrupt) && !errors.Is(err, wire.ErrUnsupported) {
			t.Errorf("%s: wrong class %v", c.Why, err)
		}
	}
}

func TestEncryptedFormSelection(t *testing.T) {
	plain := []byte(`{"seq":"1","op":"DEL","path":"a","file_ver":"1"}`)
	if _, err := DecodeLine(plain, true); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatalf("plaintext record in encrypted archive: %v", err)
	}
	if _, err := DecodeLine([]byte(`{"seq":"1","op":"DEL_ENC","enc":"x"}`), true); !errors.Is(err, wire.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := DecodeLine([]byte(`{"seq":"1","op":"RENAME"}`), false); !errors.Is(err, wire.ErrUnsupported) {
		t.Fatal("unknown op must fail closed as unsupported")
	}
}

func TestStringEscaping(t *testing.T) {
	got := string(appendString(nil, "a\"b\\c\x00\x1f/é\x7f"))
	if got != `"a\"b\\c\u0000\u001f/é`+"\x7f"+`"` {
		t.Fatal(got)
	}
	v, err := parseJSON([]byte(got))
	if err != nil || v.s != "a\"b\\c\x00\x1f/é\x7f" {
		t.Fatal(v.s, err)
	}
}

func TestLineLimit(t *testing.T) {
	long := append([]byte(`{"seq":"1","op":"DEL","path":"`), bytes.Repeat([]byte("a"), MaxLineBytes)...)
	long = append(long, `","file_ver":"1"}`...)
	if _, err := DecodeLine(long, false); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal(err)
	}
	deep := bytes.Repeat([]byte("["), 50)
	if _, err := parseJSON(deep); err == nil {
		t.Fatal("deep nesting accepted")
	}
}

func FuzzDecodeLine(f *testing.F) {
	g := loadGolden(f)
	for _, c := range g.Records {
		f.Add([]byte(c.Line))
	}
	for _, c := range g.Reject {
		b, _ := hex.DecodeString(c.Hex)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeLine(b, false)
		if err != nil {
			return
		}
		// every accepted record re-encodes canonically and decodes equal
		line, err := AppendLine(nil, r)
		if err != nil {
			t.Fatalf("accepted record does not encode: %v", err)
		}
		r2, err := DecodeLine(line[:len(line)-1], false)
		if err != nil || !reflect.DeepEqual(r, r2) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
