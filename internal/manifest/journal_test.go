package manifest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"stash/internal/vfs"
	"stash/internal/wire"
)

func newFS(t testing.TB) *vfs.CrashFS {
	c := vfs.NewCrashFS()
	c.MkdirAll("g/submanifests", 0o755)
	return c
}

func openJ(t testing.TB, fsys vfs.FS) (*Journal, OpenResult) {
	t.Helper()
	j, _, res, err := OpenJournal(fsys, "g", hdr(), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return j, res
}

func readManifest(t testing.TB, fsys vfs.FS) string {
	b, err := vfs.ReadFile(fsys, "g/"+ManifestName, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestJournalRoundTrip(t *testing.T) {
	c := newFS(t)
	j, _ := openJ(t, c)
	if err := j.Add("small", 1, loc1(1, 100)); err != nil {
		t.Fatal(err)
	}
	big := locN(2, 20000, 77) // needs several ADD_EXTENT lines
	if err := j.Add("big", 2, big); err != nil {
		t.Fatal(err)
	}
	if err := j.Del("small", 1); err != nil {
		t.Fatal(err)
	}
	tx, _ := j.Begin("stream", 3)
	tx.Extent(locN(3, 2, 0)[:1])
	tx.Extent(locN(3, 2, 0)[1:])
	tx.Commit()
	j.Sync()
	j.Close()
	text := readManifest(t, c)
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if len(line) > MaxLineBytes {
			t.Fatalf("line of %d bytes", len(line))
		}
	}
	if n := strings.Count(text, `"op":"ADD_EXTENT"`); n < 3 {
		t.Fatalf("%d ADD_EXTENT lines", n)
	}
	st, info, err := Load(c, "g", hdr(), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Torn != 0 || info.ValidEnd != int64(len(text)) {
		t.Fatal(info)
	}
	v, ok := st.Lookup("big")
	if !ok || v.Length != 20000*4096+77 || len(v.Loc) != 20001 {
		t.Fatalf("big: %v", ok)
	}
	if _, ok := st.Lookup("small"); ok {
		t.Fatal("deleted path live")
	}
	if v, _ := st.Lookup("stream"); v.Length != 8192 {
		t.Fatal(v)
	}
}

func TestWriterRules(t *testing.T) {
	c := newFS(t)
	j, _ := openJ(t, c)
	tx, err := j.Begin("p", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Add("p", 2, loc1(1, 1)); !errors.Is(err, ErrPathBusy) {
		t.Fatal(err)
	}
	if _, err := j.Begin("p", 2); !errors.Is(err, ErrPathBusy) {
		t.Fatal(err)
	}
	tx.Abort()
	if err := j.Add("p", 2, loc1(1, 1)); err != nil {
		t.Fatal(err)
	}
	// a commit the fold rejects (coverage gap) is aborted automatically
	tx, _ = j.Begin("q", 3)
	tx.Extent([]Loc{{Offset: 0, Length: 4096}, {Offset: 8192, Length: 1}})
	if err := tx.Commit(); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal(err)
	}
	if len(j.State().OpenTransactions()) != 0 {
		t.Fatal("rejected commit left the transaction open")
	}
	// invalid record is never written
	before := j.End()
	if err := j.Del("absent", 1); err == nil || j.End() != before {
		t.Fatal("invalid DEL written")
	}
	j.Sync()
	if _, _, err := Load(c, "g", hdr(), LoadOptions{}); err != nil {
		t.Fatalf("writer produced an invalid manifest: %v", err)
	}
}

// E1-1: crashes inside transactions never accumulate open transactions.
func TestColdStartAborts(t *testing.T) {
	c := newFS(t)
	for i := 0; i < 1100; i++ { // more than MAX_OPEN_TRANSACTIONS
		j, res := openJ(t, c)
		if i > 0 && len(res.Aborted) != 1 {
			t.Fatalf("round %d: aborted %d", i, len(res.Aborted))
		}
		tx, err := j.Begin(fmt.Sprintf("p%d", i%3), uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		tx.Extent(loc1(i, 1))
		j.Sync()
		j.Close() // "crash" without commit
	}
	st, _, err := Load(c, "g", hdr(), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.OpenTransactions()) != 1 || st.Aborted != 1099 {
		t.Fatal(len(st.OpenTransactions()), st.Aborted)
	}
}

// Synced records survive every crash; unsynced records survive only as an
// in-order prefix; the writer truncates the rest and continues.
func TestCrashTornManifest(t *testing.T) {
	var nul, unterminated int
	for seed := int64(0); seed < 300; seed++ {
		rng := rand.New(rand.NewSource(seed))
		c := newFS(t)
		j, _ := openJ(t, c)
		var written []string
		ver := uint64(1)
		add := func() {
			p := fmt.Sprintf("f%d", rng.Intn(5))
			if v, ok := j.State().Lookup(p); ok && rng.Intn(3) == 0 {
				j.Del(p, v.FileVer)
			} else {
				j.Add(p, ver, locN(int(ver), rng.Intn(40), uint64(rng.Intn(4000)+1)))
				ver++
			}
		}
		for i := 0; i < 5+rng.Intn(10); i++ {
			add()
		}
		j.Sync()
		synced := readManifest(t, c)
		for i := 0; i < 1+rng.Intn(10); i++ {
			add()
		}
		full := readManifest(t, c)
		_ = written
		after := c.Crash(vfs.CrashTear, rng)
		j2, st, res, err := OpenJournal(after, "g", hdr(), LoadOptions{})
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		switch res.Load.TornReason {
		case "NUL":
			nul++
		case "unterminated":
			unterminated++
		}
		kept := readManifest(t, after)
		if !strings.HasPrefix(kept, synced) || !strings.HasPrefix(full, kept) || !strings.HasSuffix(kept, "\n") && kept != "" {
			t.Fatalf("seed %d: kept %d bytes, synced %d, full %d", seed, len(kept), len(synced), len(full))
		}
		if err := j2.Add("after-crash", ver+100, loc1(1, 1)); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		j2.Sync()
		if _, _, err := Load(after, "g", hdr(), LoadOptions{}); err != nil {
			t.Fatalf("seed %d: reload: %v", seed, err)
		}
		_ = st
	}
	if nul == 0 || unterminated == 0 {
		t.Fatalf("crash model did not exercise both torn forms (NUL %d, unterminated %d)", nul, unterminated)
	}
}

func writeFile(t testing.TB, c vfs.FS, name string, data []byte) {
	if err := vfs.ReplaceFile(c, name, data); err != nil {
		t.Fatal(err)
	}
}

func line(t testing.TB, r *Record) string {
	b, err := AppendLine(nil, r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLinkedManifests(t *testing.T) {
	sub := line(t, &Record{Seq: 3, Op: OpAdd, Path: "s1", FileVer: 3, Loc: loc1(1, 1)}) +
		line(t, &Record{Seq: 5, Op: OpAdd, Path: "s2", FileVer: 5, Loc: loc1(2, 1)})
	digest := sha256.Sum256([]byte(sub))
	link := &Record{Seq: 2, Op: OpLinkManifest, Path: "submanifests/a.jsonl", HashID: uint8(wire.HashSHA256), Hash: digest, Lines: 2}
	mainText := line(t, &Record{Seq: 1, Op: OpAdd, Path: "m1", FileVer: 1, Loc: loc1(3, 1)}) + line(t, link) +
		line(t, &Record{Seq: 4, Op: OpDel, Path: "s1", FileVer: 3}) +
		line(t, &Record{Seq: 6, Op: OpAdd, Path: "m2", FileVer: 6, Loc: loc1(4, 1)})
	c := newFS(t)
	writeFile(t, c, "g/submanifests/a.jsonl", []byte(sub))
	writeFile(t, c, "g/"+ManifestName, []byte(mainText))
	var order []uint64
	st, info, err := LoadWith(c, "g", hdr(), LoadOptions{}, func(r *Record, _ int) { order = append(order, r.Seq) })
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(order) != "[1 2 3 4 5 6]" || info.Linked != 1 {
		t.Fatalf("merge order %v", order)
	}
	if p := st.Paths(); fmt.Sprint(p) != "[m1 m2 s2]" {
		t.Fatal(p)
	}

	bad := map[string]func() (mainText, sub string){
		"digest": func() (string, string) { return mainText, strings.Replace(sub, "s2", "s3", 1) },
		"lines": func() (string, string) {
			l := *link
			l.Lines = 3
			return strings.Replace(mainText, line(t, link), line(t, &l), 1), sub
		},
		"nested link": func() (string, string) {
			s := line(t, &Record{Seq: 3, Op: OpLinkManifest, Path: "submanifests/b.jsonl", HashID: 2, Hash: digest, Lines: 1})
			return relink(t, mainText, link, s), s
		},
		"seq not after link": func() (string, string) {
			s := line(t, &Record{Seq: 1, Op: OpAdd, Path: "z", FileVer: 9, Loc: loc1(1, 1)})
			return relink(t, mainText, link, s), s
		},
		"duplicate seq across files": func() (string, string) {
			s := line(t, &Record{Seq: 4, Op: OpAdd, Path: "z", FileVer: 9, Loc: loc1(1, 1)})
			return relink(t, mainText, link, s), s
		},
		"no final LF": func() (string, string) {
			s := strings.TrimSuffix(sub, "\n")
			l := *link
			l.Hash, l.Lines = sha256.Sum256([]byte(s)), 1
			return strings.Replace(mainText, line(t, link), line(t, &l), 1), s
		},
		"hash_id": func() (string, string) {
			l := *link
			l.HashID = 1
			return strings.Replace(mainText, line(t, link), line(t, &l), 1), sub
		},
		"linked twice": func() (string, string) {
			l := *link
			l.Seq = 7
			return mainText + line(t, &l), sub
		},
	}
	for why, mk := range bad {
		m, s := mk()
		c := newFS(t)
		writeFile(t, c, "g/submanifests/a.jsonl", []byte(s))
		if why == "nested link" {
			writeFile(t, c, "g/submanifests/b.jsonl", []byte(s))
		}
		writeFile(t, c, "g/"+ManifestName, []byte(m))
		if _, _, err := Load(c, "g", hdr(), LoadOptions{}); !errors.Is(err, wire.ErrCorrupt) {
			t.Errorf("%s: %v", why, err)
		}
	}
}

func relink(t *testing.T, mainText string, link *Record, sub string) string {
	l := *link
	l.Hash, l.Lines = sha256.Sum256([]byte(sub)), uint64(strings.Count(sub, "\n"))
	return strings.Replace(mainText, line(t, link), line(t, &l), 1)
}

func TestTornForms(t *testing.T) {
	good := line(t, &Record{Seq: 1, Op: OpAdd, Path: "a", FileVer: 1, Loc: loc1(1, 1)})
	cases := map[string]struct {
		text   string
		torn   bool
		reason string
	}{
		"unterminated":           {good + `{"seq":"2","op"`, true, "unterminated"},
		"NUL page then record":   {good + string(make([]byte, 100)) + strings.TrimPrefix(good, "{"), true, "NUL"},
		"huge unterminated tail": {good + string(bytes.Repeat([]byte{0}, 3<<20)), true, "unterminated"},
		"clean":                  {good, false, ""},
	}
	for why, tc := range cases {
		c := newFS(t)
		writeFile(t, c, "g/"+ManifestName, []byte(tc.text))
		st, info, err := Load(c, "g", hdr(), LoadOptions{})
		if err != nil {
			t.Fatalf("%s: %v", why, err)
		}
		if (info.Torn > 0) != tc.torn || info.TornReason != tc.reason || info.ValidEnd != int64(len(good)) || st.Records() != 1 {
			t.Fatalf("%s: %+v records %d", why, info, st.Records())
		}
	}
	// a complete line that fails validation is corruption, also at the end
	for why, text := range map[string]string{
		"bad last line":  good + "{\"seq\":\"2\"}\n",
		"over-long line": good + strings.Repeat("x", MaxLineBytes+1) + "\n",
	} {
		c := newFS(t)
		writeFile(t, c, "g/"+ManifestName, []byte(text))
		if _, _, err := Load(c, "g", hdr(), LoadOptions{}); !errors.Is(err, wire.ErrCorrupt) {
			t.Fatalf("%s: %v", why, err)
		}
	}
}

func TestSnapshotLimit(t *testing.T) {
	c := newFS(t)
	j, _ := openJ(t, c)
	j.Add("a", 1, loc1(1, 1))
	j.Sync()
	cut := j.End()
	j.Add("b", 2, loc1(2, 1))
	j.Sync()
	st, _, err := Load(c, "g", hdr(), LoadOptions{Limit: cut})
	if err != nil || len(st.Paths()) != 1 {
		t.Fatal(err, st.Paths())
	}
	if _, _, err := Load(c, "g", hdr(), LoadOptions{Limit: j.End() + 1}); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal("snapshot longer than file accepted")
	}
}

type failWrites struct{ vfs.FS }
type failFile struct{ vfs.File }

func (f failWrites) OpenFile(n string, fl int, p os.FileMode) (vfs.File, error) {
	x, err := f.FS.OpenFile(n, fl, p)
	if err != nil {
		return nil, err
	}
	return failFile{x}, nil
}

func (failFile) WriteAt([]byte, int64) (int, error) { return 0, errors.New("injected") }

func TestPoisonOnWriteError(t *testing.T) {
	c := newFS(t)
	openJ(t, c) // creates the file
	j, _, _, err := OpenJournal(failWrites{c}, "g", hdr(), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Add("a", 1, loc1(1, 1)); err == nil {
		t.Fatal("write error lost")
	}
	if err := j.Add("b", 2, loc1(1, 1)); !errors.Is(err, ErrPoisoned) {
		t.Fatal(err)
	}
	if err := j.Sync(); !errors.Is(err, ErrPoisoned) {
		t.Fatal(err)
	}
}

func BenchmarkAppendAdd(b *testing.B) {
	c := newFS(b)
	j, _ := openJ(b, c)
	l := locN(1, 16, 100)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := j.Add(fmt.Sprintf("p%d", i), uint64(i+1), l); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoad(b *testing.B) {
	c := newFS(b)
	j, _ := openJ(b, c)
	l := locN(1, 16, 100)
	for i := 0; i < 20000; i++ {
		j.Add(fmt.Sprintf("p%d", i%5000), uint64(i+1), l)
	}
	j.Sync()
	size := j.End()
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Load(c, "g", hdr(), LoadOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
