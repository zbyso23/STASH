package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"strings"
	"testing"

	"stash/internal/kvtab"
	"stash/internal/membudget"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// spillEnv is an environment whose state table flushes after every few
// records and whose load sorts spill at the smallest working set.
func spillEnv(fsys vfs.FS) *Env {
	b := membudget.New(64 << 20)
	return &Env{
		Budget:     b,
		Cache:      kvtab.NewCache(b, 1<<20),
		Scratch:    func() (vfs.FS, string, error) { return fsys, "scratch", nil },
		MemLimit:   4 << 10,
		SortMemory: 1,
	}
}

type stateDump struct {
	live    []string
	applied []string
	refs    []string
	txs     int
	maxVer  uint64
	lastSeq uint64
	records uint64
}

func dump(t *testing.T, st *State, paths []string, ids []TxID) stateDump {
	t.Helper()
	var d stateDump
	if err := st.Walk("", "", func(p string, v *Version) bool {
		d.live = append(d.live, fmt.Sprintf("%s@%d:%d/%d", p, v.FileVer, v.Length, len(v.Loc)))
		return true
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		m, ok, err := st.AppliedMax(p)
		if err != nil {
			t.Fatal(err)
		}
		d.applied = append(d.applied, fmt.Sprint(p, m, ok))
	}
	for b := uint8(0); b < 4; b++ {
		r, err := st.Refs(b)
		if err != nil {
			t.Fatal(err)
		}
		d.refs = append(d.refs, fmt.Sprint(len(r), r[:min(len(r), 3)]))
	}
	for _, id := range ids {
		ok, err := st.IsTxKnown(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			d.txs++
		}
	}
	d.maxVer, d.lastSeq, d.records = st.MaxFileVer(), st.LastSeq(), st.Records()
	return d
}

// A load that spills its sorts and its table yields exactly the state of
// an in-memory load: live versions, applied_max of deleted paths, loc
// references, transaction ids and the counters.
func TestSpilledLoadEquivalent(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a large journal")
	}
	c := newFS(t)
	j, _ := openJ(t, c)
	rng := rand.New(rand.NewSource(7))
	var paths []string
	for i := 0; i < 3000; i++ {
		paths = append(paths, fmt.Sprintf("d%02d/f%05d", i%37, i))
	}
	var ids []TxID
	ver := uint64(0)
	for i := 0; i < 20000; i++ {
		p := paths[rng.Intn(len(paths))]
		ver++
		switch k := rng.Intn(10); {
		case k < 5:
			if err := j.Add(p, ver, loc1(i, uint64(1+rng.Intn(5000)))); err != nil {
				t.Fatal(err)
			}
		case k < 7:
			if v, ok := j.State().look(p); ok {
				if err := j.Del(p, v.FileVer); err != nil {
					t.Fatal(err)
				}
			}
		case k < 9:
			tx, err := j.Begin(p, ver)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, tx.ID())
			tx.Extent(locN(i, 1+rng.Intn(3), 9))
			if k == 8 {
				tx.Abort()
			} else {
				tx.Commit()
			}
		case rng.Intn(8) == 0:
			// over a state chunk of locs
			if err := j.Add(p, ver, locN(i%50, 1500+rng.Intn(1200), 1)); err != nil {
				t.Fatal(err)
			}
		}
	}
	j.Sync()
	j.Close()

	mem, _, err := Load(c, "g", hdr(), LoadOptions{TrackRefs: true})
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	env := spillEnv(c)
	spl, _, err := Load(c, "g", hdr(), LoadOptions{TrackRefs: true, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	ents, err := c.ReadDir("scratch")
	if err != nil || len(ents) == 0 {
		t.Fatalf("no table files in scratch: %v", err)
	}
	a, b := dump(t, mem, paths, ids), dump(t, spl, paths, ids)
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("spilled state differs:\n%v\n%v", a, b)
	}
	if len(a.live) < 100 || a.txs != len(ids) {
		t.Fatalf("weak journal: %d live, %d/%d tx", len(a.live), a.txs, len(ids))
	}
	if hits, reads := env.Cache.Stats(); reads == 0 {
		t.Fatalf("state never read from scratch (%d hits)", hits)
	}
	spl.Close()
	if ents, _ := c.ReadDir("scratch"); len(ents) != 0 {
		t.Fatalf("%d table files left after Close", len(ents))
	}
}

// Rules about one path are checked in the per-path fold of a bounded load
// exactly as in journal order: a violation is corruption either way.
func TestFoldRejects(t *testing.T) {
	cases := []struct {
		name string
		recs []*Record
	}{
		{"del of absent path", []*Record{
			{Op: OpAdd, Path: "a", FileVer: 1, Loc: loc1(1, 1)},
			{Op: OpDel, Path: "b", FileVer: 1},
		}},
		{"del of an older version", []*Record{
			{Op: OpAdd, Path: "a", FileVer: 1, Loc: loc1(1, 1)},
			{Op: OpAdd, Path: "a", FileVer: 2, Loc: loc1(2, 1)},
			{Op: OpDel, Path: "a", FileVer: 1},
		}},
		{"file_ver not increasing", []*Record{
			{Op: OpAdd, Path: "a", FileVer: 5, Loc: loc1(1, 1)},
			{Op: OpAdd, Path: "b", FileVer: 6, Loc: loc1(1, 1)},
			{Op: OpAdd, Path: "a", FileVer: 4, Loc: loc1(2, 1)},
		}},
		{"tx_id reused", []*Record{
			{Op: OpAddBegin, Path: "a", FileVer: 1, TxID: tid(1)},
			{Op: OpAddAbort, TxID: tid(1)},
			{Op: OpAdd, Path: "z", FileVer: 2, Loc: loc1(1, 1)},
			{Op: OpAddBegin, Path: "b", FileVer: 3, TxID: tid(1)},
			{Op: OpAddAbort, TxID: tid(1)},
		}},
	}
	for _, tc := range cases {
		for _, spill := range []bool{false, true} {
			c := newFS(t)
			var text strings.Builder
			for i, r := range tc.recs {
				r.Seq = uint64(i + 1)
				text.WriteString(line(t, r))
			}
			writeFile(t, c, "g/"+ManifestName, []byte(text.String()))
			opt := LoadOptions{}
			if spill {
				opt.Env = spillEnv(c)
			}
			st, _, err := Load(c, "g", hdr(), opt)
			if !errors.Is(err, wire.ErrCorrupt) {
				if st != nil {
					st.Close()
				}
				t.Fatalf("%s (spill %v): %v", tc.name, spill, err)
			}
		}
	}
}

// The bytes of a table file in scratch space are authenticated: a change
// is an error, never state.
func TestScratchTamper(t *testing.T) {
	c := newFS(t)
	j, _ := openJ(t, c)
	for i := 0; i < 2000; i++ {
		if err := j.Add(fmt.Sprintf("p%04d", i), uint64(i+1), loc1(i, 10)); err != nil {
			t.Fatal(err)
		}
	}
	j.Sync()
	j.Close()
	env := spillEnv(c)
	st, _, err := Load(c, "g", hdr(), LoadOptions{Env: env})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ents, _ := c.ReadDir("scratch")
	if len(ents) == 0 {
		t.Fatal("nothing spilled")
	}
	for _, e := range ents {
		name := "scratch/" + e.Name()
		b, err := vfs.ReadFile(c, name, 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		for i := 40; i < len(b); i += 997 {
			b[i] ^= 0x10
		}
		f, err := c.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteAt(b, 0)
		f.Close()
	}
	// a fresh cache, so blocks are read again
	env.Cache.Close()
	*env.Cache = *kvtab.NewCache(env.Budget, 1<<20)
	err = st.Walk("", "", func(string, *Version) bool { return true })
	if !errors.Is(err, kvtab.ErrTampered) {
		t.Fatalf("walk over tampered scratch: %v", err)
	}
	if _, _, err := st.Lookup("p1000"); !errors.Is(err, kvtab.ErrTampered) {
		t.Fatalf("lookup over tampered scratch: %v", err)
	}
}

func TestWalkPrefixStart(t *testing.T) {
	for _, spill := range []bool{false, true} {
		c := newFS(t)
		j, _ := openJ(t, c)
		names := []string{"a", "a/b", "a/c/d", "a0", "ab", "b/x", "b/y", "c"}
		for i, n := range names {
			if err := j.Add(n, uint64(i+1), loc1(i, 1)); err != nil {
				t.Fatal(err)
			}
		}
		j.Del("b/x", 6)
		j.Sync()
		j.Close()
		opt := LoadOptions{}
		if spill {
			opt.Env = spillEnv(c)
			opt.Env.MemLimit = 1
		}
		st, _, err := Load(c, "g", hdr(), opt)
		if err != nil {
			t.Fatal(err)
		}
		walk := func(prefix, start string, stop int) string {
			var out []string
			err := st.Walk(prefix, start, func(p string, _ *Version) bool {
				out = append(out, p)
				return len(out) != stop
			})
			if err != nil {
				t.Fatal(err)
			}
			return strings.Join(out, " ")
		}
		for _, w := range []struct{ prefix, start, want string }{
			{"", "", "a a/b a/c/d a0 ab b/y c"},
			{"a/", "", "a/b a/c/d"},
			{"a", "", "a a/b a/c/d a0 ab"},
			{"a/", "a/c", "a/c/d"},
			{"", "a0", "a0 ab b/y c"},
			{"b/", "", "b/y"},
			{"", "c0", ""},
			{"a/", "b", ""},
		} {
			if got := walk(w.prefix, w.start, -1); got != w.want {
				t.Errorf("spill %v Walk(%q,%q) = %q, want %q", spill, w.prefix, w.start, got, w.want)
			}
		}
		if got := walk("", "", 2); got != "a a/b" {
			t.Errorf("early stop: %q", got)
		}
		st.Close()
		if _, err := c.ReadDir("scratch"); spill && err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
}
