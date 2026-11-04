package manifest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"stash/internal/wire"
)

func hdr() *wire.ArchiveHeader {
	h := &wire.ArchiveHeader{Mode: wire.ModeVariable, HashID: wire.HashSHA256, BlobCount: 4, MaxFrameQuanta: 1024, GenerationID: 1}
	if err := h.Validate(); err != nil {
		panic(err)
	}
	return h
}

func hsh(i int) (h [32]byte) {
	h[0], h[1] = byte(i), byte(i>>8)
	h[31] = 0xAA
	return
}

// one-extent loc of n bytes
func loc1(i int, n uint64) []Loc { return []Loc{{Blob: uint8(i % 4), Hash: hsh(i), Length: n}} }

// k extents of 4096 bytes plus a final one of tail bytes
func locN(i, k int, tail uint64) []Loc {
	var out []Loc
	for j := 0; j < k; j++ {
		out = append(out, Loc{Blob: uint8(j % 4), Hash: hsh(i*100000 + j), Offset: uint64(j) * 4096, Length: 4096})
	}
	if tail > 0 {
		out = append(out, Loc{Hash: hsh(i*100000 + k), Offset: uint64(k) * 4096, Length: tail})
	}
	return out
}

type seqr struct {
	t  *testing.T
	st *State
	n  uint64
}

func newSeqr(t *testing.T) *seqr { return &seqr{t: t, st: NewState(hdr(), Limits{})} }

func (s *seqr) apply(r *Record) error {
	s.n++
	r.Seq = s.n
	return s.st.Apply(r, 0)
}

func (s *seqr) ok(r *Record) {
	s.t.Helper()
	if err := s.apply(r); err != nil {
		s.t.Fatal(err)
	}
}

func (s *seqr) corrupt(r *Record, why string) {
	s.t.Helper()
	before := s.st.Records()
	if err := s.apply(r); !errors.Is(err, wire.ErrCorrupt) {
		s.t.Fatalf("%s: want corruption, got %v", why, err)
	}
	if s.st.Records() != before {
		s.t.Fatalf("%s: rejected record changed state", why)
	}
}

func tid(i byte) TxID { return TxID{i, 1, 2, 3} }

func TestFoldAddDel(t *testing.T) {
	s := newSeqr(t)
	s.ok(&Record{Op: OpAdd, Path: "a", FileVer: 5, Loc: loc1(1, 10)})
	s.ok(&Record{Op: OpAdd, Path: "a", FileVer: 6, Loc: loc1(2, 0)})
	if v, _ := s.st.Lookup("a"); v.FileVer != 6 || v.Length != 0 {
		t.Fatal(v)
	}
	s.corrupt(&Record{Op: OpAdd, Path: "a", FileVer: 6, Loc: loc1(3, 1)}, "same file_ver")
	s.corrupt(&Record{Op: OpDel, Path: "a", FileVer: 5}, "DEL of a dead version")
	s.corrupt(&Record{Op: OpDel, Path: "b", FileVer: 1}, "DEL of absent path")
	s.ok(&Record{Op: OpDel, Path: "a", FileVer: 6})
	s.corrupt(&Record{Op: OpAdd, Path: "a", FileVer: 6, Loc: loc1(3, 1)}, "re-add below applied_max")
	s.ok(&Record{Op: OpAdd, Path: "a", FileVer: 7, Loc: loc1(3, 1)})
	if p := s.st.Paths(); len(p) != 1 {
		t.Fatal(p)
	}
	// seq must increase
	if err := s.st.Apply(&Record{Op: OpDel, Seq: 1, Path: "a", FileVer: 7}, 0); !errors.Is(err, wire.ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestLocRules(t *testing.T) {
	s := newSeqr(t)
	max := hdr().MaxFrameSize()
	bad := map[string][]Loc{
		"gap":            {{Offset: 0, Length: 4096}, {Offset: 8192, Length: 1}},
		"overlap":        {{Offset: 0, Length: 8192}, {Offset: 4096, Length: 4096}},
		"not from 0":     {{Offset: 4096, Length: 1}},
		"unaligned":      {{Offset: 0, Length: 4000}, {Offset: 4000, Length: 1}},
		"zero in middle": {{Offset: 0, Length: 0}, {Offset: 0, Length: 1}},
		"too long":       {{Offset: 0, Length: max + 1}},
		"blob count":     {{Blob: 4, Offset: 0, Length: 1}},
	}
	for why, l := range bad {
		s.corrupt(&Record{Op: OpAdd, Path: "x", FileVer: 1, Loc: l}, why)
	}
	// order inside loc carries no meaning (§9.2)
	s.ok(&Record{Op: OpAdd, Path: "x", FileVer: 1, Loc: []Loc{{Offset: 4096, Length: 3}, {Offset: 0, Length: 4096}}})
	if v, _ := s.st.Lookup("x"); v.Length != 4099 || v.Loc[0].Offset != 0 {
		t.Fatal(v)
	}
}

func TestTransactions(t *testing.T) {
	s := newSeqr(t)
	A, B := tid(1), tid(2)
	s.ok(&Record{Op: OpAddBegin, TxID: A, Path: "big", FileVer: 10})
	s.ok(&Record{Op: OpAddBegin, TxID: B, Path: "other", FileVer: 11})
	s.ok(&Record{Op: OpAddExtent, TxID: A, ExtentSequence: 1, Loc: []Loc{{Offset: 4096, Length: 5}}})
	s.ok(&Record{Op: OpAddExtent, TxID: B, ExtentSequence: 0, Loc: loc1(9, 1)})
	s.ok(&Record{Op: OpAddExtent, TxID: A, ExtentSequence: 0, Loc: []Loc{{Offset: 0, Length: 4096}}})
	if _, ok := s.st.Lookup("big"); ok {
		t.Fatal("visible before commit")
	}
	s.ok(&Record{Op: OpAddCommit, TxID: A, ExtentRecordCount: 2, ExtentCount: 2})
	if v, ok := s.st.Lookup("big"); !ok || v.Length != 4101 {
		t.Fatal(v)
	}
	s.ok(&Record{Op: OpAddAbort, TxID: B})
	if _, ok := s.st.Lookup("other"); ok || s.st.Aborted != 1 {
		t.Fatal("aborted version visible")
	}
	s.corrupt(&Record{Op: OpAddExtent, TxID: A, ExtentSequence: 2, Loc: loc1(1, 1)}, "extent after commit")
	s.corrupt(&Record{Op: OpAddCommit, TxID: B, ExtentRecordCount: 1, ExtentCount: 1}, "commit after abort")
	s.corrupt(&Record{Op: OpAddAbort, TxID: tid(9)}, "abort of unknown tx")
	s.corrupt(&Record{Op: OpAddBegin, TxID: A, Path: "z", FileVer: 99}, "tx_id reuse")

	// count mismatch and duplicate extent_sequence: ignored, not corrupt
	C, D := tid(3), tid(4)
	s.ok(&Record{Op: OpAddBegin, TxID: C, Path: "c", FileVer: 20})
	s.ok(&Record{Op: OpAddExtent, TxID: C, ExtentSequence: 0, Loc: loc1(1, 1)})
	s.ok(&Record{Op: OpAddCommit, TxID: C, ExtentRecordCount: 2, ExtentCount: 1})
	s.ok(&Record{Op: OpAddBegin, TxID: D, Path: "d", FileVer: 21})
	s.ok(&Record{Op: OpAddExtent, TxID: D, ExtentSequence: 0, Loc: loc1(1, 1)})
	s.ok(&Record{Op: OpAddExtent, TxID: D, ExtentSequence: 0, Loc: loc1(2, 1)})
	s.ok(&Record{Op: OpAddCommit, TxID: D, ExtentRecordCount: 1, ExtentCount: 1})
	if len(s.st.Ignored) != 2 {
		t.Fatal(s.st.Ignored)
	}
	if _, ok := s.st.Lookup("c"); ok {
		t.Fatal("ignored transaction visible")
	}
	// coverage violation in a matching commit is corruption
	E := tid(5)
	s.ok(&Record{Op: OpAddBegin, TxID: E, Path: "e", FileVer: 30})
	s.ok(&Record{Op: OpAddExtent, TxID: E, ExtentSequence: 0, Loc: []Loc{{Offset: 0, Length: 4096}, {Offset: 8192, Length: 1}}})
	s.corrupt(&Record{Op: OpAddCommit, TxID: E, ExtentRecordCount: 1, ExtentCount: 2}, "gap at commit")
}

// E1-4: ADD_BEGIN(v8), ADD(v9), ADD_COMMIT(v8) for one path is rejected.
func TestOlderVersionCannotBecomeCurrent(t *testing.T) {
	s := newSeqr(t)
	s.ok(&Record{Op: OpAddBegin, TxID: tid(1), Path: "p", FileVer: 8})
	s.ok(&Record{Op: OpAddExtent, TxID: tid(1), Loc: loc1(1, 1)})
	s.ok(&Record{Op: OpAdd, Path: "p", FileVer: 9, Loc: loc1(2, 1)})
	s.corrupt(&Record{Op: OpAddCommit, TxID: tid(1), ExtentRecordCount: 1, ExtentCount: 1}, "commit of older version")
}

func TestOpenTransactionLimit(t *testing.T) {
	s := newSeqr(t)
	for i := 0; i < 1024; i++ {
		s.ok(&Record{Op: OpAddBegin, TxID: TxID{byte(i), byte(i >> 8), 7}, Path: fmt.Sprintf("p%d", i), FileVer: uint64(i + 1)})
	}
	if err := s.apply(&Record{Op: OpAddBegin, TxID: TxID{0xFF, 0xFF}, Path: "q", FileVer: 5000}); !errors.Is(err, wire.ErrResource) {
		t.Fatal(err)
	}
	if n := len(s.st.OpenTransactions()); n != 1024 {
		t.Fatal(n)
	}
}

func TestStagedCeiling(t *testing.T) {
	st := NewState(hdr(), Limits{MaxOpenTransactions: 4, MaxStagedExtents: 10})
	st.Apply(&Record{Seq: 1, Op: OpAddBegin, TxID: tid(1), Path: "a", FileVer: 1}, 0)
	err := st.Apply(&Record{Seq: 2, Op: OpAddExtent, TxID: tid(1), Loc: locN(1, 11, 0)}, 0)
	if !errors.Is(err, wire.ErrResource) {
		t.Fatal(err)
	}
}

func TestTransactionInOneFile(t *testing.T) {
	st := NewState(hdr(), Limits{})
	st.Apply(&Record{Seq: 1, Op: OpAddBegin, TxID: tid(1), Path: "a", FileVer: 1}, 0)
	if err := st.Apply(&Record{Seq: 2, Op: OpAddAbort, TxID: tid(1)}, 1); err == nil || !strings.Contains(err.Error(), "spans") {
		t.Fatal(err)
	}
}
