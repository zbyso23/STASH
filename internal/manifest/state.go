package manifest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"

	"stash/internal/blob"
	"stash/internal/kvtab"
	"stash/internal/membudget"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Limits bound reader resources (§10.3, §16.1).
type Limits struct {
	// MaxOpenTransactions is MAX_OPEN_TRANSACTIONS (1024).
	MaxOpenTransactions int
	// MaxStagedExtents is the memory ceiling for extents of open
	// transactions held in RAM; beyond it the reader fails with a resource
	// error (spilling to disk is not implemented).
	MaxStagedExtents int
}

// DefaultLimits are the SPEC limits with a 4 Mi-extent staging ceiling
// (about 200 MiB of RAM, inside the default memory limit).
var DefaultLimits = Limits{MaxOpenTransactions: 1024, MaxStagedExtents: 1 << 22}

// MaxTransactionExtents is MAX_TRANSACTION_EXTENTS.
const MaxTransactionExtents = 1<<32 - 1

// Version is the current version of a path.
type Version struct {
	FileVer uint64
	Loc     []Loc // sorted by logical offset
	Length  uint64
	Seq     uint64 // seq of the ADD or ADD_COMMIT that applied it
}

type tx struct {
	id       TxID
	path     string
	fileVer  uint64
	beginSeq uint64
	file     int
	extents  map[uint32][]Loc
	nLocs    uint64
	dupSeq   bool
}

// FrameRef is what a loc references: a frame of a blob, identified by its
// frame_hash and the object metadata that selects among payload-identical
// frames (§9.1).
type FrameRef struct {
	Blob    uint8
	Hash    [32]byte
	Path    string
	FileVer uint64
	Offset  uint64
}

// Env is the bounded-memory environment of a state: the memory budget,
// the block cache and the scratch space. A nil Env keeps the state in
// memory (tests, tools).
type Env struct {
	Budget  *membudget.Budget
	Cache   *kvtab.Cache
	Scratch func() (vfs.FS, string, error)
	// MemLimit overrides the in-memory table delta (0: the kvtab default).
	MemLimit int64
	// SortMemory overrides the memory of each load sort (0: a share of
	// the budget).
	SortMemory int64
}

func (e *Env) table() kvtab.Config {
	if e == nil {
		return kvtab.Config{}
	}
	return kvtab.Config{Budget: e.Budget, Cache: e.Cache, Scratch: e.Scratch, MemLimit: e.MemLimit}
}

// State is the live-state fold of a generation's manifest graph (§10.2.2).
//
// Per-path state (applied_max, the live version and its locs), the
// transaction ids ever used and the loc references live in a sorted table
// that spills to scratch space (kvtab), so memory does not grow with the
// archive. Only open transactions and their staged extents are held in
// RAM, under Limits. Apply validates a record completely before changing
// anything, so a rejected record leaves the state unchanged. A State is
// safe for concurrent readers; Apply must not run concurrently with
// itself (the journal serializes appends).
type State struct {
	h   *wire.ArchiveHeader
	lim Limits
	env *Env

	tab *kvtab.Table

	mu         sync.Mutex // guards the fields below against concurrent readers
	open       map[TxID]*tx
	staged     int
	maxFileVer uint64
	lastSeq    uint64
	records    uint64
	trackRefs  bool
	refCount   []int // per blob, from the load

	// Ignored lists transactions whose ADD_COMMIT counts did not match
	// (§10.3): they never became versions.
	// Only the first maxIgnoredListed are listed; IgnoredCount counts all.
	Ignored      []TxID
	IgnoredCount uint64
	// Aborted counts ADD_ABORT records applied.
	Aborted int
}

// NewState returns the empty state of a generation, held in memory.
func NewState(h *wire.ArchiveHeader, lim Limits) *State { return newState(h, lim, nil) }

func newState(h *wire.ArchiveHeader, lim Limits, env *Env) *State {
	if lim.MaxOpenTransactions == 0 {
		lim = DefaultLimits
	}
	return &State{h: h, lim: lim, env: env, tab: kvtab.New(env.table()), open: map[TxID]*tx{},
		refCount: make([]int, h.BlobCount)}
}

// Close releases the table and its scratch files.
func (s *State) Close() error { return s.tab.Close() }

// TrackRefs makes the load record every loc reference (needed by a writer
// for the blob torn-tail decision, §10.4.2; readers skip the cost). It
// must be called before the first Apply. References are those of the
// loaded journal: records appended later are the writer's own, made
// durable before they are referenced, and are not tracked.
func (s *State) TrackRefs() { s.trackRefs = true }

func corruptAt(op Op, seq uint64, format string, args ...any) error {
	return &wire.Error{Struct: "Manifest", Field: op.String(), Class: wire.ErrCorrupt,
		Detail: fmt.Sprintf("seq %d: ", seq) + fmt.Sprintf(format, args...)}
}

func (s *State) corrupt(r *Record, format string, args ...any) error {
	return corruptAt(r.Op, r.Seq, format, args...)
}

func (s *State) resource(r *Record, format string, args ...any) error {
	return &wire.Error{Struct: "Manifest", Field: r.Op.String(), Class: wire.ErrResource,
		Detail: fmt.Sprintf("seq %d: ", r.Seq) + fmt.Sprintf(format, args...)}
}

// MaxFileVer returns the largest file_ver named by any applied record
// (ADD, DEL, ADD_BEGIN), committed or not; 0 if none.
func (s *State) MaxFileVer() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxFileVer
}

// LastSeq returns the largest seq applied (0 if none).
func (s *State) LastSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

// Records returns the number of records applied.
func (s *State) Records() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records
}

// --- table layout -----------------------------------------------------
//
//	'P' path 0x00 chunk(u32 BE)  per-path state; chunk 0 carries the
//	                              header, later chunks more locs
//	'R' blob hash path 0x00 file_ver(u64 BE) offset(u64 BE)
//	                              a loc reference (writers)
//	'T' tx_id                    a transaction id used in the generation
//
// Paths contain no NUL (canonical paths, §5), so 'P' keys sort in bytewise
// path order and the chunks of one path are adjacent.

const chunkLocs = 1024

func pathKey(p string, chunk uint32) []byte {
	k := make([]byte, 0, len(p)+6)
	k = append(k, 'P')
	k = append(k, p...)
	k = append(k, 0)
	return binary.BigEndian.AppendUint32(k, chunk)
}

func txKey(id TxID) []byte { return append([]byte{'T'}, id[:]...) }

// maxIgnoredListed bounds State.Ignored.
const maxIgnoredListed = 1000

// refKey orders references by blob, then file_ver and offset: a blob holds
// its frames in roughly that order, so the torn-tail scan of a blob reads
// the table sequentially.
func refKey(r FrameRef) []byte {
	k := make([]byte, 0, 2+16+32+len(r.Path))
	k = append(k, 'R', r.Blob)
	k = binary.BigEndian.AppendUint64(k, r.FileVer)
	k = binary.BigEndian.AppendUint64(k, r.Offset)
	k = append(k, r.Hash[:]...)
	return append(k, r.Path...)
}

func parseRefKey(k []byte) (FrameRef, bool) {
	if len(k) < 2+16+32 || k[0] != 'R' {
		return FrameRef{}, false
	}
	return FrameRef{
		Blob:    k[1],
		FileVer: binary.BigEndian.Uint64(k[2:]),
		Offset:  binary.BigEndian.Uint64(k[10:]),
		Hash:    [32]byte(k[18:50]),
		Path:    string(k[50:]),
	}, true
}

func appendLoc(b []byte, l Loc) []byte {
	b = append(b, l.Blob)
	b = append(b, l.Hash[:]...)
	b = binary.AppendUvarint(b, l.Offset)
	return binary.AppendUvarint(b, l.Length)
}

func readLocs(b []byte, out []Loc) ([]Loc, error) {
	for len(b) > 0 {
		if len(b) < 33 {
			return nil, kvtab.ErrTampered
		}
		l := Loc{Blob: b[0], Hash: [32]byte(b[1:33])}
		b = b[33:]
		var n int
		if l.Offset, n = binary.Uvarint(b); n <= 0 {
			return nil, kvtab.ErrTampered
		}
		b = b[n:]
		if l.Length, n = binary.Uvarint(b); n <= 0 {
			return nil, kvtab.ErrTampered
		}
		b = b[n:]
		out = append(out, l)
	}
	return out, nil
}

// pathState is what the journal rules need of one path.
type pathState struct {
	known      bool // applied_max is defined
	appliedMax uint64
	live       *Version
}

// encodePath returns the chunks of a path state.
func encodePath(ps *pathState) [][]byte {
	var h []byte
	h = binary.AppendUvarint(h, ps.appliedMax)
	if ps.live == nil {
		return [][]byte{append(h, 0)}
	}
	v := ps.live
	nchunks := max(1, (len(v.Loc)+chunkLocs-1)/chunkLocs)
	h = append(h, 1)
	h = binary.AppendUvarint(h, v.FileVer)
	h = binary.AppendUvarint(h, v.Length)
	h = binary.AppendUvarint(h, v.Seq)
	h = binary.AppendUvarint(h, uint64(len(v.Loc)))
	out := make([][]byte, nchunks)
	out[0] = h
	for i, l := range v.Loc {
		c := i / chunkLocs
		if c > 0 && out[c] == nil {
			out[c] = binary.AppendUvarint(nil, v.FileVer) // ties a chunk to its version
		}
		out[c] = appendLoc(out[c], l)
	}
	return out
}

// decodeHeader parses chunk 0; locs of chunk 0 are appended to the version.
func decodeHeader(b []byte) (*pathState, int, error) {
	ps := &pathState{known: true}
	var n int
	if ps.appliedMax, n = binary.Uvarint(b); n <= 0 || len(b) <= n {
		return nil, 0, kvtab.ErrTampered
	}
	b = b[n:]
	if b[0] == 0 {
		return ps, 0, nil
	}
	b = b[1:]
	v := &Version{}
	var nloc uint64
	for _, p := range []*uint64{&v.FileVer, &v.Length, &v.Seq, &nloc} {
		if *p, n = binary.Uvarint(b); n <= 0 {
			return nil, 0, kvtab.ErrTampered
		}
		b = b[n:]
	}
	if nloc > MaxTransactionExtents {
		return nil, 0, kvtab.ErrTampered
	}
	var err error
	if v.Loc, err = readLocs(b, make([]Loc, 0, min(nloc, chunkLocs))); err != nil {
		return nil, 0, err
	}
	ps.live = v
	nchunks := max(1, int((nloc+chunkLocs-1)/chunkLocs))
	if uint64(len(v.Loc)) != min(nloc, chunkLocs) {
		return nil, 0, kvtab.ErrTampered
	}
	return ps, nchunks, nil
}

// getPath reads the state of path.
func (s *State) getPath(p string) (*pathState, error) {
	b, ok, err := s.tab.Get(pathKey(p, 0))
	if err != nil || !ok {
		return &pathState{}, err
	}
	ps, nchunks, err := decodeHeader(b)
	if err != nil {
		return nil, err
	}
	for c := 1; c < nchunks; c++ {
		b, ok, err := s.tab.Get(pathKey(p, uint32(c)))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, kvtab.ErrTampered
		}
		ver, n := binary.Uvarint(b)
		if n <= 0 || ver != ps.live.FileVer {
			return nil, kvtab.ErrTampered
		}
		if ps.live.Loc, err = readLocs(b[n:], ps.live.Loc); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

func (s *State) putPath(p string, ps *pathState) error {
	for c, b := range encodePath(ps) {
		if err := s.tab.Put(pathKey(p, uint32(c)), b); err != nil {
			return err
		}
	}
	return nil
}

// --- per-path rules (shared by Apply and the load fold) ----------------

// applyPath applies one path event to ps. It validates before changing.
func applyPath(ps *pathState, op Op, path string, ver, seq uint64, locs []Loc, length uint64) error {
	switch op {
	case OpAdd, OpAddCommit, OpAddBegin:
		if ps.known && ver <= ps.appliedMax {
			return corruptAt(op, seq, "file_ver %d of %q not greater than applied_max %d", ver, path, ps.appliedMax)
		}
		if op == OpAddBegin {
			return nil
		}
		ps.known, ps.appliedMax = true, ver
		ps.live = &Version{FileVer: ver, Loc: locs, Length: length, Seq: seq}
	case OpDel:
		if ps.live == nil {
			return corruptAt(op, seq, "DEL of absent path %q", path)
		}
		if ps.live.FileVer != ver {
			return corruptAt(op, seq, "DEL names file_ver %d, current is %d", ver, ps.live.FileVer)
		}
		ps.live = nil
	}
	return nil
}

// --- queries ------------------------------------------------------------

// Lookup returns the current version of path. An error means the state
// could not be read (a damaged or changed scratch file): never "absent".
func (s *State) Lookup(path string) (*Version, bool, error) {
	ps, err := s.getPath(path)
	if err != nil {
		return nil, false, err
	}
	return ps.live, ps.live != nil, nil
}

// AppliedMax returns applied_max(path) of §10.2.1.
func (s *State) AppliedMax(path string) (uint64, bool, error) {
	ps, err := s.getPath(path)
	if err != nil {
		return 0, false, err
	}
	return ps.appliedMax, ps.known, nil
}

// Walk calls fn for every live path with the given prefix, in bytewise
// order, starting at the first path >= start. fn returning false stops
// the walk. The walk sees a snapshot of the state taken when it began;
// memory does not depend on the number of paths.
func (s *State) Walk(prefix, start string, fn func(path string, v *Version) bool) error {
	from := pathKey(max(prefix, start), 0)
	from = from[:len(from)-5] // 'P' + path, before its NUL
	it := s.tab.Iter(from)
	defer it.Close()
	pfx := append([]byte{'P'}, prefix...)
	for it.Next() {
		k := it.Key()
		if !bytes.HasPrefix(k, pfx) {
			break
		}
		if len(k) < 6 || k[len(k)-5] != 0 || binary.BigEndian.Uint32(k[len(k)-4:]) != 0 {
			continue // a later chunk
		}
		ps, nchunks, err := decodeHeader(it.Value())
		if err != nil {
			return err
		}
		if ps.live == nil {
			continue
		}
		p := string(k[1 : len(k)-5])
		if nchunks > 1 {
			full, err := s.getPath(p)
			if err != nil {
				return err
			}
			ps = full
		}
		if !fn(p, ps.live) {
			return it.Err()
		}
	}
	return it.Err()
}

// Paths returns the live paths in bytewise order. It holds every path in
// memory; archive-scale callers use Walk.
func (s *State) Paths() ([]string, error) {
	var out []string
	err := s.Walk("", "", func(p string, _ *Version) bool { out = append(out, p); return true })
	return out, err
}

// OpenTransactions returns the transactions begun but neither committed nor
// aborted, in ADD_BEGIN order (cold start aborts them, §10.3.1).
func (s *State) OpenTransactions() []TxID {
	s.mu.Lock()
	defer s.mu.Unlock()
	txs := make([]*tx, 0, len(s.open))
	for _, t := range s.open {
		txs = append(txs, t)
	}
	slices.SortFunc(txs, func(a, b *tx) int { return cmpU64(a.beginSeq, b.beginSeq) })
	out := make([]TxID, len(txs))
	for i, t := range txs {
		out[i] = t.id
	}
	return out
}

// TxPath returns the path of an open transaction.
func (s *State) TxPath(id TxID) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.open[id]
	if !ok {
		return "", false
	}
	return t.path, true
}

// IsTxKnown reports whether a tx_id was ever used in this generation.
func (s *State) IsTxKnown(id TxID) (bool, error) {
	s.mu.Lock()
	_, o := s.open[id]
	s.mu.Unlock()
	if o {
		return true, nil
	}
	_, ok, err := s.tab.Get(txKey(id))
	return ok, err
}

// Refs (with TrackRefs) returns every frame of one blob referenced by a
// loc of any loaded record, committed or not, live or dead (§10.4.2).
func (s *State) Refs(b uint8) ([]FrameRef, error) {
	var out []FrameRef
	it := s.tab.Iter([]byte{'R', b})
	defer it.Close()
	for it.Next() {
		r, ok := parseRefKey(it.Key())
		if !ok || r.Blob != b {
			break
		}
		out = append(out, r)
	}
	return out, it.Err()
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// checkLocs validates the coverage rule of §10.1.2 and the placement rules
// of §6.6 for one complete object version, and returns the sorted loc and
// the object length.
func (s *State) checkLocs(r *Record, locs []Loc) ([]Loc, uint64, error) {
	sorted := slices.Clone(locs)
	slices.SortFunc(sorted, func(a, b Loc) int { return cmpU64(a.Offset, b.Offset) })
	maxLen := s.h.MaxFrameSize()
	if len(sorted) == 1 && sorted[0].Offset == 0 && sorted[0].Length == 0 {
		return sorted, 0, nil
	}
	var end uint64
	for i, l := range sorted {
		if l.Offset != end {
			if l.Offset < end {
				return nil, 0, s.corrupt(r, "loc extents overlap at %d", l.Offset)
			}
			return nil, 0, s.corrupt(r, "loc has a gap [%d, %d)", end, l.Offset)
		}
		if l.Length == 0 {
			return nil, 0, s.corrupt(r, "zero-length extent in a non-empty object")
		}
		if l.Length > maxLen {
			return nil, 0, s.corrupt(r, "extent length %d exceeds MAX_FRAME_SIZE", l.Length)
		}
		if l.Offset%wire.BaseQuantum != 0 {
			return nil, 0, s.corrupt(r, "extent offset %d not 4096-aligned", l.Offset)
		}
		if i < len(sorted)-1 && l.Length%wire.BaseQuantum != 0 {
			return nil, 0, s.corrupt(r, "non-final extent length %d not 4096-aligned", l.Length)
		}
		if end+l.Length < end {
			return nil, 0, s.corrupt(r, "object length overflows uint64")
		}
		end += l.Length
	}
	return sorted, end, nil
}

func (s *State) checkBlobs(r *Record, locs []Loc) error {
	for _, l := range locs {
		if l.Blob >= s.h.BlobCount {
			return s.corrupt(r, "blob ordinal %d >= blob_count %d", l.Blob, s.h.BlobCount)
		}
	}
	return nil
}

// sink receives what the global pass decides about paths, transaction ids
// and references: applied at once to the table (Apply), or emitted for the
// sorted fold (Load).
type sink interface {
	path(op Op, path string, ver, seq uint64, locs []Loc, length uint64) error
	txKnown(id TxID) (bool, error)
	txUsed(id TxID) error
	ref(r FrameRef) error
}

// direct is the sink of Apply: the per-path rules run against the table.
type direct struct{ s *State }

func (d direct) path(op Op, path string, ver, seq uint64, locs []Loc, length uint64) error {
	ps, err := d.s.getPath(path)
	if err != nil {
		return err
	}
	if err := applyPath(ps, op, path, ver, seq, locs, length); err != nil {
		return err
	}
	if op == OpAddBegin {
		return nil
	}
	return d.s.putPath(path, ps)
}

func (d direct) txKnown(id TxID) (bool, error) {
	_, ok, err := d.s.tab.Get(txKey(id))
	return ok, err
}

func (d direct) txUsed(id TxID) error { return d.s.tab.Put(txKey(id), nil) }
func (d direct) ref(FrameRef) error   { return nil } // see TrackRefs

// Apply applies one record in seq order. file identifies the journal file
// the record came from (0 = manifest.jsonl), for the same-file rule of
// transactions.
func (s *State) Apply(r *Record, file int) error { return s.apply(r, file, direct{s}) }

// apply runs the global rules of one record (seq order, record-local
// placement, transactions, limits) and hands path effects to k.
func (s *State) apply(r *Record, file int, k sink) error {
	if r.Seq == 0 {
		return s.corrupt(r, "seq must be >= 1")
	}
	if s.records > 0 && r.Seq <= s.lastSeq {
		return s.corrupt(r, "seq not greater than previous seq %d", s.lastSeq)
	}
	refs := func(path string, ver uint64, locs []Loc) error {
		if !s.trackRefs {
			return nil
		}
		for _, l := range locs {
			if err := k.ref(FrameRef{Blob: l.Blob, Hash: l.Hash, Path: path, FileVer: ver, Offset: l.Offset}); err != nil {
				return err
			}
		}
		return nil
	}
	switch r.Op {
	case OpAdd:
		if err := s.checkBlobs(r, r.Loc); err != nil {
			return err
		}
		locs, n, err := s.checkLocs(r, r.Loc)
		if err != nil {
			return err
		}
		if err := k.path(OpAdd, r.Path, r.FileVer, r.Seq, locs, n); err != nil {
			return err
		}
		if err := refs(r.Path, r.FileVer, r.Loc); err != nil {
			return err
		}
	case OpDel:
		if err := k.path(OpDel, r.Path, r.FileVer, r.Seq, nil, 0); err != nil {
			return err
		}
	case OpAddBegin:
		s.mu.Lock()
		_, open := s.open[r.TxID]
		s.mu.Unlock()
		known := open
		if !known {
			var err error
			if known, err = k.txKnown(r.TxID); err != nil {
				return err
			}
		}
		if known {
			return s.corrupt(r, "tx_id %s reused", r.TxID)
		}
		if err := k.path(OpAddBegin, r.Path, r.FileVer, r.Seq, nil, 0); err != nil {
			return err
		}
		if len(s.open) >= s.lim.MaxOpenTransactions {
			return s.resource(r, "more than %d open transactions", s.lim.MaxOpenTransactions)
		}
		if err := k.txUsed(r.TxID); err != nil {
			return err
		}
		s.mu.Lock()
		s.open[r.TxID] = &tx{id: r.TxID, path: r.Path, fileVer: r.FileVer, beginSeq: r.Seq, file: file, extents: map[uint32][]Loc{}}
		s.mu.Unlock()
	case OpAddExtent:
		t, err := s.openTx(r, file)
		if err != nil {
			return err
		}
		if err := s.checkBlobs(r, r.Loc); err != nil {
			return err
		}
		if t.nLocs+uint64(len(r.Loc)) > MaxTransactionExtents {
			return s.corrupt(r, "transaction exceeds MAX_TRANSACTION_EXTENTS")
		}
		if s.staged+len(r.Loc) > s.lim.MaxStagedExtents {
			return s.resource(r, "staged extents exceed the configured ceiling %d", s.lim.MaxStagedExtents)
		}
		if err := refs(t.path, t.fileVer, r.Loc); err != nil {
			return err
		}
		if _, dup := t.extents[r.ExtentSequence]; dup {
			t.dupSeq = true // the transaction will be ignored at commit
		} else {
			t.extents[r.ExtentSequence] = r.Loc
			t.nLocs += uint64(len(r.Loc))
			s.staged += len(r.Loc)
		}
	case OpAddCommit:
		t, err := s.openTx(r, file)
		if err != nil {
			return err
		}
		match := !t.dupSeq && uint64(len(t.extents)) == uint64(r.ExtentRecordCount) && t.nLocs == uint64(r.ExtentCount)
		var all []Loc
		if match {
			for i := uint32(0); i < r.ExtentRecordCount; i++ {
				e, ok := t.extents[i]
				if !ok {
					match = false
					break
				}
				all = append(all, e...)
			}
		}
		if !match {
			s.closeTx(t)
			if len(s.Ignored) < maxIgnoredListed {
				s.Ignored = append(s.Ignored, t.id)
			}
			s.IgnoredCount++
			break
		}
		locs, n, err := s.checkLocs(r, all)
		if err != nil {
			return err
		}
		if err := k.path(OpAddCommit, t.path, t.fileVer, r.Seq, locs, n); err != nil {
			return err
		}
		s.closeTx(t)
	case OpAddAbort:
		t, err := s.openTx(r, file)
		if err != nil {
			return err
		}
		s.closeTx(t)
		s.Aborted++
	case OpLinkManifest:
		if r.HashID != uint8(s.h.HashID) {
			return s.corrupt(r, "hash_id %d differs from archive hash_id %d", r.HashID, s.h.HashID)
		}
		if file != 0 {
			return s.corrupt(r, "LINK_MANIFEST inside a linked manifest (depth > 1)")
		}
	case OpParityGroup:
		for _, m := range r.Members {
			if m.Blob >= s.h.BlobCount {
				return s.corrupt(r, "member blob ordinal %d >= blob_count", m.Blob)
			}
		}
	default:
		return s.corrupt(r, "unknown op")
	}
	s.mu.Lock()
	switch r.Op {
	case OpAdd, OpDel, OpAddBegin:
		s.maxFileVer = max(s.maxFileVer, r.FileVer)
	}
	s.lastSeq = r.Seq
	s.records++
	s.mu.Unlock()
	return nil
}

func (s *State) openTx(r *Record, file int) (*tx, error) {
	s.mu.Lock()
	t, ok := s.open[r.TxID]
	s.mu.Unlock()
	if !ok {
		return nil, s.corrupt(r, "tx_id %s has no open transaction", r.TxID)
	}
	if t.file != file {
		return nil, s.corrupt(r, "transaction %s spans manifest files", r.TxID)
	}
	return t, nil
}

func (s *State) closeTx(t *tx) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staged -= int(t.nLocs)
	delete(s.open, t.id)
}

// BlobCommitted returns the torn-tail input of blob.OpenWriter for one blob
// (§10.4.2): every frame of the blob that a loc of the graph references,
// looked up in the table, and a bounded counter of the distinct ones a
// scan meets. groupReferenced is supplied by the caller that can resolve
// group ids of referenced frames (nil if the archive has no parity).
func (s *State) BlobCommitted(ordinal uint8, groupReferenced func(uint32) bool) blob.Committed {
	if !s.trackRefs {
		panic("manifest: BlobCommitted needs a state loaded with TrackRefs")
	}
	return blob.Committed{Refs: refSet{s, ordinal}, GroupReferenced: groupReferenced, Distinct: s.distinct}
}

type refSet struct {
	s *State
	b uint8
}

func (r refSet) Len() int { return r.s.refCount[r.b] }

func (r refSet) Has(k blob.FrameKey) (bool, error) {
	_, ok, err := r.s.tab.Get(refKey(FrameRef{Blob: r.b, Hash: k.Hash, Path: k.Path, FileVer: k.FileVer, Offset: k.Offset}))
	return ok, err
}

var errClosed = errors.New("manifest: state closed")
