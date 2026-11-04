package manifest

import (
	"fmt"
	"slices"
	"sort"

	"stash/internal/blob"
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

// DefaultLimits are the SPEC limits with a 16 Mi-extent staging ceiling
// (about 1 GiB of RAM).
var DefaultLimits = Limits{MaxOpenTransactions: 1024, MaxStagedExtents: 1 << 24}

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

// State is the live-state fold of a generation's manifest graph (§10.2.2).
// Apply validates a record completely before changing anything, so a
// rejected record leaves the state unchanged.
type State struct {
	h   *wire.ArchiveHeader
	lim Limits

	live       map[string]*Version
	appliedMax map[string]uint64
	open       map[TxID]*tx
	closed     map[TxID]struct{}
	refs       map[FrameRef]struct{} // nil unless tracking (writers)
	staged     int
	maxFileVer uint64
	lastSeq    uint64
	records    uint64

	// Ignored lists transactions whose ADD_COMMIT counts did not match
	// (§10.3): they never became versions.
	Ignored []TxID
	// Aborted counts ADD_ABORT records applied.
	Aborted int
}

// NewState returns the empty state of a generation.
func NewState(h *wire.ArchiveHeader, lim Limits) *State {
	if lim.MaxOpenTransactions == 0 {
		lim = DefaultLimits
	}
	return &State{h: h, lim: lim, live: map[string]*Version{}, appliedMax: map[string]uint64{},
		open: map[TxID]*tx{}, closed: map[TxID]struct{}{}}
}

// TrackRefs makes the state record every loc reference (needed by a
// writer for the blob torn-tail decision, §10.4.2; readers skip the cost).
// It must be called before the first Apply.
func (s *State) TrackRefs() { s.refs = map[FrameRef]struct{}{} }

func (s *State) corrupt(r *Record, format string, args ...any) error {
	return &wire.Error{Struct: "Manifest", Field: r.Op.String(), Class: wire.ErrCorrupt,
		Detail: fmt.Sprintf("seq %d: ", r.Seq) + fmt.Sprintf(format, args...)}
}

func (s *State) resource(r *Record, format string, args ...any) error {
	return &wire.Error{Struct: "Manifest", Field: r.Op.String(), Class: wire.ErrResource,
		Detail: fmt.Sprintf("seq %d: ", r.Seq) + fmt.Sprintf(format, args...)}
}

// MaxFileVer returns the largest file_ver named by any applied record
// (ADD, DEL, ADD_BEGIN), committed or not; 0 if none.
func (s *State) MaxFileVer() uint64 { return s.maxFileVer }

// LastSeq returns the largest seq applied (0 if none).
func (s *State) LastSeq() uint64 { return s.lastSeq }

// Records returns the number of records applied.
func (s *State) Records() uint64 { return s.records }

// Lookup returns the current version of path.
func (s *State) Lookup(path string) (*Version, bool) {
	v, ok := s.live[path]
	return v, ok
}

// Paths returns the live paths in bytewise order.
func (s *State) Paths() []string {
	out := make([]string, 0, len(s.live))
	for p := range s.live {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// AppliedMax returns applied_max(path) of §10.2.1.
func (s *State) AppliedMax(path string) (uint64, bool) {
	v, ok := s.appliedMax[path]
	return v, ok
}

// OpenTransactions returns the transactions begun but neither committed nor
// aborted, in ADD_BEGIN order (cold start aborts them, §10.3.1).
func (s *State) OpenTransactions() []TxID {
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
	t, ok := s.open[id]
	if !ok {
		return "", false
	}
	return t.path, true
}

// IsTxKnown reports whether a tx_id was ever used in this generation.
func (s *State) IsTxKnown(id TxID) bool {
	_, o := s.open[id]
	_, c := s.closed[id]
	return o || c
}

// Refs (with TrackRefs) returns every frame referenced by a loc of any applied record,
// committed or not, live or dead (§10.4.2), for one blob.
func (s *State) Refs(blob uint8) []FrameRef {
	var out []FrameRef
	for r := range s.refs {
		if r.Blob == blob {
			out = append(out, r)
		}
	}
	return out
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

func (s *State) checkVersion(r *Record, path string, v uint64) error {
	if m, ok := s.appliedMax[path]; ok && v <= m {
		return s.corrupt(r, "file_ver %d of %q not greater than applied_max %d", v, path, m)
	}
	return nil
}

func (s *State) addRefs(path string, ver uint64, locs []Loc) {
	if s.refs == nil {
		return
	}
	for _, l := range locs {
		s.refs[FrameRef{Blob: l.Blob, Hash: l.Hash, Path: path, FileVer: ver, Offset: l.Offset}] = struct{}{}
	}
}

func (s *State) setLive(path string, ver uint64, locs []Loc, length, seq uint64) {
	s.live[path] = &Version{FileVer: ver, Loc: locs, Length: length, Seq: seq}
	s.appliedMax[path] = ver
}

// Apply applies one record in seq order. file identifies the journal file
// the record came from (0 = manifest.jsonl), for the same-file rule of
// transactions.
func (s *State) Apply(r *Record, file int) error {
	if r.Seq == 0 {
		return s.corrupt(r, "seq must be >= 1")
	}
	if s.records > 0 && r.Seq <= s.lastSeq {
		return s.corrupt(r, "seq not greater than previous seq %d", s.lastSeq)
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
		if err := s.checkVersion(r, r.Path, r.FileVer); err != nil {
			return err
		}
		s.addRefs(r.Path, r.FileVer, r.Loc)
		s.setLive(r.Path, r.FileVer, locs, n, r.Seq)
	case OpDel:
		cur, ok := s.live[r.Path]
		if !ok {
			return s.corrupt(r, "DEL of absent path %q", r.Path)
		}
		if cur.FileVer != r.FileVer {
			return s.corrupt(r, "DEL names file_ver %d, current is %d", r.FileVer, cur.FileVer)
		}
		delete(s.live, r.Path)
	case OpAddBegin:
		if s.IsTxKnown(r.TxID) {
			return s.corrupt(r, "tx_id %s reused", r.TxID)
		}
		if err := s.checkVersion(r, r.Path, r.FileVer); err != nil {
			return err
		}
		if len(s.open) >= s.lim.MaxOpenTransactions {
			return s.resource(r, "more than %d open transactions", s.lim.MaxOpenTransactions)
		}
		s.open[r.TxID] = &tx{id: r.TxID, path: r.Path, fileVer: r.FileVer, beginSeq: r.Seq, file: file, extents: map[uint32][]Loc{}}
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
		s.addRefs(t.path, t.fileVer, r.Loc)
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
			s.Ignored = append(s.Ignored, t.id)
			break
		}
		locs, n, err := s.checkLocs(r, all)
		if err != nil {
			return err
		}
		if err := s.checkVersion(r, t.path, t.fileVer); err != nil {
			return err
		}
		s.closeTx(t)
		s.setLive(t.path, t.fileVer, locs, n, r.Seq)
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
	switch r.Op {
	case OpAdd, OpDel, OpAddBegin:
		s.maxFileVer = max(s.maxFileVer, r.FileVer)
	}
	s.lastSeq = r.Seq
	s.records++
	return nil
}

func (s *State) openTx(r *Record, file int) (*tx, error) {
	t, ok := s.open[r.TxID]
	if !ok {
		return nil, s.corrupt(r, "tx_id %s has no open transaction", r.TxID)
	}
	if t.file != file {
		return nil, s.corrupt(r, "transaction %s spans manifest files", r.TxID)
	}
	return t, nil
}

func (s *State) closeTx(t *tx) {
	s.staged -= int(t.nLocs)
	delete(s.open, t.id)
	s.closed[t.id] = struct{}{}
}

// BlobCommitted returns the torn-tail input of blob.OpenWriter for one blob
// (§10.4.2): every frame of the blob that a loc of the graph references.
// groupReferenced is supplied by the caller that can resolve group ids of
// referenced frames (nil if the archive has no parity).
func (s *State) BlobCommitted(ordinal uint8, groupReferenced func(uint32) bool) blob.Committed {
	if s.refs == nil {
		panic("manifest: BlobCommitted needs a state loaded with TrackRefs")
	}
	refs := map[blob.FrameKey]struct{}{}
	for r := range s.refs {
		if r.Blob == ordinal {
			refs[blob.FrameKey{Hash: r.Hash, Path: r.Path, FileVer: r.FileVer, Offset: r.Offset}] = struct{}{}
		}
	}
	return blob.Committed{Refs: refs, GroupReferenced: groupReferenced}
}
