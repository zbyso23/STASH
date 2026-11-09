// Package recovery is raw disaster recovery (SPEC §11): it reconstructs
// object versions from blob files alone, using the frames' self-describing
// metadata, resynchronization after damage (§11.2.1) and parity (§11.6),
// and uses a surviving manifest only to label what it finds (§11.2.2).
package recovery

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"stash/internal/archive"
	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/manifest"
	"stash/internal/parity"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Options configures Scan.
type Options struct {
	Pool *bufpool.Pool
	// Generation selects the generation to recover. nil: the one
	// root.current names, or, when the root is missing or damaged, the
	// highest generation directory (reported as not authoritative).
	Generation *uint64
	// Budget bounds the payload bytes hashed by resynchronization probes
	// per blob (§11.2.1); 0 selects blob.DefaultResyncBudget.
	Budget int64
	// NoManifest ignores the manifest entirely.
	NoManifest bool
	// Key is the DEK of an encrypted archive. Without it recovery is
	// keyless (§15.10): frames are validated structurally, DATA extents
	// are grouped by their opaque object_id, nothing can be extracted.
	Key []byte
}

// Source tells where an extent's frame came from.
type Source int

const (
	// Scanned: found by the normal scan before any damage in its blob.
	Scanned Source = iota
	// Resynced: found by resynchronization (or after it) (§11.2.1).
	Resynced
	// Rebuilt: reconstructed from its parity group (§7.3).
	Rebuilt
)

func (s Source) String() string {
	return [...]string{"scanned", "resynced", "rebuilt"}[s]
}

// Range is a logical byte range [Offset, Offset+Length).
type Range struct{ Offset, Length uint64 }

// Extent is one recovered piece of a version.
type Extent struct {
	Offset, Length uint64
	Source         Source
	// Blob and FrameOffset locate the frame (FrameOffset -1 when rebuilt).
	Blob        int
	FrameOffset int64
	fr          *frameRec
}

// Version is one recovered object version (path, file_ver). Raw recovery
// reports versions, never the archive's live state (§11.2.2).
type Version struct {
	Path    string
	FileVer uint64
	// Opaque: a keyless recovery of an encrypted archive grouped these
	// extents by ObjectID; Path and FileVer are unknown (§6.5, §15.10).
	Opaque   bool
	ObjectID [16]byte
	Packed   bool
	// End is the end of the last extent found.
	End     uint64
	Extents []Extent // by offset
	// Gaps are ranges below End that no extent covers (and, when the
	// manifest knows the length, the missing range at the end).
	Gaps []Range
	// Complete: extents cover [0, End) exactly once and, when the
	// manifest knows the version, End equals its length. Without a
	// manifest a lost final extent cannot be detected: Complete then
	// means "no gap below the last extent found".
	Complete bool
	// LengthKnown: the manifest recorded the version's length.
	LengthKnown bool
	Length      uint64
	// Unverified: some extent comes from a resync candidate (or was
	// rebuilt from one) that no surviving manifest references (§11.2.1).
	Unverified bool
	// Committed: a surviving manifest record references the version.
	// Otherwise it is "not known to be committed" (§11.2.2).
	Committed bool
	// Current: it is the live version of its path in the surviving
	// manifest (only when the whole manifest loaded).
	Current bool
	// Conflict: frames of this version overlap, disagree, or mix PACKED
	// and DATA; its content is not trusted.
	Conflict bool
}

// BlobReport describes one blob file.
type BlobReport struct {
	Ordinal    uint8
	Err        error // the blob could not be opened
	Size       int64
	Frames     int
	Candidates int
	Conflicts  int
	Damaged    []blob.Region
	Unscanned  []blob.Region
}

// GroupReport counts parity groups (§11.6, §13.9 classification).
type GroupReport struct {
	Total int
	// Intact: every member was found.
	Intact int
	// Degraded: members are missing, but every DATA/PACKED member is
	// present or was rebuilt.
	Degraded int
	// Unrecoverable: a DATA/PACKED member is missing and cannot be rebuilt.
	Unrecoverable int
	// Conflicting: members disagree on group fields (§7); unused.
	Conflicting int
	// RebuiltFrames counts DATA/PACKED members reconstructed.
	RebuiltFrames int
}

// ManifestReport says what the surviving manifest contributed.
type ManifestReport struct {
	Loaded bool  // the whole manifest graph loaded
	Err    error // why not (records before the failure are still used)
	// Records applied (also before a failure).
	Records int
}

// Report is the result of Scan.
type Report struct {
	Header        *wire.ArchiveHeader
	Generation    uint64
	Authoritative bool  // the generation root.current names
	RootErr       error // root.current unusable
	Blobs         []BlobReport
	Groups        GroupReport
	Manifest      ManifestReport
	Versions      []*Version // by path, then file_ver (opaque ones first)
	// Keyless is set for an encrypted archive scanned without the DEK;
	// OpaquePacked counts PACKED frames whose objects stay unknown.
	Keyless      bool
	OpaquePacked int
}

// frameRec is a frame found intact or rebuilt.
type frameRec struct {
	blob      int
	off       int64 // -1: rebuilt
	quanta    uint32
	t         wire.MasterTrailer
	entries   []wire.Entry
	candidate bool // resync candidate or rebuilt from one
	conflict  bool
}

// Recovery holds an open scan; Extract reads data through it.
type Recovery struct {
	Report
	fsys    vfs.FS
	h       *wire.ArchiveHeader
	k       *seal.Keys
	key     []byte
	pool    *bufpool.Pool
	readers []*blob.Reader
	groups  map[uint32][]*frameRec

	cacheMu  sync.Mutex
	cacheG   uint32
	cacheBuf map[uint8][]byte // rebuilt frames of group cacheG
}

// Scan recovers the versions of one generation.
func Scan(fsys vfs.FS, opt Options) (*Recovery, error) {
	if opt.Pool == nil {
		opt.Pool = bufpool.Default
	}
	rep := Report{}
	gen, err := pickGeneration(fsys, opt, &rep)
	if err != nil {
		return nil, err
	}
	genDir := archive.GenDir(gen)
	h, err := archive.ReadHeader(fsys, genDir)
	if err != nil {
		return nil, fmt.Errorf("archive header of %s: %w", genDir, err)
	}
	k, err := archive.RecoveryKeys(fsys, h, opt.Key)
	if err != nil {
		return nil, err
	}
	rep.Header, rep.Generation = h, gen
	rep.Keyless = h.Encrypted() && k == nil
	rc := &Recovery{fsys: fsys, h: h, k: k, key: opt.Key, pool: opt.Pool, readers: make([]*blob.Reader, h.BlobCount), groups: map[uint32][]*frameRec{}}
	rep.Blobs = make([]BlobReport, h.BlobCount)
	results := make([]blob.ResyncResult, h.BlobCount)
	errs := make([]error, h.BlobCount)
	var wg sync.WaitGroup
	for b := range rc.readers {
		rep.Blobs[b].Ordinal = uint8(b)
		name, _ := blob.Name(uint8(b))
		r, err := blob.OpenKeyed(fsys, path.Join(genDir, name), h, opt.Pool, k)
		if err != nil {
			rep.Blobs[b].Err = err
			continue
		}
		rc.readers[b] = r
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[b], errs[b] = r.Resync(opt.Budget)
		}()
	}
	wg.Wait()
	var frames []*frameRec
	for b, res := range results {
		if errs[b] != nil {
			rep.Blobs[b].Err = errs[b]
			continue
		}
		if rc.readers[b] == nil {
			continue
		}
		br := &rep.Blobs[b]
		br.Size, br.Frames, br.Candidates, br.Conflicts = res.Size, len(res.Frames), res.Candidates, res.Conflicts
		br.Damaged, br.Unscanned = res.Damaged, res.Unscanned
		for _, f := range res.Frames {
			frames = append(frames, &frameRec{blob: b, off: f.Offset, quanta: f.Trailer.FrameQuanta, t: f.Trailer,
				entries: f.Entries, candidate: f.Candidate, conflict: f.Conflict})
		}
	}
	rc.Report = rep
	frames = append(frames, rc.rebuildGroups(frames)...)
	committed, current := rc.readManifest(genDir, opt)
	rc.Versions, rc.OpaquePacked = assemble(frames, committed, current, rep.Keyless)
	return rc, nil
}

func pickGeneration(fsys vfs.FS, opt Options, rep *Report) (uint64, error) {
	root, rootErr := archive.ReadRoot(fsys)
	rep.RootErr = rootErr
	if opt.Generation != nil {
		rep.Authoritative = rootErr == nil && root.GenerationID == *opt.Generation
		return *opt.Generation, nil
	}
	if rootErr == nil {
		rep.Authoritative = true
		return root.GenerationID, nil
	}
	gens, err := archive.Generations(fsys)
	if err != nil {
		return 0, err
	}
	if len(gens) == 0 {
		return 0, fmt.Errorf("no generation directory (%v)", rootErr)
	}
	return slices.Max(gens), nil
}

// Close releases the blob files.
func (rc *Recovery) Close() error {
	for _, r := range rc.readers {
		if r != nil {
			r.Close()
		}
	}
	return nil
}

// usable applies §7: equal group_k, group_m and frame_quanta, no repeated
// group_index.
func usable(ms []*frameRec) bool {
	seen := map[uint8]bool{}
	for _, m := range ms {
		if m.t.GroupK != ms[0].t.GroupK || m.t.GroupM != ms[0].t.GroupM || m.quanta != ms[0].quanta || seen[m.t.GroupIndex] {
			return false
		}
		seen[m.t.GroupIndex] = true
	}
	return true
}

// rebuildGroups groups frames by frame-local metadata (§11.6) and
// reconstructs missing DATA/PACKED members; it returns the rebuilt frames.
func (rc *Recovery) rebuildGroups(frames []*frameRec) []*frameRec {
	for _, f := range frames {
		if f.t.GroupID != 0 && !f.conflict {
			rc.groups[f.t.GroupID] = append(rc.groups[f.t.GroupID], f)
		}
	}
	gr := &rc.Groups
	var out []*frameRec
	ids := make([]uint32, 0, len(rc.groups))
	for g := range rc.groups {
		ids = append(ids, g)
	}
	slices.Sort(ids)
	for _, g := range ids {
		ms := rc.groups[g]
		gr.Total++
		if !usable(ms) {
			gr.Conflicting++
			delete(rc.groups, g)
			continue
		}
		k, m := int(ms[0].t.GroupK), int(ms[0].t.GroupM)
		if len(ms) == k+m {
			gr.Intact++
			continue
		}
		rebuilt, err := rc.rebuild(g)
		if err != nil || rebuilt == nil {
			missingData := false
			have := map[uint8]bool{}
			for _, f := range ms {
				have[f.t.GroupIndex] = true
			}
			for i := 0; i < k; i++ {
				missingData = missingData || !have[uint8(i)]
			}
			if missingData {
				gr.Unrecoverable++
			} else {
				gr.Degraded++
			}
			continue
		}
		gr.Degraded++
		cand := false
		for _, f := range ms {
			cand = cand || f.candidate
		}
		for i, buf := range rebuilt {
			fr, err := frame.ParseKeyed(buf, rc.h, rc.k)
			if err != nil {
				continue
			}
			rec := &frameRec{blob: -1, off: -1, quanta: fr.Prefix.FrameQuanta, t: fr.Trailer, candidate: cand,
				entries: append([]wire.Entry(nil), fr.Entries...)}
			if rec.t.GroupID != g || rec.t.GroupIndex != i {
				continue
			}
			out = append(out, rec)
			gr.RebuiltFrames++
		}
	}
	return out
}

// rebuild reconstructs the missing DATA/PACKED members of group g and
// returns their complete frames by group_index (not yet parsed), or nil
// when nothing is missing or too few members survive. Results of the last
// group are cached for Extract.
func (rc *Recovery) rebuild(g uint32) (map[uint8][]byte, error) {
	rc.cacheMu.Lock()
	defer rc.cacheMu.Unlock()
	if rc.cacheBuf != nil && rc.cacheG == g {
		return rc.cacheBuf, nil
	}
	ms := rc.groups[g]
	if len(ms) == 0 {
		return nil, nil
	}
	k, m, q := int(ms[0].t.GroupK), int(ms[0].t.GroupM), ms[0].quanta
	code, err := parity.New(rc.h.ParityScheme, k, m)
	if err != nil {
		return nil, err
	}
	shardLen := int(wire.ParityShardLen(q))
	shards := make([][]byte, k+m)
	present := make([]bool, k+m)
	for _, f := range ms {
		ref, err := rc.readers[f.blob].ReadFrame(f.off)
		if err != nil {
			continue
		}
		i := int(f.t.GroupIndex)
		if ref.Trailer.BlockType == wire.BlockParity {
			shards[i] = append([]byte(nil), ref.Payload...)
		} else if shards[i], err = frame.AppendRecoveryShard(nil, ref.Bytes()); err != nil {
			ref.Release()
			continue
		}
		present[i] = true
		ref.Release()
	}
	have := 0
	var missing []int
	for i := 0; i < k+m; i++ {
		if present[i] {
			have++
		} else if i < k {
			shards[i] = make([]byte, shardLen)
			missing = append(missing, i)
		}
	}
	if len(missing) == 0 || have < k {
		return nil, nil
	}
	if err := code.Reconstruct(shards, present); err != nil {
		return nil, err
	}
	out := map[uint8][]byte{}
	for _, i := range missing {
		fr, err := frame.AppendFromRecoveryShard(nil, shards[i], q)
		if err != nil {
			continue
		}
		out[uint8(i)] = fr
	}
	rc.cacheG, rc.cacheBuf = g, out
	return out, nil
}

type verKey struct {
	path string
	ver  uint64
	oid  [16]byte // keyless encrypted recovery only
}

// readManifest collects the versions that surviving records reference and
// their lengths, and the live versions when the whole graph loads.
func (rc *Recovery) readManifest(genDir string, opt Options) (map[verKey]uint64, map[verKey]bool) {
	committed := map[verKey]uint64{}
	if opt.NoManifest {
		return committed, nil
	}
	if rc.h.Encrypted() && rc.k == nil {
		rc.Manifest.Err = archive.ErrKeyRequired
		return committed, nil
	}
	type txInfo struct {
		k   verKey
		len uint64
	}
	txs := map[manifest.TxID]*txInfo{}
	var crypto *manifest.Crypto
	if rc.k != nil {
		crypto = &manifest.Crypto{Keys: rc.k, GenerationID: rc.h.GenerationID}
	}
	st, _, err := manifest.LoadWith(rc.fsys, genDir, rc.h, manifest.LoadOptions{Crypto: crypto}, func(r *manifest.Record, _ int) {
		rc.Manifest.Records++
		switch r.Op {
		case manifest.OpAdd:
			n := uint64(0)
			for _, l := range r.Loc {
				n += l.Length
			}
			committed[verKey{path: r.Path, ver: r.FileVer}] = n
		case manifest.OpAddBegin:
			txs[r.TxID] = &txInfo{k: verKey{path: r.Path, ver: r.FileVer}}
		case manifest.OpAddExtent:
			if t := txs[r.TxID]; t != nil {
				for _, l := range r.Loc {
					t.len += l.Length
				}
			}
		case manifest.OpAddCommit:
			if t := txs[r.TxID]; t != nil {
				committed[t.k] = t.len
			}
		}
	})
	if err != nil {
		rc.Manifest.Err = err
		return committed, nil
	}
	rc.Manifest.Loaded = true
	current := map[verKey]bool{}
	for _, p := range st.Paths() {
		v, _ := st.Lookup(p)
		current[verKey{path: p, ver: v.FileVer}] = true
	}
	return committed, current
}

// assemble builds versions from frame entries (§11.4, §11.5).
func assemble(frames []*frameRec, committed map[verKey]uint64, current map[verKey]bool, keyless bool) ([]*Version, int) {
	vs := map[verKey]*Version{}
	get := func(k verKey) *Version {
		v := vs[k]
		if v == nil {
			v = &Version{Path: k.path, FileVer: k.ver, ObjectID: k.oid}
			vs[k] = v
		}
		return v
	}
	opaquePacked := 0
	for _, f := range frames {
		if keyless && f.t.BlockType == wire.BlockPacked {
			opaquePacked++
			continue
		}
		if keyless && f.t.BlockType == wire.BlockData {
			// the object_id is an opaque grouping key without the key
			v := get(verKey{oid: f.t.ObjectID})
			v.Opaque = true
			if f.conflict {
				v.Conflict = true
				continue
			}
			src := Scanned
			switch {
			case f.off < 0:
				src = Rebuilt
			case f.candidate:
				src = Resynced
			}
			v.Extents = append(v.Extents, Extent{Offset: f.t.LogicalOffset, Length: f.t.LogicalLength, Source: src, Blob: f.blob, FrameOffset: f.off, fr: f})
			continue
		}
		src := Scanned
		switch {
		case f.off < 0:
			src = Rebuilt
		case f.candidate:
			src = Resynced
		}
		for _, e := range f.entries {
			v := get(verKey{path: e.Path, ver: e.FileVer})
			if f.conflict {
				v.Conflict = true
				continue
			}
			ext := Extent{Offset: e.Offset, Length: e.Length, Source: src, Blob: f.blob, FrameOffset: f.off, fr: f}
			switch f.t.BlockType {
			case wire.BlockPacked:
				if len(v.Extents) > 0 && !v.Packed {
					v.Conflict = true
				}
				v.Packed = true
				ext.Offset = 0
			case wire.BlockData:
				if v.Packed {
					v.Conflict = true
				}
			}
			v.Extents = append(v.Extents, ext)
		}
	}
	out := make([]*Version, 0, len(vs))
	for k, v := range vs {
		if n, ok := committed[k]; ok {
			v.Committed, v.LengthKnown, v.Length = true, true, n
		}
		v.Current = current[k]
		finish(v)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := strings.Compare(out[i].Path, out[j].Path); c != 0 {
			return c < 0
		}
		if out[i].FileVer != out[j].FileVer {
			return out[i].FileVer < out[j].FileVer
		}
		return string(out[i].ObjectID[:]) < string(out[j].ObjectID[:])
	})
	return out, opaquePacked
}

// finish sorts extents, drops duplicates (preferring scanned over resynced
// over rebuilt frames), finds gaps and overlaps, and labels provenance.
func finish(v *Version) {
	sort.SliceStable(v.Extents, func(i, j int) bool {
		a, b := v.Extents[i], v.Extents[j]
		if a.Offset != b.Offset {
			return a.Offset < b.Offset
		}
		return a.Source < b.Source
	})
	var ex []Extent
	for _, e := range v.Extents {
		if n := len(ex); n > 0 && ex[n-1].Offset == e.Offset {
			if ex[n-1].Length != e.Length {
				v.Conflict = true
			}
			continue // same extent from another frame
		}
		ex = append(ex, e)
	}
	v.Extents = ex
	if v.Packed && len(ex) > 1 {
		v.Conflict = true
	}
	at := uint64(0)
	for _, e := range ex {
		if e.Offset < at {
			v.Conflict = true
		} else if e.Offset > at {
			v.Gaps = append(v.Gaps, Range{at, e.Offset - at})
		}
		at = max(at, e.Offset+e.Length)
		if e.Source != Scanned && (e.Source == Resynced || e.fr.candidate) && !v.Committed {
			v.Unverified = true
		}
	}
	v.End = at
	if v.LengthKnown && v.Length > at {
		v.Gaps = append(v.Gaps, Range{at, v.Length - at})
	}
	if v.LengthKnown && v.Length < at {
		v.Conflict = true
	}
	v.Complete = len(v.Gaps) == 0 && !v.Conflict && len(ex) > 0
}

// ErrIncompleteVersion reports an Extract of a version with gaps or
// conflicts.
var ErrIncompleteVersion = errors.New("version is not completely recoverable")
