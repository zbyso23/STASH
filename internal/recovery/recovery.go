// Package recovery is raw disaster recovery (SPEC §11): it reconstructs
// object versions from blob files alone, using the frames' self-describing
// metadata, resynchronization after damage (§11.2.1) and parity (§11.6),
// and uses a surviving manifest only to label what it finds (§11.2.2).
package recovery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"stash/internal/archive"
	"stash/internal/blob"
	"stash/internal/bufpool"
	"stash/internal/frame"
	"stash/internal/kvtab"
	"stash/internal/manifest"
	"stash/internal/membudget"
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
	// WorkDir is where the scan keeps its working tables (what it found,
	// sorted; never inside the archive, which recovery does not write).
	// A private directory is created below it and removed by Close. Empty
	// means os.TempDir(). When it cannot be created, Scan fails with
	// ErrWorkDir.
	WorkDir string
	// MemoryLimit bounds the scan's working memory (0: 1 GiB).
	MemoryLimit int64
}

// ErrWorkDir reports a work directory that cannot be used.
var ErrWorkDir = errors.New("recovery: work directory unavailable")

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
	// Blob and FrameOffset locate the frame (-1 and -1 when rebuilt).
	Blob        int
	FrameOffset int64
	// the frame, to read it again
	hash      [wire.HashSize]byte
	group     uint32
	index     uint8
	candidate bool
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
	// Damaged lists the first blob.MaxRegions damaged regions;
	// DamagedRegions and DamagedBytes count all.
	Damaged        []blob.Region
	DamagedRegions int
	DamagedBytes   int64
	Unscanned      []blob.Region
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

// Report is the result of Scan. The versions themselves are streamed by
// Recovery.All and Recovery.Default.
type Report struct {
	Header        *wire.ArchiveHeader
	Generation    uint64
	Authoritative bool  // the generation root.current names
	RootErr       error // root.current unusable
	Blobs         []BlobReport
	Groups        GroupReport
	Manifest      ManifestReport
	// NVersions counts the versions found.
	NVersions int
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
//
// What the scan found lives in a sorted table in the work directory
// (kvtab, MAC-protected), not in memory:
//
//	'F' blob off         → a frame found by the scan
//	'G' group_id blob off → a member of a usable parity group
//	'E' version offset source → an extent (sorted: versions stream in
//	                       path, file_ver, object_id order)
//	'C' path 0 file_ver  → length of a version a manifest record commits
type Recovery struct {
	Report
	fsys    vfs.FS
	h       *wire.ArchiveHeader
	k       *seal.Keys
	key     []byte
	pool    *bufpool.Pool
	readers []*blob.Reader
	work    string
	cache   *kvtab.Cache
	tab     *kvtab.Table
	st      *manifest.State // the surviving manifest (Current), when loaded

	cacheMu  sync.Mutex
	cacheG   uint32
	cacheBuf map[uint8][]byte // rebuilt frames of group cacheG
}

// Scan recovers the versions of one generation.
func Scan(fsys vfs.FS, opt Options) (rc *Recovery, err error) {
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
	work, err := os.MkdirTemp(opt.WorkDir, "stash-recovery-")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWorkDir, err)
	}
	limit := opt.MemoryLimit
	if limit <= 0 {
		limit = 1 << 30
	}
	budget := membudget.New(limit)
	cache := kvtab.NewCache(budget, limit/8)
	scratch := func() (vfs.FS, string, error) { return vfs.OS{Root: work}, "kv", nil }
	env := &manifest.Env{Budget: budget, Cache: cache, Scratch: scratch, MemLimit: testKVMem, SortMemory: testKVMem}
	rep.Header, rep.Generation = h, gen
	rep.Keyless = h.Encrypted() && k == nil
	rc = &Recovery{fsys: fsys, h: h, k: k, key: opt.Key, pool: opt.Pool, readers: make([]*blob.Reader, h.BlobCount),
		work: work, cache: cache, tab: kvtab.New(kvtab.Config{Budget: budget, Cache: cache, Scratch: scratch, MemLimit: testKVMem})}
	defer func() {
		if err != nil {
			rc.Close()
			rc = nil
		}
	}()
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
			// frames go straight into the table, in offset order
			results[b], errs[b] = r.ResyncEach(opt.Budget, func(f blob.ResyncFrame) error {
				return rc.putFrame(&frameRec{blob: b, off: f.Offset, quanta: f.Trailer.FrameQuanta, t: f.Trailer,
					entries: f.Entries, candidate: f.Candidate, conflict: f.Conflict})
			})
		}()
	}
	wg.Wait()
	for b, res := range results {
		if errs[b] != nil {
			if !wire.IsFormatError(errs[b]) && errors.Is(errs[b], kvtab.ErrTampered) {
				return nil, errs[b]
			}
			rep.Blobs[b].Err = errs[b]
			continue
		}
		if rc.readers[b] == nil {
			continue
		}
		br := &rep.Blobs[b]
		br.Size, br.Frames, br.Candidates, br.Conflicts = res.Size, res.NFrames, res.Candidates, res.Conflicts
		br.Damaged, br.DamagedRegions, br.DamagedBytes, br.Unscanned = res.Damaged, res.DamagedRegions, res.DamagedBytes, res.Unscanned
	}
	rc.Report = rep
	if err := rc.rebuildGroups(); err != nil {
		return nil, err
	}
	if err := rc.readManifest(genDir, opt, env); err != nil {
		return nil, err
	}
	if err := rc.assemble(); err != nil {
		return nil, err
	}
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

// Close releases the blob files and removes the work directory.
func (rc *Recovery) Close() error {
	for _, r := range rc.readers {
		if r != nil {
			r.Close()
		}
	}
	if rc.st != nil {
		rc.st.Close()
		rc.st = nil
	}
	if rc.tab != nil {
		rc.tab.Close()
		rc.cache.Close()
		rc.tab = nil
	}
	if rc.work != "" {
		err := os.RemoveAll(rc.work)
		rc.work = ""
		return err
	}
	return nil
}

// testKVMem overrides the in-memory table delta (tests force spills).
var testKVMem int64

// ---- the frame table

func frameKey(b int, off int64) []byte {
	return binary.BigEndian.AppendUint64([]byte{'F', byte(b)}, uint64(off))
}

func encodeFrame(f *frameRec) ([]byte, error) {
	v := binary.BigEndian.AppendUint32(nil, f.quanta)
	v, err := f.t.AppendBinary(v)
	if err != nil {
		return nil, err
	}
	var flags byte
	if f.candidate {
		flags |= 1
	}
	if f.conflict {
		flags |= 2
	}
	if f.entries != nil {
		flags |= 4
	}
	v = append(v, flags)
	if f.entries != nil {
		if v, err = wire.AppendEntries(v, f.entries); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func decodeFrame(b int, off int64, v []byte) (*frameRec, error) {
	if len(v) < 4+wire.MasterTrailerSize+1 {
		return nil, kvtab.ErrTampered
	}
	f := &frameRec{blob: b, off: off, quanta: binary.BigEndian.Uint32(v)}
	var err error
	if f.t, err = wire.DecodeMasterTrailer(v[4 : 4+wire.MasterTrailerSize]); err != nil {
		return nil, kvtab.ErrTampered
	}
	flags := v[4+wire.MasterTrailerSize]
	f.candidate, f.conflict = flags&1 != 0, flags&2 != 0
	if flags&4 != 0 {
		if f.entries, err = wire.DecodeEntries(v[5+wire.MasterTrailerSize:]); err != nil {
			return nil, kvtab.ErrTampered
		}
	}
	return f, nil
}

// putFrame records a frame found by the scan. A PACKED frame's entry list
// can exceed what one table value holds; it is then read again from the
// blob when needed (flag 8, no entries stored).
func (rc *Recovery) putFrame(f *frameRec) error {
	v, err := encodeFrame(f)
	if err != nil {
		return err
	}
	if len(v) > kvtab.MaxValue {
		g := *f
		g.entries = nil
		if v, err = encodeFrame(&g); err != nil {
			return err
		}
		v[4+wire.MasterTrailerSize] |= 8
	}
	if err := rc.tab.Put(frameKey(f.blob, f.off), v); err != nil {
		return err
	}
	if g := f.t.GroupID; g != 0 && !f.conflict {
		k := binary.BigEndian.AppendUint32([]byte{'G'}, g)
		k = append(k, byte(f.blob))
		return rc.tab.Put(binary.BigEndian.AppendUint64(k, uint64(f.off)), nil)
	}
	return nil
}

func (rc *Recovery) frame(b int, off int64) (*frameRec, error) {
	v, ok, err := rc.tab.Get(frameKey(b, off))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, kvtab.ErrTampered
	}
	f, err := decodeFrame(b, off, v)
	if err != nil {
		return nil, err
	}
	if v[4+wire.MasterTrailerSize]&8 != 0 {
		ref, err := rc.readers[b].ReadFrame(off)
		if err != nil {
			return nil, err
		}
		f.entries = append([]wire.Entry(nil), ref.Entries...)
		ref.Release()
	}
	return f, nil
}

// group returns the members of group g (at most 257: more repeat an index).
func (rc *Recovery) group(g uint32) ([]*frameRec, error) {
	pfx := binary.BigEndian.AppendUint32([]byte{'G'}, g)
	it := rc.tab.Iter(pfx)
	defer it.Close()
	var ms []*frameRec
	for it.Next() && len(ms) < 257 {
		k := it.Key()
		if !bytes.HasPrefix(k, pfx) {
			break
		}
		if len(k) != len(pfx)+9 {
			return nil, kvtab.ErrTampered
		}
		f, err := rc.frame(int(k[5]), int64(binary.BigEndian.Uint64(k[6:])))
		if err != nil {
			return nil, err
		}
		ms = append(ms, f)
	}
	return ms, it.Err()
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

// rebuildGroups classifies the groups by frame-local metadata (§11.6) and
// reconstructs missing DATA/PACKED members; the rebuilt frames' extents
// join the others. Groups are visited in id order, one at a time.
func (rc *Recovery) rebuildGroups() error {
	gr := &rc.Groups
	var ids []uint32
	flush := func() error {
		for _, g := range ids {
			if err := rc.classify(g, gr); err != nil {
				return err
			}
		}
		ids = ids[:0]
		return nil
	}
	// collect ids in batches (the group table is read while extents are
	// added to the same table, so the iteration is not held across it)
	last, started := uint32(0), false
	for {
		start := []byte{'G'}
		if started {
			start = binary.BigEndian.AppendUint32([]byte{'G'}, last+1)
			if last == ^uint32(0) {
				return nil
			}
		}
		it := rc.tab.Iter(start)
		for it.Next() && len(ids) < 4096 {
			k := it.Key()
			if k[0] != 'G' {
				break
			}
			if len(k) != 14 {
				it.Close()
				return kvtab.ErrTampered
			}
			g := binary.BigEndian.Uint32(k[1:])
			if len(ids) == 0 || ids[len(ids)-1] != g {
				ids = append(ids, g)
			}
		}
		err := it.Err()
		it.Close()
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		last, started = ids[len(ids)-1], true
		if err := flush(); err != nil {
			return err
		}
	}
}

func (rc *Recovery) classify(g uint32, gr *GroupReport) error {
	ms, err := rc.group(g)
	if err != nil {
		return err
	}
	gr.Total++
	if !usable(ms) {
		gr.Conflicting++
		return rc.dropGroup(g)
	}
	k, m := int(ms[0].t.GroupK), int(ms[0].t.GroupM)
	if len(ms) == k+m {
		gr.Intact++
		return nil
	}
	rebuilt, err := rc.rebuildFrom(g, ms)
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
		return nil
	}
	gr.Degraded++
	cand := false
	for _, f := range ms {
		cand = cand || f.candidate
	}
	for i := 0; i < k; i++ {
		buf := rebuilt[uint8(i)]
		if buf == nil {
			continue
		}
		fr, err := frame.ParseKeyed(buf, rc.h, rc.k)
		if err != nil {
			continue
		}
		rec := &frameRec{blob: -1, off: -1, quanta: fr.Prefix.FrameQuanta, t: fr.Trailer, candidate: cand, entries: fr.Entries}
		if rec.t.GroupID != g || int(rec.t.GroupIndex) != i {
			continue
		}
		if err := rc.addExtents(rec); err != nil {
			return err
		}
		gr.RebuiltFrames++
	}
	return nil
}

// dropGroup removes a conflicting group's membership (its frames stay).
func (rc *Recovery) dropGroup(g uint32) error {
	pfx := binary.BigEndian.AppendUint32([]byte{'G'}, g)
	var keys [][]byte
	it := rc.tab.Iter(pfx)
	for it.Next() && bytes.HasPrefix(it.Key(), pfx) {
		keys = append(keys, bytes.Clone(it.Key()))
	}
	err := it.Err()
	it.Close()
	for _, k := range keys {
		if err == nil {
			err = rc.tab.Delete(k)
		}
	}
	return err
}

// rebuild reconstructs the missing DATA/PACKED members of group g and
// returns their complete frames by group_index (not yet parsed), or nil
// when nothing is missing or too few members survive. Results of the last
// group are cached for Extract.
func (rc *Recovery) rebuild(g uint32) (map[uint8][]byte, error) {
	ms, err := rc.group(g)
	if err != nil || len(ms) == 0 || !usable(ms) {
		return nil, err
	}
	return rc.rebuildFrom(g, ms)
}

func (rc *Recovery) rebuildFrom(g uint32, ms []*frameRec) (map[uint8][]byte, error) {
	rc.cacheMu.Lock()
	defer rc.cacheMu.Unlock()
	if rc.cacheBuf != nil && rc.cacheG == g {
		return rc.cacheBuf, nil
	}
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

// ---- manifest labels

func committedKey(p string, ver uint64) []byte {
	k := append([]byte{'C'}, p...)
	k = append(k, 0)
	return binary.BigEndian.AppendUint64(k, ver)
}

// readManifest records the versions that surviving records reference with
// their lengths ('C'), and keeps the loaded state for the live versions
// when the whole graph loads. Open transactions are tracked in the table
// too ('T'), so nothing per record stays in memory.
func (rc *Recovery) readManifest(genDir string, opt Options, env *manifest.Env) error {
	if opt.NoManifest {
		return nil
	}
	if rc.h.Encrypted() && rc.k == nil {
		rc.Manifest.Err = archive.ErrKeyRequired
		return nil
	}
	var crypto *manifest.Crypto
	if rc.k != nil {
		crypto = &manifest.Crypto{Keys: rc.k, GenerationID: rc.h.GenerationID}
	}
	var terr error
	put := func(k, v []byte) {
		if terr == nil {
			terr = rc.tab.Put(k, v)
		}
	}
	txKey := func(id manifest.TxID) []byte { return append([]byte{'T'}, id[:]...) }
	st, _, err := manifest.LoadWith(rc.fsys, genDir, rc.h, manifest.LoadOptions{Crypto: crypto, Env: env}, func(r *manifest.Record, _ int) {
		rc.Manifest.Records++
		switch r.Op {
		case manifest.OpAdd:
			n := uint64(0)
			for _, l := range r.Loc {
				n += l.Length
			}
			put(committedKey(r.Path, r.FileVer), binary.BigEndian.AppendUint64(nil, n))
		case manifest.OpAddBegin:
			put(txKey(r.TxID), binary.BigEndian.AppendUint64(committedKey(r.Path, r.FileVer), 0))
		case manifest.OpAddExtent:
			if v, ok, err := rc.tab.Get(txKey(r.TxID)); err != nil {
				terr = err
			} else if ok && len(v) >= 8 {
				n := binary.BigEndian.Uint64(v[len(v)-8:])
				for _, l := range r.Loc {
					n += l.Length
				}
				put(txKey(r.TxID), binary.BigEndian.AppendUint64(v[:len(v)-8], n))
			}
		case manifest.OpAddCommit:
			if v, ok, err := rc.tab.Get(txKey(r.TxID)); err != nil {
				terr = err
			} else if ok && len(v) >= 8 {
				put(v[:len(v)-8], v[len(v)-8:])
			}
		}
	})
	if terr != nil {
		if st != nil {
			st.Close()
		}
		return terr
	}
	if err != nil {
		rc.Manifest.Err = err
		return nil
	}
	rc.Manifest.Loaded = true
	rc.st = st
	return nil
}

// ---- versions

// extent record key: path 0 file_ver object_id | offset source; the value
// locates the frame and carries its flags
func versionPrefix(p string, ver uint64, oid [16]byte) []byte {
	k := append([]byte{'E'}, p...)
	k = append(k, 0)
	k = binary.BigEndian.AppendUint64(k, ver)
	return append(k, oid[:]...)
}

const (
	extConflict = 1 << iota // the version has a conflicting frame (no extent)
	extPacked
	extData
	extOpaque
	extCandidate
)

var extSeq uint64 // distinguishes equal (offset, source) records

func (rc *Recovery) putExtent(p string, ver uint64, oid [16]byte, off uint64, src Source, flags byte, length uint64, f *frameRec) error {
	k := versionPrefix(p, ver, oid)
	k = binary.BigEndian.AppendUint64(k, off)
	k = append(k, byte(src))
	k = binary.BigEndian.AppendUint64(k, atomicAdd(&extSeq))
	v := []byte{flags}
	v = binary.BigEndian.AppendUint64(v, length)
	v = append(v, byte(f.blob+1))
	v = binary.BigEndian.AppendUint64(v, uint64(f.off))
	v = append(v, f.t.HashPayload[:]...)
	v = binary.BigEndian.AppendUint32(v, f.t.GroupID)
	return rc.tab.Put(k, append(v, f.t.GroupIndex))
}

// addExtents records the extents a frame contributes (§11.4, §11.5).
func (rc *Recovery) addExtents(f *frameRec) error {
	keyless := rc.Keyless
	if keyless && f.t.BlockType == wire.BlockPacked {
		rc.OpaquePacked++
		return nil
	}
	src := Scanned
	switch {
	case f.off < 0:
		src = Rebuilt
	case f.candidate:
		src = Resynced
	}
	var cand byte
	if f.candidate {
		cand = extCandidate
	}
	if keyless && f.t.BlockType == wire.BlockData {
		// the object_id is an opaque grouping key without the key
		if f.conflict {
			return rc.putExtent("", 0, f.t.ObjectID, 0, src, extOpaque|extConflict, 0, f)
		}
		return rc.putExtent("", 0, f.t.ObjectID, f.t.LogicalOffset, src, extOpaque|extData|cand, f.t.LogicalLength, f)
	}
	for _, e := range f.entries {
		switch {
		case f.conflict:
			if err := rc.putExtent(e.Path, e.FileVer, [16]byte{}, 0, src, extConflict, 0, f); err != nil {
				return err
			}
		case f.t.BlockType == wire.BlockPacked:
			if err := rc.putExtent(e.Path, e.FileVer, [16]byte{}, 0, src, extPacked|cand, e.Length, f); err != nil {
				return err
			}
		case f.t.BlockType == wire.BlockData:
			if err := rc.putExtent(e.Path, e.FileVer, [16]byte{}, e.Offset, src, extData|cand, e.Length, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// assemble turns every scanned frame into extent records and counts the
// versions.
func (rc *Recovery) assemble() error {
	it := rc.tab.Iter([]byte{'F'})
	var batch []*frameRec
	flush := func() error {
		for _, f := range batch {
			if err := rc.addExtents(f); err != nil {
				return err
			}
		}
		batch = batch[:0]
		return nil
	}
	// frames are read in batches, then their extents written (writing
	// while iterating the same table is allowed, but batches keep the
	// iterator short-lived)
	var next []byte
	for {
		if next != nil {
			it = rc.tab.Iter(next)
		}
		for it.Next() && len(batch) < 1024 {
			k := it.Key()
			if k[0] != 'F' {
				break
			}
			if len(k) != 10 {
				it.Close()
				return kvtab.ErrTampered
			}
			f, err := rc.frame(int(k[1]), int64(binary.BigEndian.Uint64(k[2:])))
			if err != nil {
				it.Close()
				return err
			}
			batch = append(batch, f)
			next = append(bytes.Clone(k), 0)
		}
		err := it.Err()
		it.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		if err := flush(); err != nil {
			return err
		}
	}
	return rc.All()(func(*Version) bool { rc.NVersions++; return true })
}

// Selection streams versions to fn until it returns false.
type Selection func(fn func(*Version) bool) error

// Select is a selection of the given versions.
func Select(vs ...*Version) Selection {
	return func(fn func(*Version) bool) error {
		for _, v := range vs {
			if !fn(v) {
				break
			}
		}
		return nil
	}
}

// All streams every version found, by path, then file_ver (opaque ones
// first, by object_id). Only the version being visited is in memory.
func (rc *Recovery) All() Selection {
	return func(fn func(*Version) bool) error {
		it := rc.tab.Iter([]byte{'E'})
		defer it.Close()
		var cur []byte
		var v *Version
		emit := func() (bool, error) {
			if v == nil {
				return true, nil
			}
			if err := rc.label(v); err != nil {
				return false, err
			}
			finish(v)
			more := fn(v)
			v = nil
			return more, nil
		}
		for it.Next() {
			k, val := it.Key(), it.Value()
			if k[0] != 'E' {
				break
			}
			i := bytes.IndexByte(k, 0)
			if i < 0 || len(k) != i+1+8+16+8+1+8 || len(val) != 1+8+1+8+32+4+1 {
				return kvtab.ErrTampered
			}
			vk := k[:i+1+8+16]
			if v == nil || !bytes.Equal(vk, cur) {
				if more, err := emit(); err != nil || !more {
					return err
				}
				cur = append(cur[:0], vk...)
				v = &Version{Path: string(k[1:i]), FileVer: binary.BigEndian.Uint64(k[i+1:]), ObjectID: [16]byte(k[i+9 : i+25])}
			}
			flags := val[0]
			if flags&extOpaque != 0 {
				v.Opaque = true
			}
			if flags&extConflict != 0 {
				v.Conflict = true
				continue
			}
			rest := k[i+25:]
			e := Extent{Offset: binary.BigEndian.Uint64(rest), Source: Source(rest[8]), Length: binary.BigEndian.Uint64(val[1:]),
				Blob: int(val[9]) - 1, FrameOffset: int64(binary.BigEndian.Uint64(val[10:])), hash: [32]byte(val[18:50]),
				group: binary.BigEndian.Uint32(val[50:]), index: val[54], candidate: flags&extCandidate != 0}
			switch {
			case flags&extPacked != 0:
				if len(v.Extents) > 0 && !v.Packed {
					v.Conflict = true
				}
				v.Packed = true
			case flags&extData != 0 && !v.Opaque:
				if v.Packed {
					v.Conflict = true
				}
			}
			v.Extents = append(v.Extents, e)
		}
		if err := it.Err(); err != nil {
			return err
		}
		_, err := emit()
		return err
	}
}

// label adds what the manifest says about a version.
func (rc *Recovery) label(v *Version) error {
	if v.Opaque {
		return nil
	}
	b, ok, err := rc.tab.Get(committedKey(v.Path, v.FileVer))
	if err != nil {
		return err
	}
	if ok && len(b) == 8 {
		v.Committed, v.LengthKnown, v.Length = true, true, binary.BigEndian.Uint64(b)
	}
	if rc.st != nil {
		live, ok, err := rc.st.Lookup(v.Path)
		if err != nil {
			return err
		}
		v.Current = ok && live.FileVer == v.FileVer
	}
	return nil
}

// Versions collects every version (memory grows with the result; All
// streams them).
func (rc *Recovery) Versions() ([]*Version, error) { return collect(rc.All()) }

// DefaultSelection collects Default().
func (rc *Recovery) DefaultSelection() ([]*Version, error) { return collect(rc.Default()) }

func collect(s Selection) ([]*Version, error) {
	var out []*Version
	err := s(func(v *Version) bool { out = append(out, v); return true })
	return out, err
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
		if e.Source != Scanned && (e.Source == Resynced || e.candidate) && !v.Committed {
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

func atomicAdd(p *uint64) uint64 { return atomic.AddUint64(p, 1) }
