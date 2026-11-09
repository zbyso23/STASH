package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"runtime"
	"slices"
	"sync"

	"stash/internal/blob"
	"stash/internal/frame"
	"stash/internal/index"
	"stash/internal/manifest"
	"stash/internal/parity"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// CompactOptions configures Compact.
type CompactOptions struct {
	// KeepOld leaves the previous generation on disk after the switch;
	// GC removes it later.
	KeepOld bool
}

// CompactResult describes a compaction.
type CompactResult struct {
	From, To uint64 // generation ids
	// Versions is the number of live versions in the destination.
	Versions int
	// Delta counts paths changed after the Mark and merged at the freeze
	// (§13.4).
	Delta int
	// CopiedFrames were copied byte for byte (§13.2).
	CopiedFrames int
	// RebuiltFrames were reconstructed from parity and copied byte for
	// byte (§7.3.1 repair).
	RebuiltFrames int
	// RecomputedParity counts PARITY frames that were lost or damaged and
	// were recomputed with their group fields (§7.3.1).
	RecomputedParity int
	// RewrittenFrames were rewritten into new parity groups (§13.7.1);
	// RepackedObjects are small objects moved out of partly dead PACKED
	// frames into new ones.
	RewrittenFrames int
	RepackedObjects int
	// SourceBytes and DestBytes are the blob bytes of both generations.
	SourceBytes, DestBytes int64
	// Removed lists the generations GC removed afterwards.
	Removed []uint64
}

type liveKey struct {
	blob uint8
	k    blob.FrameKey
}

type verKey struct {
	path string
	ver  uint64
}

// compactor copies the live frames of a source view into a destination
// generation opened as a second Writer.
type compactor struct {
	src *view
	d   *Writer
	// groupFloor: destination group ids are allocated from here on, so a
	// copied group keeps its id only when it lies below (§7).
	groupFloor uint64
	res        *CompactResult

	mu         sync.Mutex
	live       map[liveKey]bool // wanted and not yet copied
	locs       map[verKey][]manifest.Loc
	doneFrames map[[2]int64]bool
	doneGroups map[uint32]bool
	maxOrd     []uint64
	hasOrd     []bool
	maxGroup   uint64
	regroup    map[uint32][]*frame.Spec // by frame_quanta, fewer than parity_k each
	repack     []*commitReq
	repackSize int
}

// Compact runs Mark -> Sweep -> Freeze/Merge -> Switch -> GC (§13): the live
// versions are copied into a new generation, byte for byte where possible;
// dead frames are dropped; damaged frames are repaired from parity on the
// way (§7.3.1); parity groups with dead members are regrouped (§13.7.1) and
// partly dead PACKED frames repacked. Writes continue during the Sweep and
// are merged while writes wait in the final Freeze. Sealed blobs are
// writable again in the new generation.
//
// A committed extent that cannot be found or rebuilt fails the compaction
// (the generation is GC-blocked, §13.8); nothing is switched.
func (w *Writer) Compact(ctx context.Context, opt CompactOptions) (res CompactResult, err error) {
	w.compactMu.Lock()
	defer w.compactMu.Unlock()

	// Mark (§13.1): the live state at one point
	w.genMu.RLock()
	src := w.view
	w.stateMu.RLock()
	snap := liveOf(w.journal.State())
	w.stateMu.RUnlock()
	var floor uint64
	if w.groupAlloc != nil {
		floor = w.groupAlloc.ReservedThrough()
	}
	var ordFloor uint64
	for _, a := range w.ordAlloc {
		ordFloor = max(ordFloor, a.ReservedThrough())
	}
	w.genMu.RUnlock()
	res.From = src.h.GenerationID

	id, err := w.genAlloc.Next()
	if err != nil {
		return res, err
	}
	res.To = id
	dh := *src.h
	dh.GenerationID = id
	if err := createGeneration(w.fsys, &dh); err != nil {
		return res, err
	}
	d := &Writer{fsys: w.fsys, opt: w.opt, busy: map[string]bool{}, genAlloc: w.genAlloc, verAlloc: w.verAlloc,
		health: Health{Sealed: map[uint8]error{}, TornBlobBytes: map[uint8]int64{}}}
	switched := false
	defer func() {
		if !switched {
			d.closeGeneration()
			vfs.RemoveAll(w.fsys, GenDir(id)) // an aborted attempt; its id is never reused
		}
	}()
	if err := d.openGeneration(GenDir(id), &dh); err != nil {
		return res, err
	}
	for _, a := range d.ordAlloc {
		if err := a.RaiseTo(ordFloor); err != nil {
			return res, err
		}
	}
	if d.groupAlloc != nil {
		if err := d.groupAlloc.RaiseTo(max(floor, 1)); err != nil {
			return res, err
		}
	}
	c := &compactor{src: src, d: d, groupFloor: floor, res: &res,
		live: map[liveKey]bool{}, locs: map[verKey][]manifest.Loc{}, doneFrames: map[[2]int64]bool{}, doneGroups: map[uint32]bool{},
		maxOrd: make([]uint64, dh.BlobCount), hasOrd: make([]bool, dh.BlobCount), regroup: map[uint32][]*frame.Spec{}}

	// Sweep (§13.2): concurrent with writes to the source
	if err := c.copyVersions(ctx, snap); err != nil {
		return res, err
	}
	paths := make([]string, 0, len(snap))
	for p := range snap {
		paths = append(paths, p)
	}
	slices.Sort(paths) // §13.2.1: one record per live path in bytewise order
	for _, p := range paths {
		if err := d.journal.Add(p, snap[p].FileVer, c.sortedLocs(p, snap[p])); err != nil {
			return res, fmt.Errorf("destination record %s: %w", p, err)
		}
	}
	if err := c.durable(); err != nil {
		return res, err
	}
	if err := c.verify(ctx, paths, true); err != nil {
		return res, err
	}

	// Freeze/Merge (§13.5): no commit against the old root from here on
	w.genMu.Lock()
	defer w.genMu.Unlock()
	w.stateMu.RLock()
	final := liveOf(w.journal.State())
	w.stateMu.RUnlock()
	delta := map[string]*manifest.Version{}
	var deltaPaths, gone []string
	for p, v := range final {
		if s, ok := snap[p]; !ok || s.FileVer != v.FileVer {
			delta[p] = v
			deltaPaths = append(deltaPaths, p)
		}
	}
	for p := range snap {
		if _, ok := final[p]; !ok {
			gone = append(gone, p)
		}
	}
	slices.Sort(deltaPaths)
	slices.Sort(gone)
	res.Delta = len(deltaPaths) + len(gone)
	if len(delta) > 0 {
		if err := c.copyVersions(ctx, delta); err != nil {
			return res, err
		}
	}
	for _, p := range gone {
		if err := d.journal.Del(p, snap[p].FileVer); err != nil {
			return res, err
		}
	}
	for _, p := range deltaPaths {
		if err := d.journal.Add(p, delta[p].FileVer, c.sortedLocs(p, delta[p])); err != nil {
			return res, fmt.Errorf("destination record %s: %w", p, err)
		}
	}
	if err := c.durable(); err != nil {
		return res, err
	}
	if err := c.verify(ctx, deltaPaths, false); err != nil {
		return res, err
	}
	res.Versions = len(final)
	res.SourceBytes, res.DestBytes = blobBytes(src), blobBytes(d.view)

	// Switch (§13.6): HARDENED advances the anchor first (§13.6.1 steps
	// 6-9); an error leaves the destination in place, because the anchor
	// may name it already, and the writer needs a reopen
	if w.hard.anchor != nil {
		if err := w.advanceSwitch(ctx, d, id); err != nil {
			switched = true // keep the destination directory
			d.closeGeneration()
			return res, err
		}
	}
	root := wire.Root{GenerationID: id, ArchiveID: dh.ArchiveID}
	if err := vfs.ReplaceFile(w.fsys, RootName, root.AppendBinary(nil)); err != nil {
		return res, err
	}
	switched = true
	old, oldWriters, oldJournal := w.view, w.writers, w.journal
	w.view, w.journal, w.seqAlloc, w.groupAlloc, w.ordAlloc, w.writers, w.health = d.view, d.journal, d.seqAlloc, d.groupAlloc, d.ordAlloc, d.writers, d.health
	for _, bw := range oldWriters {
		if bw != nil {
			bw.Close()
		}
	}
	oldJournal.Close()
	w.retiredMu.Lock()
	w.retired = append(w.retired, old)
	w.retiredMu.Unlock()
	old.retire()

	// GC (§13): old generations nothing pins any more
	if !opt.KeepOld {
		removed, err := w.gcLocked()
		res.Removed = removed
		if err != nil {
			return res, fmt.Errorf("compaction switched to generation %d; GC: %w", id, err)
		}
	}
	return res, nil
}

// closeGeneration closes the files of a generation opened by
// openGeneration without writing anything.
func (w *Writer) closeGeneration() {
	if w.view != nil {
		w.close()
	}
	for _, bw := range w.writers {
		if bw != nil {
			bw.Close()
		}
	}
	if w.journal != nil {
		w.journal.Close()
	}
}

func blobBytes(v *view) int64 {
	var n int64
	for _, bv := range v.blobs {
		if bv != nil {
			if s, err := bv.r.Size(); err == nil {
				n += s
			}
		}
	}
	return n
}

// keyOf is the identity a loc references (§9.1).
func keyOf(b uint8, hash [wire.HashSize]byte, e wire.Entry, bt wire.BlockType) liveKey {
	off := e.Offset
	if bt == wire.BlockPacked {
		off = 0
	}
	return liveKey{b, blob.FrameKey{Hash: hash, Path: e.Path, FileVer: e.FileVer, Offset: off}}
}

// copyVersions copies the frames of vers into the destination.
func (c *compactor) copyVersions(ctx context.Context, vers map[string]*manifest.Version) error {
	c.mu.Lock()
	for p, v := range vers {
		for _, l := range v.Loc {
			c.live[liveKey{l.Blob, blob.FrameKey{Hash: l.Hash, Path: p, FileVer: v.FileVer, Offset: l.Offset}}] = true
		}
	}
	c.mu.Unlock()
	fd := c.src.dir()
	fd.mu.Lock()
	err := c.src.refresh(fd)
	all := append([]*hopMember(nil), fd.all...)
	groups := make(map[uint32][]*hopMember, len(fd.groups))
	for g, ms := range fd.groups {
		groups[g] = append([]*hopMember(nil), ms...)
	}
	fd.mu.Unlock()
	if err != nil {
		return err
	}
	// units: ungrouped frames and groups holding a wanted entry
	var singles []*hopMember
	var gids []uint32
	seenG := map[uint32]bool{}
	c.mu.Lock()
	for _, m := range all {
		if c.doneFrames[[2]int64{int64(m.blob), m.off}] {
			continue
		}
		wanted := false
		for _, e := range m.entries {
			wanted = wanted || c.live[keyOf(m.blob, m.t.HashPayload, e, m.t.BlockType)]
		}
		if !wanted {
			continue
		}
		if g := m.t.GroupID; g != 0 {
			if !c.doneGroups[g] && !seenG[g] {
				seenG[g] = true
				gids = append(gids, g)
			}
		} else {
			singles = append(singles, m)
		}
	}
	c.mu.Unlock()
	run := func(n int, fn func(i int) error) error {
		var mu sync.Mutex
		var first error
		next := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < max(1, runtime.GOMAXPROCS(0)); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					mu.Lock()
					stop := first != nil
					mu.Unlock()
					if stop {
						continue
					}
					if err := fn(i); err != nil {
						mu.Lock()
						if first == nil {
							first = err
						}
						mu.Unlock()
					}
				}
			}()
		}
		for i := 0; i < n; i++ {
			if ctx.Err() != nil {
				break
			}
			next <- i
		}
		close(next)
		wg.Wait()
		if first == nil {
			first = ctx.Err()
		}
		return first
	}
	if err := run(len(singles), func(i int) error { return c.single(singles[i]) }); err != nil {
		return err
	}
	if err := run(len(gids), func(i int) error { return c.group(gids[i], groups[gids[i]]) }); err != nil {
		return err
	}
	// wanted entries not found intact: they can only sit in members that
	// are lost; rebuild the incomplete groups (§7.3)
	c.mu.Lock()
	missing := len(c.live) > 0
	var incomplete []uint32
	if missing {
		for g, ms := range groups {
			if !c.doneGroups[g] && len(ms) < int(ms[0].t.GroupK)+int(ms[0].t.GroupM) {
				incomplete = append(incomplete, g)
			}
		}
	}
	c.mu.Unlock()
	slices.Sort(incomplete)
	if err := run(len(incomplete), func(i int) error { return c.group(incomplete[i], groups[incomplete[i]]) }); err != nil {
		return err
	}
	if err := c.flush(true); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := len(c.live); n > 0 {
		for k := range c.live {
			return fmt.Errorf("%w: %d committed extents cannot be found or rebuilt, e.g. %s v%d at %d (blob %02X); the generation is GC-blocked (§13.8)",
				ErrMissingData, n, k.k.Path, k.k.FileVer, k.k.Offset, k.blob)
		}
	}
	return nil
}

// take claims the wanted entries of a frame of source blob b. full is true
// when every entry is wanted. c.mu is held.
func (c *compactor) takeLocked(b uint8, t *wire.MasterTrailer, entries []wire.Entry) (live []wire.Entry, full bool) {
	for _, e := range entries {
		k := keyOf(b, t.HashPayload, e, t.BlockType)
		if c.live[k] {
			delete(c.live, k)
			live = append(live, e)
		}
	}
	return live, len(live) == len(entries) && len(entries) > 0
}

// copyTo appends an encoded frame byte for byte to destination blob b.
func (c *compactor) copyTo(b int, fr []byte) (wire.IndexRecord, error) {
	rec, err := c.d.writers[b].AppendBuilt(fr)
	if err != nil {
		return rec, err
	}
	bv := c.d.blobs[b]
	bv.mu.Lock()
	bv.idx.Add(rec)
	bv.mu.Unlock()
	c.mu.Lock()
	if !c.hasOrd[b] || rec.FrameOrdinal > c.maxOrd[b] {
		c.maxOrd[b], c.hasOrd[b] = rec.FrameOrdinal, true
	}
	c.mu.Unlock()
	return rec, nil
}

// assign records the destination locs of live entries of a frame.
func (c *compactor) assign(b int, hash [wire.HashSize]byte, bt wire.BlockType, es []wire.Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range es {
		l := manifest.Loc{Blob: uint8(b), Hash: hash, Offset: e.Offset, Length: e.Length}
		if bt == wire.BlockPacked {
			l.Offset = 0
		}
		k := verKey{e.Path, e.FileVer}
		c.locs[k] = append(c.locs[k], l)
	}
}

func (c *compactor) sortedLocs(p string, v *manifest.Version) []manifest.Loc {
	c.mu.Lock()
	defer c.mu.Unlock()
	ls := c.locs[verKey{p, v.FileVer}]
	slices.SortFunc(ls, func(a, b manifest.Loc) int {
		switch {
		case a.Offset < b.Offset:
			return -1
		case a.Offset > b.Offset:
			return 1
		}
		return 0
	})
	return ls
}

// single handles an ungrouped frame.
func (c *compactor) single(m *hopMember) error {
	bv := c.src.blobs[m.blob]
	if bv == nil {
		return nil
	}
	ref, err := bv.r.ReadFrame(m.off)
	if err != nil {
		return nil // damaged: its entries stay wanted
	}
	defer ref.Release()
	t := &ref.Trailer
	if t.HashPayload != m.t.HashPayload || t.GroupID != 0 {
		return nil
	}
	c.mu.Lock()
	c.doneFrames[[2]int64{int64(m.blob), m.off}] = true
	live, full := c.takeLocked(m.blob, t, ref.Entries)
	c.mu.Unlock()
	if len(live) == 0 {
		return nil
	}
	if t.BlockType == wire.BlockData || full {
		if _, err := c.copyTo(int(m.blob), ref.Bytes()); err != nil {
			return err
		}
		c.assign(int(m.blob), t.HashPayload, t.BlockType, live)
		c.count(func(r *CompactResult) { r.CopiedFrames++ })
		return nil
	}
	return c.addRepack(live, ref.Payload)
}

func (c *compactor) count(fn func(*CompactResult)) {
	c.mu.Lock()
	fn(c.res)
	c.mu.Unlock()
}

// group handles one parity group: every member is read and validated,
// lost DATA/PACKED members are rebuilt (§7.3). A group whose members are
// all live is copied whole with its id (lost PARITY frames recomputed,
// §7.3.1); otherwise its live members are regrouped or repacked (§13.7.1).
func (c *compactor) group(g uint32, ms []*hopMember) error {
	c.mu.Lock()
	if c.doneGroups[g] {
		c.mu.Unlock()
		return nil
	}
	c.doneGroups[g] = true
	c.mu.Unlock()
	if !groupUsable(ms) {
		return nil // conflicting group_id: unused (§7)
	}
	h := c.src.h
	k, m, q := int(ms[0].t.GroupK), int(ms[0].t.GroupM), ms[0].quanta
	n := k + m
	refs := make([]*blob.Ref, n)
	srcBlob := make([]int, n)
	for i := range srcBlob {
		srcBlob[i] = -1
	}
	defer func() {
		for _, r := range refs {
			if r != nil {
				r.Release()
			}
		}
	}()
	for _, mem := range ms {
		i := int(mem.t.GroupIndex)
		srcBlob[i] = int(mem.blob)
		bv := c.src.blobs[mem.blob]
		if bv == nil {
			continue
		}
		ref, err := bv.r.ReadFrame(mem.off)
		if err != nil {
			continue
		}
		if ref.Trailer.GroupID != g || int(ref.Trailer.GroupIndex) != i {
			ref.Release()
			continue
		}
		refs[i] = ref
		c.mu.Lock()
		c.doneFrames[[2]int64{int64(mem.blob), mem.off}] = true
		c.mu.Unlock()
	}
	rebuilt := make([]bool, n)
	if err := c.rebuildMissing(g, refs, rebuilt, k, m, q); err != nil {
		return err
	}
	// claim wanted entries and decide
	live := make([][]wire.Entry, k)
	full := make([]bool, k)
	any := false
	c.mu.Lock()
	for i := 0; i < k; i++ {
		if refs[i] != nil {
			b := uint8(max(srcBlob[i], 0))
			live[i], full[i] = c.takeLocked(b, &refs[i].Trailer, refs[i].Entries)
			if srcBlob[i] < 0 {
				// a member lost with its blob: its loc names the blob it
				// was written to, which only the manifest knows; match any
				// blob of the archive
				for bb := 0; bb < int(h.BlobCount) && len(live[i]) < len(refs[i].Entries); bb++ {
					more, _ := c.takeLocked(uint8(bb), &refs[i].Trailer, refs[i].Entries)
					live[i] = append(live[i], more...)
				}
				full[i] = len(live[i]) == len(refs[i].Entries)
			}
			any = any || len(live[i]) > 0
		}
	}
	c.mu.Unlock()
	if !any {
		return nil
	}
	whole := uint64(g) < c.groupFloor
	for i := 0; i < k && whole; i++ {
		whole = refs[i] != nil && full[i]
	}
	if !whole {
		for i := 0; i < k; i++ {
			if refs[i] == nil || len(live[i]) == 0 {
				continue
			}
			t := &refs[i].Trailer
			if t.BlockType == wire.BlockData || full[i] {
				s := &frame.Spec{BlockType: t.BlockType, Codec: t.CodecID, Payload: append([]byte(nil), refs[i].Payload...),
					Entries: append([]wire.Entry(nil), refs[i].Entries...)}
				if err := c.addRegroup(s, q); err != nil {
					return err
				}
			} else if err := c.addRepack(live[i], refs[i].Payload); err != nil {
				return err
			}
		}
		return nil
	}
	// whole group: members keep their blobs; members lost with their blob
	// go to a blob the group does not use yet
	used := map[int]bool{}
	for _, b := range srcBlob {
		if b >= 0 {
			used[b] = true
		}
	}
	place := func(i int) int {
		if srcBlob[i] >= 0 {
			return srcBlob[i]
		}
		for b := range c.d.writers {
			if !used[b] {
				used[b] = true
				srcBlob[i] = b
				return b
			}
		}
		srcBlob[i] = (i + int(g)) % len(c.d.writers)
		return srcBlob[i]
	}
	for i := 0; i < k; i++ {
		b := place(i)
		if _, err := c.copyTo(b, refs[i].Bytes()); err != nil {
			return err
		}
		c.assign(b, refs[i].Trailer.HashPayload, refs[i].Trailer.BlockType, live[i])
		if rebuilt[i] {
			c.count(func(r *CompactResult) { r.RebuiltFrames++ })
		} else {
			c.count(func(r *CompactResult) { r.CopiedFrames++ })
		}
	}
	var parityShards [][]byte
	for j := 0; j < m; j++ {
		i := k + j
		b := place(i)
		if refs[i] != nil {
			if _, err := c.copyTo(b, refs[i].Bytes()); err != nil {
				return err
			}
			c.count(func(r *CompactResult) { r.CopiedFrames++ })
			continue
		}
		if parityShards == nil {
			var err error
			if parityShards, err = encodeGroup(h, refs[:k], k, m, q); err != nil {
				return err
			}
		}
		ord, err := c.d.ordAlloc[b].Next()
		if err != nil {
			return err
		}
		s := &frame.Spec{BlockType: wire.BlockParity, Codec: wire.CodecStore, Payload: parityShards[j],
			GroupID: g, GroupIndex: uint8(i), GroupK: uint8(k), GroupM: uint8(m), FrameOrdinal: ord, FrameQuanta: q}
		fr, err := frame.AppendFrame(nil, h, s)
		if err != nil {
			return err
		}
		if _, err := c.copyTo(b, fr); err != nil {
			return err
		}
		c.count(func(r *CompactResult) { r.RecomputedParity++ })
	}
	c.mu.Lock()
	c.maxGroup = max(c.maxGroup, uint64(g))
	c.mu.Unlock()
	return nil
}

// rebuildMissing reconstructs the DATA/PACKED members of a group that are
// missing from refs, when enough members survive.
func (c *compactor) rebuildMissing(g uint32, refs []*blob.Ref, rebuilt []bool, k, m int, q uint32) error {
	var missing []int
	have := 0
	for i := range refs {
		if refs[i] != nil {
			have++
		} else if i < k {
			missing = append(missing, i)
		}
	}
	if len(missing) == 0 || have < k {
		return nil
	}
	code, err := parity.New(c.src.h.ParityScheme, k, m)
	if err != nil {
		return nil
	}
	shardLen := int(wire.ParityShardLen(q))
	shards := make([][]byte, k+m)
	present := make([]bool, k+m)
	for i, r := range refs {
		if r == nil {
			if i < k {
				shards[i] = make([]byte, shardLen)
			}
			continue
		}
		if r.Trailer.BlockType == wire.BlockParity {
			shards[i] = r.Payload
		} else if shards[i], err = frame.AppendRecoveryShard(nil, r.Bytes()); err != nil {
			return err
		}
		present[i] = true
	}
	if err := code.Reconstruct(shards, present); err != nil {
		return nil
	}
	for _, i := range missing {
		buf := c.src.pool.Get(int(wire.FrameSize(q)))
		fr, err := frame.AppendFromRecoveryShard(buf[:0], shards[i], q)
		if err != nil {
			c.src.pool.Put(buf)
			continue
		}
		ref, err := blob.NewRef(fr, c.src.h, c.src.pool)
		if err != nil {
			c.src.pool.Put(buf)
			continue
		}
		if t := &ref.Trailer; t.GroupID != g || int(t.GroupIndex) != i || int(t.GroupK) != k || int(t.GroupM) != m {
			ref.Release()
			continue
		}
		refs[i], rebuilt[i] = ref, true
	}
	return nil
}

// encodeGroup computes the parity shards of a group from its data members.
func encodeGroup(h *wire.ArchiveHeader, data []*blob.Ref, k, m int, q uint32) ([][]byte, error) {
	code, err := parity.New(h.ParityScheme, k, m)
	if err != nil {
		return nil, err
	}
	shards := make([][]byte, k)
	for i, r := range data {
		if shards[i], err = frame.AppendRecoveryShard(nil, r.Bytes()); err != nil {
			return nil, err
		}
	}
	out := make([][]byte, m)
	for j := range out {
		out[j] = make([]byte, wire.ParityShardLen(q))
	}
	return out, code.Encode(shards, out)
}

// addRegroup queues a live member for a new group of equal frame size
// (§13.7.1) and writes a group once parity_k members are queued.
func (c *compactor) addRegroup(s *frame.Spec, q uint32) error {
	k := int(c.src.h.ParityK)
	c.mu.Lock()
	c.regroup[q] = append(c.regroup[q], s)
	var batch []*frame.Spec
	if len(c.regroup[q]) >= k {
		batch = c.regroup[q]
		delete(c.regroup, q)
	}
	c.mu.Unlock()
	if batch == nil {
		return nil
	}
	return c.writeRegroup(batch, q)
}

func (c *compactor) writeRegroup(specs []*frame.Spec, q uint32) error {
	placed, _, err := c.d.writeGroupFrames(specs, q)
	if err != nil {
		return err
	}
	for i, pl := range placed {
		c.assign(pl.blob, pl.rec.FrameHash, specs[i].BlockType, specs[i].Entries)
	}
	c.count(func(r *CompactResult) { r.RewrittenFrames += len(specs) })
	return nil
}

// repackBatch is the payload volume packed at once.
const repackBatch = 32 << 20

// addRepack queues the live objects of a partly dead PACKED frame for new
// PACKED frames (§8).
func (c *compactor) addRepack(live []wire.Entry, payload []byte) error {
	c.mu.Lock()
	for _, e := range live {
		c.repack = append(c.repack, &commitReq{path: e.Path, fileVer: e.FileVer, pack: true,
			small: append([]byte(nil), payload[e.Offset:e.Offset+e.Length]...)})
		c.repackSize += int(e.Length)
	}
	full := c.repackSize >= repackBatch
	c.mu.Unlock()
	if full {
		return c.flush(false)
	}
	return nil
}

// flush writes queued repacks, and with all also the short regroups.
func (c *compactor) flush(all bool) error {
	c.mu.Lock()
	batch := c.repack
	c.repack, c.repackSize = nil, 0
	var rg map[uint32][]*frame.Spec
	if all {
		rg, c.regroup = c.regroup, map[uint32][]*frame.Spec{}
	}
	c.mu.Unlock()
	if len(batch) > 0 {
		c.d.writePacked(batch)
		for _, r := range batch {
			if r.err != nil {
				return r.err
			}
			c.mu.Lock()
			k := verKey{r.path, r.fileVer}
			c.locs[k] = append(c.locs[k], r.locs...)
			c.res.RepackedObjects++
			c.mu.Unlock()
		}
	}
	qs := make([]uint32, 0, len(rg))
	for q := range rg {
		qs = append(qs, q)
	}
	slices.Sort(qs)
	for _, q := range qs {
		if err := c.writeRegroup(rg[q], q); err != nil {
			return err
		}
	}
	return nil
}

// durable makes the destination durable: blobs, allocators above every
// copied identifier, indexes, manifest, directories (§13.6).
func (c *compactor) durable() error {
	d := c.d
	var wg sync.WaitGroup
	errs := make([]error, len(d.writers))
	for b, bw := range d.writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[b] = bw.Sync()
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	c.mu.Lock()
	maxOrd, hasOrd, maxGroup := slices.Clone(c.maxOrd), slices.Clone(c.hasOrd), c.maxGroup
	c.mu.Unlock()
	for b, a := range d.ordAlloc {
		if hasOrd[b] {
			if err := a.RaiseTo(maxOrd[b] + 1); err != nil {
				return err
			}
		}
	}
	if d.groupAlloc != nil && maxGroup > 0 {
		if err := d.groupAlloc.RaiseTo(maxGroup + 1); err != nil {
			return err
		}
	}
	for b, bv := range d.blobs {
		iname, _ := index.Name(uint8(b))
		bv.mu.Lock()
		err := bv.idx.Write(d.fsys, path.Join(d.gen, iname))
		bv.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if err := d.journal.Sync(); err != nil {
		return err
	}
	for _, dir := range []string{d.gen, path.Join(d.gen, "frames"), path.Join(d.gen, "alloc"), path.Join(d.gen, "index"), "."} {
		if err := d.fsys.SyncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// verify reads the given destination paths completely and checks the
// parity groups (§13.5 step 4, §13.6, §13.8): with full every group's
// parity is recomputed, otherwise every group must have all members.
func (c *compactor) verify(ctx context.Context, paths []string, full bool) error {
	d := c.d
	st := d.journal.State()
	before := d.view.Repairs()
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		v, ok := st.Lookup(p)
		if !ok {
			return fmt.Errorf("%w: destination lacks %s", ErrMissingData, p)
		}
		o := d.view.object(p, v)
		_, err := io.Copy(io.Discard, o)
		o.Close()
		if err != nil {
			return fmt.Errorf("destination verification of %s: %w", p, err)
		}
	}
	if after := d.view.Repairs(); after != before {
		return fmt.Errorf("%w: destination needed repairs while verifying (%+v)", wire.ErrCorrupt, after)
	}
	if d.code == nil {
		return nil
	}
	if full {
		var gv GroupVerify
		if err := d.view.verifyGroups(ctx, &gv); err != nil {
			return err
		}
		if gv.Healthy != gv.Total {
			return fmt.Errorf("%w: destination parity groups not healthy (%+v)", wire.ErrCorrupt, gv)
		}
		return nil
	}
	fd := d.view.dir()
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if err := d.view.refresh(fd); err != nil {
		return err
	}
	for g, ms := range fd.groups {
		if !groupUsable(ms) || len(ms) != int(ms[0].t.GroupK)+int(ms[0].t.GroupM) {
			return fmt.Errorf("%w: destination group %d incomplete", wire.ErrCorrupt, g)
		}
	}
	return nil
}
