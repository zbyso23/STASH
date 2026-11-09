package archive

import (
	"fmt"
	"sync"

	"stash/internal/blob"
	"stash/internal/frame"
	"stash/internal/manifest"
	"stash/internal/parity"
	"stash/internal/wire"
)

// RepairStats counts reads that needed more than the index and the
// streaming scan.
type RepairStats struct {
	// Hopped counts frames found intact only by hop-and-read (behind a
	// damaged region, where the index and the scan stop).
	Hopped uint64
	// Rebuilt counts frames reconstructed from parity (§7.3).
	Rebuilt uint64
	// Failed counts extents that stayed missing.
	Failed uint64
}

// hopMember is a frame found by hop-and-read (§11.2): Prefix and tail
// valid, payload not yet checked.
type hopMember struct {
	blob    uint8
	off     int64
	quanta  uint32
	t       wire.MasterTrailer
	entries []wire.Entry
}

func (m *hopMember) matches(p string, ver uint64, l manifest.Loc) bool {
	if m.t.HashPayload != l.Hash {
		return false
	}
	switch m.t.BlockType {
	case wire.BlockData:
		return len(m.entries) == 1 && m.entries[0].Path == p && m.entries[0].FileVer == ver && m.entries[0].Offset == l.Offset
	case wire.BlockPacked:
		return l.Offset == 0 && m.holds(p, ver)
	}
	return false
}

// holds reports whether the frame carries an entry of (p, ver).
func (m *hopMember) holds(p string, ver uint64) bool {
	for _, e := range m.entries {
		if e.Path == p && e.FileVer == ver {
			return true
		}
	}
	return false
}

// frameDir is the raw directory of every frame found by hopping all
// available blobs, with parity groups by frame-local metadata (§7.4,
// §11.6). It is built on the first repair and extended incrementally.
type frameDir struct {
	mu     sync.Mutex
	end    []int64 // per blob: hop resumes here
	seen   map[[2]int64]bool
	byHash map[[wire.HashSize]byte][]*hopMember
	groups map[uint32][]*hopMember
	all    []*hopMember // every frame found, in discovery order
	// rebuiltAs remembers which group holds a frame that was already
	// rebuilt once, so a lost blob is not decoded group by group again.
	rebuiltAs map[blob.FrameKey]uint32
	stats     RepairStats
}

func (v *view) dir() *frameDir {
	v.dirOnce.Do(func() {
		v.fdir = &frameDir{end: make([]int64, len(v.blobs)), seen: map[[2]int64]bool{},
			byHash: map[[wire.HashSize]byte][]*hopMember{}, groups: map[uint32][]*hopMember{},
			rebuiltAs: map[blob.FrameKey]uint32{}}
		for b := range v.fdir.end {
			v.fdir.end[b] = wire.FrameAreaStart
		}
	})
	return v.fdir
}

// Repairs returns the repair counters.
func (v *view) Repairs() RepairStats {
	d := v.dir()
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// refresh hops every available blob from where the last refresh stopped.
// Frames behind a gap are recorded too, but the next refresh resumes at
// the gap, because a writer may still be filling it. d.mu is held.
func (v *view) refresh(d *frameDir) error {
	for b, bv := range v.blobs {
		if bv == nil {
			continue
		}
		end, err := bv.r.HopFrom(d.end[b], func(f blob.HopFrame) error {
			k := [2]int64{int64(b), f.Offset}
			if d.seen[k] {
				return nil
			}
			d.seen[k] = true
			m := &hopMember{blob: uint8(b), off: f.Offset, quanta: f.Quanta, t: f.Trailer, entries: f.Entries}
			d.all = append(d.all, m)
			if f.Trailer.BlockType != wire.BlockParity {
				d.byHash[f.Trailer.HashPayload] = append(d.byHash[f.Trailer.HashPayload], m)
			}
			if g := f.Trailer.GroupID; g != 0 {
				d.groups[g] = append(d.groups[g], m)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("blob %02X: %w", b, err)
		}
		d.end[b] = end
	}
	return nil
}

// groupUsable applies the raw-recovery rule of §7: members agree on
// group_k, group_m and frame_quanta, and no group_index repeats.
// Otherwise the group_id is in conflict and none of it is used.
func groupUsable(ms []*hopMember) bool {
	if len(ms) == 0 {
		return false
	}
	seen := map[uint8]bool{}
	for _, m := range ms {
		if m.t.GroupK != ms[0].t.GroupK || m.t.GroupM != ms[0].t.GroupM || m.quanta != ms[0].quanta || seen[m.t.GroupIndex] {
			return false
		}
		seen[m.t.GroupIndex] = true
	}
	return true
}

// recover finds the frame of extent l of (p, ver) when the index and the
// scan did not: first among frames that hop-and-read finds intact (behind
// a damaged region), then by parity reconstruction (§7.3). accept checks
// the candidate's object metadata. The Ref must be released.
func (v *view) recover(p string, ver *manifest.Version, l manifest.Loc, accept func(*blob.Ref) bool) (*blob.Ref, error) {
	d := v.dir()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := v.refresh(d); err != nil {
		return nil, err
	}
	// 1. an intact frame the index and the scan could not reach
	for _, m := range d.byHash[l.Hash] {
		if m.blob != l.Blob || !m.matches(p, ver.FileVer, l) || v.blobs[m.blob] == nil {
			continue
		}
		ref, err := v.blobs[m.blob].r.ReadFrame(m.off)
		if err != nil {
			continue
		}
		if accept(ref) {
			d.stats.Hopped++
			return ref, nil
		}
		ref.Release()
	}
	if v.h.ParityScheme == wire.ParityNone {
		d.stats.Failed++
		return nil, nil
	}
	// 2. parity: groups that hold the frame by its intact tail, groups
	// already known to hold it, groups with sibling extents of the same
	// version, then every group that lacks members
	key := blob.FrameKey{Hash: l.Hash, Path: p, FileVer: ver.FileVer, Offset: l.Offset}
	var order []uint32
	tried := map[uint32]bool{}
	add := func(g uint32) {
		if g != 0 && !tried[g] {
			tried[g] = true
			order = append(order, g)
		}
	}
	for _, m := range d.byHash[l.Hash] {
		if m.matches(p, ver.FileVer, l) {
			add(m.t.GroupID)
		}
	}
	add(d.rebuiltAs[key])
	for _, o := range ver.Loc {
		for _, m := range d.byHash[o.Hash] {
			if m.holds(p, ver.FileVer) {
				add(m.t.GroupID)
			}
		}
	}
	for g, ms := range d.groups {
		if len(ms) < int(ms[0].t.GroupK)+int(ms[0].t.GroupM) {
			add(g)
		}
	}
	for _, g := range order {
		ref, err := v.rebuildFrom(d, g, key, accept)
		if err != nil {
			return nil, err
		}
		if ref != nil {
			d.stats.Rebuilt++
			return ref, nil
		}
	}
	d.stats.Failed++
	return nil, nil
}

// rebuildFrom reconstructs the data members of group g that do not
// validate and returns the one with identity key that accept approves.
// Every rebuilt member is remembered in d.rebuiltAs. d.mu is held.
func (v *view) rebuildFrom(d *frameDir, g uint32, key blob.FrameKey, accept func(*blob.Ref) bool) (*blob.Ref, error) {
	ms := d.groups[g]
	if !groupUsable(ms) {
		return nil, nil
	}
	k, m, q := int(ms[0].t.GroupK), int(ms[0].t.GroupM), ms[0].quanta
	code, err := parity.New(v.h.ParityScheme, k, m)
	if err != nil {
		return nil, nil
	}
	shardLen := int(wire.ParityShardLen(q))
	shards := make([][]byte, k+m)
	present := make([]bool, k+m)
	var bufs [][]byte
	defer func() {
		for _, b := range bufs {
			v.pool.Put(b)
		}
	}()
	get := func() []byte {
		b := v.pool.Get(shardLen)[:shardLen]
		bufs = append(bufs, b)
		return b
	}
	for _, mem := range ms {
		bv := v.blobs[mem.blob]
		if bv == nil {
			continue
		}
		ref, err := bv.r.ReadFrame(mem.off)
		if err != nil {
			continue // damaged member: treat as missing
		}
		i := int(mem.t.GroupIndex)
		if ref.Trailer.GroupID != g || int(ref.Trailer.GroupIndex) != i {
			ref.Release()
			continue
		}
		if ref.Trailer.BlockType == wire.BlockParity {
			shards[i] = append(get()[:0], ref.Payload...)
		} else if shards[i], err = frame.AppendRecoveryShard(get()[:0], ref.Bytes()); err != nil {
			shards[i] = nil
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
			shards[i] = get()
			missing = append(missing, i)
		}
	}
	if len(missing) == 0 || have < k {
		return nil, nil
	}
	if err := code.Reconstruct(shards, present); err != nil {
		return nil, nil
	}
	var found *blob.Ref
	for _, i := range missing {
		buf := v.pool.Get(int(wire.FrameSize(q)))
		fr, err := frame.AppendFromRecoveryShard(buf[:0], shards[i], q)
		if err != nil {
			v.pool.Put(buf)
			continue
		}
		ref, err := blob.NewRef(fr, v.h, v.pool, v.k)
		if err != nil {
			v.pool.Put(buf)
			continue
		}
		t := &ref.Trailer
		if t.GroupID != g || int(t.GroupIndex) != i || t.GroupK != uint8(k) || t.GroupM != uint8(m) {
			ref.Release()
			continue
		}
		hit := false
		for _, e := range ref.Entries {
			off := e.Offset
			if t.BlockType == wire.BlockPacked {
				off = 0 // §9.1: a PACKED loc names offset 0
			}
			rk := blob.FrameKey{Hash: t.HashPayload, Path: e.Path, FileVer: e.FileVer, Offset: off}
			d.rebuiltAs[rk] = g
			hit = hit || rk == key
		}
		if found == nil && hit && accept(ref) {
			found = ref
			continue
		}
		ref.Release()
	}
	return found, nil
}

// repairs is embedded in view.
type repairs struct {
	dirOnce sync.Once
	fdir    *frameDir
}
