package archive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"stash/internal/blob"
	"stash/internal/frame"
	"stash/internal/kvtab"
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
//
// It lives in a sorted table in scratch space (kvtab, MAC-protected, never
// persistent), so memory does not grow with the archive:
//
//	'F' blob off          → quanta, trailer, entries (a member)
//	'H' hash blob off     → (non-PARITY frames by hash_payload)
//	'G' group_id blob off → (members of a parity group)
//	'K' frame key         → group_id that rebuilt the frame once
type frameDir struct {
	mu    sync.Mutex
	end   []int64 // per blob: hop resumes here
	tab   *kvtab.Table
	v     *view // rereads entries too large for the table
	stats RepairStats
}

// maxGroupMembers bounds what one group listing holds: group_index is a
// byte, so more members than this repeat an index and make the group_id
// conflicting (§7) whatever the rest says.
const maxGroupMembers = 257

// maxStoredEntries is the largest encoded entry list kept in the table;
// longer ones are read again from the frame's tail when needed.
const maxStoredEntries = 64 << 10

func (v *view) dir() *frameDir {
	v.dirOnce.Do(func() {
		v.fdir = &frameDir{end: make([]int64, len(v.blobs)), tab: kvtab.New(v.kv), v: v}
		for b := range v.fdir.end {
			v.fdir.end[b] = wire.FrameAreaStart
		}
	})
	return v.fdir
}

func (d *frameDir) close() {
	if d != nil {
		d.tab.Close()
	}
}

func memberKey(tag byte, pre []byte, b uint8, off int64) []byte {
	k := make([]byte, 0, 1+len(pre)+9)
	k = append(k, tag)
	k = append(k, pre...)
	k = append(k, b)
	return binary.BigEndian.AppendUint64(k, uint64(off))
}

func groupPrefix(g uint32) []byte { return binary.BigEndian.AppendUint32(nil, g) }

// put records a frame found by hopping; false when it was known.
func (d *frameDir) put(m *hopMember) (bool, error) {
	fk := memberKey('F', nil, m.blob, m.off)
	if _, ok, err := d.tab.Get(fk); err != nil || ok {
		return false, err
	}
	v := binary.BigEndian.AppendUint32(nil, m.quanta)
	v, err := m.t.AppendBinary(v)
	if err != nil {
		return false, err
	}
	switch {
	case m.entries == nil:
		v = append(v, 0)
	default:
		e, err := wire.AppendEntries(nil, m.entries)
		if err != nil {
			return false, err
		}
		if len(e) > maxStoredEntries {
			v = append(v, 2) // read again from the tail
		} else {
			v = append(append(v, 1), e...)
		}
	}
	if err := d.tab.Put(fk, v); err != nil {
		return false, err
	}
	if m.t.BlockType != wire.BlockParity {
		if err := d.tab.Put(memberKey('H', m.t.HashPayload[:], m.blob, m.off), nil); err != nil {
			return false, err
		}
	}
	if g := m.t.GroupID; g != 0 {
		if err := d.tab.Put(memberKey('G', groupPrefix(g), m.blob, m.off), nil); err != nil {
			return false, err
		}
	}
	return true, nil
}

// member decodes the 'F' record of a frame.
func (d *frameDir) member(b uint8, off int64) (*hopMember, error) {
	v, ok, err := d.tab.Get(memberKey('F', nil, b, off))
	if err != nil {
		return nil, err
	}
	if !ok || len(v) < 4+wire.MasterTrailerSize+1 {
		return nil, kvtab.ErrTampered
	}
	m := &hopMember{blob: b, off: off, quanta: binary.BigEndian.Uint32(v)}
	if m.t, err = wire.DecodeMasterTrailer(v[4 : 4+wire.MasterTrailerSize]); err != nil {
		return nil, kvtab.ErrTampered
	}
	rest := v[4+wire.MasterTrailerSize:]
	switch rest[0] {
	case 0:
	case 1:
		if m.entries, err = wire.DecodeEntries(rest[1:]); err != nil {
			return nil, kvtab.ErrTampered
		}
	case 2:
		bv := d.v.blobs[b]
		if bv == nil {
			return nil, fmt.Errorf("blob %02X unavailable", b)
		}
		hf, ok, err := bv.r.TailAt(off)
		if err != nil {
			return nil, err
		}
		if !ok || hf.Trailer != m.t {
			return nil, fmt.Errorf("%w: frame at %d of blob %02X changed", wire.ErrCorrupt, off, b)
		}
		m.entries = hf.Entries
	default:
		return nil, kvtab.ErrTampered
	}
	return m, nil
}

// scan iterates the members under a key prefix; key yields (blob, off)
// from the last nine bytes of each key.
func (d *frameDir) scan(pfx []byte, fn func(*hopMember) (bool, error)) error {
	it := d.tab.Iter(pfx)
	defer it.Close()
	for it.Next() {
		k := it.Key()
		if !bytes.HasPrefix(k, pfx) {
			break
		}
		if len(k) < len(pfx)+9 {
			return kvtab.ErrTampered
		}
		t := k[len(k)-9:]
		m, err := d.member(t[0], int64(binary.BigEndian.Uint64(t[1:])))
		if err != nil {
			return err
		}
		more, err := fn(m)
		if err != nil || !more {
			return err
		}
	}
	return it.Err()
}

// each visits every frame, by blob and offset.
func (d *frameDir) each(fn func(*hopMember) (bool, error)) error { return d.scan([]byte{'F'}, fn) }

// eachHash visits the non-PARITY frames with hash_payload h.
func (d *frameDir) eachHash(h [wire.HashSize]byte, fn func(*hopMember) (bool, error)) error {
	return d.scan(append([]byte{'H'}, h[:]...), fn)
}

// group returns the members of group g (at most maxGroupMembers).
func (d *frameDir) group(g uint32) ([]*hopMember, error) {
	var ms []*hopMember
	err := d.scan(append([]byte{'G'}, groupPrefix(g)...), func(m *hopMember) (bool, error) {
		ms = append(ms, m)
		return len(ms) < maxGroupMembers, nil
	})
	return ms, err
}

// eachGroup visits every group in id order with its members.
func (d *frameDir) eachGroup(fn func(g uint32, ms []*hopMember) (bool, error)) error {
	var cur uint32
	var ms []*hopMember
	stop := false
	flush := func() error {
		if len(ms) == 0 {
			return nil
		}
		more, err := fn(cur, ms)
		ms = nil
		stop = !more
		return err
	}
	it := d.tab.Iter([]byte{'G'})
	defer it.Close()
	for it.Next() && !stop {
		k := it.Key()
		if k[0] != 'G' {
			break
		}
		if len(k) != 1+4+9 {
			return kvtab.ErrTampered
		}
		g := binary.BigEndian.Uint32(k[1:])
		if g != cur {
			if err := flush(); err != nil || stop {
				return err
			}
			cur = g
		}
		if len(ms) >= maxGroupMembers {
			continue
		}
		m, err := d.member(k[5], int64(binary.BigEndian.Uint64(k[6:])))
		if err != nil {
			return err
		}
		ms = append(ms, m)
	}
	if err := it.Err(); err != nil {
		return err
	}
	if stop {
		return nil
	}
	return flush()
}

func rebuiltKey(k blob.FrameKey) []byte {
	b := append([]byte{'K'}, k.Hash[:]...)
	b = append(b, k.Path...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, k.FileVer)
	return binary.BigEndian.AppendUint64(b, k.Offset)
}

func (d *frameDir) rebuiltAs(k blob.FrameKey) (uint32, error) {
	v, ok, err := d.tab.Get(rebuiltKey(k))
	if err != nil || !ok {
		return 0, err
	}
	if len(v) != 4 {
		return 0, kvtab.ErrTampered
	}
	return binary.BigEndian.Uint32(v), nil
}

func (d *frameDir) setRebuiltAs(k blob.FrameKey, g uint32) error {
	return d.tab.Put(rebuiltKey(k), binary.BigEndian.AppendUint32(nil, g))
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
			_, err := d.put(&hopMember{blob: uint8(b), off: f.Offset, quanta: f.Quanta, t: f.Trailer, entries: f.Entries})
			return err
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
	var found *blob.Ref
	err := d.eachHash(l.Hash, func(m *hopMember) (bool, error) {
		if m.blob != l.Blob || !m.matches(p, ver.FileVer, l) || v.blobs[m.blob] == nil {
			return true, nil
		}
		ref, err := v.blobs[m.blob].r.ReadFrame(m.off)
		if err != nil {
			return true, nil
		}
		if accept(ref) {
			found = ref
			return false, nil
		}
		ref.Release()
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if found != nil {
		d.stats.Hopped++
		return found, nil
	}
	if v.h.ParityScheme == wire.ParityNone {
		d.stats.Failed++
		return nil, nil
	}
	// 2. parity: groups that hold the frame by its intact tail, groups
	// already known to hold it, groups with sibling extents of the same
	// version, then every group that lacks members. The candidates are
	// tried as they are found, so nothing per group is collected.
	key := blob.FrameKey{Hash: l.Hash, Path: p, FileVer: ver.FileVer, Offset: l.Offset}
	tried := map[uint32]bool{} // the groups of this one extent
	var ref *blob.Ref
	try := func(g uint32) (bool, error) {
		if g == 0 || tried[g] {
			return true, nil
		}
		if len(tried) < 1<<16 {
			tried[g] = true
		}
		r, err := v.rebuildFrom(d, g, key, accept)
		if err != nil {
			return false, err
		}
		if r != nil {
			ref = r
			return false, nil
		}
		return true, nil
	}
	err = d.eachHash(l.Hash, func(m *hopMember) (bool, error) {
		if m.matches(p, ver.FileVer, l) {
			return try(m.t.GroupID)
		}
		return true, nil
	})
	if err == nil && ref == nil {
		var g uint32
		if g, err = d.rebuiltAs(key); err == nil {
			_, err = try(g)
		}
	}
	for _, o := range ver.Loc {
		if err != nil || ref != nil {
			break
		}
		err = d.eachHash(o.Hash, func(m *hopMember) (bool, error) {
			if m.holds(p, ver.FileVer) {
				return try(m.t.GroupID)
			}
			return true, nil
		})
	}
	if err == nil && ref == nil {
		err = d.eachGroup(func(g uint32, ms []*hopMember) (bool, error) {
			if len(ms) < int(ms[0].t.GroupK)+int(ms[0].t.GroupM) {
				return try(g)
			}
			return true, nil
		})
	}
	if err != nil {
		if ref != nil {
			ref.Release()
		}
		return nil, err
	}
	if ref != nil {
		d.stats.Rebuilt++
		return ref, nil
	}
	d.stats.Failed++
	return nil, nil
}

// rebuildFrom reconstructs the data members of group g that do not
// validate and returns the one with identity key that accept approves.
// Every rebuilt member is remembered in d.rebuiltAs. d.mu is held.
func (v *view) rebuildFrom(d *frameDir, g uint32, key blob.FrameKey, accept func(*blob.Ref) bool) (*blob.Ref, error) {
	ms, err := d.group(g)
	if err != nil {
		return nil, err
	}
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
			if err := d.setRebuiltAs(rk, g); err != nil {
				ref.Release()
				if found != nil {
					found.Release()
				}
				return nil, err
			}
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
