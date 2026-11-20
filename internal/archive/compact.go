package archive

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"stash/internal/kvtab"
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

	// tab is the compaction's working table in scratch space (kvtab):
	//
	//	'S' path              → file_ver at the Mark (the snapshot)
	//	'X' path / 'Y' path   → file_ver of a path changed / removed after it
	//	'L' blob frame key    → an extent wanted and not yet copied
	//	'D' path 0 ver off    → its destination loc
	//	'd' blob off, 'g' gid → frames and groups handled
	//	'q' gid               → groups holding a wanted entry
	tab *kvtab.Table

	mu         sync.Mutex
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
	c := &compactor{src: src, res: &res, tab: kvtab.New(src.kv),
		maxOrd: make([]uint64, src.h.BlobCount), hasOrd: make([]bool, src.h.BlobCount), regroup: map[uint32][]*frame.Spec{}}
	defer c.tab.Close()
	w.stateMu.RLock()
	err = w.journal.State().Walk("", "", func(p string, v *manifest.Version) bool {
		if err = c.tab.Put(append([]byte{'S'}, p...), binary.BigEndian.AppendUint64(nil, v.FileVer)); err == nil {
			err = c.want(p, v)
		}
		return err == nil
	})
	w.stateMu.RUnlock()
	if err != nil {
		w.genMu.RUnlock()
		return res, err
	}
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
	d := &Writer{fsys: w.fsys, opt: w.opt, env: w.env, stEnv: w.stEnv, busy: map[string]bool{}, genAlloc: w.genAlloc, verAlloc: w.verAlloc, keys: w.keys,
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
	c.d, c.groupFloor = d, floor

	// Sweep (§13.2): concurrent with writes to the source
	if err := c.copyVersions(ctx); err != nil {
		return res, err
	}
	// §13.2.1: one record per live path in bytewise order
	if err := c.eachPath('S', func(p string, ver uint64) error {
		locs, err := c.sortedLocs(p, ver)
		if err == nil {
			err = d.journal.Add(p, ver, locs)
		}
		if err != nil {
			return fmt.Errorf("destination record %s: %w", p, err)
		}
		return nil
	}); err != nil {
		return res, err
	}
	if err := c.durable(); err != nil {
		return res, err
	}
	if err := c.verify(ctx, 'S', true); err != nil {
		return res, err
	}

	// Freeze/Merge (§13.5): no commit against the old root from here on
	w.genMu.Lock()
	defer w.genMu.Unlock()
	// the delta: a merge of the final state with the snapshot, both in
	// path order
	ndelta, ngone := 0, 0
	snapIt := c.tab.Iter([]byte{'S'})
	snapNext := func() (string, uint64, bool, error) {
		if !snapIt.Next() {
			return "", 0, false, snapIt.Err()
		}
		k := snapIt.Key()
		if k[0] != 'S' {
			return "", 0, false, nil
		}
		if len(snapIt.Value()) != 8 {
			return "", 0, false, kvtab.ErrTampered
		}
		return string(k[1:]), binary.BigEndian.Uint64(snapIt.Value()), true, nil
	}
	sp, sver, sok, err := snapNext()
	gone := func(p string, ver uint64) error {
		ngone++
		return c.tab.Put(append([]byte{'Y'}, p...), binary.BigEndian.AppendUint64(nil, ver))
	}
	w.stateMu.RLock()
	if err == nil {
		err = w.journal.State().Walk("", "", func(p string, v *manifest.Version) bool {
			res.Versions++
			for err == nil && sok && sp < p {
				if err = gone(sp, sver); err == nil {
					sp, sver, sok, err = snapNext()
				}
			}
			if err != nil {
				return false
			}
			same := sok && sp == p && sver == v.FileVer
			if sok && sp == p {
				if sp, sver, sok, err = snapNext(); err != nil {
					return false
				}
			}
			if !same {
				ndelta++
				if err = c.tab.Put(append([]byte{'X'}, p...), binary.BigEndian.AppendUint64(nil, v.FileVer)); err == nil {
					err = c.want(p, v)
				}
			}
			return err == nil
		})
	}
	for err == nil && sok {
		if err = gone(sp, sver); err == nil {
			sp, sver, sok, err = snapNext()
		}
	}
	w.stateMu.RUnlock()
	snapIt.Close()
	if err != nil {
		return res, err
	}
	res.Delta = ndelta + ngone
	if ndelta > 0 {
		if err := c.copyVersions(ctx); err != nil {
			return res, err
		}
	}
	if err := c.eachPath('Y', func(p string, ver uint64) error { return d.journal.Del(p, ver) }); err != nil {
		return res, err
	}
	if err := c.eachPath('X', func(p string, ver uint64) error {
		locs, err := c.sortedLocs(p, ver)
		if err == nil {
			err = d.journal.Add(p, ver, locs)
		}
		if err != nil {
			return fmt.Errorf("destination record %s: %w", p, err)
		}
		return nil
	}); err != nil {
		return res, err
	}
	if err := c.durable(); err != nil {
		return res, err
	}
	if err := c.verify(ctx, 'X', false); err != nil {
		return res, err
	}
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
	if w.hard.anchor != nil && w.h.Encrypted() {
		// the adopted allocators are bound from now on (§2.1.3.5)
		if err := w.hookReservations(ctx); err != nil {
			return res, err
		}
	}

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

func liveKeyBytes(k liveKey) []byte {
	b := append([]byte{'L', k.blob}, k.k.Hash[:]...)
	b = append(b, k.k.Path...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, k.k.FileVer)
	return binary.BigEndian.AppendUint64(b, k.k.Offset)
}

func parseLiveKey(b []byte) (liveKey, bool) {
	if len(b) < 2+32+1+16 || b[0] != 'L' {
		return liveKey{}, false
	}
	k := liveKey{blob: b[1]}
	k.k.Hash = [32]byte(b[2:34])
	rest := b[34:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 || len(rest)-i-1 != 16 {
		return liveKey{}, false
	}
	k.k.Path = string(rest[:i])
	k.k.FileVer = binary.BigEndian.Uint64(rest[i+1:])
	k.k.Offset = binary.BigEndian.Uint64(rest[i+9:])
	return k, true
}

func frameKeyBytes(tag byte, b uint8, off int64) []byte {
	return binary.BigEndian.AppendUint64([]byte{tag, b}, uint64(off))
}

// want marks the extents of a version as wanted.
func (c *compactor) want(p string, v *manifest.Version) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// no lookup first: a key is wanted once or more, the table holds it once
	for _, l := range v.Loc {
		k := liveKeyBytes(liveKey{l.Blob, blob.FrameKey{Hash: l.Hash, Path: p, FileVer: v.FileVer, Offset: l.Offset}})
		if err := c.tab.Put(k, nil); err != nil {
			return err
		}
	}
	return nil
}

// eachPath visits the paths under tag ('S', 'X', 'Y') in order.
func (c *compactor) eachPath(tag byte, fn func(p string, ver uint64) error) error {
	it := c.tab.Iter([]byte{tag})
	defer it.Close()
	for it.Next() {
		k := it.Key()
		if k[0] != tag {
			break
		}
		if len(it.Value()) != 8 {
			return kvtab.ErrTampered
		}
		if err := fn(string(k[1:]), binary.BigEndian.Uint64(it.Value())); err != nil {
			return err
		}
	}
	return it.Err()
}

func (c *compactor) has(k []byte) (bool, error) {
	_, ok, err := c.tab.Get(k)
	return ok, err
}

// copyVersions copies the frames holding wanted extents into the
// destination: frames come from the repair directory in blob and offset
// order and are handed to workers as they are found, so nothing per frame
// is collected in memory.
func (c *compactor) copyVersions(ctx context.Context) error {
	fd := c.src.dir()
	fd.mu.Lock()
	err := c.src.refresh(fd)
	fd.mu.Unlock()
	if err != nil {
		return err
	}
	run := func(feed func(send func(fn func() error) bool) error) error {
		var mu sync.Mutex
		var first error
		next := make(chan func() error)
		var wg sync.WaitGroup
		for w := 0; w < max(1, runtime.GOMAXPROCS(0)); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for fn := range next {
					mu.Lock()
					stop := first != nil
					mu.Unlock()
					if stop {
						continue
					}
					if err := fn(); err != nil {
						mu.Lock()
						if first == nil {
							first = err
						}
						mu.Unlock()
					}
				}
			}()
		}
		ferr := feed(func(fn func() error) bool {
			if ctx.Err() != nil {
				return false
			}
			mu.Lock()
			stop := first != nil
			mu.Unlock()
			if stop {
				return false
			}
			next <- fn
			return true
		})
		close(next)
		wg.Wait()
		if first == nil {
			first = ferr
		}
		if first == nil {
			first = ctx.Err()
		}
		return first
	}
	// ungrouped frames holding a wanted entry are copied as they are
	// found; groups holding one are queued ('q') and handled after
	if err := run(func(send func(func() error) bool) error {
		return fd.each(func(m *hopMember) (bool, error) {
			if done, err := c.has(frameKeyBytes('d', m.blob, m.off)); err != nil || done {
				return err == nil, err
			}
			wanted := false
			for _, e := range m.entries {
				ok, err := c.has(liveKeyBytes(keyOf(m.blob, m.t.HashPayload, e, m.t.BlockType)))
				if err != nil {
					return false, err
				}
				if wanted = ok; wanted {
					break
				}
			}
			if !wanted {
				return true, nil
			}
			if g := m.t.GroupID; g != 0 {
				q := binary.BigEndian.AppendUint32([]byte{'q'}, g)
				done, err := c.has(binary.BigEndian.AppendUint32([]byte{'g'}, g))
				if err == nil && !done {
					err = c.tab.Put(q, nil)
				}
				return err == nil, err
			}
			return send(func() error { return c.single(m) }), nil
		})
	}); err != nil {
		return err
	}
	groupsUnder := func(tag byte, send func(func() error) bool) error {
		it := c.tab.Iter([]byte{tag})
		defer it.Close()
		for it.Next() {
			k := it.Key()
			if k[0] != tag {
				break
			}
			if len(k) != 5 {
				return kvtab.ErrTampered
			}
			g := binary.BigEndian.Uint32(k[1:])
			if !send(func() error {
				ms, err := fd.group(g)
				if err != nil {
					return err
				}
				return c.group(g, ms)
			}) {
				break
			}
		}
		return it.Err()
	}
	if err := run(func(send func(func() error) bool) error { return groupsUnder('q', send) }); err != nil {
		return err
	}
	if err := c.clear('q'); err != nil {
		return err
	}
	// wanted entries not found intact: they can only sit in members that
	// are lost; rebuild the incomplete groups (§7.3)
	missing, err := c.liveLeft(1)
	if err != nil {
		return err
	}
	if missing > 0 {
		if err := run(func(send func(func() error) bool) error {
			return fd.eachGroup(func(g uint32, ms []*hopMember) (bool, error) {
				if len(ms) >= int(ms[0].t.GroupK)+int(ms[0].t.GroupM) {
					return true, nil
				}
				done, err := c.has(binary.BigEndian.AppendUint32([]byte{'g'}, g))
				if err != nil || done {
					return err == nil, err
				}
				return send(func() error { return c.group(g, ms) }), nil
			})
		}); err != nil {
			return err
		}
	}
	if err := c.flush(true); err != nil {
		return err
	}
	n, err := c.liveLeft(-1)
	if err != nil {
		return err
	}
	if n > 0 {
		it := c.tab.Iter([]byte{'L'})
		defer it.Close()
		if it.Next() {
			if k, ok := parseLiveKey(it.Key()); ok {
				return fmt.Errorf("%w: %d committed extents cannot be found or rebuilt, e.g. %s v%d at %d (blob %02X); the generation is GC-blocked (§13.8)",
					ErrMissingData, n, k.k.Path, k.k.FileVer, k.k.Offset, k.blob)
			}
		}
		if err := it.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: %d committed extents cannot be found or rebuilt; the generation is GC-blocked (§13.8)", ErrMissingData, n)
	}
	return nil
}

// verifyFrames verifies the whole destination with every frame read once:
// each blob is scanned completely (every frame fully validated: grid,
// CRCs, hash, Pre-Trailer), the extents found are recorded ('v' keys:
// path 0 file_ver offset → blob, hash, offset, length), and then every
// live version of the destination state must have each of its extents in
// a scanned frame of the right blob and hash, and in that blob's index.
// It checks what reading every version would, without parsing a PACKED
// frame once per object.
func (c *compactor) verifyFrames(ctx context.Context) error {
	d := c.d
	vkey := func(p string, ver, off uint64) []byte {
		k := append([]byte{'v'}, p...)
		k = append(k, 0)
		k = binary.BigEndian.AppendUint64(k, ver)
		return binary.BigEndian.AppendUint64(k, off)
	}
	// a table of its own, dropped whole afterwards
	vt := kvtab.New(c.src.kv)
	defer vt.Close()
	// the blobs are scanned in parallel (validation is the CPU cost)
	errs := make([]error, len(d.view.blobs))
	var wg sync.WaitGroup
	for b, bv := range d.view.blobs {
		if bv == nil {
			return fmt.Errorf("%w: destination blob %02X unavailable", ErrMissingData, b)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := bv.r.Scan(func(off int64, f *frame.Frame) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				bt := f.Trailer.BlockType
				if bt != wire.BlockData && bt != wire.BlockPacked {
					return nil
				}
				for _, e := range f.Entries {
					lo := e.Offset
					if bt == wire.BlockPacked {
						lo = 0
					}
					v := append([]byte{byte(b)}, f.Trailer.HashPayload[:]...)
					v = binary.BigEndian.AppendUint64(v, uint64(off))
					v = binary.BigEndian.AppendUint64(v, e.Length)
					if err := vt.Put(vkey(e.Path, e.FileVer, lo), v); err != nil {
						return err
					}
				}
				return nil
			})
			if err == nil && (res.Err != nil || res.End != res.Size) {
				err = fmt.Errorf("%w: destination blob %02X: %v", wire.ErrCorrupt, b, res.Err)
			}
			errs[b] = err
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	var werr error
	walked := 0
	if err := d.journal.State().Walk("", "", func(p string, v *manifest.Version) bool {
		walked++
		if werr = ctx.Err(); werr != nil {
			return false
		}
		for _, l := range v.Loc {
			val, ok, err := vt.Get(vkey(p, v.FileVer, l.Offset))
			if err == nil && (!ok || len(val) != 49 || val[0] != l.Blob || [wire.HashSize]byte(val[1:33]) != l.Hash ||
				binary.BigEndian.Uint64(val[41:]) != l.Length) {
				err = fmt.Errorf("%w: destination lacks %s v%d extent at %d", ErrMissingData, p, v.FileVer, l.Offset)
			}
			if err == nil {
				var has bool
				if has, err = d.view.blobs[l.Blob].idx.Has(l.Hash, binary.BigEndian.Uint64(val[33:])); err == nil && !has {
					err = fmt.Errorf("%w: destination index %02X lacks %s v%d extent at %d", wire.ErrCorrupt, l.Blob, p, v.FileVer, l.Offset)
				}
			}
			if err != nil {
				werr = err
				return false
			}
		}
		return true
	}); err != nil {
		return err
	}
	if werr != nil {
		return werr
	}
	// every snapshot path is in the destination (and nothing else)
	want := 0
	if err := c.eachPath('S', func(string, uint64) error { want++; return nil }); err != nil {
		return err
	}
	if walked != want {
		return fmt.Errorf("%w: destination has %d paths, the snapshot %d", ErrMissingData, walked, want)
	}
	return nil
}

// liveLeft counts the wanted extents not copied yet ('L' keys), up to
// limit (-1: all).
func (c *compactor) liveLeft(limit int) (int, error) {
	it := c.tab.Iter([]byte{'L'})
	defer it.Close()
	n := 0
	for (limit < 0 || n < limit) && it.Next() && it.Key()[0] == 'L' {
		n++
	}
	return n, it.Err()
}

// clear deletes the keys under tag.
func (c *compactor) clear(tag byte) error {
	var keys [][]byte
	from := []byte{tag}
	for {
		// continue after the last batch: restarting at the tag would step
		// over every tombstone written so far again
		it := c.tab.Iter(from)
		for it.Next() && it.Key()[0] == tag && len(keys) < 4096 {
			keys = append(keys, bytes.Clone(it.Key()))
		}
		err := it.Err()
		it.Close()
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return nil
		}
		for _, k := range keys {
			if err := c.tab.Delete(k); err != nil {
				return err
			}
		}
		from = append(keys[len(keys)-1], 0)
		keys = keys[:0]
	}
}

// take claims the wanted entries of a frame of source blob b. full is true
// when every entry is wanted. c.mu is held.
func (c *compactor) takeLocked(b uint8, t *wire.MasterTrailer, entries []wire.Entry) (live []wire.Entry, full bool, err error) {
	for _, e := range entries {
		k := liveKeyBytes(keyOf(b, t.HashPayload, e, t.BlockType))
		ok, err := c.has(k)
		if err != nil {
			return nil, false, err
		}
		if ok {
			if err := c.tab.Delete(k); err != nil {
				return nil, false, err
			}
			live = append(live, e)
		}
	}
	return live, len(live) == len(entries) && len(entries) > 0, nil
}

// copyTo appends an encoded frame byte for byte to destination blob b.
func (c *compactor) copyTo(b int, fr []byte) (wire.IndexRecord, error) {
	rec, err := c.d.writers[b].AppendBuilt(fr)
	if err != nil {
		return rec, err
	}
	if err := c.d.blobs[b].idx.Add(rec); err != nil {
		return rec, err
	}
	c.mu.Lock()
	if !c.hasOrd[b] || rec.FrameOrdinal > c.maxOrd[b] {
		c.maxOrd[b], c.hasOrd[b] = rec.FrameOrdinal, true
	}
	c.mu.Unlock()
	return rec, nil
}

// assign records the destination locs of live entries of a frame.
func (c *compactor) assign(b int, hash [wire.HashSize]byte, bt wire.BlockType, es []wire.Entry) error {
	for _, e := range es {
		l := manifest.Loc{Blob: uint8(b), Hash: hash, Offset: e.Offset, Length: e.Length}
		if bt == wire.BlockPacked {
			l.Offset = 0
		}
		if err := c.putLoc(e.Path, e.FileVer, l); err != nil {
			return err
		}
	}
	return nil
}

func destPrefix(p string, ver uint64) []byte {
	k := append([]byte{'D'}, p...)
	k = append(k, 0)
	return binary.BigEndian.AppendUint64(k, ver)
}

func (c *compactor) putLoc(p string, ver uint64, l manifest.Loc) error {
	k := binary.BigEndian.AppendUint64(destPrefix(p, ver), l.Offset)
	v := append([]byte{l.Blob}, l.Hash[:]...)
	return c.tab.Put(k, binary.BigEndian.AppendUint64(v, l.Length))
}

// sortedLocs returns the destination locs of a version in offset order.
// It holds the version's locs (the manifest record needs them at once).
func (c *compactor) sortedLocs(p string, ver uint64) ([]manifest.Loc, error) {
	pfx := destPrefix(p, ver)
	it := c.tab.Iter(pfx)
	defer it.Close()
	var ls []manifest.Loc
	for it.Next() {
		k, v := it.Key(), it.Value()
		if !bytes.HasPrefix(k, pfx) {
			break
		}
		if len(k) != len(pfx)+8 || len(v) != 1+32+8 {
			return nil, kvtab.ErrTampered
		}
		ls = append(ls, manifest.Loc{Blob: v[0], Hash: [32]byte(v[1:33]), Offset: binary.BigEndian.Uint64(k[len(pfx):]),
			Length: binary.BigEndian.Uint64(v[33:])})
	}
	return ls, it.Err()
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
	err = c.tab.Put(frameKeyBytes('d', m.blob, m.off), nil)
	var live []wire.Entry
	var full bool
	if err == nil {
		live, full, err = c.takeLocked(m.blob, t, ref.Entries)
	}
	c.mu.Unlock()
	if err != nil || len(live) == 0 {
		return err
	}
	if t.BlockType == wire.BlockData || full {
		if _, err := c.copyTo(int(m.blob), ref.Bytes()); err != nil {
			return err
		}
		if err := c.assign(int(m.blob), t.HashPayload, t.BlockType, live); err != nil {
			return err
		}
		c.count(func(r *CompactResult) { r.CopiedFrames++ })
		return nil
	}
	if err := ref.Decode(); err != nil {
		return fmt.Errorf("repack: %w", err)
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
	gk := binary.BigEndian.AppendUint32([]byte{'g'}, g)
	c.mu.Lock()
	done, err := c.has(gk)
	if err == nil && !done {
		err = c.tab.Put(gk, nil)
	}
	c.mu.Unlock()
	if err != nil || done {
		return err
	}
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
		err = c.tab.Put(frameKeyBytes('d', mem.blob, mem.off), nil)
		c.mu.Unlock()
		if err != nil {
			return err
		}
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
	for i := 0; i < k && err == nil; i++ {
		if refs[i] != nil {
			b := uint8(max(srcBlob[i], 0))
			live[i], full[i], err = c.takeLocked(b, &refs[i].Trailer, refs[i].Entries)
			if srcBlob[i] < 0 {
				// a member lost with its blob: its loc names the blob it
				// was written to, which only the manifest knows; match any
				// blob of the archive
				for bb := 0; bb < int(h.BlobCount) && len(live[i]) < len(refs[i].Entries) && err == nil; bb++ {
					var more []wire.Entry
					more, _, err = c.takeLocked(uint8(bb), &refs[i].Trailer, refs[i].Entries)
					live[i] = append(live[i], more...)
				}
				full[i] = len(live[i]) == len(refs[i].Entries)
			}
			any = any || len(live[i]) > 0
		}
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
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
				// a regrouped member is rewritten: new group fields are
				// AAD-covered, so it is sealed again with a fresh nonce
				// (§13.7.1, §15.7); the compressed bytes are kept
				plain, err := refs[i].Plain()
				if err != nil {
					return fmt.Errorf("regroup: %w", err)
				}
				s := &frame.Spec{BlockType: t.BlockType, Codec: t.CodecID, Payload: append([]byte(nil), plain...),
					Entries: append([]wire.Entry(nil), refs[i].Entries...)}
				if err := c.addRegroup(s, q); err != nil {
					return err
				}
			} else {
				if err := refs[i].Decode(); err != nil {
					return fmt.Errorf("repack: %w", err)
				}
				if err := c.addRepack(live[i], refs[i].Payload); err != nil {
					return err
				}
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
		if err := c.assign(b, refs[i].Trailer.HashPayload, refs[i].Trailer.BlockType, live[i]); err != nil {
			return err
		}
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
		ref, err := blob.NewRef(fr, c.src.h, c.src.pool, c.src.k)
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
		if err := c.assign(pl.blob, pl.rec.FrameHash, specs[i].BlockType, specs[i].Entries); err != nil {
			return err
		}
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
			for _, l := range r.locs {
				if err := c.putLoc(r.path, r.fileVer, l); err != nil {
					return err
				}
			}
			c.count(func(r *CompactResult) { r.RepackedObjects++ })
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
func (c *compactor) verify(ctx context.Context, tag byte, full bool) error {
	d := c.d
	st := d.journal.State()
	before := d.view.Repairs()
	if tag == 'S' {
		// all of it: by frame (each read once), not by path
		if err := c.verifyFrames(ctx); err != nil {
			return err
		}
	} else if err := c.eachPath(tag, func(p string, _ uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		v, ok, err := st.Lookup(p)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: destination lacks %s", ErrMissingData, p)
		}
		o := d.view.object(p, v)
		_, err = io.Copy(io.Discard, o)
		o.Close()
		if err != nil {
			return fmt.Errorf("destination verification of %s: %w", p, err)
		}
		return nil
	}); err != nil {
		return err
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
	err := d.view.refresh(fd)
	fd.mu.Unlock()
	if err != nil {
		return err
	}
	return fd.eachGroup(func(g uint32, ms []*hopMember) (bool, error) {
		if !groupUsable(ms) || len(ms) != int(ms[0].t.GroupK)+int(ms[0].t.GroupM) {
			return false, fmt.Errorf("%w: destination group %d incomplete", wire.ErrCorrupt, g)
		}
		return true, nil
	})
}
