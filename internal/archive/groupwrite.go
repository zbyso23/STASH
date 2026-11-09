package archive

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"stash/internal/frame"
	"stash/internal/manifest"
	"stash/internal/parity"
	"stash/internal/wire"
)

// pending is one extent read from the source, not yet written.
type pending struct {
	off     int
	payload []byte
	release func()
}

// writeGroupsAndCommit is writeAndCommit for a parity archive (§7, §10.4).
// Consecutive extents of the version with equal frame size form a group of
// up to parity_k DATA members (a smaller remainder is a short group); each
// group gets a group_id from groups.alloc, its members are spread over
// distinct writable blobs, and its parity_m PARITY frames are written
// before the commit, so the commit's blob syncs make data and parity
// durable in the same step and no committed extent lacks its protection.
//
// Groups never span versions: a group belongs to exactly one Put. Small
// objects therefore get short groups (k=1, a copy per parity frame);
// packing small objects into shared frames (§8) is the remedy.
func (w *Writer) writeGroupsAndCommit(ctx context.Context, p string, ver uint64, src extentSource) (uint64, error) {
	k := int(w.h.ParityK)
	workers := max(1, min(runtime.GOMAXPROCS(0), 2*len(w.writers)))
	inflight := make(chan struct{}, max(1, workers/k)) // groups in flight
	var mu sync.Mutex
	var firstErr error
	var locs []manifest.Loc
	blobs := map[int]bool{}
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	failed := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return firstErr != nil
	}
	var wg sync.WaitGroup
	dispatch := func(g []pending, q uint32) {
		inflight <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-inflight }()
			gl, gb, err := w.writeGroup(p, ver, g, q)
			if err != nil {
				fail(err)
				return
			}
			mu.Lock()
			locs = append(locs, gl...)
			for b := range gb {
				blobs[b] = true
			}
			mu.Unlock()
		}()
	}
	var cur []pending
	var curQ uint32
	releaseAll := func(g []pending) {
		for _, e := range g {
			if e.release != nil {
				e.release()
			}
		}
	}
	off := 0
	for {
		if err := ctx.Err(); err != nil {
			fail(err)
			break
		}
		if failed() {
			break
		}
		payload, release, err := src(off)
		if err == errDone {
			break
		}
		if err != nil {
			fail(err)
			break
		}
		q, err := w.memberQuanta(p, len(payload))
		if err != nil {
			if release != nil {
				release()
			}
			fail(err)
			break
		}
		if len(cur) > 0 && q != curQ {
			dispatch(cur, curQ)
			cur = nil
		}
		cur, curQ = append(cur, pending{off, payload, release}), q
		if len(cur) == k {
			dispatch(cur, curQ)
			cur = nil
		}
		off += len(payload)
		if len(payload) == 0 {
			break // the single extent of an empty object
		}
	}
	if len(cur) > 0 {
		if failed() {
			releaseAll(cur)
		} else {
			dispatch(cur, curQ)
		}
	}
	wg.Wait()
	if firstErr != nil {
		return 0, firstErr // written frames stay unreferenced
	}
	req := &commitReq{path: p, fileVer: ver, blobs: blobs, locs: locs}
	if err := w.commit(req); err != nil {
		return 0, err
	}
	return ver, nil
}

// memberQuanta is the frame size of a DATA group member holding n payload
// bytes of path p, with the 112 bytes of parity padding (§7.2).
func (w *Writer) memberQuanta(p string, n int) (uint32, error) {
	if w.h.Mode == wire.ModeFixed {
		return w.h.MaxFrameQuanta, nil
	}
	pt := uint64(4 + 1 + len(p) + 24) // count, path_len, path, offset/length/file_ver
	if len(p) >= 128 {
		pt++
	}
	if len(p) >= 1<<14 {
		pt++
	}
	return frame.RequiredQuanta(frame.StoredLen(w.h, wire.BlockData, uint64(n)), frame.PreTrailerLen(w.h, wire.BlockData, pt), true)
}

// placement returns the blob of every member of a group of n frames:
// consecutive writable blobs from a rotating start, so a group spans
// distinct blobs and no blob holds more than ceil(n / writable) members
// (§7.4).
func (w *Writer) placement(n int) ([]int, error) {
	var writable []int
	for b, bw := range w.writers {
		if bw != nil {
			writable = append(writable, b)
		}
	}
	if len(writable) < 2 {
		return nil, fmt.Errorf("%w: a parity group needs 2 writable blobs, %d left (§7.4)", ErrNoWritableBlob, len(writable))
	}
	start := int(w.rr.Add(1))
	out := make([]int, n)
	for j := range out {
		out[j] = writable[(start+j)%len(writable)]
	}
	return out, nil
}

// writeGroup writes the DATA members and PARITY frames of one group. It
// releases the members' source buffers. The frames are not durable yet.
func (w *Writer) writeGroup(p string, ver uint64, members []pending, q uint32) ([]manifest.Loc, map[int]bool, error) {
	defer func() {
		for _, e := range members {
			if e.release != nil {
				e.release()
			}
		}
	}()
	specs := make([]*frame.Spec, len(members))
	rels := make([]func(), len(members))
	defer func() {
		for _, r := range rels {
			if r != nil {
				r()
			}
		}
	}()
	// compress in parallel; the group's frame size is its largest member
	// after compression (§7.1 equal geometry)
	var wg sync.WaitGroup
	for i, e := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, stored, rel := w.encode(e.payload)
			rels[i] = rel
			specs[i] = &frame.Spec{BlockType: wire.BlockData, Codec: c, Payload: stored,
				Entries: []wire.Entry{{Path: p, Offset: uint64(e.off), Length: uint64(len(e.payload)), FileVer: ver}}}
		}()
	}
	wg.Wait()
	if w.h.CodecID != wire.CodecStore {
		q = 0
		for _, s := range specs {
			sq, err := w.memberQuanta(p, len(s.Payload))
			if err != nil {
				return nil, nil, err
			}
			q = max(q, sq)
		}
	}
	placed, touched, err := w.writeGroupFrames(specs, q)
	if err != nil {
		return nil, nil, err
	}
	locs := make([]manifest.Loc, len(members))
	for i, pl := range placed {
		e := specs[i].Entries[0]
		locs[i] = manifest.Loc{Blob: uint8(pl.blob), Hash: pl.rec.FrameHash, Offset: e.Offset, Length: e.Length}
	}
	return locs, touched, nil
}

// placedFrame is where a frame was written.
type placedFrame struct {
	blob int
	rec  wire.IndexRecord
}

// writeGroupFrames writes the given DATA or PACKED frames as one parity
// group of frame size q (group fields, ordinals and placement are filled
// in here), computes and writes its PARITY frames, and indexes everything.
// It returns where each member went and every blob touched. The frames
// are not durable yet.
func (w *Writer) writeGroupFrames(specs []*frame.Spec, q uint32) ([]placedFrame, map[int]bool, error) {
	k, m := len(specs), int(w.h.ParityM)
	code, err := parity.New(w.h.ParityScheme, k, m)
	if err != nil {
		return nil, nil, err
	}
	gid, err := w.groupAlloc.Next()
	if err != nil {
		return nil, nil, err
	}
	if gid == 0 || gid > 0xFFFFFFFF {
		return nil, nil, fmt.Errorf("%w: group_id %d", wire.ErrResource, gid)
	}
	place, err := w.placement(k + m)
	if err != nil {
		return nil, nil, err
	}
	fsz := int(wire.FrameSize(q))
	shardLen := int(wire.ParityShardLen(q))
	shards := make([][]byte, k+m)
	var bufs [][]byte
	var bufMu sync.Mutex
	get := func(n int) []byte {
		b := w.pool.Get(n)
		bufMu.Lock()
		bufs = append(bufs, b)
		bufMu.Unlock()
		return b
	}
	defer func() {
		for _, b := range bufs {
			w.pool.Put(b)
		}
	}()
	placed := make([]placedFrame, k)
	errs := make([]error, k+m)
	write := func(i int, s *frame.Spec) {
		s.GroupID, s.GroupIndex, s.GroupK, s.GroupM, s.FrameQuanta = uint32(gid), uint8(i), uint8(k), uint8(m), q
		b := place[i]
		ord, err := w.ordAlloc[b].Next()
		if err != nil {
			errs[i] = err
			return
		}
		s.FrameOrdinal = ord
		w.writers[b].Seal(s)
		fr, err := frame.AppendFrame(get(fsz)[:0], w.h, s)
		if err != nil {
			errs[i] = err
			return
		}
		if s.BlockType != wire.BlockParity {
			if shards[i], err = frame.AppendRecoveryShard(get(shardLen)[:0], fr); err != nil {
				errs[i] = err
				return
			}
		}
		rec, err := w.writers[b].AppendBuilt(fr)
		if err != nil {
			errs[i] = err
			return
		}
		bv := w.blobs[b]
		bv.mu.Lock()
		bv.idx.Add(rec)
		bv.mu.Unlock()
		if i < k {
			placed[i] = placedFrame{b, rec}
		}
	}
	var wg sync.WaitGroup
	for i, s := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			write(i, s)
		}()
	}
	wg.Wait()
	for _, err := range errs[:k] {
		if err != nil {
			return nil, nil, err
		}
	}
	for j := 0; j < m; j++ {
		shards[k+j] = get(shardLen)[:shardLen]
	}
	if err := code.Encode(shards[:k], shards[k:]); err != nil {
		return nil, nil, err
	}
	for j := 0; j < m; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			write(k+j, &frame.Spec{BlockType: wire.BlockParity, Codec: wire.CodecStore, Payload: shards[k+j]})
		}()
	}
	wg.Wait()
	for _, err := range errs[k:] {
		if err != nil {
			return nil, nil, err
		}
	}
	touched := map[int]bool{}
	for _, b := range place {
		touched[b] = true
	}
	return placed, touched, nil
}
