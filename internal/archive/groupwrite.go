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
	pt := uint64(4 + 1 + len(p) + 24 + 4) // count, path_len, path, offset/length/file_ver, CRC
	if len(p) >= 128 {
		pt++
	}
	if len(p) >= 1<<14 {
		pt++
	}
	return frame.RequiredQuanta(uint64(n), pt, true)
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
	k, m := len(members), int(w.h.ParityM)
	defer func() {
		for _, e := range members {
			if e.release != nil {
				e.release()
			}
		}
	}()
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
	spec := func(i int) *frame.Spec {
		return &frame.Spec{GroupID: uint32(gid), GroupIndex: uint8(i), GroupK: uint8(k), GroupM: uint8(m), FrameQuanta: q}
	}
	locs := make([]manifest.Loc, k)
	var wg sync.WaitGroup
	errs := make([]error, k+m)
	write := func(i int, s *frame.Spec) {
		b := place[i]
		ord, err := w.ordAlloc[b].Next()
		if err != nil {
			errs[i] = err
			return
		}
		s.FrameOrdinal = ord
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
		if s.BlockType == wire.BlockData {
			e := s.Entries[0]
			locs[i] = manifest.Loc{Blob: uint8(b), Hash: rec.FrameHash, Offset: e.Offset, Length: e.Length}
		}
	}
	for i, e := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := spec(i)
			s.BlockType, s.Codec, s.Payload = wire.BlockData, wire.CodecStore, e.payload
			s.Entries = []wire.Entry{{Path: p, Offset: uint64(e.off), Length: uint64(len(e.payload)), FileVer: ver}}
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
			s := spec(k + j)
			s.BlockType, s.Codec, s.Payload = wire.BlockParity, wire.CodecStore, shards[k+j]
			write(k+j, s)
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
	return locs, touched, nil
}
