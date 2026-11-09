package archive

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"stash/internal/compress"
	"stash/internal/frame"
	"stash/internal/manifest"
	"stash/internal/wire"
)

// errDone ends an extent source.
var errDone = errors.New("done")

// commitReq is one Put or Delete waiting for the group commit.
type commitReq struct {
	del     bool
	path    string
	fileVer uint64
	locs    []manifest.Loc
	blobs   map[int]bool
	// pack: the leader writes small into a PACKED frame (§8)
	pack   bool
	small  []byte
	packed bool // the packing stage handled it

	done bool
	err  error
}

// groupCommit batches commits (§10.4 "Multiple manifest records MAY share
// one group fsync boundary"). Leader/follower: every request is queued;
// whoever takes the commit lock commits the whole queue with one sync per
// touched blob and one manifest sync. No timer, no added latency: batches
// form exactly while a sync is in progress.
type groupCommit struct {
	qMu    sync.Mutex
	queue  []*commitReq
	leader sync.Mutex
	// packing stage: small objects of concurrent Puts are packed by one
	// leader while the previous batch syncs (§8)
	pMu     sync.Mutex
	pQueue  []*commitReq
	pLeader sync.Mutex
	batches int // statistics
	records int
}

// Stats returns how many commit batches and records were written.
func (w *Writer) CommitStats() (batches, records int) {
	w.gc.qMu.Lock()
	defer w.gc.qMu.Unlock()
	return w.gc.batches, w.gc.records
}

// commitPacked runs a small-object request through the packing stage,
// then through the group commit. Packing of one batch overlaps the syncs
// of the previous one.
func (w *Writer) commitPacked(r *commitReq) error {
	g := &w.gc
	g.pMu.Lock()
	g.pQueue = append(g.pQueue, r)
	g.pMu.Unlock()

	g.pLeader.Lock()
	g.pMu.Lock()
	if !r.packed {
		batch := g.pQueue
		g.pQueue = nil
		g.pMu.Unlock()
		w.writePacked(batch)
		g.pMu.Lock()
		for _, b := range batch {
			b.packed = true
		}
	}
	g.pMu.Unlock()
	g.pLeader.Unlock()
	if r.err != nil {
		return r.err
	}
	return w.commit(r)
}

func (w *Writer) commit(r *commitReq) error {
	g := &w.gc
	g.qMu.Lock()
	g.queue = append(g.queue, r)
	g.qMu.Unlock()

	g.leader.Lock()
	defer g.leader.Unlock()
	g.qMu.Lock()
	if r.done { // a previous leader committed it
		g.qMu.Unlock()
		return r.err
	}
	batch := g.queue
	g.queue = nil
	g.qMu.Unlock()

	w.commitBatch(batch)

	g.qMu.Lock()
	g.batches++
	g.records += len(batch)
	for _, b := range batch {
		b.done = true
	}
	g.qMu.Unlock()
	return r.err
}

// commitBatch makes the frames of every request durable, appends the
// records, and syncs the manifest once (§10.4 ordering).
func (w *Writer) commitBatch(batch []*commitReq) {
	if err := w.hard.failed; err != nil {
		for _, r := range batch {
			if r.err == nil {
				r.err = err
			}
		}
		return
	}
	blobs := map[int]bool{}
	for _, r := range batch {
		for b := range r.blobs {
			blobs[b] = true
		}
	}
	syncErr := map[int]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for b := range blobs { // blob syncs in parallel
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			err := w.writers[b].Sync()
			mu.Lock()
			syncErr[b] = err
			mu.Unlock()
		}(b)
	}
	wg.Wait()

	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	appended := false
	for _, r := range batch {
		for b := range r.blobs {
			if syncErr[b] != nil {
				r.err = fmt.Errorf("blob %02X sync: %w", b, syncErr[b])
			}
		}
		if r.err != nil {
			continue // frames not durable: never reference them
		}
		if r.del {
			v, ok := w.journal.State().Lookup(r.path)
			if !ok {
				r.err = fmt.Errorf("%w: %s", ErrNotFound, r.path)
				continue
			}
			r.err = w.journal.Del(r.path, v.FileVer)
		} else {
			r.err = w.journal.Add(r.path, r.fileVer, r.locs)
		}
		appended = appended || r.err == nil
	}
	if !appended {
		return
	}
	err := w.journal.Sync()
	if err == nil && w.hard.anchor != nil {
		// §10.4.1: durable only once the anchor covers the records
		err = w.advanceCommit(context.Background())
	}
	if err != nil {
		for _, r := range batch {
			if r.err == nil {
				r.err = err
			}
		}
	}
}

// extentSource yields the payload of the extent at off; errDone ends it.
// release (may be nil) is called once the payload has been written.
type extentSource func(off int) (payload []byte, release func(), err error)

// writeAndCommit allocates file_ver, writes the extents of one version in
// parallel across blobs (building and hashing frames concurrently), then
// commits through the group commit.
func (w *Writer) writeAndCommit(ctx context.Context, p string, src extentSource) (uint64, error) {
	ver, err := w.verAlloc.Next()
	if err != nil {
		return 0, err
	}
	if w.code != nil {
		return w.writeGroupsAndCommit(ctx, p, ver, src)
	}
	type result struct {
		loc  manifest.Loc
		blob int
		err  error
	}
	workers := max(1, min(runtime.GOMAXPROCS(0), 2*len(w.writers)))
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var results []result
	var wg sync.WaitGroup
	var firstErr error
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	off := 0
	for {
		if err := ctx.Err(); err != nil {
			fail(err)
			break
		}
		mu.Lock()
		stop := firstErr != nil
		mu.Unlock()
		if stop {
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
		sem <- struct{}{}
		wg.Add(1)
		go func(off int, payload []byte, release func()) {
			defer wg.Done()
			defer func() { <-sem }()
			if release != nil {
				defer release()
			}
			loc, b, err := w.writeExtent(p, ver, off, payload)
			mu.Lock()
			results = append(results, result{loc, b, err})
			mu.Unlock()
			if err != nil {
				fail(err)
			}
		}(off, payload, release)
		off += len(payload)
		if len(payload) == 0 {
			break // the single extent of an empty object
		}
	}
	wg.Wait()
	if firstErr != nil {
		// frames already written stay unreferenced: torn-tail rules and
		// compaction reclaim them; the file_ver is skipped, never reused
		return 0, firstErr
	}
	req := &commitReq{path: p, fileVer: ver, blobs: map[int]bool{}}
	for _, r := range results {
		req.locs = append(req.locs, r.loc)
		req.blobs[r.blob] = true
	}
	if err := w.commit(req); err != nil {
		return 0, err
	}
	return ver, nil
}

// encode compresses logical bytes with the archive's codec (§5): it
// returns the codec actually used (STORE when compression does not make
// the payload smaller), the payload plaintext, and a release for its
// buffer (nil when the payload is logical itself).
func (w *Writer) encode(logical []byte) (wire.CodecID, []byte, func()) {
	if w.h.CodecID == wire.CodecStore || len(logical) == 0 {
		return wire.CodecStore, logical, nil
	}
	buf := w.pool.Get(len(logical))
	c, out, err := compress.Encode(w.h.CodecID, logical, buf[:0])
	if err != nil || c == wire.CodecStore {
		w.pool.Put(buf)
		return wire.CodecStore, logical, nil
	}
	return c, out, func() { w.pool.Put(buf) }
}

// writeExtent writes one DATA frame and indexes it.
func (w *Writer) writeExtent(p string, ver uint64, off int, payload []byte) (manifest.Loc, int, error) {
	b, err := w.pickBlob()
	if err != nil {
		return manifest.Loc{}, 0, err
	}
	ord, err := w.ordAlloc[b].Next()
	if err != nil {
		return manifest.Loc{}, 0, err
	}
	codec, stored, rel := w.encode(payload)
	if rel != nil {
		defer rel()
	}
	s := &frame.Spec{BlockType: wire.BlockData, Codec: codec, Payload: stored, FrameOrdinal: ord,
		Entries: []wire.Entry{{Path: p, Offset: uint64(off), Length: uint64(len(payload)), FileVer: ver}}}
	rec, err := w.writers[b].AppendIndexed(s)
	if err != nil {
		return manifest.Loc{}, 0, err
	}
	bv := w.blobs[b]
	bv.mu.Lock()
	bv.idx.Add(rec)
	bv.mu.Unlock()
	return manifest.Loc{Blob: uint8(b), Hash: rec.FrameHash, Offset: uint64(off), Length: uint64(len(payload))}, b, nil
}
