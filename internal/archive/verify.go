package archive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"sync"

	"stash/internal/blob"
	"stash/internal/frame"
	"stash/internal/manifest"
	"stash/internal/parity"
	"stash/internal/wire"
)

// BlobVerify is the full-scan result of one blob.
type BlobVerify struct {
	Ordinal uint8
	Err     error // unavailable
	Frames  int
	// Damaged regions and frames found only by resynchronization
	// (§11.2.1); both mean the blob is damaged.
	Damaged    []blob.Region
	Unscanned  []blob.Region
	Candidates int
}

// GroupVerify classifies parity groups (§13.9 terms).
type GroupVerify struct {
	Total int
	// Healthy: every member validates and the stored parity equals the
	// parity recomputed from the data members.
	Healthy int
	// Degraded: members are missing or damaged, every DATA/PACKED member
	// is still reconstructable.
	Degraded int
	// Unrecoverable: a DATA/PACKED member cannot be reconstructed.
	Unrecoverable int
	// Conflicting: group fields disagree (§7); the group is unusable.
	Conflicting int
	// Inconsistent: all members validate but stored parity differs from
	// the recomputed one.
	Inconsistent int
}

// VerifyReport is the result of Verify.
type VerifyReport struct {
	Blobs    []BlobVerify
	Versions int
	Bytes    int64
	// Failed lists live paths that could not be read completely.
	Failed map[string]error
	Groups GroupVerify
	// Repairs made while reading (hop-and-read and parity rebuilds).
	Repairs RepairStats
}

// OK reports whether nothing is damaged, missing or degraded.
func (r *VerifyReport) OK() bool {
	for _, b := range r.Blobs {
		if b.Err != nil || len(b.Damaged) > 0 || len(b.Unscanned) > 0 || b.Candidates > 0 {
			return false
		}
	}
	g := r.Groups
	return len(r.Failed) == 0 && g.Degraded+g.Unrecoverable+g.Conflicting+g.Inconsistent == 0
}

// verify runs a full verification (§11): every blob scanned with
// resynchronization, every live version read completely (validating every
// frame, repairing through parity where needed), and every parity group
// checked for completeness and parity consistency.
func (v *view) verify(ctx context.Context, live func() map[string]*manifest.Version) (*VerifyReport, error) {
	rep := &VerifyReport{Failed: map[string]error{}, Blobs: make([]BlobVerify, v.h.BlobCount)}
	before := v.Repairs()
	var wg sync.WaitGroup
	errs := make([]error, len(v.blobs))
	for b := range v.blobs {
		rep.Blobs[b].Ordinal = uint8(b)
		bv := v.blobs[b]
		if bv == nil {
			rep.Blobs[b].Err = v.unavailable[uint8(b)]
			if rep.Blobs[b].Err == nil {
				rep.Blobs[b].Err = fmt.Errorf("blob %02X unavailable", b)
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := bv.r.Resync(0)
			if err != nil {
				errs[b] = err
				return
			}
			bvr := &rep.Blobs[b]
			bvr.Frames, bvr.Damaged, bvr.Unscanned, bvr.Candidates = len(res.Frames), res.Damaged, res.Unscanned, res.Candidates
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	paths := live()
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	slices.Sort(names)
	for _, p := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ver := paths[p]
		o := v.object(p, ver)
		n, err := io.Copy(io.Discard, o)
		o.Close()
		rep.Versions++
		rep.Bytes += n
		if err != nil {
			rep.Failed[p] = err
		}
	}
	if v.h.ParityScheme != wire.ParityNone {
		if err := v.verifyGroups(ctx, &rep.Groups); err != nil {
			return nil, err
		}
	}
	after := v.Repairs()
	rep.Repairs = RepairStats{Hopped: after.Hopped - before.Hopped, Rebuilt: after.Rebuilt - before.Rebuilt, Failed: after.Failed - before.Failed}
	return rep, nil
}

func (v *view) verifyGroups(ctx context.Context, gv *GroupVerify) error {
	d := v.dir()
	d.mu.Lock()
	if err := v.refresh(d); err != nil {
		d.mu.Unlock()
		return err
	}
	groups := make(map[uint32][]*hopMember, len(d.groups))
	for g, ms := range d.groups {
		groups[g] = append([]*hopMember(nil), ms...)
	}
	d.mu.Unlock()
	ids := make([]uint32, 0, len(groups))
	for g := range groups {
		ids = append(ids, g)
	}
	slices.Sort(ids)
	for _, g := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		ms := groups[g]
		gv.Total++
		if !groupUsable(ms) {
			gv.Conflicting++
			continue
		}
		k, m, q := int(ms[0].t.GroupK), int(ms[0].t.GroupM), ms[0].quanta
		shards := make([][]byte, k+m)
		present := make([]bool, k+m)
		n := 0
		for _, mem := range ms {
			bv := v.blobs[mem.blob]
			if bv == nil {
				continue
			}
			ref, err := bv.r.ReadFrame(mem.off)
			if err != nil {
				continue
			}
			i := int(mem.t.GroupIndex)
			if ref.Trailer.BlockType == wire.BlockParity {
				shards[i] = append([]byte(nil), ref.Payload...)
			} else if shards[i], err = frame.AppendRecoveryShard(nil, ref.Bytes()); err != nil {
				ref.Release()
				continue
			}
			ref.Release()
			present[i] = true
			n++
		}
		if n < k+m {
			dataMissing := false
			for i := 0; i < k; i++ {
				dataMissing = dataMissing || !present[i]
			}
			if dataMissing && n < k {
				gv.Unrecoverable++
			} else {
				gv.Degraded++
			}
			continue
		}
		code, err := parity.New(v.h.ParityScheme, k, m)
		if err != nil {
			gv.Conflicting++
			continue
		}
		want := make([][]byte, m)
		for j := range want {
			want[j] = make([]byte, wire.ParityShardLen(q))
		}
		if err := code.Encode(shards[:k], want); err != nil {
			return err
		}
		ok := true
		for j := 0; j < m; j++ {
			ok = ok && bytes.Equal(want[j], shards[k+j])
		}
		if ok {
			gv.Healthy++
		} else {
			gv.Inconsistent++
		}
	}
	return nil
}

func liveOf(st *manifest.State) map[string]*manifest.Version {
	out := map[string]*manifest.Version{}
	for _, p := range st.Paths() {
		v, _ := st.Lookup(p)
		out[p] = v
	}
	return out
}

// Verify verifies the snapshot completely (see VerifyReport).
func (r *Reader) Verify(ctx context.Context) (*VerifyReport, error) {
	return r.verify(ctx, func() map[string]*manifest.Version { return liveOf(r.st) })
}

// Verify verifies the current generation completely. Writes wait until it
// is done.
func (w *Writer) Verify(ctx context.Context) (*VerifyReport, error) {
	w.genMu.Lock() // quiesce writes: in-flight appends would look like damage
	defer w.genMu.Unlock()
	return w.verify(ctx, func() map[string]*manifest.Version {
		w.stateMu.RLock()
		defer w.stateMu.RUnlock()
		return liveOf(w.journal.State())
	})
}
