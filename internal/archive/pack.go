package archive

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"

	"stash/internal/frame"
	"stash/internal/manifest"
	"stash/internal/wire"
)

// DefaultPackThreshold is the largest object written into PACKED frames
// when Options.PackThreshold is 0.
const DefaultPackThreshold = 64 << 10

// minPackedFrame is the smallest PACKED frame a batch is split into to
// fill a parity group.
const minPackedFrame = 16 << 10

// packMax returns the largest object of path p that goes into a PACKED
// frame, or -1 when packing is off. An object must fit an otherwise empty
// frame (§8).
func (w *Writer) packMax(p string) int {
	t := w.opt.PackThreshold
	if t < 0 {
		return -1
	}
	if t == 0 {
		t = DefaultPackThreshold
	}
	return min(t, w.packCapacity(entrySize(p)))
}

// entrySize is the Pre-Trailer bytes of one entry for path p (§6.4.2).
func entrySize(p string) int {
	n := len(p)
	l := 1
	for v := n >> 7; v > 0; v >>= 7 {
		l++
	}
	return l + n + 24
}

// packCapacity is the payload a PACKED frame can hold next to entries of
// entryBytes in total.
func (w *Writer) packCapacity(entryBytes int) int {
	n := int(w.h.MaxFrameSize()) - wire.FrameOverhead - 4 - entryBytes - 4 // count, entries, outer CRC
	if w.code != nil {
		n -= wire.MinParityPadding
	}
	return n
}

// packFrame is one PACKED frame being filled.
type packFrame struct {
	reqs    []*commitReq
	payload int
	entries int // entry bytes
}

// writePacked writes the small objects of a commit batch into PACKED
// frames (§8): sorted by canonical path, packed greedily up to the frame
// capacity and MAX_PACKED_ENTRIES, written in parallel (with parity in
// groups of up to parity_k frames of equal size). Every packed request
// gets its single loc [blob, frame_hash, 0, length] (§9.1); every blob
// written is added to every packed request so the batch's syncs cover
// data and parity. On failure all packed requests of the batch fail.
func (w *Writer) writePacked(batch []*commitReq) {
	var items []*commitReq
	for _, r := range batch {
		if r.pack && r.err == nil {
			items = append(items, r)
		}
	}
	if len(items) == 0 {
		return
	}
	slices.SortFunc(items, func(a, b *commitReq) int { return strings.Compare(a.path, b.path) })
	// With parity, spread the batch over parity_k similar frames (or a
	// multiple), so groups are full and parity costs m/k instead of m per
	// byte; frames stay at least minPackedFrame so tiny batches are not
	// split.
	// Without parity, spread it over one frame per core so hashing and
	// writing run in parallel.
	total := 0
	for _, r := range items {
		total += len(r.small) + entrySize(r.path)
	}
	want := runtime.GOMAXPROCS(0)
	if w.code != nil {
		k := int(w.h.ParityK)
		want = k * max(1, want/k)
	}
	target := max(minPackedFrame, (total+want-1)/want)
	var frames []*packFrame
	cur := &packFrame{}
	for _, r := range items {
		es := entrySize(r.path)
		if len(cur.reqs) > 0 && (len(cur.reqs) == wire.MaxPackedEntries ||
			cur.payload+cur.entries >= target ||
			cur.payload+len(r.small) > w.packCapacity(cur.entries+es)) {
			frames = append(frames, cur)
			cur = &packFrame{}
		}
		cur.reqs = append(cur.reqs, r)
		cur.payload += len(r.small)
		cur.entries += es
	}
	frames = append(frames, cur)

	specs := make([]*frame.Spec, len(frames))
	bufs := make([][]byte, len(frames))
	for i, f := range frames {
		buf := w.pool.Get(f.payload)[:0]
		s := &frame.Spec{BlockType: wire.BlockPacked, Codec: wire.CodecStore}
		for _, r := range f.reqs {
			s.Entries = append(s.Entries, wire.Entry{Path: r.path, Offset: uint64(len(buf)), Length: uint64(len(r.small)), FileVer: r.fileVer})
			buf = append(buf, r.small...)
		}
		s.Payload, bufs[i] = buf, buf
		specs[i] = s
	}
	defer func() {
		for _, b := range bufs {
			w.pool.Put(b)
		}
	}()
	placed, touched, err := w.writeSpecs(specs)
	for i, f := range frames {
		for _, r := range f.reqs {
			if err != nil {
				r.err = err
				continue
			}
			r.locs = []manifest.Loc{{Blob: uint8(placed[i].blob), Hash: placed[i].rec.FrameHash, Length: uint64(len(r.small))}}
			r.blobs = touched
		}
	}
}

// writeSpecs writes frames: without parity each to the next writable blob,
// with parity as groups of up to parity_k consecutive frames sized to
// their largest member. All work runs in parallel.
func (w *Writer) writeSpecs(specs []*frame.Spec) ([]placedFrame, map[int]bool, error) {
	placed := make([]placedFrame, len(specs))
	touched := map[int]bool{}
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	run := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	if w.code == nil {
		for i, s := range specs {
			run(func() error {
				b, err := w.pickBlob()
				if err != nil {
					return err
				}
				if s.FrameOrdinal, err = w.ordAlloc[b].Next(); err != nil {
					return err
				}
				rec, err := w.writers[b].AppendIndexed(s)
				if err != nil {
					return err
				}
				bv := w.blobs[b]
				bv.mu.Lock()
				bv.idx.Add(rec)
				bv.mu.Unlock()
				mu.Lock()
				placed[i] = placedFrame{b, rec}
				touched[b] = true
				mu.Unlock()
				return nil
			})
		}
	} else {
		k := int(w.h.ParityK)
		for lo := 0; lo < len(specs); lo += k {
			hi := min(lo+k, len(specs))
			run(func() error {
				q := uint32(0)
				for _, s := range specs[lo:hi] {
					sq, err := w.packedQuanta(s)
					if err != nil {
						return err
					}
					q = max(q, sq)
				}
				pl, t, err := w.writeGroupFrames(specs[lo:hi], q)
				if err != nil {
					return err
				}
				mu.Lock()
				copy(placed[lo:hi], pl)
				for b := range t {
					touched[b] = true
				}
				mu.Unlock()
				return nil
			})
		}
	}
	wg.Wait()
	if firstErr != nil {
		return nil, nil, firstErr
	}
	return placed, touched, nil
}

// packedQuanta is the frame size of a PACKED group member (§7.2 padding).
func (w *Writer) packedQuanta(s *frame.Spec) (uint32, error) {
	if w.h.Mode == wire.ModeFixed {
		return w.h.MaxFrameQuanta, nil
	}
	pt := 4 + 4
	for _, e := range s.Entries {
		pt += entrySize(e.Path)
	}
	q, err := frame.RequiredQuanta(uint64(len(s.Payload)), uint64(pt), true)
	if err != nil {
		return 0, fmt.Errorf("packed frame: %w", err)
	}
	return q, nil
}
