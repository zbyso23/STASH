package manifest

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"stash/internal/blob"
	"stash/internal/extsort"
	"stash/internal/kvtab"
	"stash/internal/membudget"
	"stash/internal/vfs"
)

// Loading with bounded memory (SPEC §10.3, §16.1).
//
// The journal is read once in journal order (manifest.jsonl and linked
// files merged by seq) and every global rule is checked there exactly as
// Apply checks it: seq order, record-local placement, the transaction
// rules, ADD_COMMIT matching and the limits. What concerns one path
// (applied_max, DEL of the live version, the file_ver of ADD_BEGIN and
// ADD_COMMIT) is emitted as an event keyed by (path, seq) into an external
// sort; transaction ids and loc references go into two more. Sorted by
// path, the events of each path are folded in seq order with the same
// per-path rules (applyPath), and the result is bulk-loaded into the
// state table. A violation found in the fold fails the load exactly like
// one found in journal order; only which violation is reported first can
// differ.

// loadSink emits the path effects of the global pass.
type loadSink struct {
	ev, refs, txs *extsort.Sorter
	buf           []byte
}

func sortMem(env *Env, share int64) (int64, func() (vfs.FS, string, error)) {
	if env == nil || env.Scratch == nil {
		return 1 << 60, func() (vfs.FS, string, error) { return nil, "", fmt.Errorf("manifest: no scratch space") }
	}
	if env.SortMemory > 0 {
		return max(env.SortMemory, extsort.MinMemory), env.Scratch
	}
	return max(min(env.Budget.Limit()/share, 256<<20), extsort.MinMemory), env.Scratch
}

func newSorter(env *Env, share int64) (*extsort.Sorter, error) {
	m, scratch := sortMem(env, share)
	var b *membudget.Budget
	if env != nil {
		b = env.Budget
	}
	return extsort.New(context.Background(), extsort.Config{Scratch: scratch, Compare: bytes.Compare, Memory: m, Budget: b, Degrade: true})
}

func newLoadSink(env *Env, refs bool) (*loadSink, error) {
	ls := &loadSink{}
	var err error
	if ls.ev, err = newSorter(env, 4); err != nil {
		return nil, err
	}
	if ls.txs, err = newSorter(env, 16); err != nil {
		ls.close()
		return nil, err
	}
	if refs {
		if ls.refs, err = newSorter(env, 8); err != nil {
			ls.close()
			return nil, err
		}
	}
	return ls, nil
}

func (ls *loadSink) close() {
	for _, s := range []*extsort.Sorter{ls.ev, ls.refs, ls.txs} {
		if s != nil {
			s.Close()
		}
	}
}

// event record: path 0x00 seq(8) part(2) | op ver length [nloc] locs...
func (ls *loadSink) path(op Op, path string, ver, seq uint64, locs []Loc, length uint64) error {
	part := uint16(0)
	for {
		b := append(ls.buf[:0], path...)
		b = append(b, 0)
		b = binary.BigEndian.AppendUint64(b, seq)
		b = binary.BigEndian.AppendUint16(b, part)
		b = append(b, byte(op))
		b = binary.AppendUvarint(b, ver)
		b = binary.AppendUvarint(b, length)
		if part == 0 {
			b = binary.AppendUvarint(b, uint64(len(locs)))
		}
		n := min(len(locs), chunkLocs)
		for _, l := range locs[:n] {
			b = appendLoc(b, l)
		}
		ls.buf = b
		if err := ls.ev.Add(b); err != nil {
			return err
		}
		locs = locs[n:]
		if len(locs) == 0 {
			return nil
		}
		if part == 0xFFFF {
			return fmt.Errorf("manifest: object with too many extents for the state")
		}
		part++
	}
}

func (ls *loadSink) txKnown(TxID) (bool, error) { return false, nil } // reuse is found in the fold
func (ls *loadSink) txUsed(id TxID) error       { return ls.txs.Add(id[:]) }
func (ls *loadSink) ref(r FrameRef) error {
	if ls.refs == nil {
		return nil
	}
	return ls.refs.Add(refKey(r))
}

type event struct {
	path   string
	seq    uint64
	op     Op
	ver    uint64
	length uint64
	nloc   uint64
	locs   []Loc
}

func parseEvent(b []byte) (event, uint16, error) {
	var e event
	i := bytes.IndexByte(b, 0)
	if i < 0 || len(b) < i+1+10+1 {
		return e, 0, kvtab.ErrTampered
	}
	e.path = string(b[:i])
	b = b[i+1:]
	e.seq = binary.BigEndian.Uint64(b)
	part := binary.BigEndian.Uint16(b[8:])
	e.op = Op(b[10])
	b = b[11:]
	var n int
	if e.ver, n = binary.Uvarint(b); n <= 0 {
		return e, 0, kvtab.ErrTampered
	}
	b = b[n:]
	if e.length, n = binary.Uvarint(b); n <= 0 {
		return e, 0, kvtab.ErrTampered
	}
	b = b[n:]
	if part == 0 {
		if e.nloc, n = binary.Uvarint(b); n <= 0 {
			return e, 0, kvtab.ErrTampered
		}
		b = b[n:]
	}
	var err error
	e.locs, err = readLocs(b, nil)
	return e, part, err
}

// build folds the sorted events into the table.
func (s *State) build(ls *loadSink) error {
	ev, err := ls.ev.Sort()
	if err != nil {
		return err
	}
	defer ev.Close()
	txs, err := ls.txs.Sort()
	if err != nil {
		return err
	}
	defer txs.Close()
	var refs extsort.Iterator
	if ls.refs != nil {
		if refs, err = ls.refs.Sort(); err != nil {
			return err
		}
		defer refs.Close()
	}
	return s.tab.Bulk(func(add func(k, v []byte) error) error {
		var (
			cur     string
			ps      *pathState
			pend    *event
			started bool
		)
		flushEvent := func() error {
			if pend == nil {
				return nil
			}
			e := pend
			pend = nil
			if uint64(len(e.locs)) != e.nloc {
				return kvtab.ErrTampered
			}
			return applyPath(ps, e.op, e.path, e.ver, e.seq, e.locs, e.length)
		}
		flushPath := func() error {
			if err := flushEvent(); err != nil {
				return err
			}
			if !started || !ps.known {
				return nil
			}
			for c, b := range encodePath(ps) {
				if err := add(pathKey(cur, uint32(c)), b); err != nil {
					return err
				}
			}
			return nil
		}
		for ev.Next() {
			e, part, err := parseEvent(ev.Record())
			if err != nil {
				return err
			}
			if !started || e.path != cur {
				if err := flushPath(); err != nil {
					return err
				}
				cur, ps, started = e.path, &pathState{}, true
			}
			if part == 0 {
				if err := flushEvent(); err != nil {
					return err
				}
				e := e
				pend = &e
				continue
			}
			if pend == nil || pend.seq != e.seq {
				return kvtab.ErrTampered
			}
			pend.locs = append(pend.locs, e.locs...)
		}
		if err := ev.Err(); err != nil {
			return err
		}
		if err := flushPath(); err != nil {
			return err
		}
		if refs != nil {
			var prev []byte
			for refs.Next() {
				k := refs.Record()
				if prev != nil && bytes.Equal(prev, k) {
					continue
				}
				prev = append(prev[:0], k...)
				if err := add(k, nil); err != nil {
					return err
				}
				s.refCount[k[1]]++
			}
			if err := refs.Err(); err != nil {
				return err
			}
		}
		var prev []byte
		for txs.Next() {
			id := txs.Record()
			if prev != nil && bytes.Equal(prev, id) {
				return corruptAt(OpAddBegin, 0, "tx_id %x reused", id)
			}
			prev = append(prev[:0], id...)
			if err := add(append([]byte{'T'}, id...), nil); err != nil {
				return err
			}
		}
		return txs.Err()
	})
}

// distinct returns a bounded counter of distinct frame keys (torn-tail
// scans of a writer open).
func (s *State) distinct() (blob.DistinctCounter, error) {
	c := &sortCounter{env: s.env}
	return c, c.Reset()
}

type sortCounter struct {
	env *Env
	srt *extsort.Sorter
	buf []byte
}

func (c *sortCounter) Add(k blob.FrameKey) error {
	b := append(c.buf[:0], k.Hash[:]...)
	b = append(b, k.Path...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, k.FileVer)
	b = binary.BigEndian.AppendUint64(b, k.Offset)
	c.buf = b
	return c.srt.Add(b)
}

func (c *sortCounter) Count() (int, error) {
	it, err := c.srt.Sort()
	if err != nil {
		return 0, err
	}
	defer it.Close()
	n := 0
	var prev []byte
	for it.Next() {
		if prev == nil || !bytes.Equal(prev, it.Record()) {
			n++
		}
		prev = append(prev[:0], it.Record()...)
	}
	c.srt = nil
	return n, it.Err()
}

func (c *sortCounter) Reset() error {
	c.Close()
	var err error
	c.srt, err = newSorter(c.env, 16)
	return err
}

func (c *sortCounter) Close() {
	if c.srt != nil {
		c.srt.Close()
		c.srt = nil
	}
}
