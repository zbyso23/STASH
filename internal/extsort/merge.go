package extsort

import (
	"context"
	"io"
)

// Source is one ordered input of a merge.
type Source interface {
	Next() bool
	Record() []byte
	Err() error
}

type mergeSrc struct {
	rr Source
	c  io.Closer // closed with the merge; may be nil
}

func closeSrcs(s []mergeSrc) {
	for _, x := range s {
		if x.c != nil {
			x.c.Close()
		}
	}
}

// merger is a k-way merge over ordered sources. Equal records come out in
// source order, so merging consecutive runs of a stable sort stays stable.
type merger struct {
	ctx   context.Context
	cmp   Compare
	srcs  []mergeSrc
	heap  []int // indexes into srcs, a binary min-heap
	cur   int   // source of the current record, -1 before the first
	steps int
	err   error
	init  bool
}

func newMerger(ctx context.Context, srcs []mergeSrc, cmp Compare) *merger {
	return &merger{ctx: ctx, cmp: cmp, srcs: srcs, cur: -1}
}

// Merge returns an iterator over the k-way merge of ordered sources.
// Closing it closes nothing it was given; the caller owns the sources.
func Merge(ctx context.Context, cmp Compare, srcs ...Source) Iterator {
	ms := make([]mergeSrc, len(srcs))
	for i, s := range srcs {
		ms[i] = mergeSrc{rr: s}
	}
	return &mergeIter{newMerger(ctx, ms, cmp)}
}

type mergeIter struct{ *merger }

func (m *mergeIter) Close() error { return nil }

func (m *merger) less(a, b int) bool {
	if r := m.cmp(m.srcs[a].rr.Record(), m.srcs[b].rr.Record()); r != 0 {
		return r < 0
	}
	return a < b
}

func (m *merger) down(i int) {
	h := m.heap
	for {
		l := 2*i + 1
		if l >= len(h) {
			return
		}
		j := l
		if r := l + 1; r < len(h) && m.less(h[r], h[l]) {
			j = r
		}
		if !m.less(h[j], h[i]) {
			return
		}
		h[i], h[j] = h[j], h[i]
		i = j
	}
}

// Next advances the source of the current record and restores the heap.
func (m *merger) Next() bool {
	if m.err != nil {
		return false
	}
	if m.steps++; m.steps&4095 == 0 {
		if m.err = m.ctx.Err(); m.err != nil {
			return false
		}
	}
	if !m.init {
		m.init = true
		for i := range m.srcs {
			if m.srcs[i].rr.Next() {
				m.heap = append(m.heap, i)
			} else if err := m.srcs[i].rr.Err(); err != nil {
				m.err = err
				return false
			}
		}
		for i := len(m.heap)/2 - 1; i >= 0; i-- {
			m.down(i)
		}
	} else if len(m.heap) > 0 {
		top := m.heap[0]
		if m.srcs[top].rr.Next() {
			m.down(0)
		} else {
			if err := m.srcs[top].rr.Err(); err != nil {
				m.err = err
				return false
			}
			last := len(m.heap) - 1
			m.heap[0] = m.heap[last]
			m.heap = m.heap[:last]
			if last > 0 {
				m.down(0)
			}
		}
	}
	if len(m.heap) == 0 {
		m.cur = -1
		return false
	}
	m.cur = m.heap[0]
	return true
}

func (m *merger) Record() []byte { return m.srcs[m.cur].rr.Record() }
func (m *merger) Err() error     { return m.err }

func (m *merger) closeFiles() {
	closeSrcs(m.srcs)
	m.srcs, m.heap = nil, nil
}
