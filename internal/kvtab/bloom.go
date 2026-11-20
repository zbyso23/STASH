package kvtab

import "hash/maphash"

// bloom is the in-memory filter of one file: a lookup of a key the file
// does not hold skips the file without reading a block (a miss would
// otherwise seek in every run). Files live for one session, so the
// filter is never stored.
type bloom struct {
	bits []uint64
	seed maphash.Seed
}

const bloomBitsPerKey = 10
const bloomProbes = 7

// newBloom sizes a filter for up to n keys (nil for none).
func newBloom(n uint64, seed maphash.Seed) *bloom {
	if n == 0 {
		return nil
	}
	words := (n*bloomBitsPerKey + 63) / 64
	return &bloom{bits: make([]uint64, words), seed: seed}
}

func (b *bloom) bytes() int64 { return int64(len(b.bits)) * 8 }

func (b *bloom) probe(k []byte, fn func(word int, bit uint64) bool) bool {
	h := maphash.Bytes(b.seed, k)
	h1, h2 := h, h>>33|h<<31|1
	n := uint64(len(b.bits)) * 64
	for i := uint64(0); i < bloomProbes; i++ {
		p := (h1 + i*h2) % n
		if !fn(int(p/64), 1<<(p%64)) {
			return false
		}
	}
	return true
}

func (b *bloom) add(k []byte) {
	b.probe(k, func(w int, bit uint64) bool { b.bits[w] |= bit; return true })
}

// mayHave is false only when the key is certainly absent.
func (b *bloom) mayHave(k []byte) bool {
	if b == nil {
		return true
	}
	return b.probe(k, func(w int, bit uint64) bool { return b.bits[w]&bit != 0 })
}
