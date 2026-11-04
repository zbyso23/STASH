// Package parity implements the two parity codes of SPEC §7: bytewise XOR
// and the systematic Vandermonde Reed-Solomon code over GF(2^8) of §7.2.1.
//
// The package works on equal-length shards only; building canonical
// recovery shards from frames (§7.2) is internal/frame's job.
package parity

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"stash/internal/wire"
)

// ErrTooFewShards reports that fewer than k shards survive.
var ErrTooFewShards = errors.New("parity: too few shards to reconstruct")

// GF(2^8) with x^8 + x^4 + x^3 + x^2 + 1 (0x11D); 2 is a generator.
var (
	expTable [510]byte
	logTable [256]byte
	mulTable [256][256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		expTable[i] = byte(x)
		expTable[i+255] = byte(x)
		logTable[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for a := 1; a < 256; a++ {
		for b := 1; b < 256; b++ {
			mulTable[a][b] = expTable[int(logTable[a])+int(logTable[b])]
		}
	}
}

func gfMul(a, b byte) byte { return mulTable[a][b] }

func gfInv(a byte) byte {
	if a == 0 {
		panic("parity: inverse of 0")
	}
	return expTable[255-int(logTable[a])]
}

func gfPow(a byte, e int) byte {
	r := byte(1)
	for ; e > 0; e-- {
		r = gfMul(r, a)
	}
	return r
}

// invert returns the inverse of the n×n matrix m (Gauss-Jordan), or an
// error when m is singular.
func invert(m [][]byte) ([][]byte, error) {
	n := len(m)
	a := make([][]byte, n)
	for i := range m {
		a[i] = make([]byte, 2*n)
		copy(a[i], m[i])
		a[i][n+i] = 1
	}
	for col := 0; col < n; col++ {
		piv := -1
		for r := col; r < n; r++ {
			if a[r][col] != 0 {
				piv = r
				break
			}
		}
		if piv < 0 {
			return nil, errors.New("parity: singular matrix")
		}
		a[col], a[piv] = a[piv], a[col]
		inv := gfInv(a[col][col])
		for c := range a[col] {
			a[col][c] = gfMul(a[col][c], inv)
		}
		for r := 0; r < n; r++ {
			if f := a[r][col]; r != col && f != 0 {
				for c := range a[r] {
					a[r][c] ^= gfMul(f, a[col][c])
				}
			}
		}
	}
	out := make([][]byte, n)
	for i := range a {
		out[i] = a[i][n:]
	}
	return out, nil
}

func matMul(a, b [][]byte) [][]byte {
	out := make([][]byte, len(a))
	for i := range a {
		out[i] = make([]byte, len(b[0]))
		for c := range b[0] {
			var s byte
			for j := range b {
				s ^= gfMul(a[i][j], b[j][c])
			}
			out[i][c] = s
		}
	}
	return out
}

// EncodingMatrix returns E = V × T^-1 of §7.2.1, (k+m) rows of k columns.
func EncodingMatrix(k, m int) ([][]byte, error) {
	n := k + m
	if k < 1 || m < 1 || n > wire.MaxParityShards {
		return nil, fmt.Errorf("parity: invalid code k=%d m=%d", k, m)
	}
	v := make([][]byte, n)
	for r := range v {
		v[r] = make([]byte, k)
		for c := range v[r] {
			v[r][c] = gfPow(byte(r), c) // 0^0 = 1
		}
	}
	ti, err := invert(v[:k])
	if err != nil {
		return nil, err
	}
	return matMul(v, ti), nil
}

// Code is one (scheme, k, m) code. It is immutable and safe for
// concurrent use.
type Code struct {
	Scheme wire.ParityScheme
	K, M   int
	enc    [][]byte // full encoding matrix (RS only)

	invMu sync.Mutex
	inv   map[string][][]byte // decode matrices by surviving rows
}

var codes sync.Map // codeKey -> *Code

type codeKey struct {
	s    wire.ParityScheme
	k, m int
}

// New returns the code for scheme with k data and m parity shards (cached).
func New(s wire.ParityScheme, k, m int) (*Code, error) {
	key := codeKey{s, k, m}
	if c, ok := codes.Load(key); ok {
		return c.(*Code), nil
	}
	c := &Code{Scheme: s, K: k, M: m, inv: map[string][][]byte{}}
	switch s {
	case wire.ParityXOR:
		if k < 1 || m != 1 || k+m > wire.MaxParityShards {
			return nil, fmt.Errorf("parity: XOR needs k>=1, m=1, got k=%d m=%d", k, m)
		}
	case wire.ParityRS:
		var err error
		if c.enc, err = EncodingMatrix(k, m); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: parity scheme 0x%02x", wire.ErrUnsupported, uint8(s))
	}
	got, _ := codes.LoadOrStore(key, c)
	return got.(*Code), nil
}

func (c *Code) checkLens(shards [][]byte, n int) (int, error) {
	size := -1
	for _, s := range shards[:n] {
		if s == nil {
			continue
		}
		if size >= 0 && len(s) != size {
			return 0, fmt.Errorf("parity: shard lengths differ (%d, %d)", size, len(s))
		}
		size = len(s)
	}
	return size, nil
}

// Encode computes the M parity shards from the K data shards. All shards
// must have the same length; parity must hold M buffers of that length.
func (c *Code) Encode(data, parity [][]byte) error {
	if len(data) != c.K || len(parity) != c.M {
		return fmt.Errorf("parity: Encode wants %d+%d shards, got %d+%d", c.K, c.M, len(data), len(parity))
	}
	all := append(append(make([][]byte, 0, c.K+c.M), data...), parity...)
	for _, s := range all {
		if s == nil {
			return errors.New("parity: nil shard")
		}
	}
	if _, err := c.checkLens(all, len(all)); err != nil {
		return err
	}
	if c.Scheme == wire.ParityXOR {
		parallel(len(parity[0]), func(lo, hi int) { xorInto(parity[0][lo:hi], data, lo, hi) })
		return nil
	}
	rows := c.enc[c.K:]
	parallel(len(parity[0]), func(lo, hi int) {
		for j, row := range rows {
			combine(parity[j][lo:hi], row, data, lo, hi)
		}
	})
	return nil
}

// Reconstruct fills the missing shards in place. shards has K+M entries
// (data first); present[i] tells whether shards[i] holds a valid shard.
// Every missing entry that should be rebuilt must be a buffer of the shard
// length; a nil missing entry is left alone. At least K shards must be
// present.
func (c *Code) Reconstruct(shards [][]byte, present []bool) error {
	n := c.K + c.M
	if len(shards) != n || len(present) != n {
		return fmt.Errorf("parity: Reconstruct wants %d shards", n)
	}
	var have, missing []int
	for i := 0; i < n; i++ {
		if present[i] {
			if shards[i] == nil {
				return errors.New("parity: present shard is nil")
			}
			have = append(have, i)
		} else if shards[i] != nil {
			missing = append(missing, i)
		}
	}
	if len(have) < c.K {
		return fmt.Errorf("%w: %d of %d needed", ErrTooFewShards, len(have), c.K)
	}
	if len(missing) == 0 {
		return nil
	}
	size, err := c.checkLens(shards, n)
	if err != nil {
		return err
	}
	if c.Scheme == wire.ParityXOR {
		// the one missing shard is the XOR of all others
		if len(missing) > 1 {
			return fmt.Errorf("%w: XOR rebuilds one shard", ErrTooFewShards)
		}
		srcs := make([][]byte, 0, len(have))
		for _, i := range have {
			srcs = append(srcs, shards[i])
		}
		dst := shards[missing[0]]
		parallel(size, func(lo, hi int) { xorInto(dst[lo:hi], srcs, lo, hi) })
		return nil
	}
	use := have[:c.K] // data rows come first, so surviving data is preferred
	dec, err := c.decodeMatrix(use)
	if err != nil {
		return err
	}
	srcs := make([][]byte, c.K)
	for i, r := range use {
		srcs[i] = shards[r]
	}
	var dataMissing, parityMissing []int
	for _, i := range missing {
		if i < c.K {
			dataMissing = append(dataMissing, i)
		} else {
			parityMissing = append(parityMissing, i)
		}
	}
	parallel(size, func(lo, hi int) {
		for _, i := range dataMissing {
			combine(shards[i][lo:hi], dec[i], srcs, lo, hi)
		}
	})
	if len(parityMissing) > 0 {
		data := shards[:c.K]
		for _, i := range data {
			if i == nil {
				return errors.New("parity: rebuilding parity needs every data shard buffer")
			}
		}
		parallel(size, func(lo, hi int) {
			for _, i := range parityMissing {
				combine(shards[i][lo:hi], c.enc[i], data, lo, hi)
			}
		})
	}
	return nil
}

// decodeMatrix returns the inverse of the rows of E selected by use: data
// shard i = sum dec[i][j] * shard(use[j]).
func (c *Code) decodeMatrix(use []int) ([][]byte, error) {
	key := string(func() []byte {
		b := make([]byte, len(use))
		for i, u := range use {
			b[i] = byte(u)
		}
		return b
	}())
	c.invMu.Lock()
	defer c.invMu.Unlock()
	if m, ok := c.inv[key]; ok {
		return m, nil
	}
	sub := make([][]byte, len(use))
	for i, r := range use {
		sub[i] = c.enc[r]
	}
	m, err := invert(sub)
	if err != nil {
		return nil, err
	}
	if len(c.inv) > 64 {
		clear(c.inv)
	}
	c.inv[key] = m
	return m, nil
}

// combine sets dst = sum coef[j] * src[j][lo:hi].
func combine(dst, coef []byte, src [][]byte, lo, hi int) {
	first := true
	for j, s := range src {
		cf := coef[j]
		if cf == 0 {
			continue
		}
		s = s[lo:hi]
		switch {
		case first && cf == 1:
			copy(dst, s)
		case first:
			t := &mulTable[cf]
			for i, v := range s {
				dst[i] = t[v]
			}
		case cf == 1:
			subtle.XORBytes(dst, dst, s)
		default:
			t := &mulTable[cf]
			for i, v := range s {
				dst[i] ^= t[v]
			}
		}
		first = false
	}
	if first {
		clear(dst)
	}
}

// xorInto sets dst = XOR of src[j][lo:hi].
func xorInto(dst []byte, src [][]byte, lo, hi int) {
	copy(dst, src[0][lo:hi])
	for _, s := range src[1:] {
		subtle.XORBytes(dst, dst, s[lo:hi])
	}
}

// parallel splits [0, n) into chunks processed concurrently; small inputs
// stay on the calling goroutine.
func parallel(n int, fn func(lo, hi int)) {
	const minChunk = 256 << 10
	w := min(runtime.GOMAXPROCS(0), n/minChunk)
	if w <= 1 {
		fn(0, n)
		return
	}
	chunk := (n + w - 1) / w
	chunk = (chunk + 63) &^ 63
	var wg sync.WaitGroup
	for lo := 0; lo < n; lo += chunk {
		hi := min(lo+chunk, n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(lo, hi)
		}()
	}
	wg.Wait()
}
