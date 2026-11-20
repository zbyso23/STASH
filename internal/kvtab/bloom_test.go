package kvtab

import (
	"fmt"
	"hash/maphash"
	"testing"
)

// A filter never rejects a key it holds, and rejects most others.
func TestBloom(t *testing.T) {
	const n = 100000
	b := newBloom(n, maphash.MakeSeed())
	for i := 0; i < n; i++ {
		b.add([]byte(fmt.Sprintf("key-%d", i)))
	}
	for i := 0; i < n; i++ {
		if !b.mayHave([]byte(fmt.Sprintf("key-%d", i))) {
			t.Fatalf("false negative %d", i)
		}
	}
	fp := 0
	for i := 0; i < n; i++ {
		if b.mayHave([]byte(fmt.Sprintf("other-%d", i))) {
			fp++
		}
	}
	if fp > n/50 { // 10 bits per key: about 1 %
		t.Fatalf("%d false positives of %d", fp, n)
	}
	var none *bloom
	if !none.mayHave([]byte("x")) {
		t.Fatal("no filter must not reject")
	}
}
