package archive

import (
	"os"
	"strconv"
)

// STASH_TEST_DELTA=n runs the whole package with an in-memory index delta
// of n records, so every writer, reader, compaction and recovery path also
// runs over spilled session runs, and the manifest state with the smallest
// in-memory delta and load sorts, so it runs over spilled tables too.
func init() {
	if v, err := strconv.Atoi(os.Getenv("STASH_TEST_DELTA")); err == nil && v > 0 {
		testDeltaMax = v
		testKVMem = 1 // the smallest state delta and load sorts
	}
}
