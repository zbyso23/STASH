package recovery

import (
	"os"
	"strconv"
)

// STASH_TEST_DELTA=n runs the whole package with the smallest in-memory
// table delta and manifest load sorts, so every scan spills its working
// tables to the work directory.
func init() {
	if v, err := strconv.Atoi(os.Getenv("STASH_TEST_DELTA")); err == nil && v > 0 {
		testKVMem = 1
	}
}
