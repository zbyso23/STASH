#!/bin/sh
# Scale harness (M19 phase 5). Runs every phase of the archive, recovery
# and index harnesses in a fresh process each and prints their RESULT
# lines (peak live heap, RSS high-water mark, wall time, latencies).
#
#   tools/scale.sh workdir [small_n] [extents_n] [index_n]
#
# small_n    objects of 100 bytes (PACKED), default 10000000: ~8 GB
# extents_n  objects of 10 x 4 KiB frames, default 1000000 (10^7 frames):
#            ~41 GB, 0 skips it
# index_n    records of the synthetic index, default 100000000: 6.4 GB plus
#            as much scratch while its runs merge, 0 skips it
#
# Compaction writes a second copy of each archive; the archive is removed
# after its phases. STASH_MEMLIMIT (MiB, default 64) limits every phase.
set -eu
work=$1
sn=${2:-10000000}
en=${3:-1000000}
xn=${4:-100000000}
export STASH_MEMLIMIT=${STASH_MEMLIMIT:-64}
mkdir -p "$work"
go test -c -o "$work/archive.test" ./internal/archive
go test -c -o "$work/recovery.test" ./internal/recovery
go test -c -o "$work/index.test" ./internal/index
out=$work/results.txt
run() { # binary test env...
	bin=$1 test=$2
	shift 2
	env "$@" "$work/$bin" -test.run "^$test\$" -test.v -test.count=1 -test.timeout 12h 2>&1 |
		sed -n 's/.*RESULT /RESULT /p; /FAIL\|panic/p' | tee -a "$out"
}
for spec in small:$sn extents:$en; do
	kind=${spec%%:*} n=${spec##*:}
	[ "$n" -gt 0 ] || continue
	dir=$work/$kind-$n
	rm -rf "$dir"
	mkdir -p "$dir"
	for phase in build writer reader read verify; do
		run archive.test TestZZMemory STASH_DIR="$dir" STASH_KIND=$kind STASH_N=$n STASH_PHASE=$phase
	done
	run recovery.test TestZZRecoverMemory STASH_DIR="$dir" STASH_WORKDIR="$work"
	run archive.test TestZZMemory STASH_DIR="$dir" STASH_KIND=$kind STASH_N=$n STASH_PHASE=compact
	run archive.test TestZZMemory STASH_DIR="$dir" STASH_KIND=$kind STASH_N=$n STASH_PHASE=reader
	rm -rf "$dir"
done
if [ "$xn" -gt 0 ]; then
	run index.test TestZZIndexBuild STASH_INDEX_BUILD=$xn STASH_INDEX_DIR="$work"
fi
