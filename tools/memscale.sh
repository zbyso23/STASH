#!/bin/sh
# Memory scale harness (M19 phase 1). Builds archives at a base size and at
# ten times that size, measures each phase in a fresh process and compares
# the retained heap after open: bounded-memory metadata must keep the 10x
# archive within 1.2x of the base; the script exits 1 when it does not.
#
# The writer and the reader run with a memory limit of $STASH_MEMLIMIT MiB
# (default 64): their block caches retain up to their share of the limit,
# which is bounded by design but would otherwise hide growth below the
# 1 GiB default. The gate compares the retained heap without the cached
# blocks (cache_mb, reported apart), which is what must not grow.
#
# usage: tools/memscale.sh [workdir] [extents_n] [small_n]
set -eu
work=${1:-$(mktemp -d)}
en=${2:-10000}
sn=${3:-100000}
bin=$work/archive.test
export STASH_MEMLIMIT=${STASH_MEMLIMIT:-64}
go test -c -o "$bin" ./internal/archive
fail=0
for kind in extents small; do
	n=$en
	[ "$kind" = small ] && n=$sn
	for scale in 1 10; do
		dir=$work/$kind-$scale
		rm -rf "$dir"
		mkdir -p "$dir"
		for phase in build writer reader read; do
			STASH_DIR=$dir STASH_KIND=$kind STASH_N=$((n * scale)) STASH_PHASE=$phase \
				"$bin" -test.run '^TestZZMemory$' -test.v -test.count=1 |
				sed -n 's/.*RESULT /RESULT /p' | tee -a "$work/results.txt"
		done
	done
	for phase in writer reader; do
		units1=$n
		[ "$kind" = extents ] && units1=$((n * 10))
		r1=$(grep "kind=$kind phase=$phase units=$units1 " "$work/results.txt" | tail -1 | sed 's/.*retained_nocache_per_unit=\([0-9.]*\).*/\1/')
		r10=$(grep "kind=$kind phase=$phase units=$((units1 * 10)) " "$work/results.txt" | tail -1 | sed 's/.*retained_nocache_per_unit=\([0-9.]*\).*/\1/')
		# total retained grows by 10*r10/r1; bounded metadata keeps it <= 1.2
		ratio=$(awk -v a="$r1" -v b="$r10" 'BEGIN { printf "%.2f", (a > 0 ? 10 * b / a : 0) }')
		ok=$(awk -v r="$ratio" 'BEGIN { print (r <= 1.2) ? "ok" : "FAIL" }')
		echo "GATE kind=$kind phase=$phase retained_10x/1x=$ratio $ok"
		[ "$ok" = ok ] || fail=1
	done
done
exit $fail
