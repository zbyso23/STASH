package frame

import (
	"bytes"
	"testing"

	"stash/internal/wire"
)

// FuzzFromRecoveryShard: arbitrary shard bytes never panic, and whatever
// frame they produce either fails Parse or round-trips to the same shard.
func FuzzFromRecoveryShard(f *testing.F) {
	h := &wire.ArchiveHeader{Mode: wire.ModeVariable, HashID: wire.HashSHA256, ParityScheme: wire.ParityXOR,
		ParityK: 2, ParityM: 1, BlobCount: 3, MaxFrameQuanta: 4}
	fr, err := Build(h, &Spec{BlockType: wire.BlockData, Payload: []byte("seed payload"), GroupID: 1, GroupK: 1, GroupM: 1,
		Entries: []wire.Entry{{Path: "p", Length: 12, FileVer: 1}}})
	if err != nil {
		f.Fatal(err)
	}
	seed, err := AppendRecoveryShard(nil, fr)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, shard []byte) {
		if len(shard) > int(wire.ParityShardLen(1)) {
			shard = shard[:wire.ParityShardLen(1)]
		}
		shard = append(shard, make([]byte, int(wire.ParityShardLen(1))-len(shard))...)
		out, err := AppendFromRecoveryShard(nil, shard, 1)
		if err != nil {
			return
		}
		if len(out) != wire.BaseQuantum {
			t.Fatalf("frame of %d bytes", len(out))
		}
		if _, err := Parse(out, h); err != nil {
			return
		}
		again, err := AppendRecoveryShard(nil, out)
		if err != nil {
			return // a valid frame outside a group may lack the padding
		}
		if !bytes.Equal(again, shard) {
			t.Fatal("valid rebuilt frame does not round-trip to its shard")
		}
	})
}
