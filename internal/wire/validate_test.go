package wire

import (
	"errors"
	"testing"
)

func dataTrailer(h *ArchiveHeader) MasterTrailer {
	return MasterTrailer{HashID: h.HashID, CodecID: CodecStore, BlockType: BlockData, DataLen: 100,
		FrameQuanta: 1, ObjectID: [16]byte{1}, LogicalLength: 100}
}

func TestValidateTrailer(t *testing.T) {
	h := testHeader() // XOR k=1 m=1, max 4 quanta, unencrypted
	p := FramePrefix{FrameQuanta: 1}
	ok := dataTrailer(&h)
	if err := ValidateTrailer(&ok, &h, p); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*MasterTrailer){
		"hash mismatch":       func(m *MasterTrailer) { m.HashID = HashBLAKE3 },
		"quanta mismatch":     func(m *MasterTrailer) { m.FrameQuanta = 2 },
		"zero object_id":      func(m *MasterTrailer) { m.ObjectID = [16]byte{} },
		"unaligned offset":    func(m *MasterTrailer) { m.LogicalOffset = 100 },
		"STORE length":        func(m *MasterTrailer) { m.DataLen = 99 },
		"length > MAX":        func(m *MasterTrailer) { m.CodecID = CodecZstdFast; m.LogicalLength = 4*4096 + 1 },
		"data_len > budget":   func(m *MasterTrailer) { m.CodecID = CodecZstdFast; m.DataLen = 4096 - 123 },
		"group fields no id":  func(m *MasterTrailer) { m.GroupK = 1 },
		"group_k 0":           func(m *MasterTrailer) { m.GroupID = 1; m.GroupM = 1 },
		"group_k > parity_k":  func(m *MasterTrailer) { m.GroupID = 1; m.GroupK = 2; m.GroupM = 1 },
		"group_m != parity_m": func(m *MasterTrailer) { m.GroupID = 1; m.GroupK = 1; m.GroupM = 2 },
		"data index in parity range": func(m *MasterTrailer) {
			m.GroupID, m.GroupK, m.GroupM, m.GroupIndex = 1, 1, 1, 1
		},
		"index >= k+m": func(m *MasterTrailer) { m.GroupID, m.GroupK, m.GroupM, m.GroupIndex = 1, 1, 1, 2 },
		"packed placement": func(m *MasterTrailer) {
			m.BlockType = BlockPacked
		},
	}
	for name, mut := range cases {
		m := ok
		mut(&m)
		if err := ValidateTrailer(&m, &h, p); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// accepted boundaries
	m := ok
	m.CodecID, m.LogicalLength = CodecZstdFast, 4*4096
	if err := ValidateTrailer(&m, &h, p); err != nil {
		t.Errorf("logical_length == MAX_FRAME_SIZE rejected: %v", err)
	}
	m = ok
	m.GroupID, m.GroupK, m.GroupM = 9, 1, 1
	if err := ValidateTrailer(&m, &h, p); err != nil {
		t.Errorf("valid group member rejected: %v", err)
	}
	m = ok
	m.DataLen, m.LogicalLength = 0, 0
	if err := ValidateTrailer(&m, &h, p); err != nil {
		t.Errorf("zero-length object rejected: %v", err)
	}
	enc := h
	enc.Flags = HeaderFlagEncrypted
	m = ok
	m.DataLen = 128
	if err := ValidateTrailer(&m, &enc, p); err != nil {
		t.Errorf("encrypted STORE length rejected: %v", err)
	}
	none := h
	none.ParityScheme, none.ParityK, none.ParityM = ParityNone, 0, 0
	m = ok
	m.GroupID, m.GroupK, m.GroupM = 1, 1, 0
	if err := ValidateTrailer(&m, &none, p); !errors.Is(err, ErrCorrupt) {
		t.Error("group in NONE archive accepted")
	}
}

func TestValidateParityTrailer(t *testing.T) {
	h := testHeader()
	p := FramePrefix{FrameQuanta: 1}
	pt := MasterTrailer{HashID: h.HashID, CodecID: CodecStore, BlockType: BlockParity, GroupID: 1, GroupIndex: 1,
		GroupK: 1, GroupM: 1, DataLen: uint32(ParityShardLen(1)), FrameQuanta: 1}
	if err := ValidateTrailer(&pt, &h, p); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*MasterTrailer){
		"codec":       func(m *MasterTrailer) { m.CodecID = CodecZstdFast },
		"shard len":   func(m *MasterTrailer) { m.DataLen-- },
		"no group":    func(m *MasterTrailer) { m.GroupID, m.GroupIndex, m.GroupK, m.GroupM = 0, 0, 0, 0 },
		"data index":  func(m *MasterTrailer) { m.GroupIndex = 0 },
		"object_id":   func(m *MasterTrailer) { m.ObjectID[0] = 1 },
		"logical len": func(m *MasterTrailer) { m.LogicalLength = 1 },
	} {
		m := pt
		mut(&m)
		if err := ValidateTrailer(&m, &h, p); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
