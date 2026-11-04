package archive

import (
	"bytes"
	"encoding/binary"
	"path"

	"stash/internal/blob"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// checkpointName is the implementation-defined health metadata file that
// holds verified checkpoints (E1-23). Readers of the format ignore it.
const checkpointName = "health/verified.bin"

var checkpointMagic = [8]byte{'S', 'T', 'V', 'E', 'R', 'I', 'F', 'Y'}

const checkpointEntry = 8 + 8 + 32

// encodeCheckpoints: magic, archive_id, generation_id, blob_count, then
// per blob End, LastOff, LastHash, then CRC32C of everything before.
func encodeCheckpoints(h *wire.ArchiveHeader, cps []blob.Checkpoint) []byte {
	b := append([]byte{}, checkpointMagic[:]...)
	b = append(b, h.ArchiveID[:]...)
	b = binary.LittleEndian.AppendUint64(b, h.GenerationID)
	b = append(b, h.BlobCount)
	for _, c := range cps {
		b = binary.LittleEndian.AppendUint64(b, uint64(c.End))
		b = binary.LittleEndian.AppendUint64(b, uint64(c.LastOff))
		b = append(b, c.LastHash[:]...)
	}
	return binary.LittleEndian.AppendUint32(b, wire.CRC32C(b))
}

// readCheckpoints returns the checkpoints of the generation, or nil when
// the file is missing, damaged or of another archive or generation; the
// open then validates every frame completely.
func readCheckpoints(fsys vfs.FS, gen string, h *wire.ArchiveHeader) []blob.Checkpoint {
	n := 8 + 32 + 8 + 1 + int(h.BlobCount)*checkpointEntry + 4
	b, err := vfs.ReadFile(fsys, path.Join(gen, checkpointName), int64(n))
	if err != nil || len(b) != n || !bytes.Equal(b[:8], checkpointMagic[:]) ||
		binary.LittleEndian.Uint32(b[n-4:]) != wire.CRC32C(b[:n-4]) ||
		!bytes.Equal(b[8:40], h.ArchiveID[:]) || binary.LittleEndian.Uint64(b[40:48]) != h.GenerationID || b[48] != h.BlobCount {
		return nil
	}
	cps := make([]blob.Checkpoint, h.BlobCount)
	p := b[49:]
	for i := range cps {
		cps[i].End = int64(binary.LittleEndian.Uint64(p))
		cps[i].LastOff = int64(binary.LittleEndian.Uint64(p[8:]))
		copy(cps[i].LastHash[:], p[16:48])
		p = p[checkpointEntry:]
	}
	return cps
}

// writeCheckpoints records, after every writable blob was synced, where
// each blob ends and which frame ends there (from the index, which holds
// every frame of the blob). Sealed blobs get no checkpoint.
func (w *Writer) writeCheckpoints() error {
	cps := make([]blob.Checkpoint, w.h.BlobCount)
	for b, bw := range w.writers {
		if bw == nil || w.blobs[b] == nil {
			continue
		}
		if err := bw.Sync(); err != nil {
			return err
		}
		end := bw.End()
		bv := w.blobs[b]
		bv.mu.Lock()
		last, ok := bv.idx.Last()
		bv.mu.Unlock()
		if ok && int64(last.PhysicalOffset)+int64(wire.FrameSize(last.FrameQuanta)) == end {
			cps[b] = blob.Checkpoint{End: end, LastOff: int64(last.PhysicalOffset), LastHash: last.FrameHash}
		}
	}
	if err := w.fsys.MkdirAll(path.Join(w.gen, "health"), 0o755); err != nil {
		return err
	}
	return vfs.ReplaceFile(w.fsys, path.Join(w.gen, checkpointName), encodeCheckpoints(w.h, cps))
}
