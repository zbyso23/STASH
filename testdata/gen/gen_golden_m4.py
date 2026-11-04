#!/usr/bin/env python3
"""Independent golden vector for a physical index file (SPEC §10.5).

Encodes the header and records with struct.pack and sorts records by
(frame_hash bytes, physical_offset) itself. The Go test feeds the same
unsorted records to index.Add and compares the written file byte for byte.
"""
import hashlib, json, os, struct

MAGIC = b"STIDX8\x00\x00"
VERSION = 0x0006

def header(gen, archive_id, blob, hash_id, count):
    return (MAGIC + struct.pack("<HHQ", VERSION, 64, gen) + archive_id
            + struct.pack("<BBHQ", blob, hash_id, 64, count))

def record(h, off, q, bt, ordinal):
    return h + struct.pack("<QIB3sQ8s", off, q, bt, b"\0" * 3, ordinal, b"\0" * 8)

archive_id = bytes(range(32))
gen, blob, hash_id = 0x0123456789ABCDEF, 0x07, 0x02  # SHA-256
recs = []
off = 0x40
for i, q in enumerate([1, 3, 1, 2, 1, 1]):
    h = hashlib.sha256(b"payload-%d" % (i % 4)).digest()  # duplicates for i=4,5
    bt = 0 if i != 2 else 1
    recs.append({"hash": h.hex(), "offset": off, "quanta": q, "block_type": bt, "ordinal": 100 + i})
    off += q * 4096
srt = sorted(recs, key=lambda r: (bytes.fromhex(r["hash"]), r["offset"]))
data = header(gen, archive_id, blob, hash_id, len(srt)) + b"".join(
    record(bytes.fromhex(r["hash"]), r["offset"], r["quanta"], r["block_type"], r["ordinal"]) for r in srt)
out = {
    "generation_id": str(gen), "archive_id": archive_id.hex(), "blob_ordinal": blob, "hash_id": hash_id,
    "records_unsorted": recs, "blob_size": off, "file_hex": data.hex(),
}
path = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "index", "testdata", "golden.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
    f.write("\n")
print("wrote", os.path.normpath(path), len(data), "bytes")
