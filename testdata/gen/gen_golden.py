#!/usr/bin/env python3
"""Independent golden-vector generator for STASH R10 wire structures.

SPEC §17.1 requires golden vectors that are NOT produced by the production
encoder under test. This script builds every byte with struct.pack and its own
CRC32C, straight from the SPEC tables, and shares no code with the Go
implementation. Output: internal/wire/testdata/golden.json

Run from the repository root:  python3 testdata/gen/gen_golden.py
"""
import hashlib
import json
import os
import struct

# --- CRC32C (Castagnoli, reflected polynomial 0x82F63B78), bitwise ---
def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF

assert crc32c(b"123456789") == 0xE3069283  # standard check value

def seq(start, n):
    return bytes((start + i) & 0xFF for i in range(n))

ARCHIVE_ID = seq(0x20, 32)
cases = []

def add(kind, name, fields, data):
    cases.append({"kind": kind, "name": name, "fields": fields, "hex": data.hex()})

# --- Archive Header §2.2 ---
def archive_header(f):
    return struct.pack("<4sHBBBBBBBBHIQ4s32s", b"STSH", 0x0006, f["mode"], f["hash_id"],
                       f["codec_id"], f["parity_scheme"], f["parity_k"], f["parity_m"],
                       f["blob_count"], f["flags"], 64, f["max_frame_quanta"],
                       f["generation_id"], b"\0" * 4, bytes.fromhex(f["archive_id"]))

for name, f in [
    ("sentinel_fixed_rs_encrypted", dict(mode=1, hash_id=2, codec_id=3, parity_scheme=2, parity_k=10,
        parity_m=4, blob_count=0x11, flags=1, max_frame_quanta=0x00012345,
        generation_id=0x0102030405060708, archive_id=ARCHIVE_ID.hex())),
    ("baseline_variable", dict(mode=0, hash_id=2, codec_id=0, parity_scheme=0, parity_k=0,
        parity_m=0, blob_count=1, flags=0, max_frame_quanta=1024, generation_id=0,
        archive_id=ARCHIVE_ID.hex())),
    ("fast_xor", dict(mode=0, hash_id=1, codec_id=1, parity_scheme=1, parity_k=4, parity_m=1,
        blob_count=5, flags=0, max_frame_quanta=0x00100000, generation_id=0xFFFFFFFFFFFFFFFF,
        archive_id=ARCHIVE_ID.hex())),
]:
    b = archive_header(f)
    assert len(b) == 64
    add("archive_header", name, f, b)

# --- root.current §2.1.1 ---
def root(f):
    b = bytearray(struct.pack("<8sHHQ32sIII", b"STROOT8\0", 0x0006, 64, f["generation_id"],
                              bytes.fromhex(f["archive_id"]), 0, 0, 0))
    assert len(b) == 64
    struct.pack_into("<I", b, 0x38, crc32c(bytes(b)))  # CRC field was zero
    return bytes(b)

for name, g in [("sentinel", 0x0102030405060708), ("generation_zero", 0)]:
    f = dict(generation_id=g, archive_id=ARCHIVE_ID.hex())
    add("root", name, f, root(f))

# --- Frame Prefix §6.1 ---
def prefix(q):
    crc = crc32c(b"STFR" + struct.pack("<I", q) + struct.pack("<I", 0))
    return b"STFR" + struct.pack("<III", q, crc, 0)

for name, q in [("sentinel", 0x00012345), ("min", 1), ("max", 0x00100000)]:
    add("frame_prefix", name, {"frame_quanta": q}, prefix(q))

# --- Master Trailer §6.2 ---
def trailer(f):
    b = struct.pack("<4sBBBBIBBBBII16sQQQ32s", b"STSH", f["hash_id"], f["codec_id"],
                    f["block_type"], 0, f["group_id"], f["group_index"], f["group_k"],
                    f["group_m"], 0, f["data_len"], f["frame_quanta"],
                    bytes.fromhex(f["object_id"]), f["logical_offset"], f["logical_length"],
                    f["frame_ordinal"], bytes.fromhex(f["hash_payload"]))
    assert len(b) == 96
    return b

tf = dict(hash_id=1, codec_id=2, block_type=0, group_id=0x11223344, group_index=3, group_k=10,
          group_m=4, data_len=0x55667788, frame_quanta=0x00012345,
          object_id=seq(0xA0, 16).hex(), logical_offset=0x0102030405060708,
          logical_length=0x1112131415161718, frame_ordinal=0x2122232425262728,
          hash_payload=seq(0xC0, 32).hex())
add("master_trailer", "sentinel", tf, trailer(tf))

# --- Allocator State §2.1.3, every kind ---
def alloc(f):
    b = bytearray(struct.pack("<8sHBBIQQ32s", b"STALLOC\0", 0x0006, f["kind"], f["blob_ordinal"], 0,
                              f["generation_id"], f["reserved_through"], bytes.fromhex(f["archive_id"])))
    assert len(b) == 64
    struct.pack_into("<I", b, 0x0C, crc32c(bytes(b)))
    return bytes(b)

for kind, blob, gen in [(0, 0, 0), (1, 0, 0), (2, 0, 0x0102030405060708),
                        (3, 0xFE, 0x0102030405060708), (4, 0, 0x0102030405060708)]:
    f = dict(kind=kind, blob_ordinal=blob, generation_id=gen,
             reserved_through=0x1112131415161718 + kind, archive_id=ARCHIVE_ID.hex())
    add("alloc_state", f"kind{kind}", f, alloc(f))

# --- Index header and record §10.5 ---
ih = dict(generation_id=0x0102030405060708, archive_id=ARCHIVE_ID.hex(), blob_ordinal=0x11,
          hash_id=2, record_count=0x2122232425262728)
b = struct.pack("<8sHHQ32sBBHQ", b"STIDX8\0\0", 0x0006, 64, ih["generation_id"],
                bytes.fromhex(ih["archive_id"]), ih["blob_ordinal"], ih["hash_id"], 64,
                ih["record_count"])
assert len(b) == 64
add("index_header", "sentinel", ih, b)

ir = dict(frame_hash=seq(0xC0, 32).hex(), physical_offset=0x40 + 0x01020304 * 4096,
          frame_quanta=0x00012345, block_type=2, frame_ordinal=0x3132333435363738)
b = struct.pack("<32sQIB3sQ8s", bytes.fromhex(ir["frame_hash"]), ir["physical_offset"],
                ir["frame_quanta"], ir["block_type"], b"\0" * 3, ir["frame_ordinal"], b"\0" * 8)
assert len(b) == 64
add("index_record", "sentinel", ir, b)

# --- canonical LEB128 path_len §6.4.1 ---
def uleb(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)

for n in [1, 127, 128, 255, 4095, 4096]:
    add("path_len", f"n{n}", {"value": n}, uleb(n))

# --- Minimum valid frame: a 4096-byte PARITY frame (§7.1) ---
# header context: VARIABLE, SHA-256, XOR k=1 m=1, 2 blobs, max 4 quanta.
S = 4096
shard_len = S - 124
payload = bytes((i * 7 + 3) & 0xFF for i in range(shard_len))
tr = dict(hash_id=2, codec_id=0, block_type=1, group_id=1, group_index=1, group_k=1, group_m=1,
          data_len=shard_len, frame_quanta=1, object_id=("00" * 16), logical_offset=0,
          logical_length=0, frame_ordinal=7, hash_payload=hashlib.sha256(payload).hexdigest())
tb = trailer(tr)
body_wo_crc = struct.pack("<I", 0)  # entry_count = 0
pt_len = 8
outer = crc32c(body_wo_crc + struct.pack("<I", pt_len) + tb)
frame = prefix(1) + payload + body_wo_crc + struct.pack("<I", outer) + struct.pack("<I", pt_len) + tb
assert len(frame) == S
add("min_parity_frame", "xor_k1_m1", {"trailer": tr, "outer_crc32c": outer,
    "header": dict(mode=0, hash_id=2, codec_id=0, parity_scheme=1, parity_k=1, parity_m=1,
                   blob_count=2, flags=0, max_frame_quanta=4, generation_id=0,
                   archive_id=ARCHIVE_ID.hex())}, frame)

out = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "wire", "testdata", "golden.json")
with open(out, "w") as fh:
    json.dump({"generator": "testdata/gen/gen_golden.py", "spec": "STASH R10 with Erratum E1",
               "cases": cases}, fh, indent=1)
    fh.write("\n")
print(f"wrote {len(cases)} cases to {os.path.normpath(out)}")
