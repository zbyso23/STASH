#!/usr/bin/env python3
"""Independent golden vectors for milestone 2 (SPEC §6, §6.4, §6.5, §8, §17.1).

Shares no code with the Go implementation. Writes
  internal/frame/testdata/golden.json      frames and object_id vectors
  internal/canonpath/testdata/golden.json  Unicode 15.0 assigned ranges, path cases

Python's unicodedata is Unicode 15.1 here; the 627 code points added in 15.1
(U+2FFC..U+2FFF, U+31EF, U+2EBF0..U+2EE5D) are removed to obtain 15.0.
Run from the repository root:  python3 testdata/gen/gen_golden_m2.py
"""
import hashlib
import hmac
import json
import os
import struct
import unicodedata

def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF

assert crc32c(b"123456789") == 0xE3069283
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
ARCHIVE_ID = bytes(range(0x20, 0x40))

def uleb(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)

def object_id(path, file_ver, key=None):
    msg = b"STASH-OBJECT-ID-V2" + path.encode() + struct.pack("<Q", file_ver)
    if key is None:
        return hashlib.sha256(msg).digest()[:16]
    return hmac.new(key, msg, hashlib.sha256).digest()[:16]

def prefix(q):
    return b"STFR" + struct.pack("<III", q, crc32c(b"STFR" + struct.pack("<II", q, 0)), 0)

def trailer(f):
    return struct.pack("<4sBBBBIBBBBII16sQQQ32s", b"STSH", 2, f["codec_id"], f["block_type"], 0,
                       f["group_id"], f["group_index"], f["group_k"], f["group_m"], 0,
                       f["data_len"], f["frame_quanta"], f["object_id"], f["logical_offset"],
                       f["logical_length"], f["frame_ordinal"], f["hash_payload"])

def entries_body(entries):
    b = struct.pack("<I", len(entries))
    for e in entries:
        p = e["path"].encode()
        b += uleb(len(p)) + p + struct.pack("<QQQ", e["offset"], e["length"], e["file_ver"])
    return b

def build(block_type, payload, entries, q, ordinal, group=(0, 0, 0, 0)):
    body = entries_body(entries)
    pt_len = len(body) + 4
    if block_type == 0:
        e = entries[0]
        oid, lo, ll = object_id(e["path"], e["file_ver"]), e["offset"], e["length"]
    else:
        oid, lo, ll = b"\0" * 16, 0, 0
    tf = dict(codec_id=0, block_type=block_type, group_id=group[0], group_index=group[1],
              group_k=group[2], group_m=group[3], data_len=len(payload), frame_quanta=q,
              object_id=oid, logical_offset=lo, logical_length=ll, frame_ordinal=ordinal,
              hash_payload=hashlib.sha256(payload).digest())
    tb = trailer(tf)
    size = q * 4096
    pad = size - 16 - len(payload) - pt_len - 4 - 96
    assert pad >= 0
    frame = (prefix(q) + payload + b"\0" * pad + body +
             struct.pack("<I", crc32c(body + struct.pack("<I", pt_len) + tb)) +
             struct.pack("<I", pt_len) + tb)
    assert len(frame) == size
    return frame, tf, pad

def header(mode, maxq, parity=(0, 0, 0), blobs=1):
    return dict(mode=mode, hash_id=2, codec_id=0, parity_scheme=parity[0], parity_k=parity[1],
                parity_m=parity[2], blob_count=blobs, flags=0, max_frame_quanta=maxq,
                generation_id=0, archive_id=ARCHIVE_ID.hex())

def pattern(n, seed):
    return bytes((i * 31 + seed) & 0xFF for i in range(n))

cases = []
def frame_case(name, hdr, block_type, payload, entries, q, ordinal, group=(0, 0, 0, 0), min_quanta=True):
    frame, tf, pad = build(block_type, payload, entries, q, ordinal, group)
    t = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in tf.items()}
    cases.append(dict(name=name, header=hdr, block_type=block_type, payload=payload.hex(),
                      entries=entries, frame_quanta=q, frame_ordinal=ordinal,
                      group=list(group), trailer=t, padding=pad, min_quanta=min_quanta,
                      hex=frame.hex()))

path = unicodedata.normalize("NFC", "docs/čtení.txt")
frame_case("data_variable", header(0, 1024), 0, pattern(5000, 1),
           [dict(path=path, offset=0, length=5000, file_ver=7)], 2, 3)
frame_case("data_zero_length", header(0, 1024), 0, b"",
           [dict(path="empty", offset=0, length=0, file_ver=1)], 1, 0)
pk = [dict(path="a.txt", offset=0, length=3, file_ver=10),
      dict(path="b/c.txt", offset=3, length=0, file_ver=11),
      dict(path="b/d.txt", offset=3, length=10, file_ver=12)]
frame_case("packed_variable", header(0, 1024), 2, b"abc" + b"0123456789", pk, 1, 4)
frame_case("data_fixed", header(1, 3), 0, pattern(100, 7),
           [dict(path="seg/0001", offset=8192, length=100, file_ver=0x0102030405060708)], 3, 5,
           min_quanta=False)
frame_case("data_parity_member", header(0, 1024, (1, 2, 1), 3), 0, pattern(3900, 9),
           [dict(path="g/x", offset=0, length=3900, file_ver=2)], 2, 6, group=(9, 0, 2, 1))

oid_cases = []
key = bytes(range(32))
for p, v in [("a", 0), (path, 7), ("seg/0001", 0x0102030405060708), ("x" * 4096, 0xFFFFFFFFFFFFFFFF)]:
    oid_cases.append(dict(path=p, file_ver=v, sha256=object_id(p, v).hex(),
                          hmac_key=key.hex(), hmac=object_id(p, v, key).hex()))

with open(os.path.join(ROOT, "internal", "frame", "testdata", "golden.json"), "w") as fh:
    json.dump({"generator": "testdata/gen/gen_golden_m2.py", "frames": cases, "object_ids": oid_cases},
              fh, indent=1, ensure_ascii=False)
    fh.write("\n")

# --- Unicode 15.0 assigned ranges (General_Category != Cn) ---
added_15_1 = set(range(0x2FFC, 0x3000)) | {0x31EF} | set(range(0x2EBF0, 0x2EE5E))
assert len(added_15_1) == 627
assert unicodedata.unidata_version == "15.1.0", unicodedata.unidata_version
ranges, start = [], None
for cp in range(0x110001):
    a = cp <= 0x10FFFF and unicodedata.category(chr(cp)) != "Cn" and cp not in added_15_1
    if a and start is None:
        start = cp
    if not a and start is not None:
        ranges.append([start, cp - 1])
        start = None

paths = [
    ("a", True), ("a/b/c.txt", True), (path, True), ("x" * 4096, True), ("x" * 4097, False),
    ("", False), ("/abs", False), ("a//b", False), ("a/", False), ("./a", False), ("a/../b", False),
    ("..", False), ("a\\b", False), ("a\x00b", False), ("a\x1fb", False), ("a\x7fb", False),
    ("a\u0085b", False), ("a﷐b", False), ("a\U0002EBF0b", False), ("a㇯b", False),
    (unicodedata.normalize("NFD", "čtení"), False), ("č", True), ("emoji\U0001FAE8", True),
    ("pua", True), ("a b", True), ("a.b/.c/..d", True),
]
with open(os.path.join(ROOT, "internal", "canonpath", "testdata", "golden.json"), "w") as fh:
    json.dump({"generator": "testdata/gen/gen_golden_m2.py", "assigned15": ranges,
               "paths": [{"path_hex": p.encode("utf-8", "surrogatepass").hex(), "valid": v} for p, v in paths]},
              fh)
    fh.write("\n")
print(f"{len(cases)} frames, {len(oid_cases)} object ids, {len(ranges)} assigned ranges, {len(paths)} paths")
