#!/usr/bin/env python3
"""Independent golden vectors for milestone 8: parity (SPEC §7, §17.8).

Shares no code with the Go implementation. GF(2^8) multiplication is done
bit by bit (carry-less multiply, reduce by 0x11D), not with log tables;
matrices are inverted by Gauss-Jordan elimination over that field. Frames
are built with the same independent byte layout as gen_golden_m2.py.

Writes internal/parity/testdata/golden.json
Run from the repository root:  python3 testdata/gen/gen_golden_m8.py
"""
import hashlib
import json
import os
import struct

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
ARCHIVE_ID = bytes(range(0x20, 0x40))

# --- GF(2^8), polynomial x^8 + x^4 + x^3 + x^2 + 1 ---------------------------

def gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11D
    return p

def gpow(a, e):
    r = 1
    for _ in range(e):
        r = gmul(r, a)
    return r

def ginv(a):
    assert a != 0
    r = gpow(a, 254)
    assert gmul(a, r) == 1
    return r

def mat_mul(a, b):
    return [[_dot(row, [b[i][c] for i in range(len(b))]) for c in range(len(b[0]))] for row in a]

def _dot(x, y):
    s = 0
    for p, q in zip(x, y):
        s ^= gmul(p, q)
    return s

def mat_inv(m):
    n = len(m)
    a = [list(row) + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(m)]
    for col in range(n):
        piv = next(r for r in range(col, n) if a[r][col])
        a[col], a[piv] = a[piv], a[col]
        inv = ginv(a[col][col])
        a[col] = [gmul(v, inv) for v in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                f = a[r][col]
                a[r] = [v ^ gmul(f, w) for v, w in zip(a[r], a[col])]
    return [row[n:] for row in a]

def encoding_matrix(k, m):
    n = k + m
    v = [[gpow(r, c) for c in range(k)] for r in range(n)]  # 0^0 = 1
    e = mat_mul(v, mat_inv(v[:k]))
    for i in range(k):
        assert e[i] == [1 if i == j else 0 for j in range(k)]
    return e

def rs_encode(k, m, data):
    e = encoding_matrix(k, m)
    size = len(data[0])
    out = []
    for j in range(m):
        row = e[k + j]
        out.append(bytes(_dot(row, [d[pos] for d in data]) for pos in range(size)))
    return out

def xor_encode(data):
    out = bytearray(len(data[0]))
    for d in data:
        for i, b in enumerate(d):
            out[i] ^= b
    return bytes(out)

def pattern(n, seed):
    x = seed * 2654435761 & 0xFFFFFFFF
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out.append(x >> 16 & 0xFF)
    return bytes(out)

# Spot checks of the field itself.
assert gmul(0x80, 2) == 0x1D and gmul(0x02, 0x8E) == 1 and ginv(2) == 0x8E
field = dict(products=[[a, b, gmul(a, b)] for a, b in
                       [(0, 7), (1, 0xFF), (2, 0x80), (0x53, 0xCA), (0xFF, 0xFF), (0x8E, 2), (3, 7), (0x1D, 0x1D)]],
             inverses=[[a, ginv(a)] for a in (1, 2, 3, 0x1D, 0x53, 0x8E, 0xFF)])

matrices = []
for k, m in [(1, 1), (1, 3), (2, 1), (2, 2), (3, 2), (4, 2), (5, 3), (10, 4), (17, 3)]:
    e = encoding_matrix(k, m)
    matrices.append(dict(k=k, m=m, parity_rows=[bytes(r).hex() for r in e[k:]]))

codes = []
def code_case(name, scheme, k, m, size, seed):
    data = [pattern(size, seed + i) for i in range(k)]
    if scheme == 1:
        assert m == 1
        parity = [xor_encode(data)]
    else:
        parity = rs_encode(k, m, data)
    codes.append(dict(name=name, scheme=scheme, k=k, m=m, data=[d.hex() for d in data],
                      parity=[p.hex() for p in parity]))

code_case("xor_k1", 1, 1, 1, 33, 1)
code_case("xor_k4", 1, 4, 1, 64, 2)
code_case("rs_k1_m1", 2, 1, 1, 17, 3)  # RS with m=1 is not XOR (k=1 row is 1 though)
code_case("rs_k2_m1", 2, 2, 1, 40, 4)  # the RS parity row of k=2, m=1 is not all ones
code_case("rs_k3_m2", 2, 3, 2, 100, 5)
code_case("rs_k4_m4", 2, 4, 4, 64, 6)
code_case("rs_k10_m4", 2, 10, 4, 50, 7)
code_case("rs_k200_m56", 2, 200, 56, 6, 8)  # n = 256: every field element is a row
assert rs_encode(2, 1, [b"\x01", b"\x01"])[0] != xor_encode([b"\x01", b"\x01"])

# --- frames (byte layout as in gen_golden_m2.py) ----------------------------

def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF

def uleb(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)

def object_id(path, file_ver):
    return hashlib.sha256(b"STASH-OBJECT-ID-V2" + path.encode() + struct.pack("<Q", file_ver)).digest()[:16]

def prefix(q):
    return b"STFR" + struct.pack("<III", q, crc32c(b"STFR" + struct.pack("<II", q, 0)), 0)

def trailer(block_type, payload, q, ordinal, group, oid=b"\0" * 16, lo=0, ll=0):
    return struct.pack("<4sBBBBIBBBBII16sQQQ32s", b"STSH", 2, 0, block_type, 0,
                       group[0], group[1], group[2], group[3], 0, len(payload), q, oid, lo, ll,
                       ordinal, hashlib.sha256(payload).digest())

def entries_body(entries):
    b = struct.pack("<I", len(entries))
    for e in entries:
        p = e["path"].encode()
        b += uleb(len(p)) + p + struct.pack("<QQQ", e["offset"], e["length"], e["file_ver"])
    return b

def build(block_type, payload, entries, q, ordinal, group):
    body = entries_body(entries)
    pt_len = len(body) + 4
    if block_type == 0:
        e = entries[0]
        tb = trailer(0, payload, q, ordinal, group, object_id(e["path"], e["file_ver"]), e["offset"], e["length"])
    else:
        tb = trailer(block_type, payload, q, ordinal, group)
    size = q * 4096
    pad = size - 16 - len(payload) - pt_len - 4 - 96
    assert pad >= 0
    stored_pt = body + struct.pack("<I", crc32c(body + struct.pack("<I", pt_len) + tb))
    frame = prefix(q) + payload + b"\0" * pad + stored_pt + struct.pack("<I", pt_len) + tb
    assert len(frame) == size
    shard = None
    if block_type != 1:
        image = payload + stored_pt + struct.pack("<I", pt_len) + tb
        shard_len = size - 124
        assert len(image) == size - 16 - pad
        if 4 + len(image) <= shard_len:
            shard = struct.pack("<I", len(image)) + image + b"\0" * (shard_len - 4 - len(image))
    return frame, shard, pad

def header(mode, maxq, parity, blobs):
    return dict(mode=mode, hash_id=2, codec_id=0, parity_scheme=parity[0], parity_k=parity[1],
                parity_m=parity[2], blob_count=blobs, flags=0, max_frame_quanta=maxq,
                generation_id=0, archive_id=ARCHIVE_ID.hex())

groups = []
def group_case(name, hdr, gid, q, members, ordinal0):
    """members: list of (block_type, payload, entries) data members."""
    k, m, scheme = len(members), hdr["parity_m"], hdr["parity_scheme"]
    frames, shards, pads = [], [], []
    for i, (bt, payload, entries) in enumerate(members):
        fr, sh, pad = build(bt, payload, entries, q, ordinal0 + i, (gid, i, k, m))
        assert sh is not None, "padding below 112"
        frames.append(fr)
        shards.append(sh)
        pads.append(pad)
    pshards = [xor_encode(shards)] if scheme == 1 else rs_encode(k, m, shards)
    for j, ps in enumerate(pshards):
        assert len(ps) == q * 4096 - 124
        fr, _, pad = build(1, ps, [], q, ordinal0 + k + j, (gid, k + j, k, m))
        assert pad == 0
        frames.append(fr)
    groups.append(dict(name=name, header=hdr, group_id=gid, frame_quanta=q, k=k, m=m,
                       members=[dict(block_type=bt, payload=p.hex(), entries=e) for bt, p, e in members],
                       padding=pads, shards=[s.hex() for s in shards], frames=[f.hex() for f in frames]))

def data(path, ver, off, payload):
    return (0, payload, [dict(path=path, offset=off, length=len(payload), file_ver=ver)])

group_case("xor_k3", header(0, 64, (1, 4, 1), 3), 7, 2,
           [data("x/a", 5, 0, pattern(4096, 11)), data("x/a", 5, 4096, pattern(4100, 12)),
            data("x/b", 6, 0, pattern(10, 13))], 100)
group_case("rs_k2_m2", header(0, 64, (2, 2, 2), 4), 1, 1,
           [data("r", 1, 0, pattern(3000, 21)), data("r", 1, 4096, b"")], 0)
group_case("rs_short_group", header(0, 64, (2, 3, 2), 3), 0xFFFFFFFF, 1,
           [data("s", 0xFFFFFFFFFFFFFFFE, 0, pattern(1, 31))], 7)
group_case("rs_packed_member", header(0, 64, (2, 2, 1), 2), 3, 1,
           [(2, b"hello" + b"world!", [dict(path="p/a", offset=0, length=5, file_ver=8),
                                      dict(path="p/b", offset=5, length=6, file_ver=9)]),
            data("p/c", 10, 0, pattern(2000, 41))], 50)
group_case("fixed_rs_k3_m1", header(1, 2, (2, 3, 1), 2), 12, 2,
           [data("f", 3, 0, pattern(7900, 51)), data("f", 3, 8192, pattern(7930, 52)),
            data("f", 3, 16384, pattern(77, 53))], 9)
# padding exactly 112: 4096 - 16 - pt_len - 4 - 96 - 112 payload bytes
pt_len = len(entries_body([dict(path="b", offset=0, length=0, file_ver=1)])) + 4
edge = 4096 - 16 - pt_len - 4 - 96 - 112
group_case("padding_112", header(0, 64, (1, 2, 1), 2), 2, 1,
           [data("b", 1, 0, pattern(edge, 61)), data("b", 1, 4096, pattern(edge, 62))], 0)
_, sh, pad = build(0, pattern(edge + 1, 63), [dict(path="b", offset=0, length=edge + 1, file_ver=1)], 1, 0, (2, 0, 1, 1))
assert pad == 111 and sh is None  # one byte more does not fit a parity group at this size

out = os.path.join(ROOT, "internal", "parity", "testdata", "golden.json")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as fh:
    json.dump({"generator": "testdata/gen/gen_golden_m8.py", "field": field, "matrices": matrices,
               "codes": codes, "groups": groups, "padding_edge_payload": edge}, fh, indent=1)
    fh.write("\n")
print("wrote", out)
