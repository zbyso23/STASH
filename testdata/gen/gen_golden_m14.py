#!/usr/bin/env python3
"""Independent golden vectors for milestones 14/15 (SPEC §5.1, §6.4.3, §6.5,
§15.2-§15.8, §17.1, §17.7, §17.9).

Shares no code with the Go implementation: HKDF and AES-256-GCM come from
the Python 'cryptography' package, Zstandard from 'zstandard' (libzstd).
Writes
  internal/seal/testdata/golden.json      HKDF keys, keyed object_id, nonces,
                                          encrypted frames, manifest envelopes
  internal/compress/testdata/golden.json  libzstd frames and malformed cases
Run from the repository root:  python3 testdata/gen/gen_golden_m14.py
"""
import base64
import hashlib
import hmac
import json
import os
import struct

import zstandard
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
ARCHIVE_ID = bytes(range(0x20, 0x40))
DEK = bytes(range(0x40, 0x60))
VERSION = 0x0006


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


assert crc32c(b"123456789") == 0xE3069283


def hkdf(info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ARCHIVE_ID, info=info).derive(DEK)


KEYS = {
    "frame": hkdf(b"STASH-FRAME-AEAD-R8"),
    "pretrailer": hkdf(b"STASH-PRETRAILER-AEAD-R8"),
    "manifest": hkdf(b"STASH-MANIFEST-AEAD-R8"),
    "object_id": hkdf(b"STASH-OBJECT-ID-KEY-R10"),
    "key_check": hkdf(b"STASH-KEY-CHECK-R10"),
}
assert len(set(KEYS.values())) == 5


def object_id(path, file_ver):
    msg = b"STASH-OBJECT-ID-V2" + path.encode() + struct.pack("<Q", file_ver)
    return hmac.new(KEYS["object_id"], msg, hashlib.sha256).digest()[:16]


def frame_nonce(gen, blob, ordinal):
    assert gen <= 0xFFFFFFFF and ordinal <= 0x00FFFFFFFFFFFFFF
    return struct.pack("<IB", gen, blob) + struct.pack("<Q", ordinal)[:7]


def manifest_nonce(gen, seq):
    return struct.pack("<IQ", gen, seq)


def uleb(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def prefix(q):
    return b"STFR" + struct.pack("<III", q, crc32c(b"STFR" + struct.pack("<II", q, 0)), 0)


def trailer(f, hash_id):
    return struct.pack("<4sBBBBIBBBBII16sQQQ32s", b"STSH", hash_id, f["codec_id"], f["block_type"], 0,
                       f["group_id"], f["group_index"], f["group_k"], f["group_m"], 0,
                       f["data_len"], f["frame_quanta"], f["object_id"], f["logical_offset"],
                       f["logical_length"], f["frame_ordinal"], f["hash_payload"])


def entries_body(entries):
    b = struct.pack("<I", len(entries))
    for e in entries:
        p = e["path"].encode()
        b += uleb(len(p)) + p + struct.pack("<QQQ", e["offset"], e["length"], e["file_ver"])
    return b


def frame_aad(flags, q, trailer64):
    return ARCHIVE_ID + struct.pack("<HB", VERSION, flags) + b"STFR" + struct.pack("<II", q, 0) + trailer64


def build_sealed(hdr, block_type, codec, plain_payload, entries, q, ordinal, blob, group=(0, 0, 0, 0)):
    """§15.6 construction order with an independent AES-GCM."""
    hash_id = hdr["hash_id"]
    gen = hdr["generation_id"]
    nonce = frame_nonce(gen, blob, ordinal)
    pt_plain = entries_body(entries)
    data_len = len(plain_payload) + 28
    pt_len = len(pt_plain) + 28 + 4
    if block_type == 0:
        e = entries[0]
        oid, lo, ll = object_id(e["path"], e["file_ver"]), e["offset"], e["length"]
    else:
        oid, lo, ll = b"\0" * 16, 0, 0
    tf = dict(codec_id=codec, block_type=block_type, group_id=group[0], group_index=group[1],
              group_k=group[2], group_m=group[3], data_len=data_len, frame_quanta=q,
              object_id=oid, logical_offset=lo, logical_length=ll, frame_ordinal=ordinal,
              hash_payload=b"\0" * 32)
    aad = frame_aad(hdr["flags"], q, trailer(tf, hash_id)[:64])
    stored = nonce + AESGCM(KEYS["frame"]).encrypt(nonce, plain_payload, aad)
    body = nonce + AESGCM(KEYS["pretrailer"]).encrypt(nonce, pt_plain, aad)
    h = hashlib.sha256 if hash_id == 2 else None
    tf["hash_payload"] = h(stored).digest()
    tb = trailer(tf, hash_id)
    assert tb[:64] == trailer(dict(tf, hash_payload=b"\0" * 32), hash_id)[:64]
    size = q * 4096
    pad = size - 16 - data_len - pt_len - 4 - 96
    assert pad >= 0
    frame = (prefix(q) + stored + b"\0" * pad + body +
             struct.pack("<I", crc32c(body + struct.pack("<I", pt_len) + tb)) +
             struct.pack("<I", pt_len) + tb)
    assert len(frame) == size
    return frame, tf


def header(mode, maxq, gen, parity=(0, 0, 0), blobs=4, codec=0):
    return dict(mode=mode, hash_id=2, codec_id=codec, parity_scheme=parity[0], parity_k=parity[1],
                parity_m=parity[2], blob_count=blobs, flags=1, max_frame_quanta=maxq,
                generation_id=gen, archive_id=ARCHIVE_ID.hex())


def pattern(n, seed):
    return bytes((i * 31 + seed) & 0xFF for i in range(n))


frames = []


def frame_case(name, hdr, block_type, codec, plain, logical, entries, q, ordinal, blob, group=(0, 0, 0, 0)):
    fr, tf = build_sealed(hdr, block_type, codec, plain, entries, q, ordinal, blob, group)
    frames.append(dict(name=name, header=hdr, block_type=block_type, codec_id=codec, payload_plain=plain.hex(),
                       logical=logical.hex(), entries=entries, frame_quanta=q, frame_ordinal=ordinal, blob=blob,
                       group=list(group), object_id=tf["object_id"].hex(), hex=fr.hex()))


d = pattern(5000, 3)
frame_case("enc_data_store", header(0, 1024, 5), 0, 0, d, d,
           [dict(path="docs/a.txt", offset=0, length=5000, file_ver=7)], 2, 9, 2)
pk = [dict(path="a", offset=0, length=3, file_ver=10), dict(path="b/c", offset=3, length=0, file_ver=11),
      dict(path="b/d", offset=3, length=10, file_ver=12)]
frame_case("enc_packed_store", header(0, 1024, 0x01020304), 2, 0, b"abc0123456789", b"abc0123456789", pk, 1,
           0x00FFFFFFFFFFFFFF, 254)
z = b"compressible " * 800
zc = zstandard.ZstdCompressor(level=3, write_content_size=True, write_checksum=False).compress(z)
frame_case("enc_data_zstd", header(0, 1024, 0xFFFFFFFF, codec=2), 0, 2, zc, z,
           [dict(path="z/big", offset=8192, length=len(z), file_ver=3)], 1, 0, 0)
frame_case("enc_data_fixed_parity_member", header(1, 3, 1, (2, 2, 2), 4), 0, 0, pattern(100, 5), pattern(100, 5),
           [dict(path="g/x", offset=0, length=100, file_ver=2)], 3, 4, 1, group=(9, 1, 2, 2))
frame_case("enc_data_empty", header(0, 1024, 0), 0, 0, b"", b"",
           [dict(path="empty", offset=0, length=0, file_ver=1)], 1, 0, 0)

nonces = [dict(gen=g, blob=b, ordinal=o, nonce=frame_nonce(g, b, o).hex())
          for g, b, o in [(0, 0, 0), (1, 2, 3), (0xFFFFFFFF, 254, 0x00FFFFFFFFFFFFFF), (0x01020304, 0x05, 0x060708090A0B0C)]]
mnonces = [dict(gen=g, seq=s, nonce=manifest_nonce(g, s).hex())
           for g, s in [(0, 1), (7, 0x0102030405060708), (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)]]
oids = [dict(path=p, file_ver=v, object_id=object_id(p, v).hex())
        for p, v in [("a", 0), ("docs/čtení.txt", 7), ("x" * 4096, 0xFFFFFFFFFFFFFFFF)]]

# manifest envelopes (§15.8): canonical plaintext = fields in listed order + prev
def jstr(s):
    out = '"'
    for ch in s:
        if ch == '"':
            out += '\\"'
        elif ch == '\\':
            out += '\\\\'
        elif ord(ch) < 0x20:
            out += '\\u%04x' % ord(ch)
        else:
            out += ch
    return out + '"'


def loc(b, h, o, l):
    return '[%d,"%s","%d","%d"]' % (b, h, o, l)


GEN = 42
H1, H2 = hashlib.sha256(b"one").hexdigest(), hashlib.sha256(b"two").hexdigest()
TX = "00112233445566778899aabbccddeeff"
records = [
    (3, "ADD", ',"path":%s,"file_ver":"5","loc":[%s]' % (jstr("photos/čtení \"q\".jpg"), loc(1, H1, 0, 4096))),
    (4, "ADD_BEGIN", ',"tx_id":"%s","path":%s,"file_ver":"6"' % (TX, jstr("big"))),
    (9, "ADD_EXTENT", ',"tx_id":"%s","extent_sequence":0,"loc":[%s,%s]' % (TX, loc(0, H1, 0, 4096), loc(2, H2, 4096, 10))),
    (10, "ADD_COMMIT", ',"tx_id":"%s","extent_record_count":1,"extent_count":2' % TX),
    (11, "DEL", ',"path":%s,"file_ver":"5"' % jstr("photos/čtení \"q\".jpg")),
    (12, "ADD_ABORT", ',"tx_id":"%s"' % "ffeeddccbbaa99887766554433221100"),
]
lines = []
prev = hashlib.sha256(ARCHIVE_ID + b"manifest.jsonl").digest()
start = prev
for seq, op, fields in records:
    plain = ("{" + fields[1:] + ',"prev":"%s"}' % prev.hex()).encode()
    opn = op + "_ENC"
    aad = ARCHIVE_ID + struct.pack("<HIQI", VERSION, GEN, seq, len(opn)) + opn.encode()
    n = manifest_nonce(GEN, seq)
    sealed = n + AESGCM(KEYS["manifest"]).encrypt(n, plain, aad)
    line = '{"seq":"%d","op":"%s","enc":"%s"}' % (seq, opn, base64.b64encode(sealed).decode())
    lines.append(dict(seq=seq, op=op, plain=plain.decode(), line=line))
    prev = hashlib.sha256(line.encode()).digest()

with open(os.path.join(ROOT, "internal", "seal", "testdata", "golden.json"), "w") as fh:
    json.dump({"generator": "testdata/gen/gen_golden_m14.py", "dek": DEK.hex(), "archive_id": ARCHIVE_ID.hex(),
               "keys": {k: v.hex() for k, v in KEYS.items()}, "object_ids": oids, "frame_nonces": nonces,
               "manifest_nonces": mnonces, "frames": frames,
               "manifest": dict(generation_id=GEN, chain_start=start.hex(), lines=lines, last_prev=prev.hex())},
              fh, indent=1, ensure_ascii=False)
    fh.write("\n")

# Zstandard (§5.1, §5.1.1)
zcases = []
def zcase(name, data, frame, ok, expected=None):
    zcases.append(dict(name=name, logical=data.hex(), frame=frame.hex(), ok=ok,
                       expected=len(data) if expected is None else expected))

text = (b"STASH zstd golden vector. " * 300) + bytes(range(256)) * 4
for lvl in (1, 3, 9, 19):
    zcase("level%d" % lvl, text, zstandard.ZstdCompressor(level=lvl, write_content_size=True).compress(text), True)
zcase("checksum", text, zstandard.ZstdCompressor(level=3, write_content_size=True, write_checksum=True).compress(text), True)
big = pattern(300000, 1) + b"\0" * 200000
zcase("multi_block", big, zstandard.ZstdCompressor(level=1, write_content_size=True).compress(big), True)
rle = b"\x41" * 100000
zcase("rle", rle, zstandard.ZstdCompressor(level=1, write_content_size=True).compress(rle), True)
good = zstandard.ZstdCompressor(level=3, write_content_size=True).compress(text)
zcase("no_content_size", text, zstandard.ZstdCompressor(level=3, write_content_size=False).compress(text), False)
zcase("wrong_expected", text, good, False, expected=len(text) + 1)
zcase("trailing_bytes", text, good + b"\0", False)
zcase("two_frames", text + text, good + good, False)
zcase("truncated", text, good[:-3], False)
zcase("skippable", text, struct.pack("<II", 0x184D2A50, 4) + b"abcd" + good, False)
zcase("bad_magic", text, b"\x29" + good[1:], False)
fhd = good[4]
zcase("reserved_bit", text, good[:4] + bytes([fhd | 0x08]) + good[5:], False)
# dictionary id: insert a 1-byte Dictionary_ID = 7 after the window descriptor (if any)
did_pos = 5 + (0 if fhd & 0x20 else 1)
zcase("dictionary_id", text, good[:4] + bytes([fhd | 0x01]) + good[5:did_pos] + b"\x07" + good[did_pos:], False)
# without a content checksum a flipped literal can decode to other bytes of
# the right length (hash_payload is what catches that); with one, it fails
corrupt = bytearray(zstandard.ZstdCompressor(level=3, write_content_size=True, write_checksum=True).compress(text))
corrupt[len(corrupt) // 2] ^= 0xFF
zcase("corrupt_block_checksum", text, bytes(corrupt), False)

with open(os.path.join(ROOT, "internal", "compress", "testdata", "golden.json"), "w") as fh:
    json.dump({"generator": "testdata/gen/gen_golden_m14.py", "libzstd": zstandard.ZSTD_VERSION, "cases": zcases}, fh, indent=1)
    fh.write("\n")
print("ok", len(frames), "frames,", len(lines), "envelopes,", len(zcases), "zstd cases")
