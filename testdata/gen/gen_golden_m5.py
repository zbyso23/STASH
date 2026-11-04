#!/usr/bin/env python3
"""Independent golden vectors for manifest records (SPEC §10.1.1, §10.1.2).

The canonical writer form is produced here by hand (no json module for
encoding): keys in the order of §10.1.2, ts last, uint64 as decimal strings,
bounded ints as JSON integers, strings escaping only '"', '\\' and
U+0000..U+001F as lowercase \\u00xx. The Go encoder must reproduce every line
byte for byte, and the Go decoder must accept the "accept" lines (decoding to
the given canonical line) and reject the "reject" lines.
"""
import hashlib, json, os

ORDER = {
    "ADD": ["seq", "op", "path", "file_ver", "loc"],
    "DEL": ["seq", "op", "path", "file_ver"],
    "ADD_BEGIN": ["seq", "op", "tx_id", "path", "file_ver"],
    "ADD_EXTENT": ["seq", "op", "tx_id", "extent_sequence", "loc"],
    "ADD_COMMIT": ["seq", "op", "tx_id", "extent_record_count", "extent_count"],
    "ADD_ABORT": ["seq", "op", "tx_id"],
    "LINK_MANIFEST": ["seq", "op", "path", "hash_id", "hash", "lines"],
    "PARITY_GROUP": ["seq", "op", "group_id", "members"],
}
DEC = {"seq", "file_ver", "lines", "ts"}
INT = {"extent_sequence", "extent_record_count", "extent_count", "hash_id", "group_id"}

def s(v):
    out = ['"']
    for ch in v:
        o = ord(ch)
        if ch in '"\\':
            out.append("\\" + ch)
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)

def enc(rec):
    parts = []
    keys = ORDER[rec["op"]] + (["ts"] if "ts" in rec else [])
    for k in keys:
        v = rec[k]
        if k in DEC:
            val = s(str(v))
        elif k in INT:
            val = str(v)
        elif k == "loc":
            val = "[" + ",".join("[%d,%s,%s,%s]" % (b, s(h), s(str(o)), s(str(l))) for b, h, o, l in v) + "]"
        elif k == "members":
            val = "[" + ",".join("[%d,%s,%d]" % (b, s(h), g) for b, h, g in v) + "]"
        else:
            val = s(v)
        parts.append(s(k) + ":" + val)
    return "{" + ",".join(parts) + "}"

H = [hashlib.sha256(b"frame-%d" % i).hexdigest() for i in range(4)]
TX = "00112233445566778899aabbccddeeff"
MAXU = 18446744073709551615
records = [
    {"seq": 1, "op": "ADD", "path": "db/data.bin", "file_ver": 7, "loc": [[3, H[0], 0, 4194304]]},
    {"seq": 2, "op": "DEL", "path": "db/data.bin", "file_ver": 7},
    {"seq": 3, "op": "ADD", "path": "q\"uo te/é/日本", "file_ver": 8, "loc": [[0, H[1], 0, 0]], "ts": 1730000000000000000},
    {"seq": 100, "op": "ADD_BEGIN", "tx_id": TX, "path": "db/huge.bin", "file_ver": 9},
    {"seq": 101, "op": "ADD_EXTENT", "tx_id": TX, "extent_sequence": 0, "loc": [[0, H[1], 0, 4194304], [1, H[2], 4194304, 4194304]]},
    {"seq": 102, "op": "ADD_COMMIT", "tx_id": TX, "extent_record_count": 2, "extent_count": 3},
    {"seq": 104, "op": "ADD_ABORT", "tx_id": TX},
    {"seq": MAXU, "op": "LINK_MANIFEST", "path": "submanifests/user-data.jsonl", "hash_id": 1, "hash": H[3], "lines": 50000},
    {"seq": 5, "op": "PARITY_GROUP", "group_id": 4294967295, "members": [[0, H[0], 0], [254, H[1], 255]]},
    {"seq": 6, "op": "ADD", "path": "x", "file_ver": MAXU, "loc": [[254, H[2], 18446744073709547520, 4095]]},
]
golden = [{"record": r, "line": enc(r)} for r in records]

base = enc(records[0])
accept = [
    # whitespace, key order, escapes: all valid JSON, decoded to the canonical form
    {"line": ' { "op" : "ADD", "seq":"1" ,\t"path":"db\\/data.bin","file_ver":"7","loc":[[3,"%s","0","4194304"]] } ' % H[0], "canonical": base},
    {"line": '{"seq":"1","op":"ADD","path":"\\u0064b/data.bin","file_ver":"7","loc":[[3,"%s","0","4194304"]]}' % H[0], "canonical": base},
    {"line": '{"seq":"3","op":"ADD","path":"q\\"uo te/\\u00e9/\\u65e5\\u672c","file_ver":"8","loc":[[0,"%s","0","0"]],"ts":"1730000000000000000"}' % H[1], "canonical": golden[2]["line"]},
    {"line": '{"seq":"9","op":"ADD","path":"\\ud83d\\ude00","file_ver":"1","loc":[[0,"%s","0","1"]]}' % H[0],
     "canonical": '{"seq":"9","op":"ADD","path":"\U0001F600","file_ver":"1","loc":[[0,"%s","0","1"]]}' % H[0]},
]

def mut(old, new, src=base):
    assert old in src, old
    return src.replace(old, new, 1)

reject = [
    ("duplicate key", '{"seq":"1","seq":"1","op":"DEL","path":"a","file_ver":"1"}'),
    ("unknown key", '{"seq":"1","op":"DEL","path":"a","file_ver":"1","x":"1"}'),
    ("missing field", '{"seq":"1","op":"DEL","path":"a"}'),
    ("field of other op", '{"seq":"1","op":"DEL","path":"a","file_ver":"1","loc":[]}'),
    ("seq leading zero", mut('"seq":"1"', '"seq":"01"')),
    ("seq number", mut('"seq":"1"', '"seq":1')),
    ("seq empty", mut('"seq":"1"', '"seq":""')),
    ("seq sign", mut('"seq":"1"', '"seq":"+1"')),
    ("seq overflow", mut('"seq":"1"', '"seq":"18446744073709551616"')),
    ("file_ver exponent", mut('"file_ver":"7"', '"file_ver":"7e0"')),
    ("blob string", mut('[[3,', '[["3",')),
    ("blob fraction", mut('[[3,', '[[3.0,')),
    ("blob exponent", mut('[[3,', '[[3e0,')),
    ("blob negative", mut('[[3,', '[[-3,')),
    ("blob 255", mut('[[3,', '[[255,')),
    ("hash uppercase", mut(H[0], H[0].upper())),
    ("hash short", mut(H[0], H[0][:62])),
    ("loc empty", mut('"loc":[[3,"%s","0","4194304"]]' % H[0], '"loc":[]')),
    ("loc arity", mut(',"4194304"]]', ']]')),
    ("offset number", mut('"0","4194304"', '0,"4194304"')),
    ("path absolute", mut('"db/data.bin"', '"/db/data.bin"')),
    ("path dotdot", mut('"db/data.bin"', '"db/../x"')),
    ("path not NFC", mut('"db/data.bin"', '"e\\u0301"')),
    ("path control", mut('"db/data.bin"', '"a\\u0001"')),
    ("lone surrogate", mut('"db/data.bin"', '"\\ud83d"')),
    ("raw control in string", mut('"db/data.bin"', '"a\tb"')),
    ("tx_id uppercase", '{"seq":"1","op":"ADD_ABORT","tx_id":"%s"}' % TX.upper()),
    ("tx_id short", '{"seq":"1","op":"ADD_ABORT","tx_id":"%s"}' % TX[:30]),
    ("extent_sequence string", '{"seq":"1","op":"ADD_EXTENT","tx_id":"%s","extent_sequence":"0","loc":[[0,"%s","0","1"]]}' % (TX, H[0])),
    ("extent_count > u32", '{"seq":"1","op":"ADD_COMMIT","tx_id":"%s","extent_record_count":1,"extent_count":4294967296}' % TX),
    ("link outside submanifests", '{"seq":"1","op":"LINK_MANIFEST","path":"other/x.jsonl","hash_id":1,"hash":"%s","lines":"1"}' % H[0]),
    ("link dir itself", '{"seq":"1","op":"LINK_MANIFEST","path":"submanifests","hash_id":1,"hash":"%s","lines":"1"}' % H[0]),
    ("members empty", '{"seq":"1","op":"PARITY_GROUP","group_id":1,"members":[]}'),
    ("group_index 256", '{"seq":"1","op":"PARITY_GROUP","group_id":1,"members":[[0,"%s",256]]}' % H[0]),
    ("ENC op in plaintext archive", '{"seq":"1","op":"ADD_ENC","enc":"x"}'),
    ("unknown op", '{"seq":"1","op":"RENAME","path":"a","file_ver":"1"}'),
    ("op not string", '{"seq":"1","op":1}'),
    ("top-level array", '[1]'),
    ("trailing comma", '{"seq":"1","op":"DEL","path":"a","file_ver":"1",}'),
    ("trailing data", '{"seq":"1","op":"DEL","path":"a","file_ver":"1"} x'),
    ("BOM", '\ufeff{"seq":"1","op":"DEL","path":"a","file_ver":"1"}'),
    ("single quotes", "{'seq':'1'}"),
    ("ts number", '{"seq":"1","op":"DEL","path":"a","file_ver":"1","ts":5}'),
]
reject_hex = [
    ("invalid UTF-8", ('{"seq":"1","op":"DEL","path":"a\xff","file_ver":"1"}').encode("latin-1").hex()),
    ("overlong UTF-8", (b'{"seq":"1","op":"DEL","path":"\xc0\xaf","file_ver":"1"}').hex()),
    ("encoded surrogate", (b'{"seq":"1","op":"DEL","path":"\xed\xa0\x80","file_ver":"1"}').hex()),
]
out = {"records": golden, "accept": accept,
       "reject": [{"why": w, "hex": l.encode("utf-8").hex()} for w, l in reject] + [{"why": w, "hex": h} for w, h in reject_hex]}
p = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "manifest", "testdata", "golden.json")
os.makedirs(os.path.dirname(p), exist_ok=True)
with open(p, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
    f.write("\n")
print("wrote", os.path.normpath(p), len(golden), "records,", len(accept), "accept,", len(out["reject"]), "reject")
