# STASH
## Version 2.0 — Consolidated Specification
### Revision R1 — Production / Enterprise Hardening

**Status:** Draft — post-review, production-hardening revision  
**Target:** Server / enterprise / datacenter / petabyte-scale storage  
**Out of scope:** General-purpose desktop archive use, tape/cold-storage profiles, sub-block/CDC deduplication

> This revision preserves the original STASH 2.0 priorities: predictable O(1) block geometry, whole-frame bit-identical deduplication, self-describing recovery, and high throughput. It incorporates the identified production gaps around blob headers, packed-frame compression, concurrent compaction, metadata encryption, and Pre-Trailer integrity, plus additional consistency fixes.

---

# 0. Design Priorities

STASH 2.0 makes explicit trade-offs. Implementations MUST preserve these priorities in this order:

1. **Predictable O(1) block geometry** — every frame occupies exactly `frame_size` bytes.
2. **Whole-frame, bit-identical deduplication** — STASH does not deduplicate sub-block content.
3. **Self-describing recovery** — raw frame data MUST contain sufficient information to identify and verify frames without `manifest.jsonl`.
4. **Throughput at enterprise scale** — implementations MAY use established external libraries; the recommended profile is not zero-dependency.

The encryption profile is an explicit exception to priority 3: when metadata encryption is enabled, frame-level recovery remains possible without keys, but reconstruction of plaintext paths and versions requires the appropriate decryption key.

---

# 1. Overview

STASH is an append-only, verifiable archival format for cloud-native and datacenter workflows.

Input data is split into fixed-size frames. A frame contains a compressed payload, optional packed-file metadata, and a fixed 48-byte Master Trailer. Every frame is content-addressed by a cryptographic hash of its stored payload representation.

All frames are immutable. Updates are expressed as new manifest entries and new frames. No frame is overwritten in place.

Data-frame placement is a write-time decision and is not derived from the frame hash. Every frame reference therefore contains both `blob_id` and `frame_hash`.

The physical representation of each blob is:

```text
+-------------------------------+ 0x00
| Archive Header (48 B)         |
+-------------------------------+ 0x30
| Frame 0 (frame_size bytes)    |
+-------------------------------+
| Frame 1 (frame_size bytes)    |
+-------------------------------+
| ...                            |
+-------------------------------+
```

Therefore:

```text
frame_start(blob_id, n) = 0x30 + n * BLOCK_STRIDE
BLOCK_STRIDE = frame_size
blob_size = 48 + frame_count * frame_size
```

The 48-byte blob-header prefix is **not part of `BLOCK_STRIDE`**.

---

# 2. Archive Header

The Archive Header is exactly 48 bytes and MUST be present at offset `0x00` of **every** blob file.

All multi-byte integers are little-endian.

Every copy describes the same logical archive.

## 2.1 Header fields

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | magic | char[4] | `STSH` |
| `0x04` | 2 | version | uint16 | `0x0002` |
| `0x06` | 1 | frame_size_class | uint8 | See §3 |
| `0x07` | 1 | hash_id | uint8 | See §4 |
| `0x08` | 1 | codec_id | uint8 | Archive default; per-frame override allowed |
| `0x09` | 1 | parity_scheme | uint8 | See §7 |
| `0x0A` | 1 | parity_k | uint8 | Data frames per parity group |
| `0x0B` | 1 | parity_m | uint8 | Parity frames per parity group |
| `0x0C` | 1 | blob_count | uint8 | Number of blobs, 1–255 |
| `0x0D` | 3 | reserved | bytes | MUST be zero in 2.0 |
| `0x10` | 32 | archive_id | bytes | Random UUID, zero-padded to 32 bytes |

The header is immutable for the life of the archive.

`frame_size_class`, `hash_id`, `codec_id`, `parity_scheme`, `parity_k`, `parity_m`, and `blob_count` MUST NOT change.

## 2.2 Header redundancy and validation

The repeated header exists specifically to remove `Blob 0` as a single point of failure.

A reader MUST:

1. read and validate the header of each available blob;
2. verify that all available headers agree on immutable archive parameters and `archive_id`;
3. reject the archive as inconsistent if two valid headers disagree;
4. permit operation with a subset of blobs when the missing blobs are unavailable, provided at least one valid header remains.

For a single-blob archive, the header is the sole on-disk source of archive geometry. Implementations SHOULD additionally protect the archive header with the surrounding storage system's integrity mechanism or an external deployment-level checksum.

A corrupted header MUST NOT be silently accepted merely because its `STSH` magic is valid.

---

# 2.3 Blob files

Blob files are named:

```text
frames/blob-00.stash
frames/blob-01.stash
...
frames/blob-FE.stash
```

For `blob_count = N`, valid blob IDs are `0 .. N-1`.

Every blob MUST begin with the 48-byte Archive Header.

Frames in every blob therefore begin at offset `0x30`.

Frame-to-blob assignment is a write-time decision. A writer MAY use round-robin, capacity-aware, or another deterministic/runtime policy.

A conformant implementation MUST ensure that two writers never concurrently allocate the same physical frame position in the same blob. The recommended model is one serialized append position per blob.

The manifest remains a separate serialization domain; see §9.3.

## 2.4 Parity-group spread

When `blob_count > 1`, data and parity frames belonging to one parity group MUST span at least two distinct blobs.

Implementations MUST enforce this rule defensively at the library boundary.

---

# 3. Frame Size Classes

`frame_size_class` selects the total on-disk frame size:

| Value | Size | Value | Size | Value | Size |
|---|---:|---|---:|---|---:|
| `0x00` | 4 KiB | `0x06` | 256 KiB | `0x0C` | 16 MiB |
| `0x01` | 8 KiB | `0x07` | 512 KiB | `0x0D` | 32 MiB |
| `0x02` | 16 KiB | `0x08` | 1 MiB | `0x0E` | 64 MiB |
| `0x03` | 32 KiB | `0x09` | 2 MiB | `0x0F` | 128 MiB |
| `0x04` | 64 KiB | `0x0A` | 4 MiB | `0x10` | 256 MiB |
| `0x05` | 128 KiB | `0x0B` | 8 MiB | | |

All frames in an archive use the same class.

```text
BLOCK_STRIDE = frame_size
```

The frame size is the complete aligned block size, including padding, Pre-Trailer, and Master Trailer.

The usable payload budget is:

```text
payload_budget =
    frame_size
    - 48                         // Master Trailer
    - 4                          // pre_trailer_len
    - pre_trailer_body_size
```

The 48-byte Archive Header at the beginning of a blob is not included in this calculation.

---

# 4. Hash Algorithms

| Value | Algorithm | Digest |
|---|---|---:|
| `0x00` | reserved | — |
| `0x01` | BLAKE3 | 32 B |
| `0x02` | SHA-256 | 32 B |
| `0x03` | SHA3-256 | 32 B |
| `0x04–0xFF` | reserved | — |

The archive's `hash_id` is fixed for its lifetime.

## 4.1 Hash scope

`hash_payload` MUST be calculated over the exact bytes stored in the frame's payload region, before padding and before the Pre-Trailer and Master Trailer are appended.

In the normal unencrypted case this is `compressed_payload`.

In encrypted mode this is the encrypted payload representation, including its nonce/AEAD overhead as specified in §15.1.

The hash MUST NOT cover:

- zero padding;
- Pre-Trailer;
- Master Trailer;
- the blob's Archive Header.

This makes whole-frame deduplication dependent on byte-identical stored payloads.

---

# 5. Compression Codecs

| Value | Codec |
|---|---|
| `0x00` | STORE |
| `0x01` | LZ4 |
| `0x02` | Zstd |
| `0x03` | LZMA |
| `0x04` | Brotli |
| `0x05–0xFF` | reserved |

`codec_id` in the Archive Header is the default and MAY be overridden per frame.

## 5.1 Canonical compression parameters

A codec identifier alone is insufficient to guarantee byte-identical output across different codec versions or settings.

Therefore, for frames intended to be reproducibly deduplicated across independent writers, the implementation MUST use a documented **canonical parameter profile** for the selected codec.

For the default Zstd profile, the STASH reference implementation MUST publish the exact compression level and relevant deterministic parameters used for archive creation.

Two implementations MAY produce different compressed bytes when using different valid codec profiles; such frames remain valid STASH frames but will not deduplicate.

The manifest and frame format do not assume that compression is globally reproducible merely from the codec name.

---

# 6. Frame Binary Layout

All multi-byte integers are little-endian.

Each frame occupies exactly `frame_size` bytes.

```text
[ compressed_payload / encrypted_payload ]
[ zero padding ]
[ pre_trailer_body ]
[ pre_trailer_len : uint32 LE ]
[ Master Trailer : 48 B ]
```

The Master Trailer is always the last 48 bytes of the frame.

---

# 6.1 Master Trailer

| Offset | Size | Field | Description |
|---|---:|---|---|
| `0x00` | 4 | magic | `STSH` |
| `0x04` | 2 | version | `0x0002` |
| `0x06` | 1 | hash_id | Must match Archive Header |
| `0x07` | 1 | codec_id | Codec used for this frame |
| `0x08` | 1 | block_type | `0 = DATA`, `1 = PARITY` |
| `0x09` | 3 | reserved | MUST be zero |
| `0x0C` | 4 | data_len | Exact stored payload length |
| `0x10` | 32 | hash_payload | Hash of stored payload |

`data_len` MUST satisfy:

```text
0 <= data_len <= frame_size - 48 - 4
```

and MUST leave enough room for the Pre-Trailer.

For a DATA frame, the payload and metadata MUST describe at least one logical file unless the frame is otherwise explicitly defined as an implementation-reserved empty frame. Empty unused frames MUST NOT be committed as valid archive frames.

---

# 6.2 Pre-Trailer

The Pre-Trailer is:

```text
[ pre_trailer_body ][ pre_trailer_len : uint32 LE ]
```

`pre_trailer_len` is the exact byte length of `pre_trailer_body`.

In unencrypted mode, `pre_trailer_body` is:

```text
uint32 entry_count
repeated entry_count times:
    varint path_len
    bytes path
    uint64 inner_off
    uint64 inner_len
    uint64 file_ver
uint32 crc32c
```

`crc32c` is the final four bytes of the body.

### 6.2.1 CRC coverage

The CRC32C MUST cover **all bytes of `pre_trailer_body` preceding the CRC field, including `entry_count` and every entry**.

The CRC does not cover `pre_trailer_len`, because that field lies outside the body.

The reader MUST:

1. read the Master Trailer;
2. read the 4-byte `pre_trailer_len`;
3. validate that the length is within the frame's hard bounds;
4. calculate the exact start of the body;
5. read the complete body;
6. verify CRC32C;
7. only after successful CRC verification parse and trust the entries.

A reader MUST NOT trust `entry_count`, paths, offsets, or versions from an unverified body.

### 6.2.2 Packed entry semantics

`inner_off` and `inner_len` refer to the **logical uncompressed packed buffer**, not to offsets in the compressed byte stream.

This is mandatory.

For a packed frame:

```text
logical_buffer =
    file(path_1) || file(path_2) || ... || file(path_n)
```

After compression, the logical buffer is represented by the frame's stored payload, but its internal offsets remain offsets in the uncompressed logical buffer.

Consequently, extraction of one packed file requires decompression of the frame payload.

This resolves the otherwise impossible situation in which arbitrary file offsets would be expected to remain directly addressable inside a compressed whole-frame stream.

### 6.2.3 Limits

Normative limits:

- `MAX_PACKED_ENTRIES = 65535`
- `path_len <= 4096` bytes
- `MIN_PAYLOAD_RESERVE = 64` bytes

The maximum Pre-Trailer body size is:

```text
max_pre_trailer_total =
    frame_size
    - 48
    - 4
    - MIN_PAYLOAD_RESERVE
```

A writer MUST enforce this incrementally while packing.

---

# 6.3 Deterministic reverse parsing

Required algorithm:

1. `block_end = block_start + frame_size`
2. read the last 48 bytes as Master Trailer;
3. validate Master Trailer magic/version/fields;
4. read `pre_trailer_len` from `block_end - 48 - 4`;
5. validate `pre_trailer_len` against the hard maximum;
6. compute:

```text
pre_trailer_body_start =
    block_end - 48 - 4 - pre_trailer_len
```

7. verify that the body does not overlap the stored payload;
8. read the body;
9. verify CRC32C;
10. only then parse entries;
11. `compressed_payload` / encrypted payload is:

```text
[block_start, block_start + data_len)
```

Everything between `data_len` and `pre_trailer_body_start` MUST be zero padding.

---

# 7. Parity / Erasure Coding

| Value | Scheme | Tolerance |
|---|---|---:|
| `0x00` | none | 0 |
| `0x01` | XOR | 1 frame/group |
| `0x02` | Reed-Solomon | `parity_m` frames/group |
| `0x03` | LRC | tunable; EXPERIMENTAL |

The scheme and parameters are fixed at archive creation.

Mixing parity schemes inside one archive is not supported.

A parity group is closed only after its required data frames are known. Data frames remain readable before the group is closed.

Parity frames MUST be written only after the corresponding group membership is fixed.

---

# 7.1 Parity frame identity

A parity frame has `block_type = PARITY`.

Parity payload identity is the exact stored parity payload bytes, and `hash_payload` is calculated over those bytes.

The manifest records:

```json
{
  "op": "PARITY_GROUP",
  "group_id": 42,
  "data_frames": [["00", "hash1"], ["03", "hash2"]],
  "parity_frames": [["07", "phash1"]]
}
```

Each reference is `[blob_id, frame_hash]`.

---

# 8. Frame Packing

Frame Packing aggregates small files into one DATA frame.

## 8.1 Packing order

Files MUST be sorted lexicographically by normalized UTF-8 path before packing.

The writer constructs:

```text
logical_buffer =
    file_1_bytes || file_2_bytes || ... || file_n_bytes
```

The complete logical buffer is then compressed using the frame's selected `codec_id`.

The stored payload is therefore:

```text
compressed_payload = CODEC(logical_buffer)
```

The frame hash is calculated over the resulting stored payload.

This allows Frame Packing to use Zstd or another archive-wide codec and preserves whole-frame deduplication.

## 8.2 Packing fit algorithm

Because compressed size is not known from the uncompressed input size, a writer MUST NOT assume that a candidate packed set fits merely because its logical input size fits.

A compliant writer SHOULD use:

1. accumulate candidate files;
2. build the candidate logical buffer;
3. compress it using the selected canonical codec profile;
4. calculate the resulting stored payload size;
5. if the candidate fits, continue;
6. if it does not fit, seal the previous candidate frame and start a new frame with the file that did not fit.

If a single file cannot fit into one frame after compression and packing metadata overhead, it MUST be handled by the normal multi-frame large-file path rather than forced into Frame Packing.

A writer MUST never produce a frame whose `data_len`, Pre-Trailer, and padding exceed `frame_size`.

## 8.3 Packed frame determinism

Identical input sets produce byte-identical packed frames only when all of the following are identical:

- normalized paths;
- path ordering;
- file contents;
- file versions;
- codec;
- canonical codec parameters;
- packing rules.

The specification does not claim cross-implementation byte identity merely from equal logical input.

---

# 9. Manifest

`manifest.jsonl` is an append-only logical journal.

The manifest is authoritative for current path state. Frame data remains immutable.

## 9.1 Record types

Example:

```json
{"seq":1,"ts":1739550001,"op":"ADD","path":"src/main.go","ver":2,"loc":[["00","f5a2b1c3...",0,4096]]}
{"seq":2,"ts":1739550002,"op":"ADD","path":"big/dataset.bin","ver":1,"loc":[["03","aaa111...",0,67108864],["11","bbb222...",0,33554432]]}
{"seq":3,"ts":1739550123,"op":"DEL","path":"src/utils.go","ver":2}
```

`seq` is a strictly increasing manifest sequence number.

`ts` is informational and MUST NOT be used to determine logical ordering.

## 9.2 Version semantics

`ver` is a per-path monotonically increasing version.

Writers MUST serialize updates to the same manifest so that two operations cannot commit the same `(path, ver)` as competing current states.

A replacement is committed by appending a new ADD with the next version.

## 9.3 Manifest write serialization

Data-frame writes MAY occur concurrently.

Append operations to one manifest MUST be serialized through one logical manifest writer.

The implementation MAY realize this through:

- a local process lock;
- a distributed lease/lock;
- a dedicated manifest-writer service;
- per-writer delta logs followed by ordered merge.

What matters at the format boundary is that each manifest record is appended as one complete logical record with a unique `seq`.

The format MUST NOT assume that arbitrary concurrent `write()` calls to the same JSONL file are atomically line-preserving.

---

# 9.4 Manifest references

`loc` is:

```text
[blob_id, frame_hash, inner_offset, inner_length]
```

For packed files, `inner_offset` and `inner_length` are offsets into the uncompressed logical packed buffer.

For a file spanning multiple frames, one tuple is emitted per frame.

---

# 9.5 Manifest corruption

A malformed or truncated JSONL record MUST NOT be treated as a valid update.

Readers MUST detect at least:

- invalid JSON;
- missing required fields;
- invalid operation;
- invalid `blob_id`;
- invalid frame-hash length;
- invalid version ordering;
- invalid `loc` structure.

An incomplete final line MAY be treated as an uncommitted append and ignored during recovery, provided the implementation can prove that the line was not fully committed.

Deployments requiring cryptographic manifest tamper detection SHOULD maintain a signed or cryptographically hashed manifest checkpoint/segment layer. This is outside the immutable frame format.

---

# 10. Manifest Scaling

## 10.1 Reverse scanning

Readers MUST support reverse chunked scanning of `manifest.jsonl`.

A checkpoint MAY accelerate startup.

A checkpoint is never authoritative if it disagrees with the manifest tail.

## 10.2 Sharding

`LINK_MANIFEST` MAY reference independently operated sub-manifests.

Each linked manifest MUST be independently verifiable by its declared hash algorithm and hash.

A sub-manifest is an operational scaling boundary, not a change to frame geometry.

---

# 11. Disaster Recovery — Hop-and-Read

If the manifest is lost:

1. For every available blob, read its Archive Header at `0x00`.
2. Validate header consistency and obtain `frame_size`.
3. Start scanning frames at offset `0x30`.
4. Advance exactly `BLOCK_STRIDE = frame_size`.
5. Read the 48-byte Master Trailer at the end of each frame.
6. Validate the frame trailer and `data_len`.
7. Verify `hash_payload` against the stored payload bytes when integrity verification is required.
8. For DATA frames, reverse-parse the Pre-Trailer and verify its CRC32C before trusting entries.
9. For PARITY frames, record parity identity and group relationships.
10. Emit recovered ADD mappings for plaintext metadata frames.
11. If encryption is active, metadata reconstruction requires the relevant decryption key; without it, frame-level inventory and payload hashes remain recoverable but plaintext path mappings do not.

The scan is:

```text
blob_start = 0x30
frame_n_start = 0x30 + n * frame_size
```

No payload scanning is necessary to locate frame boundaries.

---

# 12. Reference Implementation — Go

Recommended dependencies:

| Function | Package |
|---|---|
| BLAKE3 | `zeebo/blake3` or equivalent |
| SHA-256 | `crypto/sha256` |
| SHA3-256 | `crypto/sha3` |
| Zstd/LZ4/Brotli | `klauspost/compress` |
| Reed-Solomon | `klauspost/reedsolomon` |
| CRC32C | Go `hash/crc32` with Castagnoli |
| Binary encoding | `encoding/binary` |

The reference implementation SHOULD:

- reuse frame-sized buffers;
- avoid exposing unsealed packed frames;
- serialize append position per blob;
- serialize manifest commits;
- fsync durable frame data before manifest commit;
- fsync manifest data before reporting the manifest record committed;
- benchmark Reed-Solomon on target hardware.

## 12.1 Durability ordering

A frame MUST NOT become referenced by a committed manifest record before its complete frame bytes are durably persisted.

Recommended order:

```text
write frame
→ flush/fsync blob
→ append manifest record
→ flush/fsync manifest
→ report commit
```

For object storage, the implementation MUST use the storage provider's equivalent durability/commit primitive.

This ordering prevents a crash from producing a manifest that references a frame whose data was never durably committed.

---

# 13. Compaction / Garbage Collection

Compaction uses Mark → Sweep → Freeze/Merge → Switch.

## 13.1 Mark

Build the live frame set from the current manifest state, including reachable linked manifests.

## 13.2 Sweep

Copy live frames into a new generation of blob files.

Old blobs MUST NOT be modified in place.

Frames are copied byte-for-byte whenever possible; compaction does not need to decompress, recompress, or re-encrypt live frames.

## 13.3 Concurrent writes during Sweep

Active writers MAY continue while Sweep is running.

All writes occurring after the compaction snapshot MUST be identifiable as a manifest tail.

The implementation MUST choose one of these mechanisms:

### A. Delta manifest

Writers append to a delta manifest while Sweep runs.

At freeze time, the compactor:

1. stops accepting new manifest commits briefly;
2. drains/finalizes the delta;
3. merges the delta onto the compacted snapshot;
4. verifies that all resulting `loc` references exist;
5. writes the final manifest;
6. atomically switches the root pointer.

### B. Manifest lock

The compactor may instead use an exclusive manifest lock.

Writers may continue during Sweep but MUST be blocked during the final Freeze/Merge/Switch interval.

The lock MUST cover the complete state transition so that no writer can commit against the old root after the new root has become authoritative.

A distributed lock/lease is required when multiple machines can write the same manifest and no single manifest-writer service is used.

## 13.4 Switch

The new generation MUST be fully written and verified before becoming authoritative.

The switch MUST be atomic at the root-pointer level.

Recommended model:

```text
root.current
    ↓
generation-00042/
    ├── manifest.jsonl
    └── frames/
```

Write the new generation completely, fsync it, then atomically replace the small root pointer.

The old generation MUST remain intact until the switch is confirmed durable.

Only then may garbage collection delete the old generation.

## 13.5 Crash cases

- Crash during Sweep: old generation remains authoritative.
- Crash during Merge: retry from old generation.
- Crash before root switch: old generation remains authoritative.
- Crash after root switch but before deletion: new generation is authoritative; old generation is garbage.
- Crash during garbage deletion: restart garbage collection; do not roll back the new root.

This makes compaction restartable and prevents a partially copied blob set from being referenced by the old manifest.

---

# 14. Legacy v1.21

v1.21 standalone `.sf` files and `SUB` records are not valid 2.0 syntax.

Migration tooling MAY read v1.21 and produce a valid 2.0 archive.

---

# 15. Out of Scope

The following are not required for the base 2.0 profile:

- desktop/edge profiles;
- tape-specific optimization;
- sub-block/CDC deduplication;
- conflict resolution;
- implementation-specific KMS APIs.

Encryption is defined below as a normative interoperable profile.

---

# 15.1 Encryption — Normative Enterprise Profile

When encryption is enabled, STASH MUST protect both data and sensitive frame metadata.

The following MUST NOT remain plaintext in `manifest.jsonl`:

- `path`;
- `ver`;
- plaintext file metadata derived from those fields.

The following remain plaintext in the binary frame:

- Archive Header;
- Master Trailer;
- `pre_trailer_len`.

The following are encrypted:

- payload;
- Pre-Trailer body.

## 15.1.1 AEAD

The reference profile uses an authenticated encryption construction such as AES-256-GCM.

A frame contains an encrypted payload representation:

```text
payload_ciphertext =
    nonce || AEAD(ciphertext, tag)
```

The nonce MUST be unique for a given encryption key.

`hash_payload` is calculated over the complete stored encrypted representation, including the nonce and authentication tag.

The Pre-Trailer body uses an independently unique nonce and is encrypted as one AEAD message.

## 15.1.2 Envelope encryption

A deployment uses:

```text
KEK / KMS key
      ↓
wrapped DEK
      ↓
archive DEK
      ↓
per-frame AEAD keys/nonces
```

The wrapped DEK and key identifier are deployment metadata and MUST NOT be embedded into the fixed 48-byte frame trailer.

A deployment MAY store the envelope in a protected archive metadata object or KMS-backed configuration.

## 15.1.3 Encrypted Pre-Trailer parsing

`pre_trailer_len` remains plaintext so reverse parsing stays O(1).

After locating the encrypted body, a reader:

1. reads the encrypted Pre-Trailer body;
2. authenticates/decrypts it;
3. verifies its internal CRC32C if retained by the selected profile;
4. only then parses `entry_count` and entries.

An authentication failure MUST cause the metadata to be treated as corrupt.

## 15.1.4 Encryption and disaster recovery

Encryption changes the meaning of "self-describing recovery":

- frame boundaries remain recoverable without keys;
- frame hashes remain verifiable without keys;
- frame type and stored payload length remain visible;
- plaintext paths, versions, and packed-file mappings require the decryption key.

This limitation is explicit and normative.

## 15.1.5 Encryption and deduplication

Because the encrypted payload is hashed, deduplication requires identical ciphertext.

Therefore the implementation MUST NOT use a fresh random encryption key for every logically identical payload if cross-writer deduplication is required.

A deployment that requires convergent deduplication MUST use a documented deterministic key/nonce derivation design with an appropriate security analysis.

Otherwise, encryption remains semantically secure but naturally defeats cross-instance whole-frame deduplication.

---

# 16. Normative Invariants

A conformant STASH 2.0 implementation MUST preserve all of the following:

1. Every blob starts with the same 48-byte Archive Header.
2. The first frame in every blob begins at `0x30`.
3. `BLOCK_STRIDE == frame_size`.
4. Frame boundaries are `0x30 + n * frame_size`.
5. Frame hashes cover stored payload bytes only.
6. Padding is zero-filled and excluded from hashes.
7. Pre-Trailer integrity is checked before metadata is trusted.
8. Packed-file offsets refer to the uncompressed logical packed buffer.
9. Packed files are sorted lexicographically by normalized path.
10. Packed-frame compression is permitted and uses the frame's codec.
11. Codec settings used for reproducible deduplication MUST be canonical and documented.
12. Data-frame writes may be parallel, but each blob append position is serialized.
13. Manifest commits are serialized and have strictly increasing `seq`.
14. A manifest MUST NOT reference a frame before that frame is durably committed.
15. Compaction MUST never overwrite the active generation in place.
16. Compaction MUST provide a concurrency-safe Freeze/Merge/Switch operation.
17. Root-generation switching MUST be atomic.
18. Encryption protects both payload and sensitive Pre-Trailer metadata.
19. In encrypted mode, plaintext path/version data MUST NOT appear in the manifest.
20. Without encryption keys, encrypted archives remain frame-recoverable but not path-reconstructable.

---

# 17. Production Readiness Checklist

Before calling an implementation production-ready, verify:

- [ ] All blobs contain valid identical headers.
- [ ] `BLOCK_STRIDE` is exactly `frame_size`.
- [ ] Frame offsets start at `0x30`.
- [ ] Header disagreement is detected.
- [ ] Frame hashes are calculated over stored payload bytes.
- [ ] Zstd parameters are canonical and documented.
- [ ] Packed-frame compression is tested with incompressible and highly compressible data.
- [ ] Packed offsets are tested after decompression.
- [ ] CRC32C corruption tests cover `entry_count`, paths, offsets, versions, and CRC itself.
- [ ] Manifest append serialization is tested under concurrency.
- [ ] Blob append allocation is tested under concurrency.
- [ ] Frame durability precedes manifest durability.
- [ ] Compaction is tested with continuous concurrent writes.
- [ ] Crash injection is tested at every Switch boundary.
- [ ] Old generations remain readable after interrupted compaction.
- [ ] Encrypted metadata cannot leak paths or versions.
- [ ] AEAD nonce uniqueness is enforced.
- [ ] Key loss is explicitly tested as a recoverability boundary.
- [ ] Disaster recovery is tested with Blob 0 missing.
- [ ] Disaster recovery is tested with an arbitrary non-zero blob missing.
- [ ] Disaster recovery is tested with corrupted Pre-Trailer metadata.
- [ ] Disaster recovery is tested with corrupted frame payloads and available parity.
