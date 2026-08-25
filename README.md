# STASH

## Version 2.0 — Consolidated Specification
### Revision R2 — Production / Enterprise Hardening (Final)

**Status:** Approved Specification
**Target:** Server / enterprise / datacenter / petabyte-scale storage
**Out of scope:** General-purpose desktop archive use, tape/cold-storage profiles, sub-block/CDC deduplication

Note: R2 closes the remaining self-description gaps identified in the R1 production review: parity-group membership is now recoverable from raw frames alone, multi-frame fragment ordering is unambiguous, encrypted manifest records have a concrete wire format, and AEAD nonce construction is deterministic and collision-free at archive scale.

---

## 0. Design Priorities

Implementations MUST preserve these priorities in this order:

1. **Predictable O(1) block geometry** — every frame occupies exactly `frame_size` bytes.
2. **Whole-frame, bit-identical deduplication** — STASH does not deduplicate sub-block content.
3. **Self-describing recovery** — raw frame data MUST contain sufficient information to identify, order, and verify frames without `manifest.jsonl`.
4. **Throughput at enterprise scale** — non-zero-dependency profile utilizing optimized SIMD/hardware-accelerated libraries.

The encryption profile is an explicit exception to priority 3: when metadata encryption is enabled, frame-level recovery (including parity-group reconstruction and fragment ordering) remains possible without keys, but reconstruction of plaintext paths and versions requires the appropriate decryption key.

---

## 1. Overview

STASH is an append-only, verifiable archival format for cloud-native and datacenter workflows.

Input data is split into fixed-size frames. A frame contains a compressed payload, optional packed-file metadata, and a fixed 48-byte Master Trailer. Every frame is content-addressed by a cryptographic hash of its stored payload representation.

All frames are immutable. Updates are expressed as new manifest entries and new frames. No frame is overwritten in place.

Data-frame placement is a write-time decision and is not derived from the frame hash. Every frame reference therefore contains both `blob_id` and `frame_hash`.

The physical representation of each blob is:

```
+-------------------------------+ 0x00
| Archive Header (48 B)         |
+-------------------------------+ 0x30
| Frame 0 (frame_size bytes)    |
+-------------------------------+
| Frame 1 (frame_size bytes)    |
+-------------------------------+
| ...                           |
+-------------------------------+
```

Therefore:

```
frame_start(blob_id, n) = 0x30 + n * BLOCK_STRIDE
BLOCK_STRIDE = frame_size
blob_size = 48 + frame_count * frame_size
```

The 48-byte blob-header prefix is **not part of `BLOCK_STRIDE`**.

---

## 2. Archive Header

The Archive Header is exactly 48 bytes and MUST be present at offset `0x00` of **every** blob file.

All multi-byte integers are little-endian.

Every copy describes the same logical archive.

### 2.1 Header fields

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

### 2.2 Header redundancy and validation

The repeated header exists specifically to remove Blob 0 as a single point of failure.

A reader MUST:

- read and validate the header of each available blob;
- verify that all available headers agree on immutable archive parameters and `archive_id`;
- reject the archive as inconsistent if two valid headers disagree;
- permit operation with a subset of blobs when the missing blobs are unavailable, provided at least one valid header remains.

For a single-blob archive, the header is the sole on-disk source of archive geometry. Implementations SHOULD additionally protect the archive header with the surrounding storage system's integrity mechanism or an external deployment-level checksum.

A corrupted header MUST NOT be silently accepted merely because its `STSH` magic is valid.

### 2.3 Blob files

Blob files are named:

```
frames/blob-00.stash
frames/blob-01.stash
...
frames/blob-FE.stash
```

For `blob_count = N`, valid blob IDs are `0 .. N-1`.

Every blob MUST begin with the 48-byte Archive Header. Frames in every blob therefore begin at offset `0x30`.

Frame-to-blob assignment is a write-time decision. A writer MAY use round-robin, capacity-aware, or another deterministic/runtime policy.

A conformant implementation MUST ensure that two writers never concurrently allocate the same physical frame position in the same blob. The recommended model is one serialized append position per blob.

The manifest remains a separate serialization domain; see §9.3.

### 2.4 Parity-group spread

When `blob_count > 1`, data and parity frames belonging to one parity group MUST span at least two distinct blobs.

Implementations MUST enforce this rule defensively at the library boundary.

### 2.5 Global Parity Invariant

**Normative rule (R2):** if `parity_scheme != 0x00` (none), then `blob_count MUST be >= 2`. A configuration with active parity on a single blob is invalid and MUST be rejected by the implementation at archive initialization.

This closes the gap where a single-blob archive could otherwise declare a parity scheme it can never structurally satisfy under §2.4.

---

## 3. Frame Size Classes

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

```
BLOCK_STRIDE = frame_size
```

The frame size is the complete aligned block size, including padding, Pre-Trailer, and Master Trailer.

The usable payload budget is:

```
payload_budget =
    frame_size
  - 48   // Master Trailer
  - 4    // pre_trailer_len
  - pre_trailer_body_size
```

The 48-byte Archive Header at the beginning of a blob is not included in this calculation.

---

## 4. Hash Algorithms

| Value | Algorithm | Digest |
|---|---|---:|
| `0x00` | reserved | — |
| `0x01` | BLAKE3 | 32 B |
| `0x02` | SHA-256 | 32 B |
| `0x03` | SHA3-256 | 32 B |
| `0x04–0xFF` | reserved | — |

The archive's `hash_id` is fixed for its lifetime.

### 4.1 Hash scope

`hash_payload` MUST be calculated over the exact bytes stored in the frame's payload region, before padding and before the Pre-Trailer and Master Trailer are appended.

In the normal unencrypted case this is `compressed_payload`. In encrypted mode this is the encrypted payload representation, including its nonce/AEAD overhead as specified in §15.1.

The hash MUST NOT cover:

- zero padding;
- Pre-Trailer;
- Master Trailer;
- the blob's Archive Header.

This makes whole-frame deduplication dependent on byte-identical stored payloads.

---

## 5. Compression Codecs

| Value | Codec |
|---|---|
| `0x00` | STORE |
| `0x01` | LZ4 |
| `0x02` | Zstd |
| `0x03` | LZMA |
| `0x04` | Brotli |
| `0x05–0xFF` | reserved |

`codec_id` in the Archive Header is the default and MAY be overridden per frame.

### 5.1 Canonical compression parameters

A codec identifier alone is insufficient to guarantee byte-identical output across different codec versions or settings. Therefore, for frames intended to be reproducibly deduplicated across independent writers, the implementation MUST use a documented **canonical parameter profile** for the selected codec.

For the default Zstd profile, the STASH reference implementation MUST publish the exact compression level and relevant deterministic parameters used for archive creation.

Two implementations MAY produce different compressed bytes when using different valid codec profiles; such frames remain valid STASH frames but will not deduplicate.

The manifest and frame format do not assume that compression is globally reproducible merely from the codec name.

### 5.2 Canonical parameters — all codecs (R2)

**Normative rule:** the canonical-parameter-profile requirement of §5.1 applies symmetrically to every supported codec (LZ4, LZMA, Brotli), not only Zstd. Each implementation MUST document and fix the exact compression level and deterministic parameters for every codec it enables for archive creation, so that byte-identical deduplication is achievable regardless of which codec is in use.

---

## 6. Frame Binary Layout

All multi-byte integers are little-endian.

Each frame occupies exactly `frame_size` bytes.

```
[ compressed_payload / encrypted_payload ]
[ zero padding ]
[ pre_trailer_body ]
[ pre_trailer_len : uint32 LE ]
[ Master Trailer : 48 B ]
```

The Master Trailer is always the last 48 bytes of the frame.

### 6.1 Master Trailer

R2 replaces the 3 reserved bytes at `0x09` with explicit parity-group self-description fields, so that parity-group membership is recoverable directly from a frame scan without `manifest.jsonl`.

| Offset | Size | Field | Description |
|---|---:|---|---|
| `0x00` | 4 | magic | `STSH` |
| `0x04` | 2 | version | `0x0002` |
| `0x06` | 1 | hash_id | Must match Archive Header |
| `0x07` | 1 | codec_id | Codec used for this frame |
| `0x08` | 1 | block_type | `0 = DATA`, `1 = PARITY` |
| `0x09` | 1 | group_index | Position of this frame within its parity group (`0 .. k+m-1`). `0` if the frame belongs to no parity group. |
| `0x0A` | 2 | group_id | uint16. Unique parity-group ID within the archive. `0` if the frame belongs to no parity group. |
| `0x0C` | 4 | data_len | Exact stored payload length |
| `0x10` | 32 | hash_payload | Hash of stored payload |

`data_len` MUST satisfy the exact bound:

```
0 <= data_len <= frame_size - 48 - 4 - pre_trailer_body_size
```

i.e. `data_len` MUST NOT exceed `payload_budget` as defined in §3. A frame violating this bound, on either write or read, MUST be treated as corrupted — this is a hard structural check, not merely advisory headroom.

For a DATA frame, the payload and metadata MUST describe at least one logical file unless the frame is otherwise explicitly defined as an implementation-reserved empty frame. Empty unused frames MUST NOT be committed as valid archive frames.

`group_id` values are scoped to the archive, not to a blob; a reader reconstructing parity groups from a raw scan groups frames purely by matching `group_id` across all blobs, using `group_index` to determine each frame's position (data slots `0..k-1`, parity slots `k..k+m-1`, or an implementation-defined ordering that MUST be documented and consistent archive-wide).

### 6.2 Pre-Trailer

The Pre-Trailer is:

```
[ pre_trailer_body ][ pre_trailer_len : uint32 LE ]
```

`pre_trailer_len` is the exact byte length of `pre_trailer_body`.

In unencrypted mode, `pre_trailer_body` is:

```
uint32 entry_count
repeated entry_count times:
    varint  path_len
    bytes   path
    uint64  inner_off
    uint64  inner_len
    uint64  file_ver
uint32 crc32c
```

`crc32c` is the final four bytes of the body.

#### 6.2.1 CRC coverage

The CRC32C MUST cover **all bytes of `pre_trailer_body` preceding the CRC field, including `entry_count` and every entry**.

The CRC does not cover `pre_trailer_len`, because that field lies outside the body.

The reader MUST:

- read the Master Trailer;
- read the 4-byte `pre_trailer_len`;
- validate that the length is within the frame's hard bounds;
- calculate the exact start of the body;
- read the complete body;
- verify CRC32C;
- only after successful CRC verification parse and trust the entries.

A reader MUST NOT trust `entry_count`, paths, offsets, or versions from an unverified body.

#### 6.2.2 Entry offset semantics (R2 — unified)

R2 removes the prior ambiguity between packed and non-packed multi-frame files by defining `inner_off` / `inner_len` per case:

**Packed frames (§8):** `inner_off` and `inner_len` refer to the **logical uncompressed packed buffer** of that frame — offset and length of one packed file within the decompressed concatenation of all files packed into this frame.

```
logical_buffer =
    file(path_1) || file(path_2) || ... || file(path_n)
```

After compression, the logical buffer is represented by the frame's stored payload, but its internal offsets remain offsets in the uncompressed logical buffer. Extraction of one packed file therefore requires decompression of the frame payload.

**Non-packed / multi-frame files:** when a single large file spans more than one frame, `inner_off` is the **global byte offset of this fragment within the complete logical file**, and `inner_len` is the size of the fragment stored in this frame. This is the same value in both the frame's own embedded Pre-Trailer entry and the corresponding manifest `loc` tuple (§9.4) — the two MUST NOT diverge.

This unified semantics is what makes fragment reassembly self-describing: Hop-and-Read (§11) can reconstruct a multi-frame file purely by scanning frames for matching `path` + `file_ver` and sorting by ascending `inner_off`, without consulting the manifest.

#### 6.2.3 Limits

Normative limits:

- `MAX_PACKED_ENTRIES = 65535`
- `path_len <= 4096` bytes
- `MIN_PAYLOAD_RESERVE = 64` bytes

The maximum Pre-Trailer body size is:

```
max_pre_trailer_total =
    frame_size
  - 48
  - 4
  - MIN_PAYLOAD_RESERVE
```

A writer MUST enforce this incrementally while packing.

### 6.3 Deterministic reverse parsing

Required algorithm:

- `block_end = block_start + frame_size`
- read the last 48 bytes as Master Trailer;
- validate Master Trailer magic/version/fields;
- read `pre_trailer_len` from `block_end - 48 - 4`;
- validate `pre_trailer_len` against the hard maximum;
- compute:

```
pre_trailer_body_start =
    block_end - 48 - 4 - pre_trailer_len
```

- verify that the body does not overlap the stored payload;
- read the body;
- verify CRC32C;
- only then parse entries;
- `compressed_payload` / encrypted payload is:

```
[block_start, block_start + data_len)
```

Everything between `data_len` and `pre_trailer_body_start` MUST be zero padding.

---

## 7. Parity / Erasure Coding

| Value | Scheme | Tolerance |
|---|---|---:|
| `0x00` | none | 0 |
| `0x01` | XOR | 1 frame/group |
| `0x02` | Reed-Solomon | `parity_m` frames/group |
| `0x03` | LRC | tunable; EXPERIMENTAL |

The scheme and parameters are fixed at archive creation. Mixing parity schemes inside one archive is not supported.

A parity group is closed only after its required data frames are known. Data frames remain readable before the group is closed. Parity frames MUST be written only after the corresponding group membership is fixed.

### 7.1 Parity frame identity (R2 — self-describing)

A parity frame has `block_type = PARITY`.

Parity payload identity is the exact stored parity payload bytes, and `hash_payload` is calculated over those bytes.

As of R2, every DATA and PARITY frame belonging to a parity group self-describes its group membership via `group_id` and `group_index` in its own Master Trailer (§6.1). A reader performing disaster recovery can therefore reconstruct full group membership by scanning all available blobs and bucketing frames by `group_id`, without needing the manifest.

The manifest MAY still additionally record a `PARITY_GROUP` entry as an operational/management convenience (e.g. for tooling that wants group membership without a full blob scan), but this record is no longer load-bearing for recovery:

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

## 8. Frame Packing

Frame Packing aggregates small files into one DATA frame.

### 8.1 Packing order

Files MUST be sorted lexicographically by normalized UTF-8 path before packing.

The writer constructs:

```
logical_buffer =
    file_1_bytes || file_2_bytes || ... || file_n_bytes
```

The complete logical buffer is then compressed using the frame's selected `codec_id`. The stored payload is therefore:

```
compressed_payload = CODEC(logical_buffer)
```

The frame hash is calculated over the resulting stored payload. This allows Frame Packing to use Zstd or another archive-wide codec and preserves whole-frame deduplication.

### 8.2 Packing fit algorithm

Because compressed size is not known from the uncompressed input size, a writer MUST NOT assume that a candidate packed set fits merely because its logical input size fits.

A compliant writer SHOULD use:

- accumulate candidate files;
- build the candidate logical buffer;
- compress it using the selected canonical codec profile;
- calculate the resulting stored payload size;
- if the candidate fits, continue;
- if it does not fit, seal the previous candidate frame and start a new frame with the file that did not fit.

If a single file cannot fit into one frame after compression and packing metadata overhead, it MUST be handled by the normal multi-frame large-file path rather than forced into Frame Packing.

A writer MUST never produce a frame whose `data_len`, Pre-Trailer, and padding exceed `frame_size`.

### 8.3 Packed frame determinism

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

## 9. Manifest

`manifest.jsonl` is an append-only logical journal.

The manifest is authoritative for current path state. Frame data remains immutable.

### 9.1 Record types

Example:

```json
{"seq":1,"ts":1739550001,"op":"ADD","path":"src/main.go","ver":2,"loc":[["00","f5a2b1c3...",0,4096]]}
{"seq":2,"ts":1739550002,"op":"ADD","path":"big/dataset.bin","ver":1,"loc":[["03","aaa111...",0,67108864],["11","bbb222...",67108864,33554432]]}
{"seq":3,"ts":1739550123,"op":"DEL","path":"src/utils.go","ver":2}
```

> Note (R2): the `dataset.bin` example is corrected here — the second fragment's `inner_off` is `67108864` (the end of the first fragment), consistent with the global-offset semantics of §6.2.2. It is not `0`.

`seq` is a strictly increasing manifest sequence number. `ts` is informational and MUST NOT be used to determine logical ordering.

### 9.2 Version semantics

`ver` is a per-path monotonically increasing version.

Writers MUST serialize updates to the same manifest so that two operations cannot commit the same `(path, ver)` as competing current states.

A replacement is committed by appending a new `ADD` with the next version.

### 9.3 Manifest write serialization

Data-frame writes MAY occur concurrently.

Append operations to one manifest MUST be serialized through one logical manifest writer.

The implementation MAY realize this through:

- a local process lock;
- a distributed lease/lock;
- a dedicated manifest-writer service;
- per-writer delta logs followed by ordered merge.

What matters at the format boundary is that each manifest record is appended as one complete logical record with a unique `seq`. The format MUST NOT assume that arbitrary concurrent `write()` calls to the same JSONL file are atomically line-preserving.

### 9.4 Manifest references

`loc` is:

```
[blob_id, frame_hash, inner_offset, inner_length]
```

For packed files, `inner_offset` and `inner_length` are offsets into the uncompressed logical packed buffer (§6.2.2).

For a file spanning multiple frames, one tuple is emitted per frame, and `inner_offset` is the **global byte offset** of that fragment within the logical file — identical in meaning to the `inner_off` carried in that frame's own embedded Pre-Trailer entry. The manifest and the frame-embedded metadata MUST agree; a writer MUST NOT emit divergent offsets between the two.

### 9.5 Manifest corruption

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

## 10. Manifest Scaling

### 10.1 Reverse scanning

Readers MUST support reverse chunked scanning of `manifest.jsonl`.

A checkpoint MAY accelerate startup. A checkpoint is never authoritative if it disagrees with the manifest tail.

### 10.2 Sharding

`LINK_MANIFEST` MAY reference independently operated sub-manifests. Each linked manifest MUST be independently verifiable by its declared hash algorithm and hash.

A sub-manifest is an operational scaling boundary, not a change to frame geometry.

Example record (R2):

```json
{"seq":42,"ts":1739551000,"op":"LINK_MANIFEST","path":"submanifests/user-data.jsonl","hash_id":1,"hash":"8f2c3a5e...","lines":50000}
```

---

## 11. Disaster Recovery — Hop-and-Read (R2 — group- and order-aware)

If the manifest is lost:

- For every available blob, read its Archive Header at `0x00`; validate header consistency and obtain `frame_size` (this removes any dependency on Blob 0 specifically).
- Start scanning frames at offset `0x30`. Advance exactly `BLOCK_STRIDE = frame_size`.
- Read the 48-byte Master Trailer at the end of each frame; validate the frame trailer and `data_len`.
- Verify `hash_payload` against the stored payload bytes when integrity verification is required.
- If `block_type = PARITY`, extract `group_id` and `group_index` to map the frame to its parity group and position, for use in repairing missing/corrupted members of that group.
- If `block_type = DATA`:
  - reverse-parse the Pre-Trailer and verify its CRC32C before trusting entries;
  - if `group_id != 0`, use `group_id`/`group_index` to associate the frame with its parity group;
  - if a logical file shows the same `path` and `file_ver` across multiple frames, reassemble it by sorting the fragments in **ascending `inner_off`** (§6.2.2) and concatenating their payloads.
- Emit recovered ADD mappings for plaintext metadata frames.
- If encryption is active, metadata reconstruction requires the relevant decryption key; without it, frame-level inventory, group membership, and payload hashes remain recoverable, but plaintext path mappings and fragment identity (path/ver) do not — see §15.1.6.

The scan is:

```
blob_start      = 0x30
frame_n_start   = 0x30 + n * frame_size
```

No payload scanning is necessary to locate frame boundaries. No manifest is required to reconstruct parity-group membership or multi-frame file ordering.

---

## 12. Reference Implementation — Go

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

### 12.1 Durability ordering

A frame MUST NOT become referenced by a committed manifest record before its complete frame bytes are durably persisted.

Recommended order:

```
write frame
  → flush/fsync blob
  → append manifest record
  → flush/fsync manifest
  → report commit
```

For object storage, the implementation MUST use the storage provider's equivalent durability/commit primitive.

This ordering prevents a crash from producing a manifest that references a frame whose data was never durably committed.

---

## 13. Compaction / Garbage Collection

Compaction uses Mark → Sweep → Freeze/Merge → Switch.

### 13.1 Mark

Build the live frame set from the current manifest state, including reachable linked manifests.

### 13.2 Sweep

Copy live frames into a new generation of blob files. Old blobs MUST NOT be modified in place.

Frames are copied byte-for-byte whenever possible; compaction does not need to decompress, recompress, or re-encrypt live frames.

### 13.3 Concurrent writes during Sweep

Active writers MAY continue while Sweep is running. All writes occurring after the compaction snapshot MUST be identifiable as a manifest tail.

The implementation MUST choose one of these mechanisms:

**A. Delta manifest** — Writers append to a delta manifest while Sweep runs. At freeze time, the compactor:

- stops accepting new manifest commits briefly;
- drains/finalizes the delta;
- merges the delta onto the compacted snapshot;
- verifies that all resulting `loc` references exist;
- writes the final manifest;
- atomically switches the root pointer.

**B. Manifest lock** — The compactor may instead use an exclusive manifest lock. Writers may continue during Sweep but MUST be blocked during the final Freeze/Merge/Switch interval. The lock MUST cover the complete state transition so that no writer can commit against the old root after the new root has become authoritative. A distributed lock/lease is required when multiple machines can write the same manifest and no single manifest-writer service is used.

### 13.4 Switch

The new generation MUST be fully written and verified before becoming authoritative. The switch MUST be atomic at the root-pointer level.

Recommended model:

```
root.current
  ↓
generation-00042/
  ├── manifest.jsonl
  └── frames/
```

Write the new generation completely, fsync it, then atomically replace the small root pointer.

The old generation MUST remain intact until the switch is confirmed durable. Only then may garbage collection delete the old generation.

### 13.5 Crash cases

- Crash during Sweep: old generation remains authoritative.
- Crash during Merge: retry from old generation.
- Crash before root switch: old generation remains authoritative.
- Crash after root switch but before deletion: new generation is authoritative; old generation is garbage.
- Crash during garbage deletion: restart garbage collection; do not roll back the new root.

This makes compaction restartable and prevents a partially copied blob set from being referenced by the old manifest.

### 13.6 Parity-Group Invariants During Compaction (R2)

**Normative rule:** the compactor MUST NOT break the integrity of a parity group. If any DATA frame belonging to a parity group is copied during Sweep, every other DATA and PARITY frame sharing the same `group_id` MUST be copied into the same new generation as part of the same Sweep pass — a parity group MUST NOT be left split across generations.

**Spread rule enforcement:** when writing the new generation, the implementation MUST verify and strictly enforce the §2.4 invariant — frames sharing a `group_id` MUST be spread across at least two distinct blobs in the new generation, even if their physical blob assignment changes during Sweep.

---

## 14. Legacy v1.21

v1.21 standalone `.sf` files and SUB records are not valid 2.0 syntax.

Migration tooling MAY read v1.21 and produce a valid 2.0 archive.

---

## 15. Out of Scope

The following are not required for the base 2.0 profile:

- desktop/edge profiles;
- tape-specific optimization;
- sub-block/CDC deduplication;
- conflict resolution;
- implementation-specific KMS APIs.

Encryption is defined below as a normative interoperable profile.

### 15.1 Encryption — Normative Enterprise Profile

When encryption is enabled, STASH MUST protect both data and sensitive frame metadata.

The following MUST NOT remain plaintext in `manifest.jsonl`:

- `path`;
- `ver`;
- plaintext file metadata derived from those fields.

The following remain plaintext in the binary frame:

- Archive Header;
- Master Trailer (including `group_id` / `group_index` — parity-group structure is not considered sensitive and remains recoverable without keys, per §15.1.6);
- `pre_trailer_len`.

The following are encrypted:

- payload;
- Pre-Trailer body.

#### 15.1.1 AEAD

The reference profile uses an authenticated encryption construction: **AES-256-GCM**.

A frame contains an encrypted payload representation:

```
payload_ciphertext =
    nonce || AEAD(ciphertext, tag)
```

`hash_payload` is calculated over the complete stored encrypted representation, including the nonce and authentication tag.

The Pre-Trailer body uses an independently unique nonce and is encrypted as one AEAD message.

**Fixed nonce length (R2 — normative):** for the AES-256-GCM profile, the nonce length is fixed at **12 bytes (96 bits)**, stored immediately preceding the ciphertext, as shown above. A reader parsing `payload_ciphertext` MUST treat the first 12 bytes as `nonce` and the remainder as `ciphertext || tag`.

#### 15.1.2 Deterministic nonce construction (R2)

Purely random 96-bit nonces carry a non-trivial collision risk at petabyte scale with billions of frames (birthday-bound). To guarantee absolute nonce uniqueness across the archive without relying on entropy generation, nonce construction MUST be deterministic:

```
Nonce = first 4 bytes of archive_id || 8-byte little-endian sequential frame counter
```

The frame counter MUST be monotonically incremented per encrypted frame (or per encrypted Pre-Trailer message, which uses its own independent counter/nonce as required by §15.1.1) and MUST NOT be reused within the same `archive_id`. This construction mathematically guarantees nonce uniqueness across the entire archive while preserving high encryption throughput, since it requires no additional entropy generation per frame.

#### 15.1.3 Envelope encryption

A deployment uses:

```
KEK / KMS key
  ↓
wrapped DEK
  ↓
archive DEK
  ↓
per-frame AEAD keys/nonces
```

The wrapped DEK and key identifier are deployment metadata and MUST NOT be embedded into the fixed 48-byte frame trailer. A deployment MAY store the envelope in a protected archive metadata object or KMS-backed configuration.

#### 15.1.4 Encrypted Pre-Trailer parsing

`pre_trailer_len` remains plaintext so reverse parsing stays O(1).

After locating the encrypted body, a reader:

- reads the encrypted Pre-Trailer body;
- authenticates/decrypts it;
- verifies its internal CRC32C if retained by the selected profile;
- only then parses `entry_count` and entries.

An authentication failure MUST cause the metadata to be treated as corrupt.

#### 15.1.5 Encrypted manifest record format (R2)

When the encrypted profile (§15.1) is active, manifest records carrying `path`/`ver` MUST use the following wire format instead of plaintext `ADD`/`DEL`:

```json
{"seq":105,"ts":1739550123,"op":"ADD_ENC","enc":"<base64_string>"}
```

- **`enc` construction:** `Base64(nonce || ciphertext || tag)`, where `nonce` is 12 bytes per §15.1.1, constructed per §15.1.2 (or an equivalent manifest-scoped monotonic counter distinct from the frame-payload counter — the two counters MUST NOT overlap in nonce space).
- **Encrypted plaintext object:** the AEAD plaintext is the JSON object that would otherwise have appeared unencrypted, e.g. `{"path":"src/main.go","ver":2,"loc":[[...]]}`.
- **AAD (Authenticated Additional Data):** to prevent replay and reorder attacks (an adversary splicing or reordering encrypted manifest lines), the implementation MUST include the binary representation of `seq` and `op` (here, `105` and `"ADD_ENC"`) as AEAD Additional Authenticated Data. A decryption whose AAD does not match the record's actual `seq`/`op` MUST be rejected as tampered.

`DEL_ENC` follows the same wire shape, encrypting `{"path":...,"ver":...}`.

An implementation MUST NOT emit plaintext `ADD`/`DEL` records once the encrypted profile is active for an archive.

#### 15.1.6 Encryption and disaster recovery

Encryption changes the meaning of "self-describing recovery":

- frame boundaries remain recoverable without keys;
- frame hashes remain verifiable without keys;
- frame type, parity-group membership (`group_id`/`group_index`), and stored payload length remain visible without keys;
- plaintext paths, versions, and packed-file/fragment-offset mappings require the decryption key, since those live inside the encrypted Pre-Trailer body and/or `ADD_ENC`/`DEL_ENC` manifest records.

This limitation is explicit and normative.

#### 15.1.7 Encryption and deduplication

Because the encrypted payload is hashed, deduplication requires identical ciphertext.

With the deterministic, counter-based nonce construction of §15.1.2, two independent writers storing logically identical plaintext will still produce different ciphertext (and thus different `hash_payload`) whenever their frame counters differ — which they will, in general. Therefore the implementation MUST NOT assume counter-based nonces enable cross-writer deduplication.

A deployment that requires convergent deduplication under encryption MUST use a separate, documented, content-derived deterministic key/nonce design with an appropriate security analysis; this is distinct from, and MUST NOT reuse, the archive-counter nonce space defined in §15.1.2.

Otherwise, encryption remains semantically secure but naturally defeats cross-instance whole-frame deduplication.

---

## 16. Normative Invariants

A conformant STASH 2.0 implementation MUST preserve all of the following:

- Every blob starts with the same 48-byte Archive Header.
- The first frame in every blob begins at `0x30`.
- `BLOCK_STRIDE == frame_size`.
- Frame boundaries are `0x30 + n * frame_size`.
- Frame hashes cover stored payload bytes only.
- Padding is zero-filled and excluded from hashes.
- Pre-Trailer integrity is checked before metadata is trusted.
- Packed-file offsets refer to the uncompressed logical packed buffer; non-packed multi-frame fragment offsets refer to the global logical-file offset (§6.2.2), and manifest `loc` tuples never diverge from the frame-embedded value.
- Packed files are sorted lexicographically by normalized path.
- Packed-frame compression is permitted and uses the frame's codec.
- Codec settings used for reproducible deduplication MUST be canonical and documented, for every enabled codec (§5.2).
- `data_len` MUST satisfy the exact bound `frame_size - 48 - 4 - pre_trailer_body_size` (§6.1).
- If `parity_scheme != none`, `blob_count MUST be >= 2` (§2.5).
- Every DATA/PARITY frame in a parity group self-describes its `group_id` and `group_index` in its own Master Trailer; parity-group membership is recoverable without the manifest.
- Data-frame writes may be parallel, but each blob append position is serialized.
- Manifest commits are serialized and have strictly increasing `seq`.
- A manifest MUST NOT reference a frame before that frame is durably committed.
- Compaction MUST never overwrite the active generation in place.
- Compaction MUST provide a concurrency-safe Freeze/Merge/Switch operation.
- Compaction MUST NOT split a parity group across generations, and MUST re-verify the §2.4 spread rule after any blob reassignment (§13.6).
- Root-generation switching MUST be atomic.
- Encryption protects both payload and sensitive Pre-Trailer metadata.
- In encrypted mode, plaintext path/version data MUST NOT appear in the manifest; encrypted records use the `ADD_ENC`/`DEL_ENC` format of §15.1.5, with `seq`/`op` bound as AAD.
- AEAD nonces are 12 bytes and constructed deterministically per §15.1.2 — never purely random.
- Without encryption keys, encrypted archives remain frame-recoverable and parity-group-recoverable, but not path-reconstructable.

---
