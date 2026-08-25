# 🌀 STASH

## Version 2.0 — Consolidated Specification
### Revision R3 — Production / Enterprise Hardening (Concurrency, Manifest Scaling & GC Fixes)

**Status:** Approved Specification
**Target:** Server / enterprise / datacenter / petabyte-scale storage
**Out of scope:** General-purpose desktop archive use, tape/cold-storage profiles, sub-block/CDC deduplication

Note: R2 closed the remaining self-description gaps identified in the R1 production review (parity-group recoverability, multi-frame fragment ordering, encrypted manifest wire format, deterministic AEAD nonces). **R4 fixes a third review pass** that found operational failure modes R2 did not cover: unbounded memory allocation from `frame\_size\_class`, a 16-bit `group\_id` that wraps around at petabyte scale, dangling multi-frame fragments during scoped compaction, missing O\_DIRECT/mmap alignment for the Pre-Trailer, an infinite-loop failure mode in Frame Packing, an unbounded-manifest-line DoS in reverse scanning, and an under-specified prohibition on re-encrypting ciphertext during compaction.

**R3 changes the Master Trailer binary layout** (§6.1: `group\_id` widens from uint16 to uint32; the redundant per-frame `version` field is removed). This is a **wire-breaking change** versus R1/R2 — see §2.1, header `version` is bumped to `0x0003` so readers can dispatch on trailer layout. R2-written archives are not directly parsed by an R3-only reader without a compatibility shim keyed on header `version`.

\---

## 0\. Design Priorities

Implementations MUST preserve these priorities in this order:

1. **Predictable O(1) block geometry** — every frame occupies exactly `frame\_size` bytes.
2. **Whole-frame, bit-identical deduplication** — STASH does not deduplicate sub-block content.
3. **Self-describing recovery** — raw frame data MUST contain sufficient information to identify, order, and verify frames without `manifest.jsonl`.
4. **Throughput at enterprise scale** — non-zero-dependency profile utilizing optimized SIMD/hardware-accelerated libraries.

The encryption profile is an explicit exception to priority 3: when metadata encryption is enabled, frame-level recovery (including parity-group reconstruction and fragment ordering) remains possible without keys, but reconstruction of plaintext paths and versions requires the appropriate decryption key.

\---

## 1\. Overview

STASH is an append-only, verifiable archival format for cloud-native and datacenter workflows.

Input data is split into fixed-size frames. A frame contains a compressed payload, optional packed-file metadata, and a fixed 48-byte Master Trailer. Every frame is content-addressed by a cryptographic hash of its stored payload representation.

All frames are immutable. Updates are expressed as new manifest entries and new frames. No frame is overwritten in place.

Data-frame placement is a write-time decision and is not derived from the frame hash. Every frame reference therefore contains both `blob\_id` and `frame\_hash`.

The physical representation of each blob is:

```
+-------------------------------+ 0x00
| Archive Header (48 B)         |
+-------------------------------+ 0x30
| Frame 0 (frame\_size bytes)    |
+-------------------------------+
| Frame 1 (frame\_size bytes)    |
+-------------------------------+
| ...                           |
+-------------------------------+
```

Therefore:

```
frame\_start(blob\_id, n) = 0x30 + n \* BLOCK\_STRIDE
BLOCK\_STRIDE = frame\_size
blob\_size = 48 + frame\_count \* frame\_size
```

The 48-byte blob-header prefix is **not part of `BLOCK\_STRIDE`**.

\---

## 2\. Archive Header

The Archive Header is exactly 48 bytes and MUST be present at offset `0x00` of **every** blob file.

All multi-byte integers are little-endian.

Every copy describes the same logical archive.

### 2.1 Header fields

|Offset|Size|Field|Type|Description|
|-|-:|-|-|-|
|`0x00`|4|magic|char\[4]|`STSH`|
|`0x04`|2|version|uint16|`0x0003` (R3; was `0x0002` for R1/R2 archives)|
|`0x06`|1|frame\_size\_class|uint8|See §3. Production writers MUST NOT exceed `0x0E` (64 MiB) — see §3.1|
|`0x07`|1|hash\_id|uint8|See §4|
|`0x08`|1|codec\_id|uint8|Archive default; per-frame override allowed|
|`0x09`|1|parity\_scheme|uint8|See §7|
|`0x0A`|1|parity\_k|uint8|Data frames per parity group|
|`0x0B`|1|parity\_m|uint8|Parity frames per parity group|
|`0x0C`|1|blob\_count|uint8|Number of blobs, 1–255|
|`0x0D`|3|reserved|bytes|MUST be zero in 2.0|
|`0x10`|32|archive\_id|bytes|Random UUID, zero-padded to 32 bytes|

The header is immutable for the life of the archive.

`frame\_size\_class`, `hash\_id`, `codec\_id`, `parity\_scheme`, `parity\_k`, `parity\_m`, and `blob\_count` MUST NOT change.

**Version dispatch (R3):** because the Master Trailer binary layout changed in R3 (§6.1), a reader MUST branch its trailer-parsing logic on the Archive Header `version` field: `0x0002` selects the R1/R2 Master Trailer layout (16-bit `group\_id`, per-frame `version` field present); `0x0003` selects the R3 layout (32-bit `group\_id`, no per-frame `version` field). An implementation that only supports one layout MUST reject archives with an unsupported `version` rather than attempt to parse the trailer using the wrong layout.

### 2.2 Header redundancy and validation

The repeated header exists specifically to remove Blob 0 as a single point of failure.

A reader MUST:

* read and validate the header of each available blob;
* verify that all available headers agree on immutable archive parameters and `archive\_id`;
* reject the archive as inconsistent if two valid headers disagree;
* permit operation with a subset of blobs when the missing blobs are unavailable, provided at least one valid header remains.

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

For `blob\_count = N`, valid blob IDs are `0 .. N-1`.

Every blob MUST begin with the 48-byte Archive Header. Frames in every blob therefore begin at offset `0x30`.

Frame-to-blob assignment is a write-time decision. A writer MAY use round-robin, capacity-aware, or another deterministic/runtime policy.

A conformant implementation MUST ensure that two writers never concurrently allocate the same physical frame position in the same blob. The recommended model is one serialized append position per blob.

The manifest remains a separate serialization domain; see §9.3.

### 2.4 Parity-group spread

When `blob\_count > 1`, data and parity frames belonging to one parity group MUST span at least two distinct blobs.

Implementations MUST enforce this rule defensively at the library boundary.

### 2.5 Global Parity Invariant

**Normative rule (R2):** if `parity\_scheme != 0x00` (none), then `blob\_count MUST be >= 2`. A configuration with active parity on a single blob is invalid and MUST be rejected by the implementation at archive initialization.

This closes the gap where a single-blob archive could otherwise declare a parity scheme it can never structurally satisfy under §2.4.

\---

## 3\. Frame Size Classes

`frame\_size\_class` selects the total on-disk frame size:

|Value|Size|Value|Size|Value|Size|
|-|-:|-|-:|-|-:|
|`0x00`|4 KiB|`0x06`|256 KiB|`0x0C`|16 MiB|
|`0x01`|8 KiB|`0x07`|512 KiB|`0x0D`|32 MiB|
|`0x02`|16 KiB|`0x08`|1 MiB|`0x0E`|64 MiB|
|`0x03`|32 KiB|`0x09`|2 MiB|`0x0F`|128 MiB|
|`0x04`|64 KiB|`0x0A`|4 MiB|`0x10`|256 MiB|
|`0x05`|128 KiB|`0x0B`|8 MiB|||

All frames in an archive use the same class.

```
BLOCK\_STRIDE = frame\_size
```

The frame size is the complete aligned block size, including padding, Pre-Trailer, and Master Trailer.

The usable payload budget is:

```
payload\_budget =
    frame\_size
  - 48   // Master Trailer
  - 4    // pre\_trailer\_len
  - pre\_trailer\_body\_size
```

The 48-byte Archive Header at the beginning of a blob is not included in this calculation.

### 3.1 Production allocation ceiling (R3)

The `frame\_size\_class` table extends to `0x10` (256 MiB) for format completeness, but an unbounded class value is an operational hazard: a reader (disaster-recovery scanner, compactor, or any component that reuses `sync.Pool`-style frame-sized buffers across many concurrent goroutines/threads) allocates one buffer of `frame\_size` bytes per in-flight frame. A corrupted header byte that flips `frame\_size\_class` to a large value, combined with normal petabyte-scale concurrency, can exhaust process memory (OOM) before any content validation runs, and large single allocations (tens to hundreds of MiB) fragment the Go heap and degrade GC pause times even in the non-corrupted case.

**Normative rule:** production writers MUST NOT create archives using `frame\_size\_class > 0x0E` (i.e. the effective production ceiling is **64 MiB**). Values `0x0F` (128 MiB) and `0x10` (256 MiB) are reserved for non-default, explicitly opt-in profiles and MUST NOT be assumed safe to allocate without an explicit configuration override.

**Normative rule:** any implementation that pre-allocates or pools frame-sized buffers MUST cap the *effective* per-allocation size independently of the value read from an untrusted or unvalidated header — i.e. header parsing MUST reject (not merely warn on) a `frame\_size\_class` above the implementation's configured ceiling before any buffer sized by that value is allocated. Header validation (§2.2) MUST occur, and the ceiling MUST be enforced, before any per-frame buffer allocation.

\---

## 4\. Hash Algorithms

|Value|Algorithm|Digest|
|-|-|-:|
|`0x00`|reserved|—|
|`0x01`|BLAKE3|32 B|
|`0x02`|SHA-256|32 B|
|`0x03`|SHA3-256|32 B|
|`0x04–0xFF`|reserved|—|

The archive's `hash\_id` is fixed for its lifetime.

### 4.1 Hash scope

`hash\_payload` MUST be calculated over the exact bytes stored in the frame's payload region, before padding and before the Pre-Trailer and Master Trailer are appended.

In the normal unencrypted case this is `compressed\_payload`. In encrypted mode this is the encrypted payload representation, including its nonce/AEAD overhead as specified in §15.1.

The hash MUST NOT cover:

* zero padding;
* Pre-Trailer;
* Master Trailer;
* the blob's Archive Header.

This makes whole-frame deduplication dependent on byte-identical stored payloads.

\---

## 5\. Compression Codecs

|Value|Codec|
|-|-|
|`0x00`|STORE|
|`0x01`|LZ4|
|`0x02`|Zstd|
|`0x03`|LZMA|
|`0x04`|Brotli|
|`0x05–0xFF`|reserved|

`codec\_id` in the Archive Header is the default and MAY be overridden per frame.

### 5.1 Canonical compression parameters

A codec identifier alone is insufficient to guarantee byte-identical output across different codec versions or settings. Therefore, for frames intended to be reproducibly deduplicated across independent writers, the implementation MUST use a documented **canonical parameter profile** for the selected codec.

For the default Zstd profile, the STASH reference implementation MUST publish the exact compression level and relevant deterministic parameters used for archive creation.

Two implementations MAY produce different compressed bytes when using different valid codec profiles; such frames remain valid STASH frames but will not deduplicate.

The manifest and frame format do not assume that compression is globally reproducible merely from the codec name.

### 5.2 Canonical parameters — all codecs (R2)

**Normative rule:** the canonical-parameter-profile requirement of §5.1 applies symmetrically to every supported codec (LZ4, LZMA, Brotli), not only Zstd. Each implementation MUST document and fix the exact compression level and deterministic parameters for every codec it enables for archive creation, so that byte-identical deduplication is achievable regardless of which codec is in use.

\---

## 6\. Frame Binary Layout

All multi-byte integers are little-endian.

Each frame occupies exactly `frame\_size` bytes.

```
\[ compressed\_payload / encrypted\_payload ]
\[ zero padding ]
\[ pre\_trailer\_body ]
\[ pre\_trailer\_len : uint32 LE ]
\[ Master Trailer : 48 B ]
```

The Master Trailer is always the last 48 bytes of the frame.

### 6.1 Master Trailer

R2 first replaced the 3 reserved bytes at `0x09` with parity-group self-description fields. **R3 widens `group\_id` from uint16 to uint32** (see rationale below) and, to keep the Master Trailer at a fixed 48 bytes without growing it, **drops the per-frame `version` field**: it was redundant with the Archive Header's `version` (§2.1), which every frame in the archive already shares, and which readers now use for trailer-layout dispatch anyway (§2.1, "Version dispatch"). This is the layout selected when Archive Header `version = 0x0003`.

|Offset|Size|Field|Description|
|-|-:|-|-|
|`0x00`|4|magic|`STSH`|
|`0x04`|1|hash\_id|Must match Archive Header|
|`0x05`|1|codec\_id|Codec used for this frame|
|`0x06`|1|block\_type|`0 = DATA`, `1 = PARITY`|
|`0x07`|1|group\_index|Position of this frame within its parity group (`0 .. k+m-1`). `0` if the frame belongs to no parity group.|
|`0x08`|4|group\_id|uint32. Unique parity-group ID within the archive. `0` if the frame belongs to no parity group.|
|`0x0C`|4|data\_len|Exact stored payload length|
|`0x10`|32|hash\_payload|Hash of stored payload|

`data\_len` MUST satisfy the exact bound:

```
0 <= data\_len <= frame\_size - 48 - 4 - pre\_trailer\_body\_size
```

i.e. `data\_len` MUST NOT exceed `payload\_budget` as defined in §3. A frame violating this bound, on either write or read, MUST be treated as corrupted — this is a hard structural check, not merely advisory headroom.

For a DATA frame, the payload and metadata MUST describe at least one logical file unless the frame is otherwise explicitly defined as an implementation-reserved empty frame. Empty unused frames MUST NOT be committed as valid archive frames.

`group\_id` values are scoped to the archive, not to a blob; a reader reconstructing parity groups from a raw scan groups frames purely by matching `group\_id` across all blobs, using `group\_index` to determine each frame's position (data slots `0..k-1`, parity slots `k..k+m-1`, or an implementation-defined ordering that MUST be documented and consistent archive-wide).

**Why `group\_id` needed to widen (R3):** a 16-bit `group\_id` provides only 65,535 unique group values per archive. At `parity\_k = 8` with 1 MiB frames, an archive exhausts the full `group\_id` space after roughly 500 GB written — trivial at petabyte scale, typically within hours. Once the counter wraps and IDs are reused, frames from unrelated, non-contemporaneous parity groups collide on `group\_id`, and Hop-and-Read disaster recovery (§11) will bucket unrelated frames together — making group-based reconstruction silently wrong rather than merely unavailable. A uint32 `group\_id` (4.29 billion groups) is not exhaustible at any realistic archive lifetime and frame-size combination. Implementations MUST treat `group\_id` exhaustion (wraparound) as a fatal archive-writer error rather than silently reusing IDs, even though uint32 makes this effectively unreachable in practice.

### 6.2 Pre-Trailer

The Pre-Trailer is:

```
\[ pre\_trailer\_body ]\[ pre\_trailer\_len : uint32 LE ]
```

`pre\_trailer\_len` is the exact byte length of `pre\_trailer\_body`.

In unencrypted mode, `pre\_trailer\_body` is:

```
uint32 entry\_count
repeated entry\_count times:
    varint  path\_len
    bytes   path
    uint64  inner\_off
    uint64  inner\_len
    uint64  file\_ver
uint32 crc32c
```

`crc32c` is the final four bytes of the body.

#### 6.2.1 CRC coverage

The CRC32C MUST cover **all bytes of `pre\_trailer\_body` preceding the CRC field, including `entry\_count` and every entry**.

The CRC does not cover `pre\_trailer\_len`, because that field lies outside the body.

The reader MUST:

* read the Master Trailer;
* read the 4-byte `pre\_trailer\_len`;
* validate that the length is within the frame's hard bounds;
* calculate the exact start of the body;
* read the complete body;
* verify CRC32C;
* only after successful CRC verification parse and trust the entries.

A reader MUST NOT trust `entry\_count`, paths, offsets, or versions from an unverified body.

#### 6.2.2 Entry offset semantics (R2 — unified)

R2 removes the prior ambiguity between packed and non-packed multi-frame files by defining `inner\_off` / `inner\_len` per case:

**Packed frames (§8):** `inner\_off` and `inner\_len` refer to the **logical uncompressed packed buffer** of that frame — offset and length of one packed file within the decompressed concatenation of all files packed into this frame.

```
logical\_buffer =
    file(path\_1) || file(path\_2) || ... || file(path\_n)
```

After compression, the logical buffer is represented by the frame's stored payload, but its internal offsets remain offsets in the uncompressed logical buffer. Extraction of one packed file therefore requires decompression of the frame payload.

**Non-packed / multi-frame files:** when a single large file spans more than one frame, `inner\_off` is the **global byte offset of this fragment within the complete logical file**, and `inner\_len` is the size of the fragment stored in this frame. This is the same value in both the frame's own embedded Pre-Trailer entry and the corresponding manifest `loc` tuple (§9.4) — the two MUST NOT diverge.

This unified semantics is what makes fragment reassembly self-describing: Hop-and-Read (§11) can reconstruct a multi-frame file purely by scanning frames for matching `path` + `file\_ver` and sorting by ascending `inner\_off`, without consulting the manifest.

#### 6.2.3 Limits

Normative limits:

* `MAX\_PACKED\_ENTRIES = 65535`
* `path\_len <= 4096` bytes
* `MIN\_PAYLOAD\_RESERVE = 64` bytes

The maximum Pre-Trailer body size is:

```
max\_pre\_trailer\_total =
    frame\_size
  - 48
  - 4
  - MIN\_PAYLOAD\_RESERVE
```

A writer MUST enforce this incrementally while packing.

#### 6.2.4 Pre-Trailer alignment (R3)

Design Priority #1 (§0) exists specifically to support O\_DIRECT and NVMe flash-page-aligned I/O. A Pre-Trailer of arbitrary byte length defeats this: if `pre\_trailer\_body\_start` is not aligned, a reader doing an O\_DIRECT read of just the payload region hits an unaligned boundary, forcing a kernel-level read-modify-write and a severe throughput penalty — silently, since nothing in R1/R2 required or checked alignment.

Define `ALIGNMENT = 8` bytes.

**Normative rule:** a writer MUST size the zero-padding region between the end of `compressed\_payload`/`encrypted\_payload` and the start of `pre\_trailer\_body` such that `pre\_trailer\_body\_start` (relative to `block\_start`) is a multiple of `ALIGNMENT`. Concretely: `pre\_trailer\_body\_start MOD ALIGNMENT == 0`. This is satisfied by rounding the padding length up as needed; it does not change `max\_pre\_trailer\_total` (§6.2.3), which remains an upper bound the writer must still respect after alignment padding is added.

**Normative rule:** a reader performing reverse parsing (§6.3) MUST verify `pre\_trailer\_body\_start MOD ALIGNMENT == 0` as part of frame validation. A frame that fails this check MUST be treated as corrupted.

### 6.3 Deterministic reverse parsing

Required algorithm:

* `block\_end = block\_start + frame\_size`
* read the last 48 bytes as Master Trailer;
* validate Master Trailer `magic` and structural fields, using the Archive Header `version` (§2.1) to select the R1/R2 or R3 trailer layout;
* read `pre\_trailer\_len` from `block\_end - 48 - 4`;
* validate `pre\_trailer\_len` against the hard maximum;
* compute:

```
pre\_trailer\_body\_start =
    block\_end - 48 - 4 - pre\_trailer\_len
```

* verify that the body does not overlap the stored payload;
* verify `pre\_trailer\_body\_start MOD ALIGNMENT == 0` (§6.2.4); reject as corrupted if not;
* read the body;
* verify CRC32C;
* only then parse entries;
* `compressed\_payload` / encrypted payload is:

```
\[block\_start, block\_start + data\_len)
```

Everything between `data\_len` and `pre\_trailer\_body\_start` MUST be zero padding.

\---

## 7\. Parity / Erasure Coding

|Value|Scheme|Tolerance|
|-|-|-:|
|`0x00`|none|0|
|`0x01`|XOR|1 frame/group|
|`0x02`|Reed-Solomon|`parity\_m` frames/group|
|`0x03`|LRC|tunable; EXPERIMENTAL|

The scheme and parameters are fixed at archive creation. Mixing parity schemes inside one archive is not supported.

A parity group is closed only after its required data frames are known. Data frames remain readable before the group is closed. Parity frames MUST be written only after the corresponding group membership is fixed.

### 7.1 Parity frame identity (R2 — self-describing)

A parity frame has `block\_type = PARITY`.

Parity payload identity is the exact stored parity payload bytes, and `hash\_payload` is calculated over those bytes.

As of R2, every DATA and PARITY frame belonging to a parity group self-describes its group membership via `group\_id` and `group\_index` in its own Master Trailer (§6.1). A reader performing disaster recovery can therefore reconstruct full group membership by scanning all available blobs and bucketing frames by `group\_id`, without needing the manifest.

The manifest MAY still additionally record a `PARITY\_GROUP` entry as an operational/management convenience (e.g. for tooling that wants group membership without a full blob scan), but this record is no longer load-bearing for recovery:

```json
{
  "op": "PARITY\_GROUP",
  "group\_id": 42,
  "data\_frames": \[\["00", "hash1"], \["03", "hash2"]],
  "parity\_frames": \[\["07", "phash1"]]
}
```

Each reference is `\[blob\_id, frame\_hash]`.

\---

## 8\. Frame Packing

Frame Packing aggregates small files into one DATA frame.

### 8.1 Packing order

Files MUST be sorted lexicographically by normalized UTF-8 path before packing.

The writer constructs:

```
logical\_buffer =
    file\_1\_bytes || file\_2\_bytes || ... || file\_n\_bytes
```

The complete logical buffer is then compressed using the frame's selected `codec\_id`. The stored payload is therefore:

```
compressed\_payload = CODEC(logical\_buffer)
```

The frame hash is calculated over the resulting stored payload. This allows Frame Packing to use Zstd or another archive-wide codec and preserves whole-frame deduplication.

### 8.2 Packing fit algorithm

Because compressed size is not known from the uncompressed input size, a writer MUST NOT assume that a candidate packed set fits merely because its logical input size fits.

A compliant writer SHOULD use:

* accumulate candidate files;
* build the candidate logical buffer;
* compress it using the selected canonical codec profile;
* calculate the resulting stored payload size;
* if the candidate fits, continue;
* if it does not fit, seal the previous candidate frame and start a new frame with the file that did not fit.

If a single file cannot fit into one frame after compression and packing metadata overhead, it MUST be handled by the normal multi-frame large-file path rather than forced into Frame Packing.

A writer MUST never produce a frame whose `data\_len`, Pre-Trailer, and padding exceed `frame\_size`.

**Fail-fast rule (R3):** the algorithm above can loop indefinitely if a single candidate file — even alone, in a freshly initialized, otherwise-empty frame — does not fit once its Pre-Trailer entry overhead is accounted for (e.g. a `path` near the 4096-byte limit combined with an unfavorable compression ratio). A writer MUST detect this case explicitly: if a candidate file fails to fit into a newly initialized, empty candidate frame (i.e. it is not merely competing with other already-accumulated files for space), the writer MUST immediately fail that packing attempt with a distinct error (e.g. `ErrFrameBufferOverflow`) and escalate the file to the multi-frame large-file path (§9.4). A writer MUST NOT retry Frame Packing for that file in a new empty frame, which is the condition that produces an unbounded loop.

### 8.3 Packed frame determinism

Identical input sets produce byte-identical packed frames only when all of the following are identical:

* normalized paths;
* path ordering;
* file contents;
* file versions;
* codec;
* canonical codec parameters;
* packing rules.

The specification does not claim cross-implementation byte identity merely from equal logical input.

\---

## 9\. Manifest

`manifest.jsonl` is an append-only logical journal.

The manifest is authoritative for current path state. Frame data remains immutable.

### 9.1 Record types

Example:

```json
{"seq":1,"ts":1739550001,"op":"ADD","path":"src/main.go","ver":2,"loc":\[\["00","f5a2b1c3...",0,4096]]}
{"seq":2,"ts":1739550002,"op":"ADD","path":"big/dataset.bin","ver":1,"loc":\[\["03","aaa111...",0,67108864],\["11","bbb222...",67108864,33554432]]}
{"seq":3,"ts":1739550123,"op":"DEL","path":"src/utils.go","ver":2}
```

> Note (R2): the `dataset.bin` example is corrected here — the second fragment's `inner\_off` is `67108864` (the end of the first fragment), consistent with the global-offset semantics of §6.2.2. It is not `0`.

`seq` is a strictly increasing manifest sequence number. `ts` is informational and MUST NOT be used to determine logical ordering.

### 9.2 Version semantics

`ver` is a per-path monotonically increasing version.

Writers MUST serialize updates to the same manifest so that two operations cannot commit the same `(path, ver)` as competing current states.

A replacement is committed by appending a new `ADD` with the next version.

### 9.3 Manifest write serialization

Data-frame writes MAY occur concurrently.

Append operations to one manifest MUST be serialized through one logical manifest writer.

The implementation MAY realize this through:

* a local process lock;
* a distributed lease/lock;
* a dedicated manifest-writer service;
* per-writer delta logs followed by ordered merge.

What matters at the format boundary is that each manifest record is appended as one complete logical record with a unique `seq`. The format MUST NOT assume that arbitrary concurrent `write()` calls to the same JSONL file are atomically line-preserving.

### 9.4 Manifest references

`loc` is:

```
\[blob\_id, frame\_hash, inner\_offset, inner\_length]
```

For packed files, `inner\_offset` and `inner\_length` are offsets into the uncompressed logical packed buffer (§6.2.2).

For a file spanning multiple frames, one tuple is emitted per frame, and `inner\_offset` is the **global byte offset** of that fragment within the logical file — identical in meaning to the `inner\_off` carried in that frame's own embedded Pre-Trailer entry. The manifest and the frame-embedded metadata MUST agree; a writer MUST NOT emit divergent offsets between the two.

### 9.5 Manifest corruption

A malformed or truncated JSONL record MUST NOT be treated as a valid update.

Readers MUST detect at least:

* invalid JSON;
* missing required fields;
* invalid operation;
* invalid `blob\_id`;
* invalid frame-hash length;
* invalid version ordering;
* invalid `loc` structure.

An incomplete final line MAY be treated as an uncommitted append and ignored during recovery, provided the implementation can prove that the line was not fully committed.

Deployments requiring cryptographic manifest tamper detection SHOULD maintain a signed or cryptographically hashed manifest checkpoint/segment layer. This is outside the immutable frame format.

\---

## 10\. Manifest Scaling

### 10.1 Reverse scanning

Readers MUST support reverse chunked scanning of `manifest.jsonl` in fixed-size chunks (typically 4–16 MiB).

A checkpoint MAY accelerate startup. A checkpoint is never authoritative if it disagrees with the manifest tail.

**Maximum line length:** `MAX\_MANIFEST\_LINE\_BYTES = 1 MiB`. A reader performing reverse chunked scanning MUST treat any line exceeding this limit as manifest corruption and MUST NOT buffer an unbounded line. A writer MUST NOT emit a line exceeding the limit.

**Large logical files:** this limit MUST NOT impose a limit on the number of fragments of one logical file. A multi-frame logical file MUST use the transactional extent protocol below whenever one ordinary `ADD` record would exceed the line limit.

The canonical extent protocol is:

```json
{"seq":100,"op":"ADD_BEGIN","tx_id":"...","path":"dataset.bin","ver":7,"total_len":10995116277760,"extent_count":3000000}
{"seq":101,"op":"ADD_EXTENT","tx_id":"...","extent_index":0,"loc":[[0,"hash...",0,65536]]}
{"seq":102,"op":"ADD_EXTENT","tx_id":"...","extent_index":1,"loc":[[1,"hash...",65536,65536]]}
...
{"seq":999999,"op":"ADD_COMMIT","tx_id":"...","extent_count":3000000}
```

`ADD_BEGIN`, every `ADD_EXTENT`, and `ADD_COMMIT` share one `tx_id`. Each line MUST remain below `MAX\_MANIFEST\_LINE\_BYTES`. `extent_index` MUST start at zero and increase contiguously. The logical file becomes visible atomically only after a valid `ADD_COMMIT` is durably committed. An incomplete extent transaction MUST be ignored during recovery. The manifest journal therefore remains append-only while a single logical file can be represented by arbitrarily many bounded records.

`ADD_EXTENT` MUST carry explicit fragment offsets as defined in §6.2.2; array position is never the sole ordering mechanism. `LINK_MANIFEST` is for independent manifest namespaces and MUST NOT be used as a substitute for transactional extents of one logical file.

### 10.2 Sharding

`LINK\_MANIFEST` MAY reference independently operated sub-manifests. Each linked manifest MUST be independently verifiable by its declared hash algorithm and hash.

A sub-manifest is an operational scaling boundary, not a change to frame geometry.

Example record (R2):

```json
{"seq":42,"ts":1739551000,"op":"LINK\_MANIFEST","path":"submanifests/user-data.jsonl","hash\_id":1,"hash":"8f2c3a5e...","lines":50000}
```

\---

## 11\. Disaster Recovery — Hop-and-Read (R2 — group- and order-aware)

If the manifest is lost:

* For every available blob, read its Archive Header at `0x00`; validate header consistency and obtain `frame\_size` (this removes any dependency on Blob 0 specifically).
* Start scanning frames at offset `0x30`. Advance exactly `BLOCK\_STRIDE = frame\_size`.
* Read the 48-byte Master Trailer at the end of each frame; validate the frame trailer and `data\_len`.
* Verify `hash\_payload` against the stored payload bytes when integrity verification is required.
* If `block\_type = PARITY`, extract `group\_id` and `group\_index` to map the frame to its parity group and position, for use in repairing missing/corrupted members of that group.
* If `block\_type = DATA`:

  * reverse-parse the Pre-Trailer and verify its CRC32C before trusting entries;
  * if `group\_id != 0`, use `group\_id`/`group\_index` to associate the frame with its parity group;
  * if a logical file shows the same `path` and `file\_ver` across multiple frames, reassemble it by sorting the fragments in **ascending `inner\_off`** (§6.2.2) and concatenating their payloads.
* Emit recovered ADD mappings for plaintext metadata frames.
* If encryption is active, metadata reconstruction requires the relevant decryption key; without it, frame-level inventory, group membership, and payload hashes remain recoverable, but plaintext path mappings and fragment identity (path/ver) do not — see §15.1.6.

The scan is:

```
blob\_start      = 0x30
frame\_n\_start   = 0x30 + n \* frame\_size
```

No payload scanning is necessary to locate frame boundaries. No manifest is required to reconstruct parity-group membership or multi-frame file ordering.

\---

## 12\. Reference Implementation — Go

Recommended dependencies:

|Function|Package|
|-|-|
|BLAKE3|`zeebo/blake3` or equivalent|
|SHA-256|`crypto/sha256`|
|SHA3-256|`crypto/sha3`|
|Zstd/LZ4/Brotli|`klauspost/compress`|
|Reed-Solomon|`klauspost/reedsolomon`|
|CRC32C|Go `hash/crc32` with Castagnoli|
|Binary encoding|`encoding/binary`|

The reference implementation SHOULD:

* reuse frame-sized buffers;
* avoid exposing unsealed packed frames;
* serialize append position per blob;
* serialize manifest commits;
* fsync durable frame data before manifest commit;
* fsync manifest data before reporting the manifest record committed;
* benchmark Reed-Solomon on target hardware.

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

\---

## 13\. Compaction / Garbage Collection

Compaction uses Mark → Sweep → Freeze/Merge → Switch.

### 13.1 Mark

Build the live frame set from the current manifest state, including reachable linked manifests.

**Global liveness scope (R3):** Mark MUST resolve liveness against the *complete* manifest graph reachable from the root manifest — the root manifest plus every currently reachable `LINK\_MANIFEST` target — regardless of which sub-manifest triggered the compaction run. A compaction operation scoped to, or triggered by, a single sub-manifest MUST NOT compute liveness using only that sub-manifest's local records; doing so cannot see references held by sibling sub-manifests and risks reclaiming frames those sub-manifests still consider live.

### 13.2 Sweep

Copy live frames into a new generation of blob files. Old blobs MUST NOT be modified in place.

Frames are copied byte-for-byte whenever possible; compaction does not need to decompress, recompress, or re-encrypt live frames.

**Opaque ciphertext rule (R3 — normative):** for encrypted archives, the compactor MUST treat each frame's stored ciphertext (payload and Pre-Trailer) as an opaque binary blob during Sweep. The compactor MUST NOT decrypt and re-encrypt live frames as part of compaction, under any circumstance — not for re-packing, not for storage optimization, not for nonce "refresh." Re-encryption during Sweep would require generating a new nonce for unchanged plaintext, which breaks the deterministic nonce/counter accounting of §15.1.2 and produces ciphertext with a different `hash\_payload`, silently orphaning the original (now-undeduplicatable) copy. Ciphertext is copied byte-for-byte, identically to the unencrypted case.

### 13.3 Concurrent writes during Sweep

Active writers MAY continue while Sweep is running. All writes occurring after the compaction snapshot MUST be identifiable as a manifest tail.

The implementation MUST choose one of these mechanisms:

**A. Delta manifest** — Writers append to a delta manifest while Sweep runs. At freeze time, the compactor:

* stops accepting new manifest commits briefly;
* drains/finalizes the delta;
* merges the delta onto the compacted snapshot;
* verifies that all resulting `loc` references exist;
* writes the final manifest;
* atomically switches the root pointer.

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

* Crash during Sweep: old generation remains authoritative.
* Crash during Merge: retry from old generation.
* Crash before root switch: old generation remains authoritative.
* Crash after root switch but before deletion: new generation is authoritative; old generation is garbage.
* Crash during garbage deletion: restart garbage collection; do not roll back the new root.

This makes compaction restartable and prevents a partially copied blob set from being referenced by the old manifest.

### 13.6 Parity-Group Invariants During Compaction (R2)

**Normative rule:** the compactor MUST NOT break the integrity of a parity group. If any DATA frame belonging to a parity group is copied during Sweep, every other DATA and PARITY frame sharing the same `group\_id` MUST be copied into the same new generation as part of the same Sweep pass — a parity group MUST NOT be left split across generations.

**Spread rule enforcement:** when writing the new generation, the implementation MUST verify and strictly enforce the §2.4 invariant — frames sharing a `group\_id` MUST be spread across at least two distinct blobs in the new generation, even if their physical blob assignment changes during Sweep.

### 13.7 Multi-Frame Logical File Integrity During Compaction (R3)

§13.6 protects parity groups, but a large logical file spanning many frames (identified by matching `path` + `file\_ver` across multiple `loc` tuples, §9.4) is a second kind of multi-frame unit that compaction can otherwise split — for example if a compaction pass runs with a Mark scope that does not see every fragment's reference (see §13.1, "Global liveness scope"), only some fragments get copied to the new generation, and the fragments left in the old generation become permanently unreachable once that generation is deleted (§13.4).

**Normative rule:** the compactor MUST treat every fragment of a single logical multi-frame file (all frames referenced by one manifest `ADD` record's `loc` array, sharing `path` + `file\_ver`) as one indivisible unit for Mark and Sweep purposes. A frame that is one fragment of such a file MUST NOT be considered eligible for deletion — and the old generation containing it MUST NOT be garbage-collected (§13.4) — until every sibling fragment of that same file has been verified present and durably copied into the new generation.

This rule composes with §13.6: a frame may simultaneously be a member of a parity group and a fragment of a multi-frame file; both membership sets MUST be intact in the new generation before the old generation is eligible for deletion.

### 13.8 Emergency Pruning

A compaction process MUST NOT wait indefinitely for a missing or inaccessible sibling fragment. It MUST classify the affected object or generation as **GC-blocked** and expose the exact missing fragment references.

If an administrator explicitly invokes **Emergency Pruning**, the operation MUST be durable, auditable, and fail-closed rather than silently weakening integrity:

1. The compactor records an `EMERGENCY_PRUNE` event containing the generation, affected blob(s), missing fragment references, timestamp, and operator-supplied reason.
2. Every affected logical file is marked **DEGRADED / UNRECOVERABLE** if a manifest-referenced fragment is missing or cannot be verified.
3. The affected old generation MAY then be deleted, even though some surviving fragments of that logical file are discarded with it.
4. The active manifest MUST NOT claim the affected logical file is complete. A reader MUST surface the degraded state as an integrity error rather than returning a silently truncated file.
5. Emergency Pruning MUST NOT be used merely because a compaction worker cannot access a healthy blob temporarily; normal retry/recovery MUST be attempted first.

Emergency Pruning is therefore an explicit data-loss escape hatch, not a normal GC path. It prevents permanent storage exhaustion while preserving a durable record that integrity was intentionally sacrificed for the affected objects.

\---

## 14\. Legacy v1.21

v1.21 standalone `.sf` files and SUB records are not valid 2.0 syntax.

Migration tooling MAY read v1.21 and produce a valid 2.0 archive.

\---

## 15\. Out of Scope

The following are not required for the base 2.0 profile:

* desktop/edge profiles;
* tape-specific optimization;
* sub-block/CDC deduplication;
* conflict resolution;
* implementation-specific KMS APIs.

Encryption is defined below as a normative interoperable profile.

### 15.1 Encryption — Normative Enterprise Profile

When encryption is enabled, STASH MUST protect both data and sensitive frame metadata.

The following MUST NOT remain plaintext in `manifest.jsonl`:

* `path`;
* `ver`;
* plaintext file metadata derived from those fields.

The following remain plaintext in the binary frame:

* Archive Header;
* Master Trailer (including `group\_id` / `group\_index` — parity-group structure is not considered sensitive and remains recoverable without keys, per §15.1.6);
* `pre\_trailer\_len`.

The following are encrypted:

* payload;
* Pre-Trailer body.

#### 15.1.1 AEAD

The reference profile uses an authenticated encryption construction: **AES-256-GCM**.

A frame contains an encrypted payload representation:

```
payload\_ciphertext =
    nonce || AEAD(ciphertext, tag)
```

`hash\_payload` is calculated over the complete stored encrypted representation, including the nonce and authentication tag.

The Pre-Trailer body uses an independently unique nonce and is encrypted as one AEAD message.

**Fixed nonce length (R2 — normative):** for the AES-256-GCM profile, the nonce length is fixed at **12 bytes (96 bits)**, stored immediately preceding the ciphertext, as shown above. A reader parsing `payload\_ciphertext` MUST treat the first 12 bytes as `nonce` and the remainder as `ciphertext || tag`.

#### 15.1.2 Deterministic nonce construction (R4)

Encrypted frame payloads MUST support independent lock-free writers, one per blob. Therefore nonce allocation MUST be blob-local and MUST NOT depend on a shared global frame counter.

For the AES-256-GCM frame-payload profile, the 12-byte nonce is:

```text
Nonce = first 4 bytes of archive_id || uint32_le(blob_id) || uint32_le(blob_local_counter)
```

`blob_id` MUST be stable and unique within the archive. `blob_local_counter` starts at zero for the first encrypted payload written to a blob and is incremented exactly once per encrypted frame payload. The pair `(blob_id, blob_local_counter)` MUST NEVER be reused with the same archive DEK.

The counter state MUST be persisted as part of the blob's durable append state so crash recovery cannot reuse a nonce. A writer MUST advance the durable allocation state before exposing the corresponding encrypted frame as committed.

This construction provides an independent nonce namespace per blob and therefore preserves the lock-free-per-blob write model. The 4-byte blob identifier and 4-byte local counter each provide 2^32 values; an implementation MUST reject an archive before either field would wrap.

The encrypted Pre-Trailer body uses a separate nonce domain and MUST NOT reuse a frame-payload nonce. Its nonce MUST use an explicit domain-separation value and an independently persisted per-blob counter.

Manifest encryption uses a third nonce domain and MUST NOT reuse either frame-payload or Pre-Trailer nonces.

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

`pre\_trailer\_len` remains plaintext so reverse parsing stays O(1).

After locating the encrypted body, a reader:

* reads the encrypted Pre-Trailer body;
* authenticates/decrypts it;
* verifies its internal CRC32C if retained by the selected profile;
* only then parses `entry\_count` and entries.

An authentication failure MUST cause the metadata to be treated as corrupt.

#### 15.1.5 Encrypted manifest record format (R2)

When the encrypted profile (§15.1) is active, manifest records carrying `path`/`ver` MUST use the following wire format instead of plaintext `ADD`/`DEL`:

```json
{"seq":105,"ts":1739550123,"op":"ADD\_ENC","enc":"<base64\_string>"}
```

* **`enc` construction:** `Base64(nonce || ciphertext || tag)`, where `nonce` is 12 bytes per §15.1.1, constructed from the manifest-specific nonce domain defined below; manifest nonces MUST NOT overlap frame-payload or Pre-Trailer nonce domains.
* **Encrypted plaintext object:** the AEAD plaintext is the JSON object that would otherwise have appeared unencrypted, e.g. `{"path":"src/main.go","ver":2,"loc":\[\[...]]}`.
* **AAD (Authenticated Additional Data):** to prevent replay and reorder attacks (an adversary splicing or reordering encrypted manifest lines), the implementation MUST include the binary representation of `seq` and `op` (here, `105` and `"ADD\_ENC"`) as AEAD Additional Authenticated Data. A decryption whose AAD does not match the record's actual `seq`/`op` MUST be rejected as tampered.

`DEL\_ENC` follows the same wire shape, encrypting `{"path":...,"ver":...}`.

An implementation MUST NOT emit plaintext `ADD`/`DEL` records once the encrypted profile is active for an archive.

#### 15.1.6 Encrypted manifest nonce domain

Manifest records use a separate 12-byte nonce domain:

```text
Nonce = first 4 bytes of archive_id || 0xFFFFFFFF || uint32_le(manifest_local_counter)
```

`manifest_local_counter` MUST be persisted durably and MUST never repeat under the same archive DEK. The reserved `0xFFFFFFFF` domain value MUST NOT be used as a blob_id. Implementations MUST therefore reject `blob_id = 0xFFFFFFFF`.

AAD MUST include `seq`, `op`, and `tx_id` when present. This binds each encrypted record to its journal position and transactional extent operation.

#### 15.1.7 Encryption and disaster recovery

Encryption changes the meaning of "self-describing recovery":

* frame boundaries remain recoverable without keys;
* frame hashes remain verifiable without keys;
* frame type, parity-group membership (`group\_id`/`group\_index`), and stored payload length remain visible without keys;
* plaintext paths, versions, and packed-file/fragment-offset mappings require the decryption key, since those live inside the encrypted Pre-Trailer body and/or `ADD\_ENC`/`DEL\_ENC` manifest records.

This limitation is explicit and normative.

#### 15.1.8 Encryption and deduplication

Because the encrypted payload is hashed, deduplication requires identical ciphertext.

With the deterministic, counter-based nonce construction of §15.1.2, two independent writers storing logically identical plaintext will still produce different ciphertext (and thus different `hash\_payload`) whenever their frame counters differ — which they will, in general. Therefore the implementation MUST NOT assume counter-based nonces enable cross-writer deduplication.

A deployment that requires convergent deduplication under encryption MUST use a separate, documented, content-derived deterministic key/nonce design with an appropriate security analysis; this is distinct from, and MUST NOT reuse, the archive-counter nonce space defined in §15.1.2.

Otherwise, encryption remains semantically secure but naturally defeats cross-instance whole-frame deduplication.

**Compaction is not an exception (R3):** the counter-based nonce construction of §15.1.2 also means compaction (§13.2) MUST NOT attempt to improve deduplication or "re-pack" encrypted frames by decrypting and re-encrypting them — doing so would assign a new nonce to unchanged plaintext, changing `hash\_payload` and orphaning the prior copy with no corresponding gain, since the new ciphertext cannot deduplicate against anything either. See §13.2, "Opaque ciphertext rule."

\---

## 16\. Normative Invariants

A conformant STASH 2.0 implementation MUST preserve all of the following:

* Every blob starts with the same 48-byte Archive Header.
* The first frame in every blob begins at `0x30`.
* `BLOCK\_STRIDE == frame\_size`.
* Frame boundaries are `0x30 + n \* frame\_size`.
* Frame hashes cover stored payload bytes only.
* Padding is zero-filled and excluded from hashes.
* Pre-Trailer integrity is checked before metadata is trusted.
* Packed-file offsets refer to the uncompressed logical packed buffer; non-packed multi-frame fragment offsets refer to the global logical-file offset (§6.2.2), and manifest `loc` tuples never diverge from the frame-embedded value.
* Packed files are sorted lexicographically by normalized path.
* Packed-frame compression is permitted and uses the frame's codec.
* Codec settings used for reproducible deduplication MUST be canonical and documented, for every enabled codec (§5.2).
* `data\_len` MUST satisfy the exact bound `frame\_size - 48 - 4 - pre\_trailer\_body\_size` (§6.1).
* `pre\_trailer\_body\_start` MUST be a multiple of `ALIGNMENT` (8 bytes) (§6.2.4).
* Production writers MUST NOT use `frame\_size\_class > 0x0E` (64 MiB); readers MUST enforce an allocation ceiling before allocating any header-sized buffer (§3.1).
* If `parity\_scheme != none`, `blob\_count MUST be >= 2` (§2.5).
* Every DATA/PARITY frame in a parity group self-describes its `group\_id` (uint32) and `group\_index` in its own Master Trailer; parity-group membership is recoverable without the manifest (§6.1).
* Archive Header `version` MUST be used by readers to select the correct Master Trailer layout (`0x0002` = R1/R2 16-bit `group\_id`; `0x0003` = R3 32-bit `group\_id`, no per-frame `version` field) (§2.1).
* Frame Packing MUST fail fast (not loop) when a single file cannot fit into a freshly initialized, empty frame, and MUST escalate it to the multi-frame path (§8.2).
* A manifest line MUST NOT exceed `MAX\_MANIFEST\_LINE\_BYTES` (1 MiB); readers MUST treat an oversized line as corruption rather than buffer it (§10.1).
* A logical file with more fragments than fit in one manifest line MUST use `ADD_BEGIN`/`ADD_EXTENT`/`ADD_COMMIT`; the transaction becomes visible only after `ADD_COMMIT`.
* `extent_index` is contiguous and explicit; fragment ordering MUST NOT depend on JSON array position alone.
* Frame-payload AES-GCM nonces use independent `(blob_id, blob_local_counter)` namespaces and MUST NOT use a shared global frame counter.
* `blob_id = 0xFFFFFFFF` is reserved and MUST NOT be assigned to a blob.
* Frame-payload, Pre-Trailer, and manifest encryption nonce domains MUST be distinct.
* A GC-blocked generation MUST expose missing fragment references; Emergency Pruning is the only explicit override and MUST mark affected logical files degraded/unrecoverable.
* Data-frame writes may be parallel, but each blob append position is serialized.
* Manifest commits are serialized and have strictly increasing `seq`.
* A manifest MUST NOT reference a frame before that frame is durably committed.
* Compaction MUST never overwrite the active generation in place.
* Compaction MUST provide a concurrency-safe Freeze/Merge/Switch operation.
* Compaction MUST NOT split a parity group across generations, and MUST re-verify the §2.4 spread rule after any blob reassignment (§13.6).
* Compaction Mark MUST resolve liveness against the complete reachable manifest graph, not a single sub-manifest's local scope (§13.1).
* Compaction MUST NOT split a multi-frame logical file's fragments across generations; the old generation MUST NOT be deleted until every fragment of every live multi-frame file has been verified copied (§13.7).
* Compaction on encrypted archives MUST treat ciphertext as opaque and MUST NOT decrypt/re-encrypt live frames during Sweep (§13.2, §15.1.7).
* Root-generation switching MUST be atomic.
* Encryption protects both payload and sensitive Pre-Trailer metadata.
* In encrypted mode, plaintext path/version data MUST NOT appear in the manifest; encrypted records use the `ADD\_ENC`/`DEL\_ENC` format of §15.1.5, with `seq`/`op` bound as AAD.
* AEAD nonces are 12 bytes and constructed deterministically per §15.1.2 — never purely random.
* Without encryption keys, encrypted archives remain frame-recoverable and parity-group-recoverable, but not path-reconstructable.

\---

## 17\. Production Readiness Checklist

Before calling an implementation production-ready, verify:

* \[ ] All blobs contain valid identical headers.
* \[ ] `BLOCK\_STRIDE` is exactly `frame\_size`.
* \[ ] Frame offsets start at `0x30`.
* \[ ] Header disagreement is detected.
* \[ ] Frame hashes are calculated over stored payload bytes.
* \[ ] Zstd parameters are canonical and documented; the same holds for every other enabled codec (LZ4/LZMA/Brotli).
* \[ ] Packed-frame compression is tested with incompressible and highly compressible data.
* \[ ] Packed offsets are tested after decompression.
* \[ ] Non-packed multi-frame fragment offsets are tested for correct global-offset semantics and correct reassembly ordering.
* \[ ] `data\_len` is rejected when it exceeds `frame\_size - 48 - 4 - pre\_trailer\_body\_size`, not merely `frame\_size - 48 - 4`.
* \[ ] `pre\_trailer\_body\_start` alignment (multiple of 8 bytes) is enforced on write and validated on read; misaligned frames are rejected.
* \[ ] A corrupted `frame\_size\_class` byte cannot trigger an allocation above the configured production ceiling before header validation runs.
* \[ ] Archive initialization rejects `parity\_scheme != none` combined with `blob\_count == 1`.
* \[ ] Parity-group membership (`group\_id`/`group\_index`) is reconstructed correctly from a raw frame scan with the manifest deleted, including at `group\_id` values beyond 65,535.
* \[ ] Frame Packing is tested with a single oversized-path file in an otherwise-empty frame and fails fast with an escalation error rather than looping.
* \[ ] Reverse manifest scanning is tested with a manifest line exceeding `MAX\_MANIFEST\_LINE\_BYTES` and treats it as corruption rather than buffering unbounded memory.
* \[ ] Readers correctly dispatch Master Trailer parsing on Archive Header `version` (`0x0002` vs `0x0003`).
* \[ ] CRC32C corruption tests cover `entry\_count`, paths, offsets, versions, and CRC itself.
* \[ ] Manifest append serialization is tested under concurrency.
* \[ ] Blob append allocation is tested under concurrency.
* \[ ] Frame durability precedes manifest durability.
* \[ ] Compaction is tested with continuous concurrent writes.
* \[ ] Compaction is tested to confirm no parity group is ever split across generations, and the §2.4 spread rule holds in the new generation.
* \[ ] Compaction is tested with a multi-frame file whose fragments are only partially referenced by the sub-manifest that triggered the compaction run, confirming Mark resolves liveness against the full manifest graph and no fragment is dropped.
* \[ ] Compaction on an encrypted archive is tested to confirm ciphertext bytes are byte-identical before and after Sweep (no re-encryption, no nonce reassignment).
* \[ ] Crash injection is tested at every Switch boundary.
* \[ ] Old generations remain readable after interrupted compaction.
* \[ ] Encrypted metadata cannot leak paths or versions.
* \[ ] Encrypted manifest records (`ADD\_ENC`/`DEL\_ENC`) are rejected when AAD (`seq`/`op`) does not match the record.
* \[ ] AEAD nonce construction is verified deterministic and non-colliding (archive\_id prefix + monotonic counter), not randomly generated.
* \[ ] Key loss is explicitly tested as a recoverability boundary.
* \[ ] Disaster recovery is tested with Blob 0 missing.
* \[ ] Disaster recovery is tested with an arbitrary non-zero blob missing.
* \[ ] Disaster recovery is tested with corrupted Pre-Trailer metadata.
* \[ ] Disaster recovery is tested with corrupted frame payloads and available parity, using only `group\_id`/`group\_index` from raw frames (manifest absent).

