# 🌀 STASH

## Version 2.0 — Consolidated Specification
### Revision R7 — Production / Enterprise Hardening (Dual Frame Geometry, Self-Describing Placement, Indexed Access, and Crash-Safe Recovery)

**Status:** Final / Approved Specification  
**Wire version:** `0x0005`  
**Target:** Server / enterprise / datacenter / petabyte-scale storage  
**Out of scope:** General-purpose desktop archive use, tape/cold-storage profiles, sub-block/CDC deduplication

R7 is a wire-breaking consolidation of R5 plus the R6 Grid-Aligned Variable Frames change set. It introduces a CRC-protected 96-byte Master Trailer, a CRC-protected 64-byte self-identifying blob prefix, explicit physical and logical geometry, versioned generation identity, a mandatory rebuildable offset index, and an immutable archive-level choice between `VARIABLE` and `FIXED` frame sizing. Readers MUST dispatch on the Archive Header `version`; an R7-only reader MUST reject older layouts rather than guess.

The final R7 allocation consumes fields that were reserved in pre-final R7 drafts. A `0x0005` blob or frame lacking valid R7 prefix/trailer CRC32C values is invalid; pre-final drafts are not a separate compatibility profile.

---

## 0. Design Priorities

Implementations MUST preserve these priorities in this order:

1. **Deterministic bounded geometry** — every frame has a validated extent of `N × 4096` bytes; FIXED archives additionally provide direct slot arithmetic.
2. **Self-describing recovery** — every non-packed DATA frame carries its logical identity and placement independently of `manifest.jsonl` and the derived offset index.
3. **Whole-frame stored-payload integrity and deduplication** — STASH does not deduplicate sub-block content.
4. **Throughput at enterprise scale** — per-blob writes remain parallel, hot-path lookups use a maintained offset index, and all allocations are bounded before untrusted sizes are honored.

The offset index is load-bearing for normal-path performance but never for correctness: it MUST be rebuildable from the blobs. The encryption profile is an explicit recoverability boundary: frame geometry, ciphertext integrity, logical placement, and parity membership remain discoverable without keys; plaintext paths and versions require the appropriate key.

---

## 1. Overview

STASH is an append-only, verifiable archival format for cloud-native and datacenter workflows.

Input is stored in immutable grid-aligned frames. Every frame occupies a complete physical extent whose size is a positive multiple of `BASE_QUANTUM = 4096` bytes and includes payload, zero padding, Pre-Trailer, and a fixed 96-byte Master Trailer. The archive chooses one immutable size mode:

- `VARIABLE`: each frame selects its own valid `frame_size`, up to `MAX_FRAME_SIZE`;
- `FIXED`: every frame occupies exactly `MAX_FRAME_SIZE`.

Updates append new frames and manifest records. A committed frame is never overwritten in place.

Each blob begins with a 64-byte self-identifying prefix: a 48-byte immutable Archive Header, an 8-byte `generation_id`, a 1-byte `blob_ordinal`, three reserved zero bytes, and a 4-byte CRC32C covering the complete prefix with its own field treated as zero. Frames begin at `FRAME_REGION_START = 0x40`.

```text
+--------------------------------+ 0x00
| Archive Header (48 B)          |
+--------------------------------+ 0x30
| generation_id (8 B)            |
+--------------------------------+ 0x38
| blob_ordinal (1 B)             |
| Reserved zero prefix (3 B)     |
+--------------------------------+ 0x3C
| Prefix CRC32C (4 B)            |
+--------------------------------+ 0x40
| Frame 0 (N × 4096 B)           |
+--------------------------------+
| Frame 1 (M × 4096 B)           |
+--------------------------------+
| ...                            |
+--------------------------------+
```

For VARIABLE mode:

```text
frame_start(0)   = 0x40
frame_start(n+1) = frame_start(n) + frame_size(n)
```

For FIXED mode:

```text
frame_start(n) = 0x40 + n × MAX_FRAME_SIZE
```

`frame_hash` in the manifest is the Master Trailer's `hash_payload`. It identifies stored payload bytes, not a unique physical position; the per-blob offset index resolves it to one or more candidate physical offsets (§10.3).

---

## 2. Archive, Blob, and Generation Model

The immutable Archive Header is exactly 48 bytes and MUST be present at offset `0x00` of every blob. All multi-byte integers are little-endian. The remaining 16 bytes form the generation descriptor and checksum defined in §2.2.

### 2.1 Header fields

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | `magic` | char[4] | `STSH` |
| `0x04` | 2 | `version` | uint16 | `0x0005` for R7 |
| `0x06` | 1 | `max_frame_size_class` | uint8 | Selects `MAX_FRAME_SIZE`; see §3.1 |
| `0x07` | 1 | `hash_id` | uint8 | See §4 |
| `0x08` | 1 | `codec_id` | uint8 | Archive default; per-frame override allowed |
| `0x09` | 1 | `parity_scheme` | uint8 | See §7 |
| `0x0A` | 1 | `parity_k` | uint8 | Data frames per parity group |
| `0x0B` | 1 | `parity_m` | uint8 | Parity frames per parity group |
| `0x0C` | 1 | `blob_count` | uint8 | Active blobs per generation, `1..255` |
| `0x0D` | 1 | `frame_size_mode` | uint8 | `0x00 = VARIABLE`, `0x01 = FIXED` |
| `0x0E` | 2 | `archive_flags` | uint16 | Bit `0x0001 = ENCRYPTED`; all other bits MUST be zero in R7 |
| `0x10` | 32 | `archive_id` | bytes | Random UUID, zero-padded to 32 bytes |

All Header fields are immutable for the life of the archive, including across compaction generations. In particular, `frame_size_mode` and `archive_flags` MUST NOT change through migration, compaction, or generation switching. Changing either requires creation of a new archive instance and an explicit data migration. A reader MUST reject any unknown R7 `archive_flags` bit.

**Version dispatch:** `0x0002` selects the R1/R2 trailer, `0x0003` selects the R3-R5 48-byte trailer, `0x0004` is reserved for the R6 development layout, and `0x0005` selects the R7 96-byte trailer. A reader MUST NOT parse one layout as another.

### 2.2 Self-identifying blob prefix, checksum, and validation

The bytes following the 48-byte Header are:

| Blob offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x30` | 8 | `generation_id` | uint64 | Containing published generation; see §2.4 |
| `0x38` | 1 | `blob_ordinal` | uint8 | Blob position in this generation, `0..blob_count-1` |
| `0x39` | 3 | `prefix_reserved` | bytes[3] | MUST be zero in R7 |
| `0x3C` | 4 | `prefix_crc32c` | uint32 | CRC32C of the complete 64-byte prefix with this field treated as zero |

Throughout R7, CRC32C means the reflected Castagnoli algorithm with polynomial `0x82F63B78`, initial value `0xFFFFFFFF`, and final XOR `0xFFFFFFFF`; the check value for ASCII `123456789` is `0xE3069283`. Stored uint32 CRC values are little-endian.

To calculate `prefix_crc32c`, a writer serializes the complete 64-byte prefix with bytes `0x3C..0x3F` set to zero, calculates CRC32C over bytes `0x00..0x3F`, and stores the result at `0x3C` in little-endian form. The checksum therefore covers every immutable Header field as well as `generation_id`, `blob_ordinal`, and `prefix_reserved`.

A reader MUST read the complete 64-byte blob prefix into a fixed-size buffer, calculate and compare `prefix_crc32c`, verify `prefix_reserved == 0`, and only then trust any Header- or generation-derived field or allocate frame-sized buffers. A valid magic with an invalid Prefix CRC is corruption.

The repeated checksummed prefix removes Blob 0 and external filenames as single points of recovery failure. A reader MUST:

- validate the Prefix CRC of each available blob independently;
- verify that all valid prefixes selected for one generation agree on every immutable Header parameter, `archive_id`, and `generation_id`;
- require each selected `blob_ordinal` to be in range and unique within the generation;
- reject a filename/root binding whose declared generation or blob ordinal disagrees with its CRC-valid prefix;
- reject the archive as inconsistent if two CRC-valid prefixes claiming the same `(archive_id, generation_id, blob_ordinal)` disagree;
- permit recovery with a subset of blobs when at least one valid prefix remains, while explicitly reporting missing ordinals;
- enforce its configured allocation ceiling before allocating a buffer derived from the Header.

CRC32C provides accidental-corruption detection, not cryptographic authenticity. Deployments requiring tamper resistance MUST use the encrypted/authenticated profile or an external authenticated envelope.

### 2.3 Blob files

Blob files are named:

```text
frames/blob-00.stash
frames/blob-01.stash
...
frames/blob-FE.stash
```

For `blob_count = N`, valid `blob_ordinal` values are `0..N-1`. `blob_count` is the number of active blobs in one generation, not a global historical count.

The canonical filename ordinal MUST agree with the CRC-valid `blob_ordinal` stored in the prefix during normal operation. Raw recovery MUST use the stored ordinal rather than infer identity from an untrusted or lost filename.

Frame-to-blob assignment is a write-time decision. A conformant implementation MUST ensure that two writers never allocate overlapping physical extents in one blob. The required concurrency model is one serialized append allocator per blob; different blobs MAY be appended in parallel.

### 2.4 Generation identity

Each successfully published generation has a `generation_id : uint64` stored redundantly in every blob prefix and in its generation metadata/root namespace:

```text
initial generation_id = 0
next generation_id    = previous generation_id + 1
```

`generation_id` is not a physical frame position and is deliberately outside the immutable 48-byte Archive Header because it changes when a new generation is published. It MUST be unique and MUST NOT be reused under the same archive encryption key. Generation metadata/root identity MUST agree with every selected CRC-valid blob prefix. A mismatch is corruption or a mixed-generation input set, never an override.

At cold start, a writer or compactor MAY discover the highest existing value from generation metadata and CRC-valid blob prefixes and chooses `max(generation_id) + 1`, rejecting uint64 wraparound. During raw recovery, the tuple `(archive_id, generation_id, blob_ordinal)` in the checksummed prefix is authoritative for classifying otherwise detached or renamed blobs; directory and filename structure is only a hint.

The tuple `(generation_id, blob_ordinal, frame_ordinal)` is the creation namespace for newly encrypted frame material (§15.3). The prefix values identify the **containing generation and blob**. After byte-preserving compaction, they need not identify the historical creation namespace of every copied frame. Readers MUST NOT derive a copied frame's nonce from its current prefix or position: every AEAD nonce is stored with its ciphertext representation, so decryption and recovery do not require reconstructing the historical tuple.

### 2.5 Parity-group spread

When `blob_count > 1`, DATA/PACKED members and PARITY frames belonging to one parity group MUST span at least two distinct blobs. Implementations MUST enforce this at the library boundary.

### 2.6 Global parity invariant

If `parity_scheme != 0x00`, then `blob_count MUST be >= 2`. A single-blob archive declaring active parity is invalid.

When `parity_scheme == 0x00`, `parity_k` and `parity_m` MUST both be zero. When parity is active, both MUST be non-zero and `parity_k + parity_m <= 256` so every position fits the uint8 `group_index`; XOR additionally requires `parity_m == 1`.

---

## 3. Physical and Logical Geometry

### 3.1 Constants and maximum size class

```text
BASE_QUANTUM       = 4096 bytes
ARCHIVE_HEADER_SIZE = 48 bytes
BLOB_PREFIX_SIZE    = 64 bytes
MASTER_TRAILER_SIZE = 96 bytes
PRE_TRAILER_LEN_SIZE = 4 bytes
FRAME_REGION_START = 0x40
```

`max_frame_size_class` selects the immutable archive maximum:

| Value | Size | Value | Size | Value | Size |
|---|---:|---|---:|---|---:|
| `0x00` | 4 KiB | `0x06` | 256 KiB | `0x0C` | 16 MiB |
| `0x01` | 8 KiB | `0x07` | 512 KiB | `0x0D` | 32 MiB |
| `0x02` | 16 KiB | `0x08` | 1 MiB | `0x0E` | 64 MiB |
| `0x03` | 32 KiB | `0x09` | 2 MiB | `0x0F` | 128 MiB |
| `0x04` | 64 KiB | `0x0A` | 4 MiB | `0x10` | 256 MiB |
| `0x05` | 128 KiB | `0x0B` | 8 MiB |  |  |

```text
MAX_FRAME_SIZE = size(max_frame_size_class)
MAX_FRAME_QUANTA = MAX_FRAME_SIZE / BASE_QUANTUM
MAX_LOGICAL_FRAME_LENGTH = MAX_FRAME_SIZE
```

Production writers MUST NOT create an archive with `max_frame_size_class > 0x0E` (64 MiB) without an explicit non-default profile. A reader MUST validate the class against its configured ceiling before allocating a frame-sized buffer. Values `0x0F` and `0x10` remain format-reserved opt-in profiles.

### 3.2 Physical frame geometry

For every frame:

```text
frame_size = frame_quanta × BASE_QUANTUM
1 <= frame_quanta <= MAX_FRAME_QUANTA
4096 <= frame_size <= MAX_FRAME_SIZE
frame_size mod BASE_QUANTUM = 0
```

In `VARIABLE` mode, each frame MAY choose any value satisfying those invariants. In `FIXED` mode:

```text
frame_size   = MAX_FRAME_SIZE
frame_quanta = MAX_FRAME_QUANTA
```

A new archive writer SHOULD default to `VARIABLE` unless the caller explicitly selects `FIXED`; the chosen value is always encoded in the Header and never inferred from observed frames.

A FIXED-mode reader MUST treat any other `frame_quanta` as corruption. This check is mandatory even when the slot start was calculated arithmetically.

`physical_offset` is the byte offset of the frame from the beginning of its blob. `physical_frame_size` is `frame_size`. Neither value is a logical-file offset.

### 3.3 Logical frame geometry

For a non-packed DATA frame:

```text
logical_offset : uint64
logical_length : uint64
logical_offset mod BASE_QUANTUM = 0
0 < logical_length <= MAX_LOGICAL_FRAME_LENGTH
```

The claimed logical range is the half-open interval:

```text
[logical_offset, logical_offset + logical_length)
```

The addition MUST be checked for uint64 overflow. `logical_length` is the exact uncompressed logical byte count represented by the frame; it is distinct from stored `data_len`. The final quantum of the complete object MAY be only partially used. For a non-sparse multi-frame object, every non-final extent MUST have `logical_length mod BASE_QUANTUM == 0`; otherwise the next aligned extent would create a gap or overlap. A compressed frame MAY have `logical_length > data_len`, but decoded output MUST equal `logical_length` exactly and MUST never exceed the archive maximum above. For STORE, decrypted/plain payload length MUST equal `logical_length`; encryption overhead remains part of `data_len`, not logical length.

PACKED frames do not use trailer-level `logical_offset`/`logical_length`; their per-file `inner_off`/`inner_len` values are defined in §6.2 and §8, and the complete uncompressed packed buffer MUST NOT exceed `MAX_LOGICAL_FRAME_LENGTH`. PARITY frames have no logical object range.

### 3.4 Exact payload budget

Define:

```text
pre_trailer_total_size = pre_trailer_body_size + PRE_TRAILER_LEN_SIZE
payload_capacity =
    frame_size
  - MASTER_TRAILER_SIZE
  - pre_trailer_total_size

padding_len = payload_capacity - data_len
```

A valid frame MUST satisfy:

```text
data_len >= 0
pre_trailer_body_size >= 8
payload_capacity >= 0
padding_len >= 0
data_len + padding_len + pre_trailer_total_size
    + MASTER_TRAILER_SIZE == frame_size
```

The `data_len` field includes any stored payload nonce and authentication tag. `pre_trailer_body_size` likewise means the exact stored body representation: plaintext body in the base profile or `nonce || ciphertext || tag` in the encrypted profile. There is no implicit extra allowance. Every byte in the physical frame is accounted for by this equation.

The padding region between stored payload and Pre-Trailer body MUST be zero-filled and is excluded from `hash_payload`.

### 3.5 Logical Recovery Grid

The Logical Recovery Grid uses the same 4096-byte quantum as the physical extent grid, but the two coordinate spaces are independent:

```text
logical_sector = logical_offset / BASE_QUANTUM
quantum_count  = ceil(logical_length / BASE_QUANTUM)
```

A recovery implementation MAY represent an object as an in-memory map of Logical Recovery Quanta and map each validated DATA frame onto its claimed range. This is an implementation model, not an additional wire representation.

---

## 4. Hash Algorithms

|Value|Algorithm|Digest|
|-|-|-:|
|`0x00`|reserved|—|
|`0x01`|BLAKE3|32 B|
|`0x02`|SHA-256|32 B|
|`0x03`|SHA3-256|32 B|
|`0x04–0xFF`|reserved|—|

The archive's `hash_id` is fixed for its lifetime.

### 4.1 Hash scope

`hash_payload` MUST be calculated over the exact bytes stored in the frame's payload region, before padding and before the Pre-Trailer and Master Trailer are appended.

In the normal unencrypted case this is `compressed_payload`. In encrypted mode this is the encrypted payload representation, including its nonce/AEAD overhead as specified in §15.2.

The hash MUST NOT cover:

* zero padding;
* Pre-Trailer;
* Master Trailer;
* the blob's Archive Header.

This makes stored-payload deduplication dependent on byte-identical stored payload representations. Placement metadata is outside the digest, so equal hashes are not unique physical-frame identities (§10.3).

---

## 5. Compression Codecs

|Value|Codec|
|-|-|
|`0x00`|STORE|
|`0x01`|LZ4|
|`0x02`|Zstd|
|`0x03`|LZMA|
|`0x04`|Brotli|
|`0x05–0xFF`|reserved|

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

All multi-byte integers are little-endian. Every frame has the following complete physical representation:

```text
[ compressed_payload / encrypted_payload ]
[ zero padding ]
[ stored_pre_trailer_body ]
[ pre_trailer_len : uint32_le ]
[ Master Trailer : 96 B ]
```

The Master Trailer is always the final 96 bytes of the frame.

### 6.1 Master Trailer

The R7 Master Trailer is exactly 96 bytes:

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | `magic` | char[4] | `STSH` |
| `0x04` | 1 | `hash_id` | uint8 | MUST match Archive Header |
| `0x05` | 1 | `codec_id` | uint8 | Codec used for this frame |
| `0x06` | 1 | `block_type` | uint8 | `0x00 = DATA`, `0x01 = PARITY`, `0x02 = PACKED` |
| `0x07` | 1 | `group_index` | uint8 | Position `0..k+m-1`; zero when `group_id == 0` |
| `0x08` | 4 | `group_id` | uint32 | Archive-scoped parity-group ID; zero means no group |
| `0x0C` | 4 | `data_len` | uint32 | Exact stored payload representation length |
| `0x10` | 32 | `hash_payload` | bytes[32] | Hash of the exact stored payload representation |
| `0x30` | 4 | `frame_quanta` | uint32 | Physical extent in 4096-byte quanta |
| `0x34` | 4 | `trailer_crc32c` | uint32 | CRC32C of the 96-byte Master Trailer with this field treated as zero |
| `0x38` | 16 | `object_id` | bytes[16] | Versioned logical-object identity; zero for PACKED/PARITY |
| `0x48` | 8 | `logical_offset` | uint64 | Global logical byte offset for non-packed DATA |
| `0x50` | 8 | `logical_length` | uint64 | Logical bytes represented by non-packed DATA |
| `0x58` | 8 | `frame_ordinal` | uint64 | Immutable creation ordinal within a writer namespace |

The first 48 bytes preserve the R5 core field order; the placement extension occupies the final 48 bytes. The trailer is not optional for PACKED or PARITY frames: fields without meaning for their block type are encoded as zero and validated as such.

#### 6.1.1 Block-type invariants

**DATA (`0x00`):**

- `object_id` MUST be non-zero;
- `logical_offset` and `logical_length` MUST satisfy §3.3;
- the Pre-Trailer MUST contain exactly one entry matching the same logical placement and versioned object identity;
- empty committed DATA frames are forbidden.

If the deterministic object-ID derivation produces sixteen zero bytes, the writer MUST fail rather than encode the value reserved for PACKED/PARITY.

**PACKED (`0x02`):**

- `object_id`, `logical_offset`, and `logical_length` MUST be zero;
- the Pre-Trailer MUST contain at least one packed-file entry;
- per-file placement is carried only by `inner_off`/`inner_len` in the Pre-Trailer.

**PARITY (`0x01`):**

- `object_id`, `logical_offset`, and `logical_length` MUST be zero;
- `group_id` MUST be non-zero and `group_index` MUST select a parity slot;
- the Pre-Trailer MUST contain zero entries.

For any block type, `frame_size = frame_quanta × BASE_QUANTUM` and the exact payload-budget equation in §3.4 MUST hold. In FIXED mode, `frame_quanta` MUST equal `MAX_FRAME_QUANTA`; mismatch is corruption.

#### 6.1.2 Parity identity

`group_id` is scoped to the archive, not one blob. Every member of a parity group self-describes its membership with identical non-zero `group_id` and a unique `group_index`. Data slots are `0..parity_k-1`; parity slots are `parity_k..parity_k+parity_m-1`. Writers MUST treat uint32 wraparound as a fatal error and MUST NOT reuse an active or historical group ID in the same archive.

#### 6.1.3 Frame ordinal

For newly created frames, `frame_ordinal` is allocated monotonically within `(generation_id, blob_ordinal)`, beginning at zero. It is not a physical byte offset and, after byte-preserving compaction, need not equal the destination FIXED slot number.

On cold writer start, the next ordinal MAY be discovered by scanning valid trailers in the active generation and choosing `max(frame_ordinal) + 1`. This is conceptually the same recovery pattern as `generation_id` discovery (§2.4). Wraparound is fatal. A writer MUST NOT reuse a previously minted `(generation_id, blob_ordinal, frame_ordinal)` tuple under the same encryption key.

#### 6.1.4 Master Trailer CRC32C

`trailer_crc32c` uses the R7 CRC32C definition in §2.2. A writer MUST:

1. serialize the complete 96-byte Master Trailer with bytes `0x34..0x37` set to zero;
2. calculate CRC32C over all 96 bytes;
3. store the result at `0x34` in little-endian form.

A reader calculates the same value while logically treating bytes `0x34..0x37` as zero and compares it with the stored field. The checksum therefore covers magic, codec/hash/type fields, parity identity, `data_len`, `hash_payload`, `frame_quanta`, object placement, and `frame_ordinal`.

The reader MUST validate `trailer_crc32c` before trusting any trailer field for allocation, logical placement, parity grouping, or ordinal discovery. During raw VARIABLE scanning, a candidate with valid magic but invalid trailer CRC is not a frame candidate and scanning continues at the next quantum boundary.

CRC32C detects accidental corruption and materially strengthens keyless recovery; it is not a substitute for the encrypted profile's AEAD authenticity.

### 6.2 Pre-Trailer

The stored Pre-Trailer is:

```text
[ stored_pre_trailer_body ][ pre_trailer_len : uint32_le ]
```

`pre_trailer_len` is the exact byte length of `stored_pre_trailer_body`. In the unencrypted profile, the stored body is the plaintext body. In the encrypted profile, it is `nonce[12] || ciphertext || tag[16]`; see §15.2 and §15.4.

The plaintext body is:

```text
uint32_le entry_count
repeated entry_count times:
    varint     path_len
    bytes      canonical_path_utf8
    uint64_le  inner_off
    uint64_le  inner_len
    uint64_le  file_ver
bytes zero_metadata_padding[0..7]
uint32_le crc32c
```

The body is self-delimiting: after exactly `entry_count` entries have been parsed, every remaining byte before the final CRC32C is metadata padding and MUST be zero.

#### 6.2.1 CRC coverage and alignment

CRC32C, as defined in §2.2, covers every plaintext-body byte preceding the CRC field, including `entry_count`, all entries, and zero metadata padding. It does not cover `pre_trailer_len`.

Define `ALIGNMENT = 8`. The writer MUST choose `zero_metadata_padding` so that the **stored** Pre-Trailer representation satisfies:

```text
(pre_trailer_len + PRE_TRAILER_LEN_SIZE) mod ALIGNMENT = 0
```

Because `frame_size` and `MASTER_TRAILER_SIZE` are both multiples of 8, this guarantees:

```text
(pre_trailer_body_start - frame_start) mod ALIGNMENT = 0
```

This padding is inside the authenticated/CRC-protected Pre-Trailer body. Payload padding cannot change a reverse-anchored body start and MUST NOT be used to claim this alignment property.

The reader MUST authenticate/decrypt when applicable, verify CRC32C, validate zero metadata padding, and only then trust `entry_count`, paths, offsets, lengths, or versions.

#### 6.2.2 Entry offset semantics

**PACKED frames:** `inner_off` and `inner_len` identify one file inside the uncompressed packed buffer:

```text
logical_buffer = file_1 || file_2 || ... || file_n
```

They are never physical offsets and never synonyms for trailer-level `logical_offset`/`logical_length`.

**Non-packed DATA:** the single entry's `inner_off` is the global logical byte offset of this fragment and MUST equal the Master Trailer's `logical_offset`. `inner_len` MUST equal the Master Trailer's `logical_length`. The manifest `loc` tuple MUST carry the same values.

#### 6.2.3 Object identity

For a canonical path and per-path `file_ver`, the 16-byte object identity is:

```text
object_id = first_16_bytes(
    HASH_hash_id(
        "STASH-OBJECT-ID-V1" ||
        uint32_le(path_byte_length) ||
        canonical_path_utf8 ||
        uint64_le(file_ver)
    )
)
```

The length prefix and fixed domain label are mandatory. Every non-packed fragment of that `(canonical_path, file_ver)` MUST carry the same `object_id`. A reader that can decrypt the path metadata MUST recompute and verify the value. Two distinct decoded `(path, file_ver)` pairs producing one `object_id` are a `CORRUPTION / ID_COLLISION` condition, never an implicit merge.

`object_id` is deliberately not stable across rename: a changed canonical path produces a new object ID. R7 has no manifest-level path-to-stable-UUID indirection. A rename is therefore a new logical object/version and requires new self-describing frame placement; old frames remain addressable until GC.

#### 6.2.4 Limits

Normative limits:

- `MAX_PACKED_ENTRIES = 65535`;
- `path_len <= 4096` bytes;
- `MIN_PAYLOAD_RESERVE = 64` bytes for DATA/PACKED writer fit decisions.

The maximum stored Pre-Trailer body that a DATA/PACKED writer may select is:

```text
max_pre_trailer_body =
    frame_size
  - MASTER_TRAILER_SIZE
  - PRE_TRAILER_LEN_SIZE
  - MIN_PAYLOAD_RESERVE
```

A writer MUST account for metadata alignment padding and encryption overhead incrementally while packing.

### 6.3 Deterministic reverse parsing

When `frame_start` and `frame_size` are known, the reader MUST:

1. compute `frame_end = frame_start + frame_size`, rejecting overflow;
2. read the final 96 bytes as the R7 Master Trailer;
3. validate `trailer_crc32c` before trusting any trailer-derived size or identity;
4. validate magic, block type, `frame_quanta`, size-mode rules, group fields, placement fields, and `data_len`;
5. read `pre_trailer_len` at `frame_end - 96 - 4`;
6. reject any length that exceeds the exact frame bounds;
7. compute `pre_trailer_body_start = frame_end - 96 - 4 - pre_trailer_len`;
8. verify Pre-Trailer alignment and non-overlap with the stored payload;
9. verify every payload-padding byte is zero;
10. hash exactly `[frame_start, frame_start + data_len)` and compare it with `hash_payload`;
11. authenticate/decrypt the Pre-Trailer when enabled, verify CRC32C, then parse entries;
12. enforce the block-type-specific consistency rules in §6.1.1.

When an encrypted Pre-Trailer key is unavailable, steps 10-11 cannot establish plaintext metadata validity. The reader MAY still classify the frame as **physically/hash valid but metadata opaque** after all keyless structural, bounds, padding, and `hash_payload` checks succeed. It MUST NOT claim full semantic validation or invent PACKED entries.

Raw discovery when `frame_size` is not yet known is defined in §11.2.

---

## 7. Parity / Erasure Coding

| Value | Scheme | Tolerance |
|---|---|---:|
| `0x00` | none | 0 |
| `0x01` | XOR | 1 frame/group |
| `0x02` | Reed-Solomon | `parity_m` frames/group |
| `0x03` | LRC | tunable; EXPERIMENTAL |

The scheme and parameters are immutable archive properties. Mixing schemes in one archive is forbidden.

A group is closed only after all required data members (DATA or PACKED) are fixed. PARITY frames MUST be written only after group membership is fixed. All DATA, PACKED, and PARITY members of one group MUST use an identical physical `frame_size` and therefore identical `frame_quanta`. This is a hard structural invariant; a mixed-extent group is corrupt. In FIXED mode the invariant follows automatically from the archive geometry but MUST still be validated.

Every group member carries `group_id` and `group_index` in its own Master Trailer. Raw recovery therefore buckets frames by `group_id`, validates unique positions and equal geometry, and reconstructs missing members without the manifest.

Parity payload identity is the exact stored parity payload representation, and `hash_payload` covers those exact bytes. Padding, Pre-Trailer, and Master Trailer remain outside the hash scope.

The manifest MAY record a non-authoritative management entry:

```json
{"seq":77,"op":"PARITY_GROUP","group_id":42,"frame_quanta":1024,"data_frames":[[0,"hash1"],[3,"hash2"]],"parity_frames":[[7,"phash1"]]}
```

Each reference is `[blob_ordinal, frame_hash]`. The entry MUST agree with scanned frame metadata when both are available; disagreement is corruption, not an override.

---

## 8. Frame Packing

Frame Packing aggregates small files into one frame with `block_type = PACKED`. It operates identically at the logical level in VARIABLE and FIXED archives.

### 8.1 Packing order and representation

Files MUST be sorted lexicographically by canonical UTF-8 path before packing. The writer constructs:

```text
logical_buffer = file_1_bytes || file_2_bytes || ... || file_n_bytes
stored_payload = CODEC(logical_buffer)
```

The frame's Pre-Trailer records one entry per packed file. `inner_off`/`inner_len` address the uncompressed `logical_buffer`. The frame hash covers `stored_payload` exactly.

In VARIABLE mode, the writer SHOULD select the smallest valid grid-aligned `frame_size` that satisfies the exact payload budget after compression, metadata padding, and optional encryption overhead. In FIXED mode, every PACKED frame occupies `MAX_FRAME_SIZE`; unused capacity is zero padding.

### 8.2 Packing fit algorithm

Compressed size is not known from logical input size. A compliant writer MUST:

1. accumulate a candidate set in canonical path order;
2. build and compress the candidate logical buffer using the selected canonical codec profile;
3. build the complete stored Pre-Trailer representation, including metadata alignment and encryption overhead;
4. select a valid VARIABLE extent or the sole FIXED extent;
5. accept the candidate only if the exact §3.4 equation succeeds;
6. otherwise seal the previous non-empty candidate and retry the new file alone.

If a single file fails to fit into a fresh empty candidate at `MAX_FRAME_SIZE`, the writer MUST immediately return a distinct packing-overflow result and route the file to the non-packed multi-frame path. It MUST NOT retry the same file indefinitely in new empty PACKED frames.

### 8.3 Packed frame determinism

Byte-identical packed output requires identical canonical paths, ordering, contents, file versions, codec, canonical codec parameters, encryption representation, and packing policy. The format does not claim cross-implementation byte identity from equal logical input alone.

---

## 9. Manifest and Logical Object Semantics

`manifest.jsonl` is the append-only journal authoritative for current path state. Frames remain immutable and self-describing; physical offsets remain derived placement data.

### 9.1 Core records

```json
{"seq":1,"ts":1739550001,"op":"ADD","path":"src/main.go","ver":2,"object_id":"4cf0...32 hex chars...","total_len":4096,"loc":[[0,"f5a2...64 hex chars...",0,4096]]}
{"seq":2,"ts":1739550002,"op":"ADD","path":"big/dataset.bin","ver":1,"object_id":"ca11...32 hex chars...","total_len":100663296,"loc":[[3,"aaa1...",0,67108864],[17,"bbb2...",67108864,33554432]]}
{"seq":3,"ts":1739550123,"op":"DEL","path":"src/utils.go","ver":2}
```

`seq : uint64` is strictly increasing within one manifest generation. `ts` is informational and MUST NOT determine logical order. JSON integers used by normative fields MUST be non-negative and exactly representable as their declared unsigned type; readers MUST reject floating-point or exponent forms for these fields.

### 9.2 Version and rename semantics

Before hashing, sorting, or comparison, a path MUST be canonicalized as well-formed UTF-8 in Unicode NFC, with `/` as separator, no leading slash, no NUL, no empty component, and no `.` or `..` component. Drive letters and backslashes are not wire-path syntax. Case is preserved; deployments MUST NOT apply locale-dependent case folding. The canonical byte sequence is used unchanged by Frame Packing, manifest identity, and `object_id` derivation.

`ver : uint64` is monotonically increasing per canonical path. Two operations MUST NOT commit competing current states with the same `(path, ver)`.

`object_id` MUST equal the derivation in §6.2.3. It identifies one versioned logical object, not a stable inode. Consequently:

- a content replacement at the same path increments `ver` and produces a new `object_id`;
- a rename changes `canonical_path` and produces a new `object_id`;
- R7 defines no needs-no-rewrite rename alias;
- old frames remain immutable and addressable until they are proven dead and reclaimed by GC.

A rename is committed as a new self-describing ADD for the destination followed by a DEL for the source in the same higher-level transaction or equivalent serialized journal sequence. Implementations MUST NOT represent rename by silently changing only a manifest path while retaining frame metadata that claims the old identity.

### 9.3 Manifest write serialization

DATA/PACKED/PARITY writes MAY occur concurrently across blobs. Appends to one manifest MUST pass through one logical serializer so every complete record receives a unique `seq`. A local lock, distributed lease, dedicated writer service, or ordered delta-log merge is acceptable; arbitrary concurrent `write()` calls are not assumed to preserve JSONL records.

### 9.4 Manifest `loc` tuple

The tuple is intentionally independent of physical byte offset:

```text
loc = [blob_ordinal, frame_hash, logical_or_inner_offset, logical_or_inner_length]
```

- `blob_ordinal` is an integer in `0..blob_count-1`;
- `frame_hash` is the 32-byte `hash_payload`, canonically encoded as 64 lowercase hexadecimal characters in plaintext JSON;
- for non-packed DATA, the final two values are `logical_offset` and `logical_length` and MUST equal the Master Trailer and sole Pre-Trailer entry;
- for PACKED data, they are `inner_off` and `inner_len` into the uncompressed packed buffer and MUST match the corresponding Pre-Trailer entry.

The tuple MUST NOT contain `physical_offset`: compaction may change physical placement without changing logical references. Normal readers resolve `(blob_ordinal, frame_hash)` through the per-blob offset index (§10.3) and validate the remaining identity/placement fields against each candidate.

Because `hash_payload` excludes placement metadata, equal payload hashes can legitimately resolve to multiple physical offsets. An index MUST preserve all candidates rather than overwrite one mapping. `object_id`, block type, logical/inner range, Pre-Trailer identity, and full frame validation disambiguate them.

### 9.5 Multi-frame objects and order independence

For non-packed multi-frame objects, `logical_offset` is the only normative placement order. JSON array order, physical discovery order, `frame_ordinal`, blob order, and frame size MUST NOT determine logical order.

For each committed non-sparse object, the reader MUST:

1. validate every referenced frame independently;
2. sort claims by ascending `logical_offset`;
3. reject uint64 range overflow;
4. reject any two non-identical claims whose half-open ranges overlap;
5. reject gaps relative to `[0, total_len)`;
6. require the final covered byte to equal `total_len`.

An exact duplicate claim with the same hash, object identity, offset, and length MAY be collapsed as an idempotent duplicate. Any other overlap is `CORRUPTION / CONFLICT`; the reader MUST NOT choose a winner unless a separate explicit versioning rule selects one complete committed object version.

Physical discovery order MUST NOT affect reconstruction. A frame for offset 128 MiB may be discovered before the frame for offset zero.

### 9.6 Copy-on-Write and localized replacement

A committed frame MUST NEVER be modified in place. A replacement operation follows:

```text
read old logical content as needed
→ decompress/decrypt as needed
→ construct new immutable frame(s)
→ append and durably flush frame(s)
→ update derived offset index
→ atomically commit manifest record/transaction
```

Changing a frame's **physical** extent in VARIABLE mode does not change its logical placement and MUST NOT force changes to following logical ranges. For example, a less-compressible replacement may grow from 100 KiB to 200 KiB physically while retaining the same `logical_offset` and `logical_length`.

R7 does not permit a new version to claim that old frame metadata contains a different `object_id`, path version, or logical placement. Any reused stored payload must still be represented by self-consistent R7 frame metadata for the new committed object.

### 9.7 Insert, delete, and repartition semantics

An insert or delete that changes the byte length before a later fragment necessarily changes that later fragment's absolute logical byte offset. R7's `logical_offset` is an actual byte offset, not an order label. Therefore the format MUST NOT claim both that later embedded offsets remain unchanged and that the resulting ranges are non-overlapping.

Normatively:

- a same-length replacement may remain localized to the affected logical range;
- a true insert/delete MUST emit self-consistent placement metadata for every subsequently shifted live range;
- an implementation MAY avoid recompression of unchanged payload bytes, but it MUST NOT retain stale embedded offsets;
- a needs-no-rewrite insert/delete would require an additional indirection or piece-table layer, which R7 does not define.

If a new stored representation cannot fit within `MAX_FRAME_SIZE`, the writer MUST logically repartition it into multiple new frames. Every resulting physical extent MUST be grid-aligned, every non-final logical range SHOULD end on a Logical Recovery Quantum boundary, and no old frame is changed or deleted in place.

### 9.8 Manifest corruption

A malformed, oversized, or truncated record MUST NOT become a valid update. Readers MUST detect invalid JSON, missing fields, unknown operations, invalid ordinals/hashes/types, non-monotonic versions, invalid `object_id`, invalid `loc`, range overflow, gaps, overlaps, and frame/manifest metadata disagreement.

An incomplete final line MAY be ignored only as an uncommitted append. Deployments requiring manifest tamper evidence SHOULD additionally use signed or hash-chained manifest checkpoints/segments.

---

## 10. Manifest Scaling and Physical Offset Index

### 10.1 Reverse scanning and bounded records

Readers MUST support reverse chunked scanning of `manifest.jsonl` in bounded chunks, typically 4-16 MiB.

```text
MAX_MANIFEST_LINE_BYTES = 1 MiB
```

A writer MUST NOT emit a larger line. A reader MUST treat an oversized line as corruption and MUST NOT allocate an unbounded buffer. A path-state checkpoint MAY accelerate manifest startup, but it is not authoritative when it disagrees with a valid committed tail.

### 10.2 Transactional `ADD_EXTENT`

The line-size bound MUST NOT limit an object's fragment count. When an ordinary ADD would exceed it, the writer MUST use a bounded transaction. Canonical plaintext examples are:

```json
{"seq":100,"op":"ADD_BEGIN","transaction_id":"9dc1...","object_id":"ca11...","path":"dataset.bin","ver":7,"total_len":10995116277760,"extent_count":3000000,"extent_record_count":1000000}
{"seq":101,"op":"ADD_EXTENT","transaction_id":"9dc1...","object_id":"ca11...","extent_sequence":0,"extent_index":0,"loc":[[0,"hash0",0,65536],[1,"hash1",65536,65536],[2,"hash2",131072,65536]]}
{"seq":102,"op":"ADD_EXTENT","transaction_id":"9dc1...","object_id":"ca11...","extent_sequence":1,"extent_index":3,"loc":[[0,"hash3",196608,65536]]}
{"seq":1000101,"op":"ADD_COMMIT","transaction_id":"9dc1...","object_id":"ca11...","extent_count":3000000,"extent_record_count":1000000}
```

Normative rules:

- `transaction_id` MUST be unique among reachable transactions in the archive;
- every transaction record MUST repeat the same `transaction_id` and `object_id`;
- `extent_sequence` starts at zero and is contiguous per ADD_EXTENT record;
- `extent_index` identifies the first individual extent in that record;
- if one record carries `N` tuples, the next record's `extent_index` is the previous value plus `N`;
- every line remains below `MAX_MANIFEST_LINE_BYTES`;
- offsets are explicit; neither `extent_sequence`, `extent_index`, nor JSON array order replaces `logical_offset`;
- the object becomes visible only after a durable ADD_COMMIT whose declared record and extent counts exactly match the collected transaction;
- a transaction missing a valid ADD_BEGIN, any contiguous extent record, or ADD_COMMIT is ignored as uncommitted after a crash.

Writers SHOULD batch as many extents per record as practical. ADD_EXTENT records MUST NOT require one `fsync` each; multiple records MAY be appended and durably flushed once at the ADD_COMMIT boundary.

### 10.3 Mandatory per-blob offset index

Every active generation MUST maintain a persisted offset-index checkpoint for every active blob. Its semantic mapping is:

```text
hash_payload → one or more candidate records
candidate record = (physical_offset, frame_quanta, frame_ordinal)
```

At minimum, each index artifact MUST be bound to:

- `archive_id`;
- `generation_id`;
- `blob_ordinal`;
- R7 wire version;
- `indexed_blob_length`;
- an integrity checksum or authenticated equivalent.

The on-disk encoding of this **derived checkpoint** is implementation-defined so a reader can select an O(1) hash table, O(log N) sorted tree, or equivalent structure. Interoperability does not depend on that encoding because the index MUST be rebuildable from conformant blob scans. Implementations SHOULD use the canonical sidecar location `indexes/blob-XX.offset-index`.

The index value is multi-valued because `hash_payload` does not cover Pre-Trailer or placement metadata. A writer/indexer MUST retain every valid candidate with the same hash. A single-value implementation MUST reject a duplicate rather than silently replace the prior offset.

Normal hot-path lookup MUST use the maintained index and MUST NOT linearly scan the blob. The index-supplied `frame_quanta` is a location hint, not trusted frame truth; the reader MUST validate it against the located Master Trailer and archive mode before trusting the frame.

If an index is missing, stale, fails integrity validation, or lacks a manifest-referenced candidate, the reader MUST:

1. mark it unavailable rather than trust partial results;
2. degrade the affected lookup to bounded blob/grid scanning;
3. initiate a rebuild in the background or before the next performance-critical operation;
4. atomically publish the rebuilt checkpoint only after validation.

The fallback may be slow but MUST remain functionally correct. Failure of this derived index is not data corruption by itself.

For new writes, the durability order is frame bytes, index entry/checkpoint update, then manifest reference (§12.1). If a crash nevertheless leaves an incomplete index update, scan-and-rebuild restores it. Compaction MUST generate and validate all new-generation offset indexes before root switch (§13.4).

FIXED mode does not remove this requirement. FIXED geometry makes the address of a **known slot number** O(1) and makes full recovery scans parallelizable, but a manifest `loc` deliberately contains no slot number or physical offset; lookup by hash therefore remains index-assisted.

### 10.4 Sharding and `LINK_MANIFEST`

`LINK_MANIFEST` MAY reference an independently operated sub-manifest. Each target MUST be independently verifiable by its declared algorithm and digest. Canonical schema:

```json
{"seq":42,"ts":1739551000,"op":"LINK_MANIFEST","path":"submanifests/user-data.jsonl","hash_id":1,"hash":"8f2c3a5e...64 hex chars...","lines":50000}
```

`path`, `hash_id`, `hash`, and `lines` are required. A sub-manifest is an operational scaling boundary, not a frame-geometry boundary. `LINK_MANIFEST` MUST NOT substitute for transactional extents of one object.

---

## 11. Normal Access and Disaster Recovery

### 11.1 Normal indexed access

For a manifest `loc`, a normal reader MUST:

1. select the declared `blob_ordinal`;
2. query its generation-bound offset index by `frame_hash`;
3. inspect each candidate record without assuming the hash is physically unique;
4. locate the candidate trailer using indexed `(physical_offset, frame_quanta)`;
5. perform complete §6.3 validation;
6. require object/packed identity and logical/inner placement to match the manifest tuple;
7. return the unique valid match or report corruption/ambiguity.

The expected lookup complexity is O(1) for a hash index or O(log N) for a sorted/tree index, plus the size of a genuine equal-hash candidate bucket. A missing or invalid index triggers §10.3 degradation and rebuild.

### 11.2 Raw physical discovery

Recovery begins by validating `prefix_crc32c` for every available 64-byte blob prefix, followed by reserved-zero validation and grouping on `(archive_id, generation_id, blob_ordinal)`. It never depends on Blob 0, generation-directory names, or canonical blob filenames. Conflicting archive/generation groups MUST remain separate recovery candidates and MUST NOT be silently merged.

#### FIXED mode

Candidate slot starts are known independently:

```text
frame_start(n) = FRAME_REGION_START + n × MAX_FRAME_SIZE
```

Slots MAY be read and validated in parallel across the entire blob. Each trailer MUST report `frame_quanta == MAX_FRAME_QUANTA`. A non-zero remainder after the last complete slot is a truncated/uncommitted tail and MUST NOT be treated as a valid frame.

#### VARIABLE mode

Because `frame_quanta` is stored in the trailer at an unknown frame end, a raw scanner probes trailer positions on quantum boundaries. For every integer `q >= 1` whose candidate end is within the blob:

```text
candidate_end           = FRAME_REGION_START + q × BASE_QUANTUM
candidate_trailer_start = candidate_end - MASTER_TRAILER_SIZE
```

If the 96-byte candidate lacks R7 magic or fails `trailer_crc32c`, advance to the next quantum boundary. Only after that checksum succeeds may the scanner parse `frame_quanta`—still without allocating the claimed frame—and compute:

```text
candidate_size  = frame_quanta × BASE_QUANTUM
candidate_start = candidate_end - candidate_size
```

The candidate is accepted only if all of the following hold:

- `1 <= frame_quanta <= MAX_FRAME_QUANTA`;
- `candidate_start >= FRAME_REGION_START`;
- `(candidate_start - FRAME_REGION_START) mod BASE_QUANTUM == 0`;
- the full frame lies within the blob and passes every available §6.3 check; with keys this includes Pre-Trailer AEAD and block-type metadata consistency, while without keys the frame is classified only as physically/hash valid with opaque metadata;
- its physical range does not conflict with another independently validated frame range.

This boundary scan is not a chain: corruption of one frame does not prevent discovery of later frames. Implementations MAY batch large range reads (for example 4 MiB), examine the contained 4 KiB boundary candidates in memory, and fetch/assemble complete frames only after a trailer candidate passes structural checks.

A trailer magic match alone is never sufficient. No frame-sized allocation may occur before `frame_quanta` has passed the archive and implementation ceilings.

### 11.3 Logical reconstruction

For every accepted frame:

- verify `hash_payload` over exact stored payload bytes;
- bucket group members by `group_id` and validate identical group geometry;
- for DATA, map `(object_id, logical_offset, logical_length)` onto the Logical Recovery Grid;
- for PACKED, authenticate/verify its Pre-Trailer, decompress the packed buffer, and recover each entry by `inner_off`/`inner_len`;
- when keys are available, validate `object_id` against decoded `(canonical_path, file_ver)` and emit recovered ADD candidates;
- when keys are unavailable, retain non-packed object IDs, ranges, hashes, and parity identity, but do not invent plaintext paths or versions.

Within each object, frames are ordered solely by `logical_offset`. Physical order, discovery order, blob order, JSON order, `frame_ordinal`, and physical frame size are irrelevant to logical placement. Implementations MAY materialize a 4 KiB in-memory recovery map; frames remain whole on wire and on disk.

### 11.4 Conflict, overlap, and completeness

Two validated frames claiming overlapping logical ranges for the same `object_id` are `CORRUPTION / CONFLICT` unless they are exact idempotent duplicates or belong to separately identifiable committed versions. Recovery MUST NOT choose one based on discovery order or higher physical offset.

When plaintext metadata is available, any `object_id` collision across distinct `(path, file_ver)` pairs is a hard ID-collision error. Gaps produce an incomplete/degraded object, never silent zero filling unless a future sparse-object profile explicitly defines it.

### 11.5 Parity-assisted recovery

After raw bucketing, the reader MAY reconstruct missing/corrupted group members when at least the scheme-required number of valid equal-sized members remains. A reconstructed frame MUST pass the same payload and metadata validation as an originally present frame before it contributes to a logical object. Group membership is derived from trailer fields; a manifest `PARITY_GROUP` record is optional and non-authoritative.

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

The reference implementation SHOULD reuse bounded buffers, validate untrusted quanta before pooling/allocation, avoid exposing unsealed PACKED frames, serialize each blob's append allocator, serialize manifest commits, maintain one offset index per blob, and benchmark parity on target hardware.

### 12.1 Durability ordering

A manifest MUST NOT reference a frame before the complete frame and its normal-path index entry are durable. Required order:

```text
write all required immutable frames
→ flush/fsync affected blob(s)
→ append/update affected offset-index checkpoints
→ flush/fsync index state
→ append ADD or ADD_BEGIN / ADD_EXTENT batch(es) / ADD_COMMIT
→ flush/fsync manifest at the commit boundary
→ report commit
```

For object storage, each arrow means the provider's equivalent durable publication primitive. Index failure after a crash still degrades safely to scan/rebuild, but a conformant writer MUST follow this order during normal commit.

Intermediate ADD_EXTENT lines are not individual commit points and MUST NOT force one `fsync` each. The transaction becomes authoritative only after a valid durable ADD_COMMIT. Recovery discards a transaction lacking that boundary.

---

## 13. Compaction / Garbage Collection

Compaction uses Mark → Sweep → Freeze/Merge → Index → Switch. It creates `generation_id + 1`; it MUST NOT reuse an older generation ID or change any Archive Header property, especially `frame_size_mode` or `MAX_FRAME_SIZE`.

Before copying frames, the compactor MUST write each destination blob's CRC-valid prefix with the new containing `generation_id` and its unique destination `blob_ordinal`. The generation metadata/root prepared for publication MUST contain the same identity.

### 13.1 Mark

Mark resolves liveness against the complete manifest graph reachable from the root: the root manifest and every reachable LINK_MANIFEST target. A sub-manifest-triggered run MUST NOT use only local references. It must also close over two dependency sets:

- every DATA/PACKED/PARITY member of a live parity group;
- every extent of a live multi-frame `object_id`.

### 13.2 Sweep and immutable identity

Live frames are copied into new blob files; old blobs are never modified. Compaction MUST preserve stored payload, `hash_payload`, `object_id`, logical placement, block type, group identity, physical frame size, and archive mode. It may change generation, physical offset, and—subject to the rules below—physical blob assignment.

Frames SHOULD be copied byte-for-byte. For encrypted archives, a normal Sweep MUST copy the **entire frame byte-for-byte**, including payload ciphertext, encrypted Pre-Trailer representation, stored nonces, tags, trailer, and `frame_ordinal`. It MUST NOT decrypt/re-encrypt, refresh nonces, recompress, repack, or derive a nonce from the destination position.

If encrypted byte-preserving copies from different source blobs would create duplicate `frame_ordinal` values in one destination blob, the compactor MUST preserve the source `blob_ordinal` or choose another destination blob. It MUST NOT solve the collision by rewriting the copied trailer. Newly created frames in the destination generation start above the maximum copied ordinal for that destination blob.

### 13.3 Concurrent writes during Sweep

Writes after the Mark snapshot MUST be identifiable as a manifest tail. The implementation MUST use either:

**Delta manifest:** writers append to a delta while Sweep runs; Freeze stops commits briefly, drains the delta, merges it, validates every resulting loc, writes final manifest/index state, and switches atomically.

**Manifest lock:** writers continue during Sweep but an exclusive local/distributed lock covers the complete Freeze/Merge/Index/Switch interval so no commit can target the old root after the new root becomes authoritative.

### 13.4 Index and root switch

Before switch, the new generation MUST have:

- complete validated blobs;
- a complete manifest and reachable sub-manifests;
- a validated per-blob offset index bound to the new `generation_id` and final blob lengths;
- verified object coverage and parity-group invariants.

Recommended layout:

```text
root.current
  → generation-00000000000000000042/
       manifest.jsonl
       frames/
       indexes/
```

After all content and indexes are durable, atomically replace `root.current`. The old generation remains intact until the switch is confirmed durable.

### 13.5 Crash cases

- Crash during Sweep/Merge/Index: old generation remains authoritative.
- Crash before root switch: old generation remains authoritative.
- Crash after root switch but before old deletion: new generation is authoritative; old generation is garbage.
- Crash during garbage deletion: restart deletion; do not roll back the root.

### 13.6 Parity and multi-frame integrity

If one live DATA or PACKED member of a parity group is copied, every DATA, PACKED, and PARITY member with that `group_id` MUST enter the same new generation. Equal `frame_quanta`, unique `group_index`, and the cross-blob spread rule MUST be revalidated.

Every extent referenced by one committed multi-frame `object_id` is an indivisible Mark/Sweep unit. The old generation MUST NOT be deleted until every sibling extent is present, hash-verified, indexable, and durable in the new generation. Parity membership and logical-object membership compose; both closures must be complete.

### 13.7 Emergency Pruning

If a required sibling remains missing or inaccessible after normal retry/recovery, mark the object or generation **GC-BLOCKED** and expose the exact missing references. Emergency Pruning is an explicit audited data-loss escape hatch, not successful compaction.

Before deletion, Parity Impact Analysis MUST classify every affected group:

- **HEALTHY** — full membership and configured recovery tolerance remain intact;
- **UNPROTECTED** — required data is presently readable or reconstructable, but original membership/recovery tolerance is no longer intact; a durable repair task is mandatory;
- **UNRECOVERABLE** — surviving members cannot reconstruct required protected data.

An Emergency Pruning operation MUST:

1. durably record `generation_id`, affected blobs/frames/objects/groups, pre/post health, timestamp, and operator reason;
2. finish parity and logical-object impact analysis before physical deletion;
3. mark every affected logical object DEGRADED or UNRECOVERABLE when a referenced extent is missing/unverifiable;
4. persist every UNPROTECTED group in a repair queue/state;
5. never advertise original protection until successful repair restores it;
6. update the active manifest health state before deleting the old generation;
7. surface integrity failure rather than return a silently truncated object;
8. refuse Emergency Pruning when the only issue is temporary access to otherwise healthy storage.

---

## 14. Legacy v1.21

v1.21 standalone `.sf` files and SUB records are not valid 2.0 syntax.

Migration tooling MAY read v1.21 and produce a valid 2.0 archive.

---

## 15. Out of Scope and Encryption Profile

The base profile does not require desktop/edge behavior, tape-specific optimization, sub-block/CDC deduplication, automatic conflict resolution, or implementation-specific KMS APIs. Encryption below is a normative interoperable enterprise profile.

### 15.1 Protected and visible fields

When Archive Header `archive_flags & 0x0001 != 0`, encryption MUST protect payload bytes, paths, versions, and the complete plaintext Pre-Trailer body. Plaintext manifest ADD/DEL/extent records carrying sensitive metadata are forbidden. When the bit is zero, encrypted frame/manifest representations are not valid in the base profile.

The complete 64-byte blob prefix (including `generation_id`, `blob_ordinal`, and `prefix_crc32c`), 96-byte Master Trailer (including `trailer_crc32c`), `pre_trailer_len`, and offset-index placement hints remain visible. Consequently a keyless scanner can classify detached blobs by archive/generation/ordinal and discover and checksum frame geometry, block type, `object_id`, logical range, `frame_ordinal`, payload hash, and parity membership, but cannot recover plaintext paths/versions or PACKED entry maps.

### 15.2 AEAD and stored representation

The reference construction is AES-256-GCM with a fixed 12-byte nonce and 16-byte tag:

```text
stored_encrypted_representation = nonce[12] || ciphertext || tag[16]
```

The payload `data_len` includes all three components and `hash_payload` covers the complete stored representation. The encrypted Pre-Trailer body uses the same representation shape under a separate key domain; `pre_trailer_len` is its exact stored length.

Frame payload, Pre-Trailer, and manifest use independently derived AEAD keys with labels:

```text
STASH-FRAME-V2
STASH-PRETRAILER-V2
STASH-MANIFEST-V2
```

These key domains MUST NOT be collapsed.

### 15.3 Frame and Pre-Trailer nonce construction

For a newly encrypted frame payload:

```text
payload_nonce = first_12_bytes(
    BLAKE3(
        "STASH-FRAME-NONCE-V2" ||
        archive_id[32] ||
        uint64_le(generation_id) ||
        uint8(blob_ordinal) ||
        uint64_le(frame_ordinal)
    )
)
```

For its encrypted Pre-Trailer body:

```text
pre_trailer_nonce = first_12_bytes(
    BLAKE3(
        "STASH-PRETRAILER-NONCE-V2" ||
        archive_id[32] ||
        uint64_le(generation_id) ||
        uint8(blob_ordinal) ||
        uint64_le(frame_ordinal)
    )
)
```

The quoted labels are exact ASCII bytes without a terminator. BLAKE3 is used for nonce derivation regardless of archive `hash_id`.

For a given derived AEAD key, no nonce may ever be used for two encryption operations. `generation_id` MUST never be reused under the same archive DEK, and a writer MUST never reuse a `frame_ordinal` in one `(generation_id, blob_ordinal)` namespace. Cold-start ordinal discovery is defined in §6.1.3.

The nonce is stored with each ciphertext. Readers MUST parse the stored nonce and MUST NOT guess or rederive it from current physical position. A reader MAY recompute an expected nonce when the creation namespace is known, but mismatch is validation failure; successful decryption never depends on such recomputation.

Byte-for-byte copying an existing ciphertext during compaction is permitted and required by §13.2; it is not a new encryption operation. The destination MUST retain the stored nonce, ciphertext, and tag unchanged.

### 15.4 Frame AEAD Additional Authenticated Data

Both payload and Pre-Trailer authentication MUST bind immutable visible placement metadata. Canonical frame AAD is the concatenation:

```text
"STASH-FRAME-AAD-V1" ||
archive_id[32] ||
uint16_le(version) ||
uint8(hash_id) || uint8(codec_id) || uint8(block_type) ||
uint8(group_index) || uint32_le(group_id) ||
uint32_le(frame_quanta) || object_id[16] ||
uint64_le(logical_offset) || uint64_le(logical_length) ||
uint64_le(frame_ordinal)
```

Payload AEAD uses that sequence prefixed by exact ASCII `"PAYLOAD"`; Pre-Trailer AEAD uses it prefixed by `"PRETRAILER"`. `data_len`, `hash_payload`, and `trailer_crc32c` are excluded to avoid circular construction. Any authenticated-field mismatch is corruption.

After Pre-Trailer decryption, the reader MUST verify its CRC32C and metadata padding before parsing entries. AEAD success does not waive structural validation.

### 15.5 Envelope encryption

```text
KEK / KMS key
  → wrapped archive DEK
  → domain-separated payload / Pre-Trailer / manifest keys
```

The wrapped DEK and key identifier are protected deployment metadata and MUST NOT be embedded in the fixed 96-byte Master Trailer.

### 15.6 Encrypted manifest records

A sensitive manifest operation uses an outer record containing only sequence, encrypted operation type, and ciphertext:

```json
{"seq":123,"op":"ADD_ENC","enc":"<base64(nonce || ciphertext || tag)>"}
```

ADD, DEL, ADD_BEGIN, ADD_EXTENT, and ADD_COMMIT have corresponding encrypted operation names (`ADD_ENC`, `DEL_ENC`, `ADD_BEGIN_ENC`, `ADD_EXTENT_ENC`, `ADD_COMMIT_ENC`). The decrypted canonical JSON object contains every field that would follow `op` in the plaintext form, including `transaction_id` and `object_id` when applicable.

Manifest AAD is:

```text
uint64_le(seq) ||
uint16_le(op_utf8_length) || op_utf8
```

`transaction_id` remains inside the AEAD plaintext and is therefore authenticated without creating a circular dependency during decryption. A mismatch between outer `seq`/`op` and the supplied AAD MUST fail.

### 15.7 Manifest nonce domain

Manifest records use the `STASH-MANIFEST-V2` key and:

```text
manifest_nonce = first_12_bytes(
    BLAKE3(
        "STASH-MANIFEST-NONCE-V2" ||
        archive_id[32] ||
        uint64_le(generation_id) ||
        uint64_le(seq)
    )
)
```

`seq` is unique within the generation and `generation_id` is never reused under the DEK, so the namespace remains unique across compaction. The nonce is included in `enc`; no sidecar counter is required.

### 15.8 Encryption, recovery, deduplication, and compaction

Without keys, R7 remains physically discoverable, payload-hash-verifiable, parity-group-recoverable, and non-packed logical-range-recoverable by opaque `object_id`; plaintext naming and PACKED extraction remain unavailable.

Because `hash_payload` covers ciphertext, deduplication requires identical stored ciphertext. Independent creation namespaces produce different nonces and normally different ciphertext for equal plaintext. The base encryption profile therefore does not provide convergent cross-writer deduplication. Any convergent profile requires separate security analysis and MUST NOT reuse this nonce namespace.

Compaction MUST NOT decrypt/re-encrypt or nonce-refresh live frames. It copies the complete encrypted frame byte-for-byte as required by §13.2.

---

## 16. Normative Invariants

A conformant R7 implementation MUST preserve every invariant below.

### 16.1 Prefix, Header, generation, and mode

- Every blob has a CRC-valid 64-byte prefix: the immutable 48-byte Archive Header at `0x00`, `generation_id` at `0x30`, `blob_ordinal` at `0x38`, three zero reserved bytes at `0x39`, and little-endian `prefix_crc32c` at `0x3C`.
- `prefix_crc32c` covers all 64 prefix bytes with its own field treated as zero and is validated before any prefix field is trusted.
- All blobs selected for a generation agree on the immutable Header, `archive_id`, and `generation_id`; their in-range `blob_ordinal` values are unique and agree with normal metadata/filename bindings.
- The first possible frame byte is `FRAME_REGION_START = 0x40`.
- `version == 0x0005`; older layouts are parsed only by explicit version dispatch.
- `frame_size_mode`, `archive_flags`, `MAX_FRAME_SIZE`, archive parameters, and `archive_id` are immutable across the archive lifetime and all generations; unknown flag bits are rejected.
- `generation_id` is monotonic, unique under the archive key, stored in every blob prefix, and never reused.

### 16.2 Geometry and allocation

- `frame_size = frame_quanta × 4096`, with `1 <= frame_quanta <= MAX_FRAME_QUANTA`.
- VARIABLE frames may differ in size; FIXED frames always report `MAX_FRAME_QUANTA`.
- No allocation derived from untrusted size occurs before header/trailer ceilings are validated.
- `data_len + zero_padding + pre_trailer_len + 4 + 96 == frame_size` exactly.
- Payload padding and metadata padding are zero; the stored Pre-Trailer start is 8-byte aligned.
- FIXED slot arithmetic addresses known slot numbers; hash lookup still uses the mandatory index.

### 16.3 Identity, placement, and recovery

- Every non-packed DATA frame carries non-zero `object_id`, aligned `logical_offset`, positive `logical_length`, and matching sole Pre-Trailer metadata.
- PACKED and PARITY trailer placement fields are zero; PACKED placement exists only per entry.
- `object_id` is the 16-byte domain-separated digest of canonical path and `file_ver`; rename and version change produce new IDs.
- Physical order, JSON order, blob order, `frame_ordinal`, and frame size never determine logical order.
- Non-identical overlapping claims are detected and never resolved by discovery order.
- A true byte insert/delete cannot retain stale absolute offsets in shifted frames.

### 16.4 Integrity, packing, and parity

- `hash_payload` covers exact stored payload bytes, including stored payload nonce/tag when encrypted, and excludes padding and trailers.
- `trailer_crc32c` covers all 96 Master Trailer bytes with its own field treated as zero and is validated before any trailer field is trusted.
- Pre-Trailer AEAD/CRC32C is verified before metadata is trusted.
- Canonical codec parameters are documented for every enabled writer codec.
- PACKED entries are canonical-path sorted; a single oversized candidate fails fast into the multi-frame path.
- Every parity member self-describes `group_id`/`group_index`; group positions are unique and all members have identical `frame_quanta`.
- Active parity requires at least two blobs, valid non-zero `k/m` with `k + m <= 256`, and the group spread invariant; no-parity archives encode `k = m = 0`.

### 16.5 Manifest and index

- Manifest commits are serialized with strictly increasing `seq`.
- `loc` contains no physical offset and agrees with validated frame metadata.
- A line never exceeds 1 MiB; oversized lines are rejected without unbounded buffering.
- Large extent transactions carry consistent `transaction_id`, `object_id`, contiguous `extent_sequence` and `extent_index`, and become visible only at valid ADD_COMMIT.
- Every active blob has a generation-bound, integrity-protected, rebuildable, multi-value offset index.
- Normal lookup uses the index; index loss degrades to scan and rebuild without changing logical correctness.
- Frames and index state are durable before the manifest can reference them.

### 16.6 Concurrency, compaction, and pruning

- One append allocator serializes physical extent allocation per blob; distinct blobs may write concurrently.
- Compaction never modifies the active generation, changes size mode, splits a live parity group/object, or switches before new indexes are valid.
- Encrypted frames are copied byte-for-byte; no decrypt/re-encrypt or nonce refresh occurs.
- Root switch is atomic; the old generation remains authoritative until durable switch.
- Emergency Pruning is audited, parity-aware, and preserves explicit HEALTHY/UNPROTECTED/UNRECOVERABLE state.

### 16.7 Cryptography

- Payload, Pre-Trailer, and manifest use distinct key and nonce domains.
- Every new encryption operation has a unique 12-byte nonce under its derived key.
- Frame nonces use `(archive_id, generation_id, blob_ordinal, frame_ordinal)`; manifest nonces use `(archive_id, generation_id, seq)`.
- Nonces are stored with ciphertext and are never inferred from current physical position during recovery.
- Frame AAD binds visible immutable identity/placement fields; manifest AAD canonically binds outer `seq` and `op`, while `transaction_id` is authenticated inside the ciphertext.
- Without keys, encrypted archives remain physically and parity recoverable and expose opaque non-packed ranges, but not plaintext naming or PACKED entry maps.

---

## 17. Production Readiness Checklist

- [ ] Complete-prefix CRC coverage, Header equality, generation/ordinal binding, encryption/unknown-flag dispatch, three-byte reserved prefix, `0x40` frame start, and R7 version dispatch are tested.
- [ ] VARIABLE geometry validates 4 KiB through `MAX_FRAME_SIZE`, rejects zero, non-grid, overflow, and above-max values.
- [ ] FIXED readers reject any `frame_quanta != MAX_FRAME_QUANTA`.
- [ ] Exact payload-budget arithmetic is checked on write and read, including encrypted overhead.
- [ ] Master Trailer CRC is calculated with bytes `0x34..0x37` logically zero and is verified before trailer-derived allocation or placement.
- [ ] Metadata padding makes stored Pre-Trailer placement 8-byte aligned and is CRC/AEAD protected.
- [ ] Allocation ceilings are enforced before frame-sized buffers are created.
- [ ] DATA, PACKED, and PARITY block-type zero/non-zero field rules are tested.
- [ ] `object_id` derivation, version changes, rename changes, and collision handling are tested.
- [ ] Multi-frame reconstruction succeeds for arbitrary manifest and discovery order.
- [ ] Overlap, gap, overflow, stale-offset, and trailer/manifest disagreement fail closed.
- [ ] PACKED works in both modes; FIXED PACKED frames occupy full `MAX_FRAME_SIZE` slots.
- [ ] Last non-packed fragments use shorter `logical_length` with valid physical padding.
- [ ] Parity groups reject mixed `frame_quanta` and duplicate/out-of-range `group_index`.
- [ ] Header parity parameters reject invalid zero/non-zero combinations, `k + m > 256`, and XOR with `m != 1`.
- [ ] Per-blob indexes preserve equal-hash candidate buckets, reject stale generation/blob binding, and rebuild after deletion/corruption.
- [ ] Normal access performs no linear hot-path blob scan.
- [ ] FIXED recovery parallelizes independent slots; VARIABLE recovery finds later frames after a corrupted predecessor.
- [ ] ADD_EXTENT batching stays below 1 MiB and validates both sequence/count dimensions at commit.
- [ ] Crash injection covers frame flush, index publication, every extent stage, manifest commit, compaction index build, and root switch.
- [ ] Blob allocators and manifest serialization are race-tested under sustained concurrency.
- [ ] Compaction preserves mode, object placement, parity closure, and all live extents.
- [ ] Encrypted compaction produces byte-identical complete frames before and after Sweep.
- [ ] Frame/Pre-Trailer/manifest nonce derivation is deterministic, domain-separated, stored, and collision-tested across generations.
- [ ] AAD tampering of any bound placement or manifest field is rejected.
- [ ] Key-loss tests document the boundary between opaque frame recovery and plaintext path/PACKED recovery.
- [ ] Emergency Pruning tests persist collateral HEALTHY/UNPROTECTED/UNRECOVERABLE outcomes and repair work.

---

## 18. Required R7 Test Matrix

### 18.1 Geometry

Prefix vectors MUST flip every Header byte, every byte of `generation_id`, `blob_ordinal`, each reserved byte, and the stored Prefix CRC without recomputation; each mutation is rejected before the altered field is trusted. Additional vectors MUST reject duplicate ordinals, out-of-range ordinals, mixed-generation blob sets, and metadata/filename bindings that disagree with a CRC-valid prefix. Trailer vectors MUST flip each field class and the stored trailer CRC without recomputation; each mutation is rejected before the altered field is trusted. A quantum-boundary false `STSH` magic with invalid trailer CRC MUST be skipped rather than accepted as a frame.

For a VARIABLE archive whose `MAX_FRAME_SIZE >= 4196 KiB`, accept:

| Physical size            | `frame_quanta`         | Result                                |
|-------------------------:|-----------------------:|---------------------------------------|
| 4 KiB                    | 1                      | valid if payload/metadata budget fits |
| 8 KiB                    | 2                      | valid                                 |
| 100 KiB                  | 25                     | valid                                 |
| 4096 KiB                 | 1024                   | valid traditional 4 MiB boundary      |
| 4196 KiB                 | 1049                   | valid                                 |
| `MAX_FRAME_SIZE`         | `MAX_FRAME_QUANTA`     | valid                                 |
| `MAX_FRAME_SIZE + 4 KiB` | `MAX_FRAME_QUANTA + 1` | corruption                            |

For FIXED mode, validate `frame_start(n) = 0x40 + n × MAX_FRAME_SIZE` and reject every trailer reporting any other quantum count. Verify a last logical fragment shorter than capacity with the remainder zero-padded.

### 18.2 Packing and payload budget

- Run PACKED vectors in VARIABLE and FIXED modes with incompressible and highly compressible inputs.
- Verify `object_id/logical_offset/logical_length == 0` in the PACKED trailer.
- Verify a single file that cannot fit at `MAX_FRAME_SIZE` exits packing once and enters the non-packed path.
- Flip each metadata-padding and payload-padding byte and require rejection.

### 18.3 Object identity and logical placement

- Same canonical path and version produces the same 16-byte object ID.
- Changing only `file_ver` changes it.
- Renaming only the path changes it and requires new self-describing placement.
- Discover frames in order C, A, D, B and reconstruct in logical order A, B, C, D.
- Make two different frames claim one overlapping range and require `CORRUPTION / CONFLICT`.
- Test a same-length localized replacement separately from an insert that shifts every following absolute offset; stale later offsets MUST be rejected.

### 18.4 Index and recovery

- Remove all generation-directory and canonical blob filenames, present detached blobs in shuffled order, and recover their exact archive/generation/ordinal grouping solely from CRC-valid prefixes.
- Map one hash to two physical candidates with different object placement and resolve the correct loc without dropping either candidate.
- Delete, truncate, corrupt, and stale-bind an index; each case degrades to scan, rebuilds, and returns the same logical bytes.
- In VARIABLE mode, corrupt one frame trailer and verify quantum-boundary scanning still discovers later valid frames.
- In FIXED mode, scan slots in shuffled parallel order and obtain identical recovery output.

### 18.5 Manifest transactions

- Crash after ADD_BEGIN and after arbitrary ADD_EXTENT batches: no object becomes visible.
- Omit or duplicate one `extent_sequence` or `extent_index`: commit is rejected.
- Mismatch `object_id`, `extent_count`, or `extent_record_count`: commit is rejected.
- Complete all records plus durable ADD_COMMIT: the object becomes visible atomically.

### 18.6 Parity, compaction, and crypto

- Reject a parity group whose members have different physical sizes.
- Compact generation 0 → 1 → 2 and verify immutable archive mode, incremented CRC-valid prefix generation identity, unique destination ordinals, logical placement, group closure, and valid new indexes.
- For encryption, compare every pre/post-compaction frame byte and require identity.
- Verify that destination prefixes identify the new containing generation while copied frames retain stored nonces and decrypt without reconstructing their historical creation namespace.
- Verify stored nonce parsing and rejection of payload, Pre-Trailer, frame-AAD, manifest-AAD, and tag tampering.
- Restart a writer, discover both `max(generation_id)` from valid prefixes and `max(frame_ordinal)` within the active generation, allocate the next values, and verify no nonce tuple reuse.
- Emergency-prune one protected member and verify the exact resulting HEALTHY, UNPROTECTED, or UNRECOVERABLE state.

---

## 19. Terminology

| Deprecated or ambiguous term | R7 term |
|---|---|
| fixed frame size (unqualified) | `frame_size_mode = FIXED` |
| variable block | Grid-Aligned Variable Frame |
| `BLOCK_STRIDE` | `frame_size` for one extent; `MAX_FRAME_SIZE` for FIXED slot stride |
| frame size class | `max_frame_size_class` |
| frame position | `physical_offset` |
| frame index | FIXED slot number, only when explicitly meant |
| frame creation counter | `frame_ordinal` |
| file offset | `logical_offset` |
| file fragment length | `logical_length` |
| packed offset/length | `inner_off` / `inner_len` |
| 4 KiB chunks | Logical Recovery Quanta or Physical Grid Quanta, as context requires |
| split frame | logical repartition / Copy-on-Write rewrite |
| hash-to-offset cache | mandatory rebuildable per-blob offset index |

---

## 20. Reference Product Architecture

This section defines the official R7 implementation shape, not additional wire fields. The Go library is the authoritative implementation of format semantics. The CLI and FUSE driver are thin clients and MUST NOT independently parse or serialize Headers, frames, manifests, indexes, parity metadata, or encryption representations.

### 20.1 Go library

The public API operates on logical archives, objects, transactions, verification, and maintenance. Wire structs and binary codecs SHOULD remain implementation-internal (for example under `internal/wire`) so callers cannot construct partially valid frames.

The following is the intended compact API surface; exact names and option structs belong to separate API documentation:

```go
func Create(ctx context.Context, backend Backend, opts CreateOptions) (*Archive, error)
func Open(ctx context.Context, backend Backend, opts OpenOptions) (*Archive, error)

func (a *Archive) Begin(ctx context.Context) (Transaction, error)
func (a *Archive) OpenObject(ctx context.Context, path string, opts OpenObjectOptions) (ObjectReader, error)
func (a *Archive) List(ctx context.Context, prefix string, opts ListOptions) (ObjectIterator, error)
func (a *Archive) Stat(ctx context.Context, path string) (ObjectInfo, error)
func (a *Archive) Verify(ctx context.Context, opts VerifyOptions) (VerifyReport, error)
func (a *Archive) Recover(ctx context.Context, opts RecoverOptions) (RecoveryReport, error)
func (a *Archive) RebuildIndexes(ctx context.Context, opts IndexOptions) error
func (a *Archive) Compact(ctx context.Context, opts CompactOptions) (CompactReport, error)

type Transaction interface {
    Put(ctx context.Context, path string, src io.Reader, opts PutOptions) error
    Delete(ctx context.Context, path string) error
    Rename(ctx context.Context, oldPath, newPath string) error
    Commit(ctx context.Context) error
    Abort(ctx context.Context) error
}

type ObjectReader interface {
    io.Reader
    io.ReaderAt
    io.Closer
}
```

Enumeration is streaming/iterative rather than an archive-sized in-memory slice. Long-running verify, recovery, index, and compaction options SHOULD likewise expose progress/cancellation hooks through `context.Context` and callbacks/channels defined by the API package.

`Transaction.Rename` implements the R7 §9.2 new-object semantics; it is not a metadata-only stable-UUID alias. The library owns canonical-path validation, Copy-on-Write, frame/index/manifest durability ordering, crash recovery, compaction, encryption, and parity enforcement.

Storage access SHOULD be abstracted behind small backend interfaces for blob I/O, generation/root metadata, index/manifest persistence, and key retrieval. Local files and object storage must exercise the same format engine and conformance tests.

### 20.2 CLI client

The reference executable is `stash`. Archive-creation parameters are accepted only by `create`; immutable Header properties cannot be changed later.

```text
stash create ARCHIVE
    --mode variable|fixed
    --max-frame-size SIZE
    --hash blake3|sha256|sha3-256
    --codec store|lz4|zstd|lzma|brotli
    --blobs N
    --parity none|xor|rs
    [--parity-k K --parity-m M]
    [--encrypt --key-provider NAME]
```

Minimum command set:

| Command | Purpose / principal parameters |
|---|---|
| `stash add ARCHIVE SOURCE... [--dest PATH]` | Append files through one library transaction |
| `stash remove ARCHIVE PATH...` | Append DEL operations through one library transaction |
| `stash rename ARCHIVE OLD_PATH NEW_PATH` | Apply R7 new-object rename semantics through the library |
| `stash extract ARCHIVE [PATH...] --output DIR` | Extract selected or all objects |
| `stash list ARCHIVE [PREFIX] [--json]` | List current logical state |
| `stash stat ARCHIVE PATH [--json]` | Show object/version/extent metadata |
| `stash verify ARCHIVE [--full] [--workers N] [--json]` | Validate structure or all payload/parity content |
| `stash recover ARCHIVE --output DIR [--rebuild-manifest]` | Run raw recovery without trusting normal metadata |
| `stash index rebuild ARCHIVE [--blob N]` | Persist rebuilt per-blob offset indexes |
| `stash compact ARCHIVE [--workers N]` | Run Mark/Sweep/Freeze/Merge/Index/Switch |
| `stash gc status ARCHIVE [--json]` | Report blocked objects/groups and repair state |
| `stash gc emergency-prune ARCHIVE --reason TEXT --confirm-data-loss` | Explicit audited emergency path; MUST fail without both parameters |
| `stash mount ARCHIVE MOUNTPOINT [--generation ID]` | Invoke the mandatory read-only FUSE adapter |

Common read/maintenance commands MAY accept `--generation`, `--workers`, `--json`, and `--key-provider` where meaningful. CLI output formatting and argument parsing are not wire-format semantics.

### 20.3 Read-only FUSE driver

The official R7 FUSE profile is permanently **read-only**. It is an archive-view adapter, not a general writable POSIX filesystem.

Normative behavior:

- `stash mount` MUST request the kernel's read-only mount mode and exposes no writable override;
- the mount pins one validated `generation_id` for its complete lifetime, providing a stable snapshot even if compaction later switches the archive root;
- lookup, attribute reads, directory enumeration, open, `read`/`ReaderAt`, release, access checks, and read-only filesystem statistics are served exclusively through the Go library API;
- directories are synthesized from canonical object paths; empty directories have no independent R7 representation;
- create, write, truncate, unlink, rename, link, symlink, mkdir, rmdir, ownership/mode mutation, and xattr mutation MUST return `EROFS`;
- the driver MUST NOT modify blobs, manifests, persistent indexes, generations, or root metadata;
- when a persistent index is missing/corrupt, the driver MAY use an in-memory scan-built index for the pinned mount; persistent repair is performed explicitly through `stash index rebuild` or the Go maintenance API;
- CLI and FUSE code MUST NOT import implementation-internal wire packages or duplicate recovery logic.

Hardlinks, symlinks, writable memory mappings, mutable POSIX metadata, and write-back caching are outside the final R7 FUSE profile.

---
## License

🌀 STASH is open-source software licensed under the [MIT License](LICENSE).

**Author:** © 2025-2026 Zbigniew Lipka  
