# STASH

## Version 2.0 — Consolidated Specification
### Revision R8 — Production / Enterprise Hardening and Profile Simplification

**Status:** Final / Frozen Specification  
**Target:** Server / enterprise / datacenter / petabyte-scale storage  
**Wire version:** `0x0006`  
**Encoding:** little-endian for every multi-byte integer unless explicitly stated otherwise

The R8 version bump is required because algorithm identifiers and the cryptographic construction changed semantics even though the R7 physical field layout is retained.

R8 is the final pre-implementation wire-format hardening revision. It retains the R7 physical layout and storage capabilities while deliberately narrowing the algorithm surface, fully specifying the cryptographic construction, strengthening resource-exhaustion requirements, and making wire-conformance testing normative.

R8 does **not** introduce new storage capabilities.

> **R8 is FROZEN. Further wire-format changes require implementation evidence from conformance testing, fuzzing, crash injection, recovery testing, interoperability testing, security analysis, or measured performance results.**

R8 preserves the core STASH model:

- append-only storage;
- immutable committed frames;
- whole-frame integrity and deduplication;
- self-describing manifest-independent recovery;
- per-blob parallel writes;
- parity / erasure recovery;
- crash-safe manifest transactions;
- generation-based compaction;
- encrypted metadata and payload support;
- enterprise / petabyte-scale operation.

---

# 0. Design Priorities

Implementations MUST preserve these priorities in this order:

1. **Predictable grid geometry.** Physical frame boundaries are always aligned to the 4 KiB base quantum. In `FIXED` mode, arbitrary frame positions are directly computable in O(1). In `VARIABLE` mode, every frame self-describes its physical extent and the next frame is deterministically reachable from the current frame.
2. **Localized immutable copy-on-write.** A logical edit MUST NOT require rewriting unrelated following frames solely because the edited logical region changed length.
3. **Whole-frame, bit-identical deduplication.** STASH does not perform sub-frame content-defined chunking.
4. **Self-describing recovery.** Raw frame data MUST contain enough information to identify the logical object, logical placement, physical extent, parity membership, and integrity state without `manifest.jsonl`.
5. **Throughput at enterprise scale.** Normal hot-path reads MUST use a maintained physical offset index rather than repeated linear blob scans. Parallel per-blob writing remains supported.

Encryption is an explicit qualification to priority 4: without the appropriate key, a recovery scanner can still discover frame boundaries, physical extents, hashes, and parity structure, but plaintext paths and encrypted logical metadata are not recoverable.

## 0.1 Detection is not repair

**Integrity detection and error correction are separate mechanisms.**

- CRC32C detects accidental structural corruption.
- `hash_payload` detects mismatch of the exact stored payload representation.
- AEAD authenticates encrypted representations.
- None of those mechanisms reconstruct missing or corrupted data.
- Repair requires parity, another intact copy, external replication, or another recovery source.

> **Checksums and hashes detect corruption; redundancy repairs it. STASH never treats CRC32C or content hashes as error-correction mechanisms.**

---

# 1. Terminology

R8 uses the following terms normatively:

- **BASE_QUANTUM** — 4096 bytes.
- **Grid-Aligned Variable Frame** — a frame whose physical size is `N * BASE_QUANTUM`, where `N >= 1` and the archive is in `VARIABLE` mode.
- **FIXED frame** — a frame whose physical size is exactly `MAX_FRAME_SIZE`.
- **physical_offset** — absolute byte offset of a frame from the beginning of its blob file.
- **frame_area_offset** — `physical_offset - ARCHIVE_HEADER_SIZE`.
- **frame_quanta** — physical frame size divided by `BASE_QUANTUM`.
- **logical_offset** — byte offset of a non-packed frame's data within the logical object.
- **logical_length** — number of logical object bytes represented by that frame.
- **Logical Recovery Quantum** — a 4096-byte unit used by recovery/index implementations to map logical extents. It is not a separate wire object.
- **frame_ordinal** — immutable creation-time ordinal of a frame within its origin `(generation_id, blob_ordinal)` namespace. It is metadata, not the current physical slot after compaction.
- **physical_quantum_index** — creation-time physical start position, measured in 4 KiB quanta from the origin blob frame area.
- **blob_ordinal** — active blob number `0 .. blob_count-1` within one generation. It is not a globally unique historical blob identifier.
- **generation_id** — uint64 generation / compaction-attempt namespace identifier.
- **object_id** — binary identity derived from canonical path and object version, as defined in §6.5. It is not rename-stable.

The terms `frame_size_class`, global `BLOCK_STRIDE`, and implicit `loc[]` ordering are not valid R8 concepts.

---

# 2. Archive and Generation Layout

## 2.1 Directory model

Recommended layout:

```text
archive/
  root.current
  generation-0000000000000000/
    manifest.jsonl
    manifest.checkpoint
    index/
      blob-00.idx
      blob-01.idx
      ...
    frames/
      blob-00.stash
      blob-01.stash
      ...
  generation-0000000000000001/
    ...
```

`root.current` identifies the authoritative generation. Updating it during compaction MUST be atomic and durable.

The initial archive generation is:

```text
generation_id = 0
```

Each new generation / compaction attempt MUST use a `generation_id` that has never previously been allocated under the same archive encryption key. IDs MUST NOT be reused after abort, crash, or deletion.

A reference implementation MAY discover the next generation identifier by scanning existing `generation-XXXXXXXXXXXXXXXX/` names and allocating a value greater than every previously observed value. This is an implementation mechanism, not a wire-format dependency.

## 2.2 Archive Header — 64 bytes

Every blob file MUST begin with the same 64-byte Archive Header for its generation.

```text
ARCHIVE_HEADER_SIZE = 64 = 0x40
FRAME_AREA_START    = 0x40
```

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | magic | char[4] | `STSH` |
| `0x04` | 2 | version | uint16 | `0x0006` for R8 |
| `0x06` | 1 | frame_size_mode | uint8 | `0x00 VARIABLE`, `0x01 FIXED` |
| `0x07` | 1 | hash_id | uint8 | §4 |
| `0x08` | 1 | codec_id | uint8 | archive default; per-frame override allowed |
| `0x09` | 1 | parity_scheme | uint8 | §7 |
| `0x0A` | 1 | parity_k | uint8 | data members per parity group |
| `0x0B` | 1 | parity_m | uint8 | parity members per parity group |
| `0x0C` | 1 | blob_count | uint8 | `1..255` active blobs in this generation |
| `0x0D` | 1 | flags | uint8 | zero in base R8 profile |
| `0x0E` | 2 | header_size | uint16 | MUST equal `64` |
| `0x10` | 4 | max_frame_quanta | uint32 | `MAX_FRAME_SIZE / 4096` |
| `0x14` | 8 | generation_id | uint64 | generation identity |
| `0x1C` | 4 | reserved | bytes | MUST be zero |
| `0x20` | 32 | archive_id | bytes | immutable archive identifier |

The following fields are immutable for the entire life of one archive instance and MUST be identical across all generations:

- `frame_size_mode`;
- `hash_id`;
- archive default `codec_id` policy;
- `parity_scheme`, `parity_k`, `parity_m`;
- `blob_count` unless an explicit future format revision defines migration semantics;
- `max_frame_quanta`;
- `archive_id`.

`generation_id` is intentionally generation-specific.

Changing `frame_size_mode` requires creation of a new archive instance. Compaction MUST NOT convert `VARIABLE -> FIXED`, `FIXED -> VARIABLE`, or mix modes between generations of the same archive.

## 2.3 Header validation

A reader MUST validate all available blob headers before allocating frame-sized buffers.

Within one generation, available headers MUST agree on every archive field and on `generation_id`. A disagreement is corruption.

A reader MUST reject unknown `version`, `frame_size_mode`, invalid `max_frame_quanta`, unsupported allocation size, or inconsistent header copies before using those values for memory allocation.

## 2.4 Blob naming

Blob files remain:

```text
frames/blob-00.stash
...
frames/blob-FE.stash
```

`blob_ordinal` is therefore uint8. At most 255 active blobs exist in one generation.

Historical generations MAY reuse the same ordinal values because generation identity separates them. `blob_ordinal` MUST NOT be treated as a globally monotonically increasing archive identifier.

---

# 3. Grid Geometry and Frame Size Modes

## 3.1 Base quantum

```text
BASE_QUANTUM = 4096 bytes
```

Every physical frame size MUST be a positive integral multiple of `BASE_QUANTUM`.

```text
frame_size = frame_quanta * BASE_QUANTUM
frame_quanta >= 1
frame_quanta <= max_frame_quanta
MAX_FRAME_SIZE = max_frame_quanta * BASE_QUANTUM
```

Production implementations MUST impose a configured safe allocation ceiling before allocating a buffer based on untrusted frame metadata.

The R8 reference implementation SHOULD default to a practical `MAX_FRAME_SIZE` such as 4 MiB for mixed workloads. Production configurations MUST impose a validated allocation ceiling and SHOULD NOT exceed 64 MiB by default; larger values require explicit operator configuration and implementation-specific resource validation.

## 3.2 VARIABLE mode — `frame_size_mode = 0x00`

A frame MAY use any integral number of 4 KiB quanta from `1` through `max_frame_quanta`.

```text
4096 <= frame_size <= MAX_FRAME_SIZE
frame_size % 4096 == 0
```

There is no global `BLOCK_STRIDE`.

The next physical frame is:

```text
next_frame_offset = current_frame_offset + current_frame_size
```

The frame's fixed Prefix (§6.1) makes `current_frame_size` available before reading the variable-length body.

## 3.3 FIXED mode — `frame_size_mode = 0x01`

Every frame MUST satisfy:

```text
frame_quanta == max_frame_quanta
frame_size   == MAX_FRAME_SIZE
```

Any frame with a different `frame_quanta` is corrupt.

Exact physical addressing is restored:

```text
frame_start(n) = 0x40 + n * MAX_FRAME_SIZE
```

and:

```text
frame_ordinal_at_creation =
    (physical_offset - 0x40) / MAX_FRAME_SIZE
```

FIXED mode therefore supports direct random frame positioning and parallel disaster-recovery partitioning without a sequential dependency on previous frames.

The final logical fragment of an object MAY have `logical_length < MAX_FRAME_SIZE`; unused physical capacity is padding.

## 3.4 Physical and logical geometry are independent

Physical frame size and logical object extent are different quantities.

A compressed frame can represent a logical region whose byte length differs from `data_len`. `frame_size` is physical allocation; `data_len` is stored payload representation length; `logical_length` is logical object data length.

Implementations MUST NOT use these fields interchangeably.

---

## 3.5 VARIABLE vs FIXED intent

New archives SHOULD default to `VARIABLE` unless `FIXED` is explicitly selected.

| Mode | Primary purpose |
|---|---|
| `VARIABLE` | General enterprise archival use. Reduces padding and write amplification while retaining independent quantum-boundary recovery. |
| `FIXED` | Deterministic direct-slot geometry. Optimized for workloads where maximum recovery-scan parallelism and direct physical arithmetic justify increased padding. |

R8 defines no additional frame-size modes. `frame_size_mode` remains immutable for the entire archive lifetime.

---

# 4. Hash Algorithms and Hash Scope

R8 deliberately exposes only two payload-hash algorithms:

| Value | Algorithm | Digest |
|---|---|---:|
| `0x00` | reserved | — |
| `0x01` | BLAKE3 | 32 B |
| `0x02` | SHA-256 | 32 B |
| `0x03-0xFF` | reserved | — |

Writers MUST NOT emit reserved values. Readers MUST reject unknown non-zero `hash_id` values.

`hash_id` is immutable for the lifetime of the archive.

## 4.1 Hash scope

`hash_payload` is computed over the exact stored payload representation:

- unencrypted: STORE or compressed payload bytes exactly as stored;
- encrypted: `nonce[12] || ciphertext || tag[16]` exactly as stored.

The hash excludes:

- Frame Prefix;
- zero padding;
- Pre-Trailer;
- `pre_trailer_len`;
- Master Trailer;
- Archive Header.

Identical logical plaintext is not guaranteed to have identical `hash_payload`, because compression output and encryption nonce/key context can change the stored representation.

> STASH R8 does not define cross-archive or cross-tenant plaintext deduplication. Deduplication operates only on byte-identical stored payload representations.

---

# 5. Compression Profiles

`codec_id` identifies a complete R8 compression-strength profile, not merely an algorithm family.

| Value | Profile | Algorithm | Compression level |
|---|---|---|---:|
| `0x00` | STORE | none | — |
| `0x01` | ZSTD_FAST | Zstandard | 1 |
| `0x02` | ZSTD_DEFAULT | Zstandard | 3 |
| `0x03` | ZSTD_DENSE | Zstandard | 9 |
| `0x04-0xFF` | reserved | — | — |

The Archive Header `codec_id` remains the archive default and MAY be overridden per frame by the Master Trailer `codec_id`.

Writers MUST NOT emit reserved codec identifiers. Readers MUST reject unknown non-zero codec identifiers.

## 5.1 Zstandard requirements

For every `ZSTD_*` payload:

- the stored representation MUST contain exactly one independently decodable Zstandard frame;
- no external Zstandard dictionary is permitted;
- decoding MUST NOT depend on another STASH frame;
- malformed or truncated compressed input MUST fail closed;
- decompressed output MUST equal the declared logical representation exactly;
- decompressed output MUST NOT exceed the already validated STASH logical-length ceiling.

The writer compression-strength profiles are normative:

```text
ZSTD_FAST    = level 1
ZSTD_DEFAULT = level 3
ZSTD_DENSE   = level 9
```

R8 does **not** claim that independent Zstandard implementations or library versions necessarily produce byte-identical compressed output from equal logical input.

```text
equal logical data != guaranteed equal compressed bytes
```

Whole-frame deduplication therefore occurs only when the resulting stored representations are byte-identical.

There is no `ZSTD_MAX` profile in R8. Values `0x04-0xFF` are genuinely reserved.

## 5.2 Named interoperability and deployment profiles

The following names are combinations of existing wire fields. No `profile_id` is stored on disk.

### BASELINE

Purpose: **minimum interoperable STASH implementation**.

```text
hash        SHA-256
compression STORE
encryption  NONE
```

A minimal conformant R8 reader/writer MUST support BASELINE and MUST additionally support:

- VARIABLE geometry;
- DATA frames;
- Frame Prefix CRC32C;
- Master Trailer integrity through the mandatory Pre-Trailer CRC32C binding defined in §6.4;
- Pre-Trailer CRC32C;
- manifest reading/writing;
- physical-offset-index rebuild;
- raw physical scanning;
- logical reconstruction of non-packed DATA.

A BASELINE-only implementation MAY omit writing FIXED, PACKED, parity, encryption, and compaction, but it MUST safely recognize and reject unsupported R8 features rather than misparse them.

### SECURE

Purpose: **conservative authenticated enterprise archival profile**.

```text
hash        SHA-256
compression STORE
encryption  AES-256-GCM
```

The cryptographic construction is fully defined by §15. The SECURE **payload-hash/compression/encryption path** uses conservative standardized primitives and does not require BLAKE3 or Zstandard for those functions. R8 nevertheless retains the R7 `object_id` derivation in §6.5, which uses BLAKE3; therefore a full conformant writer still needs the object-ID primitive.

### FAST

Purpose: **maximum practical ingest and recovery throughput**.

```text
hash        BLAKE3
compression ZSTD_FAST
encryption  NONE
```

FAST is intended for deployments where encryption is unnecessary or is provided by another trusted storage/security layer.

### Profile scope

The names bind only:

```text
hash
compression
encryption
```

They do not redefine VARIABLE/FIXED, parity, PACKED, `blob_count`, or `MAX_FRAME_SIZE`. Those remain orthogonal archive properties.

The STASH Go reference implementation MUST support BASELINE, SECURE, and FAST.

---

# 6. Frame Binary Format

R8 uses a fixed 16-byte Frame Prefix at the start and a fixed 96-byte Master Trailer at the end of every frame.

```text
[ Frame Prefix: 16 B ]
[ stored payload ]
[ zero padding ]
[ Pre-Trailer body ]
[ pre_trailer_len: 4 B ]
[ Master Trailer: 96 B ]
```

The complete region above is exactly `frame_size` bytes.

## 6.1 Frame Prefix — 16 bytes

The Prefix exists so a VARIABLE-mode recovery scanner can determine the physical extent before reading the complete frame.

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | magic | char[4] | `STFR` |
| `0x04` | 4 | frame_quanta | uint32 | physical size / 4096 |
| `0x08` | 4 | prefix_crc32c | uint32 | CRC32C over `magic || frame_quanta || flags` |
| `0x0C` | 4 | flags | uint32 | zero in base R8 profile |

A reader MUST validate Prefix magic, CRC, and bounds before allocating or reading the full frame.

In FIXED mode it MUST additionally verify:

```text
frame_quanta == max_frame_quanta
```

## 6.2 Master Trailer — 96 bytes

R8 retains the larger self-describing trailer because non-packed DATA frames must carry logical placement information directly in raw storage.

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | magic | char[4] | `STSH` |
| `0x04` | 1 | hash_id | uint8 | MUST match Archive Header |
| `0x05` | 1 | codec_id | uint8 | codec used by this frame |
| `0x06` | 1 | block_type | uint8 | `0 DATA`, `1 PARITY`, `2 PACKED` |
| `0x07` | 1 | flags | uint8 | reserved / zero in base profile |
| `0x08` | 4 | group_id | uint32 | `0` if not in parity group |
| `0x0C` | 1 | group_index | uint8 | group position |
| `0x0D` | 1 | group_k | uint8 | data count |
| `0x0E` | 1 | group_m | uint8 | parity count |
| `0x0F` | 1 | reserved | uint8 | zero |
| `0x10` | 4 | data_len | uint32 | stored payload representation length |
| `0x14` | 4 | frame_quanta | uint32 | redundant with Prefix; MUST agree |
| `0x18` | 16 | object_id | bytes | logical object identity; zero for non-object parity frames |
| `0x28` | 8 | logical_offset | uint64 | non-packed logical byte offset |
| `0x30` | 8 | logical_length | uint64 | logical bytes represented |
| `0x38` | 8 | frame_ordinal | uint64 | immutable creation-time ordinal |
| `0x40` | 32 | hash_payload | bytes | §4 |

Trailer and Prefix `frame_quanta` disagreement is corruption.

### Block-type semantics

**DATA:** one non-packed logical object extent. `object_id`, `logical_offset`, `logical_length` are mandatory.

**PACKED:** multiple small logical objects described in the Pre-Trailer. Trailer-level `object_id`, `logical_offset`, and `logical_length` MUST be zero. Packed entry offsets use `inner_offset` semantics (§8).

**PARITY:** parity payload. Object-placement fields MUST be zero unless a future format revision explicitly defines otherwise.

## 6.3 Payload budget

The exact physical constraint is:

```text
data_len
+ FRAME_PREFIX_SIZE
+ zero_padding_len
+ pre_trailer_len
+ 4                       // pre_trailer_len field
+ MASTER_TRAILER_SIZE
= frame_size
```

where:

```text
FRAME_PREFIX_SIZE  = 16
MASTER_TRAILER_SIZE = 96
zero_padding_len >= 0
```

Therefore:

```text
data_len <=
    frame_size
  - 16
  - 4
  - 96
  - pre_trailer_len
```

A writer MUST calculate this exact budget before commit. A reader MUST reject overlap between payload and Pre-Trailer.

## 6.4 Pre-Trailer

Immediately before the 4-byte `pre_trailer_len` field is `pre_trailer_body`.

Unencrypted body structure:

```text
uint32 entry_count
repeated entry_count times:
    varint path_len
    bytes  canonical_path_utf8
    uint64 inner_offset_or_logical_offset
    uint64 inner_length_or_logical_length
    uint64 file_ver
uint32 crc32c
```

`pre_trailer_len` is the complete byte length of `pre_trailer_body`, including the CRC field.

R8 does not add a physical CRC field to the 96-byte Master Trailer. Instead, the mandatory Pre-Trailer CRC32C binds the externally located length field **and the complete 96-byte Master Trailer bytes**:

```text
crc32c = CRC32C(
    pre_trailer_body_without_crc
    || uint32_le(pre_trailer_len)
    || master_trailer_bytes[96]
)
```

This preserves the R7 physical layout while making accidental modification of any Master Trailer bit detectable before trailer metadata is trusted. A frame with zero logical Pre-Trailer entries still carries the minimal body (`entry_count = 0` plus CRC32C), so this integrity binding is always present.

Reverse parsing order:

1. locate the 96-byte Master Trailer from the known frame end;
2. read `pre_trailer_len` immediately before it;
3. validate length bounds before allocation;
4. locate and read the complete body;
5. verify CRC32C using the formula above, including the complete Master Trailer bytes;
6. only then trust or parse Pre-Trailer or Master Trailer metadata.

Encrypted Pre-Trailers replace the plaintext body with the AEAD representation defined in §15.4.

## 6.5 `object_id`

R8 uses a 16-byte object identifier:

```text
object_id = first_16_bytes(
    BLAKE3(
        ASCII("STASH-OBJECT-ID-V2")
        || canonical_path_utf8
        || uint64_le(file_ver)
    )
)
```

`object_id` is **not stable across rename**.

A rename changes `canonical_path`, therefore produces a new `object_id`. In R8, rename is modeled as a new logical object/version under copy-on-write semantics. Existing frames under the old identity remain valid until they become unreachable and are reclaimed by GC.

R8 does not define a path-independent inode/object UUID alias layer.

## 6.6 Logical placement invariants

For non-packed DATA frames:

```text
logical_offset % BASE_QUANTUM == 0
logical_length > 0
```

`logical_length` MAY be non-4KiB-aligned for the final logical region.

A frame represents:

```text
[logical_offset, logical_offset + logical_length)
```

Physical discovery order MUST NOT define object order.

---

# 7. Parity / Erasure Coding

R8 defines exactly two non-zero parity algorithms:

| Value | Scheme | Tolerance |
|---|---|---|
| `0x00` | none | 0 |
| `0x01` | XOR | 1 frame/group |
| `0x02` | Reed-Solomon | `parity_m` frames/group |
| `0x03-0xFF` | reserved | — |

Writers MUST NOT emit any other non-zero parity scheme. Readers MUST reject unknown non-zero parity-scheme values.

Header invariants:

```text
NONE:
    parity_k = 0
    parity_m = 0

XOR:
    parity_k > 0
    parity_m = 1

Reed-Solomon:
    parity_k > 0
    parity_m > 0

all active parity:
    blob_count >= 2
    parity_k + parity_m <= 256
```

Every DATA and PARITY member of a group self-describes:

- `group_id`;
- `group_index`;
- `group_k`;
- `group_m`.

`group_id` MUST be unique within the archive lifetime and MUST NOT wrap or be reused.

## 7.1 Equal physical geometry within a group

All members of one parity group MUST have identical `frame_quanta` and therefore identical physical `frame_size`.

This is mandatory in both modes. In FIXED mode the invariant is trivially satisfied because every frame has `frame_size = MAX_FRAME_SIZE`. In VARIABLE mode the writer MUST form groups only from equal-sized frames or defer frames until a compatible group can be formed.

## 7.2 Spread rule

A parity group MUST span at least two distinct blobs when parity is enabled. Compaction MUST preserve this rule in the destination generation.

## 7.3 Manifest redundancy

A `PARITY_GROUP` manifest record MAY redundantly list group members for operational convenience, but raw-frame `group_id`/`group_index`/`group_k`/`group_m` metadata is authoritative for manifest-independent group discovery.

Integrity detection is not repair: CRC32C, `hash_payload`, and AEAD can identify damage, but only parity or another intact source can reconstruct damaged data.

---

# 8. Frame Packing

PACKED frames aggregate small files before compression.

Packing procedure:

1. normalize paths;
2. sort files lexicographically by canonical path;
3. concatenate file bytes into one logical packed buffer;
4. compress the complete buffer using the selected canonical codec profile;
5. write one PACKED frame if physical limits permit.

Packed entries use:

```text
inner_offset
inner_length
```

relative to the **uncompressed packed logical buffer**.

Non-packed DATA frames use:

```text
logical_offset
logical_length
```

relative to the complete logical object.

These semantics MUST NOT be mixed.

PACKED frames are supported identically in VARIABLE and FIXED modes. In FIXED mode the physical container is always `MAX_FRAME_SIZE`; unused capacity is padding.

If a candidate packed file cannot fit into an otherwise-empty frame, the writer MUST fail the packing attempt immediately and route the file through the non-packed multi-frame path. It MUST NOT retry indefinitely.

---

# 9. Logical Object Mapping and Localized Copy-on-Write

## 9.1 Manifest location tuple

For non-packed extents:

```text
[blob_ordinal, frame_hash, logical_offset, logical_length]
```

The manifest intentionally does **not** contain `physical_offset`. Physical placement changes during compaction and belongs to the per-generation physical index (§10.4).

`frame_hash` lookup can return multiple physical candidates if payload-identical frames exist. The physical index is therefore a multimap; object/trailer metadata resolves the intended extent.

## 9.2 Ordering

Logical order is determined exclusively by `logical_offset`.

The order of entries inside `loc`, `ADD_EXTENT`, index files, or physical blob discovery MUST NOT be used as an ordering guarantee.

## 9.3 Logical Recovery Grid

R8 defines a conceptual 4 KiB Logical Recovery Grid:

```text
logical_quantum_index = logical_offset / 4096
quantum_count = ceil(logical_length / 4096)
```

A recovery implementation MAY map extents into 4 KiB entries, page tables, interval maps, radix structures, or another equivalent representation.

The in-memory representation is implementation-defined and is not part of the wire format.

## 9.4 Overlap and gap detection

During recovery, two live extents of the same `(object_id, version)` claiming overlapping logical byte ranges are a conflict/corruption condition unless an explicit newer manifest transaction resolves the overlap.

A reader MUST NOT silently choose one candidate.

Missing logical regions MUST be surfaced as incomplete/degraded data, not zero-filled silently unless higher-level policy explicitly requests sparse-file semantics.

## 9.5 Immutable localized rewrite

A committed frame MUST NEVER be modified in place.

A logical modification is implemented as:

```text
read affected frame(s)
-> decompress/decrypt as required
-> modify logical bytes
-> repartition into valid R8 frame extents
-> write new immutable frame(s)
-> durably commit new manifest version
-> old frame(s) remain until GC
```

This is a logical rewrite/repartition operation, not physical frame splitting.

## 9.6 Insert / resize behavior in VARIABLE mode

VARIABLE mode exists to localize size-changing edits.

Example:

```text
OLD:
[A 4096 KiB][B ...][C ...]

insert 100 KiB into A

NEW, if permitted by MAX_FRAME_SIZE:
[A' 4196 KiB][B unchanged][C unchanged]
```

Subsequent frames MUST NOT be rewritten solely to preserve old fixed-size boundaries.

If the rewritten frame would exceed `MAX_FRAME_SIZE`, only the affected local region is repartitioned into multiple new grid-aligned frames. Unaffected following frames remain referenceable with their existing hashes.

## 9.7 FIXED-mode rewrite semantics

In FIXED mode every newly written physical frame remains exactly `MAX_FRAME_SIZE`.

A local insert may therefore require one or more full fixed frames for the modified region, and the last new fragment can be logically shorter while remaining physically full-sized.

FIXED mode intentionally trades greater write amplification for direct physical O(1) geometry and faster disaster-recovery partitioning.

---

# 10. Manifest and Physical Indexing

## 10.1 Manifest journal

`manifest.jsonl` remains an append-only logical journal.

Every committed record carries a strictly increasing `seq`. `ts` is informational only and MUST NOT define ordering.

Manifest writes are serialized through one logical manifest commit stream even while blob data writes occur in parallel.

`MAX_MANIFEST_LINE_BYTES = 1 MiB`.

Readers MUST reject a line exceeding the bound rather than buffer unbounded data.

## 10.2 Normal ADD / DEL

Example non-packed ADD:

```json
{"seq":1,"op":"ADD","path":"db/data.bin","ver":7,"loc":[[3,"<hash>",0,4194304]]}
```

`DEL` removes the current logical path version but does not physically delete referenced frames.

## 10.3 Large object transactions: `ADD_BEGIN` / `ADD_EXTENT` / `ADD_COMMIT`

A logical object whose location metadata does not fit in one bounded line MUST use a transactional extent sequence.

Example:

```json
{"seq":100,"op":"ADD_BEGIN","tx_id":"...","path":"db/huge.bin","ver":8}
{"seq":101,"op":"ADD_EXTENT","tx_id":"...","extent_sequence":0,"loc":[[0,"h1",0,4194304],[1,"h2",4194304,4194304]]}
{"seq":102,"op":"ADD_EXTENT","tx_id":"...","extent_sequence":1,"loc":[[2,"h3",8388608,4194304]]}
{"seq":103,"op":"ADD_COMMIT","tx_id":"...","extent_count":3}
```

One `ADD_EXTENT` line SHOULD batch as many extent tuples as possible without exceeding `MAX_MANIFEST_LINE_BYTES`.

`ADD_EXTENT` does **not** require an `fsync` after every line.

The object becomes logically visible only after a valid durable `ADD_COMMIT`.

A transaction missing `ADD_COMMIT`, containing duplicate/missing `extent_sequence`, or failing declared extent-count validation is incomplete and MUST be ignored as a committed object version.

## 10.4 Durability / group commit

Required ordering:

```text
write all referenced frame bytes
-> flush/fsync affected blob(s)
-> append manifest transaction records
-> append ADD_COMMIT / terminal record
-> flush/fsync manifest
-> report transaction durable
```

Multiple manifest records MAY share one group `fsync` boundary.

A manifest MUST never become durably authoritative before every referenced frame is durably stored.

## 10.5 Mandatory per-generation physical offset index

R8 retains the physical frame offset index from an optional optimization to a first-class maintained structure.

Recommended path:

```text
index/blob-XX.idx
```

The index belongs to one `(generation_id, blob_ordinal)` pair and maps:

```text
frame_hash -> one or more physical frame records
```

A canonical 64-byte record is:

| Offset | Size | Field |
|---|---:|---|
| `0x00` | 32 | frame_hash |
| `0x20` | 8 | physical_offset |
| `0x28` | 4 | frame_quanta |
| `0x2C` | 1 | block_type |
| `0x2D` | 3 | reserved |
| `0x30` | 8 | frame_ordinal |
| `0x38` | 8 | reserved |

Records SHOULD be sorted lexicographically by `frame_hash` so an on-disk implementation can provide O(log N) lookup by binary search. An implementation MAY maintain an in-memory hash map for O(1) average lookup.

Duplicate `frame_hash` records are valid; lookup is a multimap.

The index:

- MUST be maintained for normal hot-path operation;
- MUST be regenerated during compaction for the new generation;
- MUST be fully rebuildable by raw blob scanning;
- MUST NOT be authoritative for correctness;
- MUST NOT make disaster recovery depend on its presence.

If an index is missing/corrupt, a reader MAY degrade to scanning for correctness, but MUST schedule/rebuild the index before returning to the normal hot path.

## 10.6 LINK_MANIFEST

Canonical example:

```json
{"seq":42,"op":"LINK_MANIFEST","path":"submanifests/user-data.jsonl","hash_id":1,"hash":"...","lines":50000}
```

Linked manifests are independently verifiable. Compaction liveness MUST evaluate the complete reachable manifest graph.

---

# 11. Disaster Recovery — Hop-and-Read

## 11.1 Common recovery start

For every available blob:

1. read the 64-byte Archive Header at `0x00`;
2. validate archive parameters and `frame_size_mode`;
3. begin at `FRAME_AREA_START = 0x40`.

## 11.2 VARIABLE-mode scan

At each current frame offset:

1. read the 16-byte Frame Prefix;
2. validate Prefix CRC and `frame_quanta` bounds;
3. compute `frame_size = frame_quanta * 4096`;
4. read or seek directly to the 96-byte Master Trailer at `current + frame_size - 96`;
5. validate Prefix/Trailer agreement;
6. validate payload and Pre-Trailer boundaries;
7. verify hash / AEAD / CRC as required;
8. recover logical metadata;
9. advance:

```text
current += frame_size
```

This scan is deterministic but sequentially dependent on the previous frame's validated size.

## 11.3 FIXED-mode scan

A reader can directly address any frame slot:

```text
physical_offset(n) = 0x40 + n * MAX_FRAME_SIZE
```

Recovery MAY partition slot ranges across threads/nodes without first walking earlier frames.

Every slot's Prefix MUST still confirm:

```text
frame_quanta == max_frame_quanta
```

## 11.4 Logical reconstruction

For DATA frames, recovery uses `object_id`, `logical_offset`, and `logical_length` from self-describing metadata.

Frames MAY be discovered in arbitrary physical order.

A recovery implementation MAY create a 4 KiB logical map and mark the quanta covered by each recovered extent. For example a 4 MiB logical extent covers 1024 Logical Recovery Quanta.

Discovery order is irrelevant; logical placement is authoritative.

## 11.5 PACKED recovery

PACKED frames are reconstructed by reverse-parsing and validating the Pre-Trailer, then mapping each entry using its packed-buffer `inner_offset` / `inner_length` metadata.

## 11.6 Parity recovery

Parity groups are reconstructed from frame-local `group_id`, `group_index`, `group_k`, and `group_m` metadata. Manifest presence is not required to discover group membership.

## 11.7 Encrypted recovery

The stored AEAD nonce is authoritative for decryption.

Recovery MUST read the nonce directly from:

```text
nonce[12] || ciphertext || tag[16]
```

It MUST NOT derive or guess the decryption nonce from the frame's **current** physical location, because compaction is permitted to byte-copy ciphertext to a different generation/blob/offset.

---

# 12. Concurrency and Writer Allocation

Data writers MAY operate concurrently across blobs.

Within one blob, physical extent allocation MUST be serialized so two writers cannot claim overlapping frame regions.

VARIABLE mode allocator advances by the just-committed `frame_size`.

FIXED mode allocator advances by `MAX_FRAME_SIZE`.

Manifest commits remain a separate serialization domain.

`frame_ordinal` allocation is writer-local to one `(generation_id, blob_ordinal)` namespace. A cold-start writer MAY discover the next ordinal by scanning/rebuilding blob state once, then keep the next value in memory. This is analogous to generation-ID discovery and does not require a global archive lock.

---

# 13. Compaction / Garbage Collection

Compaction remains:

```text
Mark -> Sweep -> Freeze/Merge -> Switch -> GC
```

## 13.1 Global Mark

Mark liveness over the complete manifest graph reachable from the root, not just the sub-manifest that triggered compaction.

Logical multi-frame files and parity groups are integrity units and MUST NOT be partially forgotten by scoped liveness analysis.

## 13.2 Sweep

Write a new generation. Never modify active-generation blob files in place.

Compaction MAY change:

- current `generation_id`;
- current `blob_ordinal`;
- current `physical_offset`;
- current physical ordering.

Byte-copy compaction MUST preserve:

- stored payload bytes;
- ciphertext nonce and tag;
- `hash_payload`;
- object/logical placement metadata;
- frame's immutable creation metadata;
- parity metadata;
- `frame_quanta`.

In VARIABLE mode a normal byte-copy Sweep MUST NOT resize a frame. Resizing/repacking is a rewrite operation, not opaque compaction.

## 13.3 Encrypted opaque-copy invariant

Encrypted frames MUST be copied byte-for-byte during normal Sweep.

The new current physical location has no effect on the stored nonce.

A compactor MUST NOT decrypt/re-encrypt a live frame for the purpose of relocation, nonce refresh, dedup optimization, or physical reordering.

## 13.4 Concurrent writes

Writes occurring after the Mark snapshot MUST be captured in a delta manifest or protected during the final Freeze/Merge/Switch interval by an appropriate lock/lease.

No writer may commit against the old root after the new root becomes authoritative.

## 13.5 Switch

The destination generation, manifest, and physical indices MUST be fully written, verified, and durable before the root pointer is atomically switched.

Old generations remain intact until the switch is durable.

## 13.6 Parity groups during compaction

If any live member of a parity group is copied, the complete required group MUST be present in the new generation before Switch.

The destination MUST preserve equal `frame_quanta` across group members and the multi-blob spread requirement.

## 13.7 Multi-frame logical object integrity

All live sibling extents of a logical object version MUST be verified in the destination before the old generation containing the only remaining copy of a required extent is deleted.

If a required extent cannot be found or verified, the generation is **GC-blocked** rather than silently deleted.

## 13.8 Emergency Pruning and parity impact

Emergency Pruning is an explicit operator-authorized data-loss escape hatch for a permanently GC-blocked generation.

Before deletion, the implementation MUST perform **Parity Impact Analysis** over every parity group touched by any frame that will be lost.

Each affected parity group MUST be classified as:

- **HEALTHY** — required protection level still intact;
- **DEGRADED** — data remains reconstructable but redundancy is below the configured target;
- **UNRECOVERABLE** — one or more protected logical data extents can no longer be reconstructed.

Emergency Pruning MUST:

1. durably record an `EMERGENCY_PRUNE` event with generation, affected blobs/frames, operator reason, and timestamp;
2. mark every directly incomplete logical object `DEGRADED` or `UNRECOVERABLE`;
3. record every parity group whose protection level changes;
4. create/schedule parity rebuild for repairable surviving groups, or explicitly mark them `UNPROTECTED/DEGRADED` until repair completes;
5. prevent the active manifest/health metadata from claiming original parity protection while the group is degraded;
6. only then permit deletion of the blocked old generation.

Emergency Pruning MUST NOT be used merely because a healthy resource is temporarily unreachable.

---

# 14. Legacy Compatibility

R8 wire version is `0x0006`.

Readers MUST dispatch on Archive Header `version` and MUST NOT parse older layouts using R8 structures.

At minimum:

- `0x0002` — R1/R2 family;
- `0x0003` — R3/R4/R5 family;
- `0x0004` — R6 development wire layout;
- `0x0005` — R7;
- `0x0006` — R8.

R8-only implementations MUST reject unsupported versions rather than guess.

Legacy v1.21 `.sf` and `SUB` syntax remains migration-only and is not valid R8 syntax.

---

# 15. Encryption — Normative R8 Enterprise Profile

R8 defines one encryption algorithm: AES-256-GCM. Encryption is optional at the archive/profile level; when enabled, the following construction is normative.

## 15.1 Archive DEK

An encrypted STASH archive uses one cryptographically random 32-byte archive data-encryption key:

```text
archive_DEK = 32 bytes
```

The archive DEK MUST remain fixed for the lifetime of the encrypted archive. It MUST NOT be embedded in blobs, Frame Prefixes, Pre-Trailers, or Master Trailers.

A deployment MAY store a wrapped copy and key identifier in protected archive metadata or an external KMS-backed configuration.

## 15.2 Domain-separated AEAD keys

Three independent 256-bit keys are derived using HKDF-SHA-256:

```text
salt = archive_id[32]
IKM  = archive_DEK
```

Exact derivations:

```text
frame_aead_key =
    HKDF-SHA256(
        IKM  = archive_DEK,
        salt = archive_id,
        info = ASCII("STASH-FRAME-AEAD-R8"),
        L    = 32
    )

pretrailer_aead_key =
    HKDF-SHA256(
        IKM  = archive_DEK,
        salt = archive_id,
        info = ASCII("STASH-PRETRAILER-AEAD-R8"),
        L    = 32
    )

manifest_aead_key =
    HKDF-SHA256(
        IKM  = archive_DEK,
        salt = archive_id,
        info = ASCII("STASH-MANIFEST-AEAD-R8"),
        L    = 32
    )
```

The quoted `info` strings are exact ASCII bytes without a trailing NUL. The three keys MUST NOT be collapsed into one key.

## 15.3 AES-256-GCM stored representation

```text
algorithm = AES-256-GCM
nonce     = 12 bytes
tag       = 16 bytes
```

Stored payload representation:

```text
payload_ciphertext = nonce[12] || ciphertext || tag[16]
```

Stored encrypted Pre-Trailer representation:

```text
pre_trailer_ciphertext = nonce[12] || ciphertext || tag[16]
```

Encrypted manifest fields similarly store `nonce || ciphertext || tag` inside the encoded manifest representation.

Payload, Pre-Trailer, and manifest use their respective independently derived AEAD keys. `hash_payload` covers the complete stored encrypted payload representation including nonce and tag.

## 15.4 Frame AAD

R8 frame payload and encrypted Pre-Trailer AEAD bind only stable bytes that are available from the frame itself after manifest loss and remain unchanged during byte-preserving compaction.

Canonical AAD is:

```text
archive_id[32]
|| uint16_le(version)              // MUST be 0x0006
|| frame_prefix_magic[4]           // exact bytes, normally "STFR"
|| uint32_le(frame_quanta)         // validated Prefix value
|| uint32_le(frame_prefix_flags)
|| master_trailer_bytes[0x00:0x40] // first 64 bytes, ending immediately before hash_payload
```

`master_trailer_bytes[0x00:0x40]` includes the trailer magic, algorithm IDs, block type/flags, parity metadata, `data_len`, redundant `frame_quanta`, `object_id`, `logical_offset`, `logical_length`, and `frame_ordinal`. It deliberately excludes `hash_payload`, because `hash_payload` is calculated over the completed stored payload representation and including it in payload AAD would create a circular dependency.

The Frame Prefix CRC32C itself is not included in AAD; its covered semantic fields are already included explicitly.

The same canonical frame AAD is used with the separately derived `frame_aead_key` and `pretrailer_aead_key`. Key separation prevents the two AEAD domains from collapsing even though their stable AAD bytes are equal.

A byte-preserving compactor MUST retain all AAD-covered frame metadata unchanged. Destination generation, destination blob ordinal, and destination physical offset are intentionally absent from AAD.

## 15.5 Collision-free numeric nonce construction

R8 removes BLAKE3-based/truncated-hash nonce derivation entirely.

For encrypted archives only, implementations MUST enforce before encryption:

```text
generation_id <= 0xFFFFFFFF
frame_ordinal <= 0x00FFFFFFFFFFFFFF
```

The physical fields remain uint64. Exceeding the encrypted-profile limit MUST fail before a new encryption operation is attempted.

### 15.5.1 Frame payload nonce

For every newly encrypted frame:

```text
payload_nonce =
    uint32_le(generation_id)
    || uint8(blob_ordinal)
    || uint56_le(frame_ordinal)
```

Exact size:

```text
4 + 1 + 7 = 12 bytes
```

`uint56_le(x)` means the low seven bytes of the canonical little-endian unsigned representation, and is valid only after the bound above has been checked.

### 15.5.2 Pre-Trailer nonce

The Pre-Trailer uses the identical numeric nonce representation:

```text
pretrailer_nonce =
    uint32_le(generation_id)
    || uint8(blob_ordinal)
    || uint56_le(frame_ordinal)
```

Reusing the numeric nonce bytes here is safe because Pre-Trailer and payload use different independently derived AEAD keys.

### 15.5.3 Manifest nonce

For every newly encrypted manifest record:

```text
manifest_nonce =
    uint32_le(generation_id)
    || uint64_le(seq)
```

Exact size:

```text
4 + 8 = 12 bytes
```

### 15.5.4 Nonce uniqueness invariant

Under one derived AEAD key:

- `generation_id` MUST never be reused;
- `frame_ordinal` MUST never be reused within one `(generation_id, blob_ordinal)` namespace;
- manifest `seq` MUST remain unique within its generation;
- any wraparound or attempted reuse is fatal.

The construction is injective inside the permitted R8 encrypted namespaces and does not rely on probabilistic collision resistance.

Stored nonces remain part of the ciphertext representation. Readers MUST use the stored nonce for decryption.

## 15.6 Compaction and encrypted frame identity

A copied frame is not a new encryption operation.

Normal compaction MUST preserve byte-for-byte:

```text
nonce
ciphertext
tag
hash_payload
frame_ordinal
origin frame identity/AAD metadata
```

Current destination `generation_id`, `blob_ordinal`, and `physical_offset` may change, but MUST NOT be used to recompute a nonce or replace authenticated origin identity.

A compactor MUST NOT decrypt/re-encrypt a live frame merely for relocation, nonce refresh, physical reordering, or dedup optimization.

## 15.7 Encrypted manifest records

Sensitive path/version-bearing records use an encrypted envelope such as:

```json
{"seq":105,"ts":1739550123,"op":"ADD_ENC","enc":"<base64(nonce || ciphertext || tag)>"}
```

Equivalent encrypted envelopes apply to DEL and transactional ADD records when sensitive fields are present.

Manifest AAD canonically binds:

```text
archive_id[32]
|| uint16_le(version)              // 0x0006
|| uint32_le(generation_id)
|| uint64_le(seq)
|| uint32_le(op_len)
|| exact UTF-8 op bytes
```

An AAD mismatch is tampering and MUST be rejected.

## 15.8 Key rotation

### KEK/KMS rotation

A deployment MAY rotate the KEK/KMS key by unwrapping and rewrapping the unchanged archive DEK:

```text
old KEK
    ↓ unwrap
archive DEK
    ↓ rewrap
new KEK
```

This does not modify STASH frames and does not require a new archive.

### Archive DEK rotation

The archive DEK is immutable for the lifetime of an encrypted STASH archive. Changing it requires a new archive plus an explicit decrypt/migrate/re-encrypt operation.

Normal compaction MUST NOT rotate the archive DEK and MUST continue to copy encrypted live frames byte-for-byte.

## 15.9 Encryption and self-describing recovery

Without keys, recovery can still obtain frame boundaries, `frame_quanta`, physical frame size, block type, payload hash, and plaintext parity metadata. Plaintext object path/version and encrypted Pre-Trailer mappings require the relevant key.

With keys, recovery reads the nonce directly from the stored `nonce || ciphertext || tag` representation. It MUST NOT derive a decryption nonce from the frame's current physical location.

## 15.10 Encryption and deduplication

R8 distinguishes logical/content identity from ciphertext identity. Standard R8 encryption does not guarantee that identical plaintext written independently produces identical ciphertext.

Convergent/content-derived encryption and cross-tenant plaintext deduplication are outside R8.

---

# 16. Resource-Exhaustion Hardening and Normative Invariants

## 16.1 General untrusted-input rule

> No untrusted on-disk value may directly cause unbounded memory allocation, recursion, goroutine/task creation, or uncontrolled work amplification before applicable wire and implementation ceilings have been validated.

Readers MUST enforce bounded processing for at least:

- frame size;
- Pre-Trailer size;
- PACKED entry count;
- path length;
- manifest record size;
- pending manifest transaction state;
- recovery concurrency;
- physical-index rebuild concurrency.

Existing R8 wire/production ceilings include:

```text
blob_count <= 255
MAX_PACKED_ENTRIES = 65535
path_len <= 4096
manifest line <= 1 MiB
parity_k + parity_m <= 256
production MAX_FRAME_SIZE <= 64 MiB by default
```

Archive-scale collections MUST be streamable rather than requiring archive-sized in-memory slices.

Checked arithmetic is mandatory for all externally influenced:

```text
offset + length
size multiplication
frame end
logical range end
index range
Pre-Trailer boundaries
```

Unsigned overflow MUST fail closed.

## 16.2 Geometry

A conformant R8 implementation MUST preserve:

- `ARCHIVE_HEADER_SIZE == 64` and `FRAME_AREA_START == 0x40`;
- `FRAME_PREFIX_SIZE == 16`;
- `MASTER_TRAILER_SIZE == 96`;
- `BASE_QUANTUM == 4096`;
- `1 <= frame_quanta <= max_frame_quanta`;
- `frame_size == frame_quanta * BASE_QUANTUM` using checked arithmetic;
- in FIXED mode, `frame_quanta == max_frame_quanta` for every frame;
- in VARIABLE mode, frame start/end are quantum aligned;
- `frame_size_mode` is immutable for the archive lifetime;
- new archives SHOULD default to VARIABLE unless FIXED is explicitly selected.

## 16.3 Immutability and logical placement

- A committed frame is never modified in place.
- Size-changing edits append replacement frame(s) and atomically update manifest state.
- Non-packed DATA carries non-zero `object_id`, explicit `logical_offset`, and `logical_length`.
- Logical reconstruction depends on logical placement, not physical discovery order or JSON array order.
- Packed `inner_offset` semantics are never confused with non-packed `logical_offset` semantics.
- Conflicting overlapping live extents are corruption unless explicitly resolved by version semantics.
- `object_id` remains path/version derived and is intentionally not rename-stable.

## 16.4 Manifest and physical index

- Manifest commits are serialized by `seq` and never reference undurable frames.
- Huge mappings use bounded transactional `ADD_BEGIN` / batched `ADD_EXTENT` / `ADD_COMMIT`.
- Incomplete transactions are ignored after crash.
- The per-generation `frame_hash -> physical_offset` index is mandatory for the normal hot path, is rebuildable from raw scan, and is not load-bearing for correctness.
- Missing/corrupt index state degrades to bounded scan/rebuild rather than data loss.

## 16.5 Parity

- R8 parity IDs are only NONE, XOR, and Reed-Solomon.
- Every parity group is self-describing.
- Group members have identical `frame_quanta`.
- Active parity spans at least two blobs.
- Emergency Pruning performs parity-impact analysis and never silently claims lost redundancy is intact.

## 16.6 Integrity

- Frame Prefix CRC32C is validated before trusting `frame_quanta`.
- The mandatory Pre-Trailer CRC32C binds `pre_trailer_len` and the complete Master Trailer bytes before either metadata region is trusted.
- `hash_payload` verifies the exact stored payload representation.
- AEAD verifies encrypted representations.
- Detection alone never implies repair.

## 16.7 Encryption

- AES-256-GCM nonce is exactly 12 bytes and tag exactly 16 bytes.
- Payload, Pre-Trailer, and manifest use separately derived HKDF-SHA-256 keys.
- Encrypted-archive `generation_id` and `frame_ordinal` limits are enforced before encryption.
- Numeric nonce layouts are exact and injective in the permitted namespaces.
- Stored nonce is authoritative for decryption.
- Byte-preserving compaction preserves nonce/ciphertext/tag/hash/frame_ordinal.
- Any nonce namespace reuse or wraparound is fatal.
- Archive DEK rotation requires migration to a new archive; ordinary KEK rewrap does not.

---

# 17. Required R8 Wire Conformance Harness and Test Matrix

The R8 required test matrix is part of the specification and is not optional implementation guidance.

## 17.1 Independent golden vectors

The reference implementation MUST include independently constructed golden vectors for:

```text
64-byte Archive Header
16-byte Frame Prefix
96-byte Master Trailer
plaintext Pre-Trailer
encrypted representation
minimum valid frame
representative VARIABLE frame
representative FIXED frame
```

Golden vectors MUST NOT be generated by the production encoder under test.

Required forms:

```text
structured value -> encoder -> exact golden bytes
exact golden bytes -> decoder -> exact structured value
encoder -> decoder round trip
```

Encoder correctness MUST therefore not rely solely on `Encode(x) -> Decode() -> x`, because encoder and decoder could share the same defect.

For fixed structures, sentinel values SHOULD make byte ordering visually unambiguous, for example `0x11223344` and `0x0102030405060708`.

## 17.2 Exhaustive metadata-corruption tests

For the 16-byte Frame Prefix, flip every individual bit without recomputing its CRC32C and require rejection before altered Prefix fields are trusted.

For the 96-byte Master Trailer, flip every individual bit without recomputing the mandatory Pre-Trailer CRC32C that binds the trailer and require rejection before altered trailer fields are trusted.

The minimal zero-entry Pre-Trailer case MUST be included so trailer-integrity testing does not depend on PACKED metadata being present.

## 17.3 Decoder fuzzing

All untrusted binary and manifest decoders MUST be fuzz-tested. For arbitrary input they MUST:

```text
never panic
never read outside validated bounds
never cause unbounded allocation
never cause uncontrolled concurrency
return either a validated value or an error
```

## 17.4 Arithmetic boundaries

Tests MUST include:

```text
0
maximum valid value
maximum valid value + 1
MaxUint32
MaxUint64
overflowing additions
overflowing multiplications
truncated buffers
```

## 17.5 Geometry and recovery

Required cases include:

- minimum 4 KiB frame;
- representative mixed VARIABLE sizes;
- `MAX_FRAME_SIZE`;
- `MAX_FRAME_SIZE + BASE_QUANTUM` rejection;
- FIXED `frame_quanta != max_frame_quanta` rejection;
- local VARIABLE insert/resize with unaffected following frames remaining byte-identical where possible;
- MAX-size repartition into multiple grid-aligned immutable frames;
- arbitrary physical discovery order reconstructing the same logical object;
- overlapping live logical ranges producing corruption/conflict;
- missing physical index degrading to scan and rebuilding the same mapping;
- raw recovery with deleted manifest/index.

## 17.6 Manifest and crash durability

Verify:

- batched `ADD_EXTENT` up to the manifest-line ceiling;
- incomplete transaction ignored after crash;
- group commit does not require one fsync per extent record;
- frame durability precedes committed manifest reference;
- crash injection at frame write, blob flush, manifest append, manifest flush, compaction Sweep, root Switch, and GC deletion boundaries.

## 17.7 Compression

Tests MUST verify exact logical round-trip for:

```text
STORE
ZSTD_FAST
ZSTD_DEFAULT
ZSTD_DENSE
```

Unknown compression IDs MUST fail closed. Every ZSTD payload MUST decode independently. Malformed/truncated streams and declared-output-limit violations MUST fail closed.

## 17.8 Parity

Tests MUST verify:

```text
NONE
XOR
Reed-Solomon
```

and reject every reserved parity identifier. Equal member physical size and multi-blob spread invariants MUST be tested. Emergency Pruning tests MUST verify parity health is downgraded/rebuilt explicitly rather than silently lost.

## 17.9 Cryptography

Tests MUST verify:

- HKDF-SHA-256 golden vectors for all three derived keys;
- exact numeric frame/pretrailer/manifest nonce byte layouts;
- nonce uniqueness across blob ordinals, frame ordinals, generations, and manifest `seq` values;
- rejection at encrypted-profile numeric limits before new encryption;
- tag tampering rejection;
- AAD tampering rejection;
- stored nonce tampering rejection;
- byte-identical encrypted compaction across multiple generations;
- recovery after compaction using stored nonce rather than current physical position;
- KEK rewrap leaves STASH frame bytes unchanged;
- archive-DEK change is rejected as an in-place operation.

## 17.10 Hash and integrity separation

Tests MUST verify both BLAKE3 and SHA-256, reject every reserved hash identifier, and demonstrate that CRC/hash/AEAD detection does not cause repair unless an actual parity/copy recovery source exists.

---

# 18. Reference Implementation Notes — Go

Recommended packages:

| Function | Package |
|---|---|
| SHA-256 | `crypto/sha256` |
| AES-256-GCM | `crypto/aes` + `crypto/cipher` |
| HKDF-SHA-256 | `crypto/hkdf` |
| CRC32C | `hash/crc32` Castagnoli |
| Binary little-endian encoding | `encoding/binary` |
| BLAKE3 | `zeebo/blake3` or equivalent |
| Zstandard | `klauspost/compress/zstd` or equivalent |
| Reed-Solomon | `klauspost/reedsolomon` or equivalent |

BASELINE and SECURE payload/compression/AEAD paths do not require Zstandard and do not use BLAKE3 as `hash_payload`. However, the unchanged §6.5 `object_id` derivation still uses BLAKE3, so a full R8 writer retains that dependency. FAST additionally uses BLAKE3 for `hash_payload` and Zstandard for payload compression.

Implementation guidance:

- validate Header and Frame Prefix before frame-sized allocation;
- pool bounded buffers, never buffers sized directly from unvalidated media values;
- serialize physical extent allocation per blob while allowing independent blob writers;
- maintain a single logical manifest commit ordering;
- batch manifest fsyncs at transaction durability boundaries;
- maintain/rebuild physical offset indexes;
- never mutate committed frames;
- treat encrypted frame bodies as opaque during ordinary compaction;
- verify parity-group physical-size compatibility before parity encode/decode;
- stream archive-scale scans and indexes;
- bound recovery/index-rebuild goroutine counts;
- use checked arithmetic helpers for all media-derived offsets/sizes;
- benchmark VARIABLE recovery scan and FIXED direct-slot recovery separately.

## 18.1 Planned CLI creation parameters

Recommended creation surface:

```text
stash create ARCHIVE
    --profile baseline|secure|fast
    --mode variable|fixed
    --max-frame-size SIZE
    --blobs N
    --parity none|xor|rs
    [--parity-k K --parity-m M]
    [--key-provider NAME]
```

Advanced explicit creation parameters MAY expose:

```text
--hash blake3|sha256
--codec store|zstd-fast|zstd-default|zstd-dense
```

A profile is a preset and is not stored as a separate wire identifier.

---

# 19. R8 Production Readiness Checklist

- [ ] Every blob Archive Header is exactly 64 bytes and begins with `STSH`.
- [ ] Header wire version is `0x0006`.
- [ ] All headers in one generation agree on generation and immutable archive parameters.
- [ ] Version dispatch recognizes `0x0002`, `0x0003`, reserved development `0x0004`, R7 `0x0005`, and R8 `0x0006` correctly.
- [ ] `frame_size_mode` cannot change through compaction or generation switch.
- [ ] `BASE_QUANTUM` is exactly 4096 bytes.
- [ ] VARIABLE frame boundaries remain 4KiB aligned across mixed sizes.
- [ ] FIXED frames all equal `MAX_FRAME_SIZE` and reject mismatched `frame_quanta` as corruption.
- [ ] Frame Prefix CRC catches corrupted extent metadata before large allocation.
- [ ] Mandatory Pre-Trailer CRC catches corruption of `pre_trailer_len` and every Master Trailer bit before those fields are trusted.
- [ ] Prefix/Trailer `frame_quanta` mismatch is rejected.
- [ ] `data_len` physical-budget equation is checked exactly with overflow-safe arithmetic.
- [ ] `object_id` changes on rename by design.
- [ ] PACKED and non-packed offset semantics are never mixed.
- [ ] Logical reconstruction is independent of manifest-list/physical discovery order.
- [ ] Localized VARIABLE edits leave unrelated following frames unchanged where possible.
- [ ] No committed frame is ever modified in place.
- [ ] Very large extent sets use batched transactional `ADD_EXTENT` records.
- [ ] Manifest durability uses group commit, not one fsync per extent.
- [ ] Incomplete ADD transaction is ignored after crash.
- [ ] Per-generation physical offset index is maintained, rebuildable, and non-load-bearing for correctness.
- [ ] Parity algorithms are only NONE/XOR/Reed-Solomon and reserved IDs fail closed.
- [ ] Parity groups use equal `frame_quanta` and are recoverable without manifest.
- [ ] Emergency Pruning performs parity-impact analysis.
- [ ] Hash algorithms are only SHA-256/BLAKE3 and reserved IDs fail closed.
- [ ] Compression profiles are only STORE/ZSTD_FAST/ZSTD_DEFAULT/ZSTD_DENSE and reserved IDs fail closed.
- [ ] Every ZSTD payload is independently decodable and bounded by declared logical output limits.
- [ ] BASELINE, SECURE, and FAST named profiles are supported by the Go reference implementation.
- [ ] AES-GCM stored nonce is 12 bytes and tag is 16 bytes.
- [ ] HKDF-SHA-256 derives three distinct exact-label 32-byte keys.
- [ ] Encrypted `generation_id` and `frame_ordinal` ceilings are enforced before encryption.
- [ ] Exact numeric nonce layouts match golden vectors.
- [ ] Nonce namespace reuse/wrap is fatal.
- [ ] Encrypted compaction preserves nonce/ciphertext/tag/hash/frame_ordinal byte-for-byte.
- [ ] Disaster recovery reads stored nonce rather than deriving from current placement.
- [ ] KEK rotation rewraps the unchanged DEK without changing STASH frames.
- [ ] Archive DEK cannot be rotated in place.
- [ ] FIXED Hop-and-Read supports direct slot arithmetic; VARIABLE Hop-and-Read advances from validated `frame_quanta`.
- [ ] All media-derived sizes/offsets are validated before allocation or concurrency creation.
- [ ] Archive-scale collections are processed streaming rather than materialized as unbounded slices.
- [ ] Golden vectors are independently constructed rather than emitted by the production encoder.
- [ ] Every bit in Frame Prefix and Master Trailer corruption tests is rejected by the applicable CRC binding.
- [ ] Binary decoders and manifest parsers pass fuzzing without panic/OOB/unbounded allocation/uncontrolled concurrency.
- [ ] Crash injection passes all required durability and compaction boundaries.

---

# 20. Summary of R8 Wire and Semantic Changes

R8 retains the R7 physical structures and storage capabilities but changes current wire semantics sufficiently to require version `0x0006`.

Version dispatch:

```text
0x0002 = R1/R2
0x0003 = R3-R5
0x0004 = reserved R6 development layout
0x0005 = R7
0x0006 = R8
```

Physical layout retained from R7:

```text
Archive Header   64 bytes
Frame Prefix     16 bytes
Master Trailer   96 bytes
BASE_QUANTUM     4096 bytes
```

No physical field is added or removed by R8.

R8 changes:

1. current wire version becomes `0x0006`;
2. hash surface is reduced to SHA-256 and BLAKE3;
3. compression surface becomes STORE plus three exact Zstandard strength profiles (1/3/9);
4. parity surface becomes NONE/XOR/Reed-Solomon only;
5. named BASELINE, SECURE, and FAST deployment/interoperability profiles are defined without adding a `profile_id` field;
6. detection is explicitly separated from repair;
7. VARIABLE remains the normal/default enterprise geometry and FIXED remains deterministic direct-slot geometry;
8. archive encryption uses AES-256-GCM with exact HKDF-SHA-256 key separation;
9. nonce creation changes from truncated-hash derivation to an injective 4+1+7 numeric frame namespace and 4+8 manifest namespace;
10. encrypted namespace bounds are explicit and fail before encryption;
11. stored nonce remains authoritative after byte-preserving compaction;
12. KEK rewrap is allowed while archive DEK rotation requires migration to a new archive;
13. untrusted-media resource-exhaustion and checked-arithmetic requirements are normative;
14. wire golden vectors, exhaustive metadata corruption tests, decoder fuzzing, arithmetic boundaries, crash injection, crypto vectors, parity tests, and compression tests are required;
15. the existing Pre-Trailer CRC32C scope is strengthened to bind the complete 96-byte Master Trailer without changing physical layout.

## 20.1 Explicitly unchanged in R8

R8 MUST NOT alter:

```text
64-byte Archive Header size
16-byte Frame Prefix size
96-byte Master Trailer size
4096-byte base quantum
VARIABLE / FIXED geometry
DATA / PACKED / PARITY block types
Pre-Trailer physical layout
object_id model
logical placement model
manifest transaction model
mandatory rebuildable offset indexes
raw recovery algorithm
generation model
append-only semantics
compaction model
read-only FUSE policy
```

No new compression algorithms, hash algorithms, parity algorithms, frame modes, encryption algorithms, filesystem semantics, IAM/RBAC model, network protocol, recovery UI, or ransomware-vault protocol belong in R8.

## 20.2 Final R8 algorithm surface

```text
HASH
    SHA-256
    BLAKE3

COMPRESSION
    STORE
    ZSTD_FAST     level 1
    ZSTD_DEFAULT  level 3
    ZSTD_DENSE    level 9

PARITY
    NONE
    XOR
    REED-SOLOMON

ENCRYPTION
    NONE
    AES-256-GCM

KDF
    HKDF-SHA-256
```

Named profiles:

```text
BASELINE
    SHA-256
    STORE
    NONE

SECURE
    SHA-256
    STORE
    AES-256-GCM

FAST
    BLAKE3
    ZSTD_FAST
    NONE
```

# 21. README / Public Specification Requirements

README material describing R8 MUST state:

```text
STASH 2.0 Revision R8
wire version 0x0006
```

Core Design SHOULD call out the deliberately narrow algorithm surface:

- SHA-256/BLAKE3 hashing;
- STORE/Zstandard compression;
- XOR/Reed-Solomon parity;
- AES-256-GCM authenticated encryption.

It MUST include the statement:

> **Checksums and hashes detect corruption; redundancy repairs it.**

It SHOULD present the named profile summary:

```text
BASELINE  SHA-256 / STORE     / no encryption
SECURE    SHA-256 / STORE     / AES-256-GCM
FAST      BLAKE3  / ZSTD_FAST / no encryption
```

It MUST describe:

```text
VARIABLE = normal/default enterprise mode
FIXED    = deterministic slot geometry / maximum recovery parallelism
```

It MUST state that the R8 required test matrix is part of the specification and is not optional implementation guidance.

# 22. Freeze

> **STASH 2.0 R8 / wire 0x0006 is FROZEN.**

The next milestone is not R9. The next milestone is:

```text
Go reference implementation
    ↓
R8 wire conformance harness
    ↓
golden vectors
    ↓
fuzzing
    ↓
crash injection
    ↓
raw recovery torture tests
    ↓
performance benchmarks
```

Further wire-format revisions require evidence from the reference implementation or conformance testing. Speculative feature additions are not sufficient reason to change the format.
