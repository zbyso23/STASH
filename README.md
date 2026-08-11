# 🌀 STASH — Self-describing Tagged Archive Streamable Heaps

**Version:** 2.0 — Consolidated Specification
**Status:** Draft (post-review, internally consistent)
**Target:** Server / enterprise / datacenter petabyte-scale storage. Not a general-purpose replacement for tar/zip. Desktop/edge use is explicitly out of scope for this version (see §14).

---

## 0. Design Priorities (read this first)

STASH 2.0 makes explicit trade-offs. Anyone extending this spec must preserve these priorities in this order:

1. **Predictable, O(1) block geometry** (fixed-size frame grid) over fine-grained space savings.
2. **Whole-frame, bit-identical deduplication** over content-defined chunking (CDC). STASH does **not** deduplicate sub-block content. If sub-block dedup is required, use a CDC-based tool (Restic/Borg/Kopia) instead.
3. **Self-describing recovery** (archive must be reconstructable from raw frame data alone, without `manifest.jsonl`) over minimal per-frame overhead.
4. **Throughput at petabyte scale** over minimal dependency count. STASH relies on a small set of well-established external Go libraries (see §11) — it is not zero-dependency.

---

## 1. Overview

STASH is an append-only, verifiable archival format for cloud-native and datacenter workflows. Input data is split into fixed-size, compressed **frames**, referenced from a flat, append-only JSONL **manifest**. Every frame is content-addressed by a cryptographic hash of its payload, enabling whole-frame deduplication and independent integrity verification.

All frames are immutable. Updates are expressed as new manifest entries and new frames — nothing is ever overwritten in place.

---

## 2. Archive Header

Located at the start of Blob 0 (the first blob file — see §2.1). Applies to the whole archive; all blobs share one logical Archive Header, physically stored in Blob 0 only.

| Offset | Size (B) | Field | Type | Description |
|---|---|---|---|---|
| 0x00 | 4 | magic | char[4] | `'STSH'` |
| 0x04 | 2 | version | uint16 | `0x0002` for 2.0 |
| 0x06 | 1 | frame_size_class | uint8 | See §3 table |
| 0x07 | 1 | hash_id | uint8 | See §4 table. Fixed for the life of the archive. |
| 0x08 | 1 | codec_id | uint8 | See §5 table. Default codec for the archive; may be overridden per-frame (see §6, field `codec_id`). |
| 0x09 | 1 | parity_scheme | uint8 | See §7 table. Fixed for the life of the archive. |
| 0x0A | 1 | parity_k | uint8 | Data frames per parity group (0 if parity_scheme = none) |
| 0x0B | 1 | parity_m | uint8 | Parity frames per parity group (0 if parity_scheme = none) |
| 0x0C | 1 | blob_count | uint8 | Number of blob files in this archive, 1–255. Fixed for the life of the archive. See §2.1. |
| 0x0D | 3 | reserved | bytes | Zero-filled, reserved for future header flags |
| 0x10 | 32 | archive_id | bytes | Random UUID (128-bit, zero-padded to 32B) generated at archive creation, for cross-archive reference in LINK_MANIFEST |

**Immutability rule:** `frame_size_class`, `hash_id`, `parity_scheme`, `parity_k`, `parity_m`, `blob_count` are fixed at archive creation and MUST NOT change for the life of the archive. Changing any of them requires creating a new archive (optionally cross-referenced via `LINK_MANIFEST`, see §9).

### 2.1 Blob Files

An archive's frame data is physically split across `blob_count` fixed blob files, named `frames/blob-XX.stash` where `XX` is a zero-padded hex index (`blob-00.stash` … `blob-FE.stash` for up to 255 blobs). Recommended starting choices: 1, 4, 8, 16, or 32 — but any value 1–255 is valid; there is no power-of-two requirement.

```
/my-archive/
├── manifest.jsonl
├── index/                  # optional, see §9.2
│   ├── 00.idx
│   └── ff.idx
├── manifest.lut            # optional, see §9.2
├── checkpoints/             # optional, see §10.1
│   └── ckpt-4820000.bin
├── frames/
│   ├── blob-00.stash        # Archive Header lives here (§2)
│   ├── blob-01.stash
│   └── ...                  # up to blob_count files
└── submanifests/            # optional, see §10.2
    └── ...
```

- **Frame-to-blob assignment is a write-time decision, not derived from the frame's hash.** A writer places each new frame into whichever blob currently has free capacity / lowest load (e.g. round-robin, or capacity-aware selection). This allows concurrent, lock-free writers (one per blob) and lets blobs be mapped 1:1 onto independent physical disks (JBOD) for aggregate throughput, without the coordination cost of a single shared write position.
- Within each blob file, frames are laid out exactly as described in §6 (`BLOCK_STRIDE` sequential grid). The Archive Header (this section) physically lives only in Blob 0; all other blobs start directly with frame data at offset 0x00.
- Because placement is not hash-derived, **every reference to a frame (in the manifest, in parity group records) MUST record which blob it lives in** — see `blob_id` in §9.1 and §7.1.
- Disaster recovery (§11) is unaffected: Hop-and-Read scans all `blob_count` blobs (in parallel, if desired) using the same per-blob `BLOCK_STRIDE` walk: placement strategy does not matter for recoverability, since every frame is found by exhaustive scan regardless of which blob it landed in.
- **Parity group spread rule:** when `blob_count > 1`, the data and parity frames of a single parity group (§7.1) MUST be distributed across at least 2 different blobs (ideally as many distinct blobs as `parity_m + 1` allows). A parity group entirely contained in one blob provides no protection against the loss of that blob's underlying disk — the whole point of parity is defeated. This is a writer responsibility, not a property the format can enforce structurally, so it MUST be stated as a normative requirement for compliant implementations.

---

## 3. Frame Size Classes

Single byte (`frame_size_class`), power-of-two multiplier from a fixed table:

| Value | Size | Value | Size | Value | Size |
|---|---|---|---|---|---|
| 0x00 | 4 KiB | 0x06 | 256 KiB | 0x0C | 16 MiB |
| 0x01 | 8 KiB | 0x07 | 512 KiB | 0x0D | 32 MiB |
| 0x02 | 16 KiB | 0x08 | 1 MiB | 0x0E | 64 MiB |
| 0x03 | 32 KiB | 0x09 | 2 MiB | 0x0F | 128 MiB |
| 0x04 | 64 KiB | 0x0A | 4 MiB | 0x10 | 256 MiB |
| 0x05 | 128 KiB | 0x0B | 8 MiB | | |

All frames in a single archive use the same class. No mid-stream adjustment. Recommended: 64 KiB–1 MiB for mixed/general datasets, 16 MiB–256 MiB for large homogeneous ML/imaging/database datasets.

`BLOCK_STRIDE = frame_size + 48` bytes is the fixed on-disk stride between consecutive frame blocks (see §6).

---

## 4. Hash Algorithms

| Value | Algorithm | Digest size | Use case |
|---|---|---|---|
| 0x00 | reserved | — | — |
| 0x01 | **BLAKE3** | 32 B | Default. Best throughput, SIMD/multi-threaded. |
| 0x02 | SHA-256 | 32 B | FIPS 140-2/3 compliance, hardware-accelerated (SHA extensions) |
| 0x03 | SHA3-256 | 32 B | Compliance requiring a non-SHA-2 construction (e.g. EU/BSI guidance) |
| 0x04–0xFF | reserved | — | future use |

**Hash scope (critical, previously ambiguous):** `hash_payload` is computed **exclusively over `compressed_payload`** — i.e., after compression, before padding and before the pre-trailer are written. This is what makes whole-frame deduplication possible: two frames with bit-identical compressed payloads but different embedded filenames/paths (common with Frame Packing, see §8) still produce the same hash and correctly deduplicate. The 48-byte Master Trailer's `hash_payload` field never covers padding or the pre-trailer.

Go implementation: BLAKE3 has no stdlib implementation — use `zeebo/blake3` or `lukechampine.com/blake3`. SHA-256 and SHA3-256 are both in Go's standard library (`crypto/sha256`, `crypto/sha3`).

---

## 5. Compression Codecs

| Value | Codec | Notes |
|---|---|---|
| 0x00 | STORE (none) | Pre-compressed data, e.g. already-compressed media |
| 0x01 | LZ4 | Fastest, lowest ratio |
| 0x02 | **Zstd** | Default. Balanced speed/ratio. |
| 0x03 | LZMA | Slow, highest ratio — cold archival tier |
| 0x04 | Brotli | Slow, best ratio on text-heavy data |
| 0x05–0xFF | reserved | future use |

`codec_id` is set archive-wide in the Archive Header but MAY be overridden per-frame via the field in §6 (e.g., STORE for a frame packing already-compressed assets). Go: none of these are in stdlib except gzip/flate/zlib (not part of this table — inadequate ratio/speed for this use case). Recommended: `klauspost/compress` for Zstd/LZ4/Brotli.

**Frame Packing exception (see §8):** frames produced by the small-file packing path always use `codec_id = STORE (0x00)`, regardless of the archive-wide default. This is a deliberate, permanent trade-off — packed frames trade compression ratio for write/read throughput.

**Stdlib-only / minimal-dependency profile:** for audit-constrained deployments, an archive MAY be configured with `hash_id = SHA-256` or `SHA3-256`, `codec_id = STORE`, `parity_scheme = XOR or none` — this combination requires zero external Go dependencies. This is *not* the recommended default; it exists as an explicit compliance fallback.

---

## 6. Frame Binary Layout

Each frame occupies exactly `BLOCK_STRIDE = frame_size + 48` bytes on disk. Layout, offsets relative to the **start of the frame block**:

```
block_start                                                    block_start + BLOCK_STRIDE
    |                                                                        |
    v                                                                        v
    [ compressed_payload ][ zero padding 0x00 ][ pre_trailer ][ 48B master trailer ]
    |<---------------------- frame_size bytes ---------------------------->|<-- 48B -->|
```

### 6.1 Master Trailer (fixed 48 bytes, last 48 bytes of every block)

| Offset (from trailer start) | Size (B) | Field | Type | Description |
|---|---|---|---|---|
| 0x00 | 4 | magic | char[4] | `'STSH'` |
| 0x04 | 2 | version | uint16 | `0x0002` |
| 0x06 | 1 | hash_id | uint8 | Matches Archive Header |
| 0x07 | 1 | codec_id | uint8 | Codec used for **this** frame's payload |
| 0x08 | 1 | block_type | uint8 | `0 = DATA`, `1 = PARITY` (see §7) |
| 0x09 | 3 | reserved | bytes | Zero-filled, reserved for future flags |
| 0x0C | 4 | data_len | uint32 | Real compressed payload length, before padding |
| 0x10 | 32 | hash_payload | bytes | Hash of `compressed_payload` only (see §4 scope rule) |

(0x10 + 32 = 0x30 = 48 bytes total ✓)

### 6.2 Pre-Trailer (Block Meta-Index) — variable length, immediately precedes the Master Trailer

Binary structured record (not free text), terminated by `0x00`:

```
repeated for each file packed into this frame:
| varint | path_len   | length of UTF-8 path string
| bytes  | path       | UTF-8 file path, path_len bytes
| uint64 | inner_off  | byte offset of this file's data within compressed_payload
| uint64 | inner_len  | byte length of this file's data within compressed_payload
| uint64 | file_ver   | version counter for this path (matches manifest 'ver')
```
Terminated by a single `0x00` byte after the last record.

**Packing determinism (required):** when Frame Packing combines multiple files into one frame, files MUST be ordered lexicographically by path before packing. This guarantees that identical sets of small files packed on different nodes produce byte-identical frames — and therefore correctly deduplicate — without any cross-node coordination.

---

## 7. Parity / Erasure Coding (optional, archive-wide)

| Value | Scheme | Failure tolerance | Notes |
|---|---|---|---|
| 0x00 | none | 0 | No redundancy beyond hash-based detection |
| 0x01 | XOR | 1 lost frame per group | Simplest; single-disk-failure protection only |
| 0x02 | Reed-Solomon | `parity_m` lost frames per group | Recommended default for enterprise/petabyte deployments |
| 0x03 | LRC (Local Reconstruction Codes) | tunable | Lower rebuild I/O than RS, higher storage overhead |

Fixed at archive creation via `parity_scheme` / `parity_k` / `parity_m` in the Archive Header (§2). **Mixing schemes within one archive is not supported** — if different data needs different protection levels, use separate archives or separate sub-manifests (§9), each with its own parity configuration.

### 7.1 Parity Group record (manifest)

```json
{"ts": 1739550200, "op": "PARITY_GROUP", "group_id": 42, "data_frames": [["01","hash1"],["03","hash2"]], "parity_frames": [["07","phash1"]]}
```

- Each frame reference is a `[blob_id, frame_hash]` pair (see §2.1) since placement is not derivable from the hash.
- A parity group is only written once all `parity_k` data frames belonging to it are known. Until a group is complete, its data frames are valid and readable individually (parity is a recovery aid, not a gate on write availability).
- `block_type = PARITY` (§6.1) distinguishes parity frames from data frames when scanning raw disk in a Hop-and-Read recovery.
- Incomplete groups (fewer than `parity_k` data frames due to archive still being written) are not erasure-protected until closed; this is expected and non-fatal.
- **Spread requirement:** see §2.1 — data and parity frames of one group MUST span ≥2 distinct blobs when `blob_count > 1`.

Go: `klauspost/reedsolomon` for RS; XOR requires no library. LRC libraries are comparatively immature — evaluate before committing to it as a default.

---

## 8. Frame Packing (small files)

Small files are packed sequentially into a single frame's `compressed_payload` rather than each triggering a full padded frame. Rules:

- **Packed data is never compressed** (`codec_id = STORE`, always). This is a deliberate design choice: it maximizes write/read throughput for the small-file path (no CPU cost for compression/decompression on the most frequently accessed file class) at the cost of on-disk size. It also removes any ambiguity about "compress before or after packing" and keeps hashing simple (§6.1 hash is computed directly over the raw concatenated bytes). Large, non-packed files are unaffected — they continue to use the archive-wide `codec_id` (§5).
- Files are sorted lexicographically by path before packing (§6.2 determinism rule).
- A frame is closed (hashed, sealed, written) either when it reaches `frame_size` or when an explicit flush is triggered (e.g., end of a batch/transaction). Until closed, a frame is a staging buffer, not yet immutable — implementations MUST NOT expose a partially-packed frame as durable/committed.
- Deduplication applies to the **entire packed frame** as a unit — i.e., only if the same set of files, in the same order, with the same byte content, was packed identically elsewhere. This is expected to be rare for small-file packing and is **not** the primary dedup target; large single/multi-frame files are (§4, §6.1).

---

## 9. Manifest

Append-only `manifest.jsonl`. Reverse Log Scanning (bottom-up) determines current state.

### 9.1 Record types

```jsonl
{"ts": 1739550001, "op": "ADD", "path": "src/main.go", "ver": 2, "loc": [["00", "f5a2b1c3...", 0, 4096]]}
{"ts": 1739550002, "op": "ADD", "path": "big/dataset.bin", "ver": 1, "loc": [["03", "aaa111...", 0, 67108864], ["11", "bbb222...", 0, 33554432]]}
{"ts": 1739550123, "op": "DEL", "path": "src/utils.go", "ver": 2}
{"ts": 1739551000, "op": "LINK_MANIFEST", "path": "submanifests/user-data.jsonl", "hash_id": "sha256", "hash": "8f2c3a...", "lines": 50000}
{"ts": 1739550200, "op": "PARITY_GROUP", "group_id": 42, "data_frames": [["00","..."],["03","..."]], "parity_frames": [["07","..."]]}
```

- **`loc`** is always an array of `[blob_id, frame_hash, inner_offset, inner_length]` quadruples, one per frame the file spans. Single-frame files simply have a one-element array. `blob_id` is the two-hex-digit blob file index (matches `frames/blob-XX.stash`, §2.1).
- **`ver`** is a per-path monotonic version counter, incremented on every ADD/replace of the same path. It has no relationship to the archive format version.
- **`op: SUB`** is **removed in 2.0**. It is a legacy v1.21 construct — see §13. Only `LINK_MANIFEST` is valid in 2.0.
- **`LINK_MANIFEST`** always declares `hash_id` explicitly (a sub-manifest may in principle be verified with a different hash algorithm than the parent's frame data, though the parent archive's own `hash_id` in the Archive Header still governs its own frames).

### 9.2 manifest.lut (optional binary index)

Fixed-size binary records, prefix-sharded into `index/00.idx`–`index/ff.idx` by path hash prefix, fully derivable/rebuildable from `manifest.jsonl` at any time, never authoritative on its own (a cache/acceleration layer only).

| Offset | Size (B) | Field | Type | Description |
|---|---|---|---|---|
| 0x00 | 8 | line_no | uint64 | Line number in manifest.jsonl |
| 0x08 | 8 | offset | uint64 | Byte offset in manifest.jsonl |
| 0x10 | 1 | blob_id | uint8 | Which blob file this frame lives in (§2.1) — required since placement is not hash-derived |
| 0x11 | 7 | reserved | bytes | Zero-filled |
| 0x18 | 32 | frame_hash | bytes | Hash of the referenced frame |
| 0x38 | 8 | ts | uint64 | Timestamp, for range queries |

(64 bytes total per record, unchanged size from the earlier draft — `blob_id` fits in previously-reserved space.)

---

## 10. Manifest Scaling

Two independent, orthogonal concerns — solved separately, not with one combined mechanism.

### 10.1 Fast startup for large manifests (checkpointing)

A single `manifest.jsonl` can grow to millions of lines. Cold-starting a reader always requires the ability to do a **reverse chunked scan**: read the file backward in fixed-size chunks (e.g. 4–16 MiB), parse lines within each chunk from last to first, and build current state with a `map[path]→loc` (or Bloom filter at extreme scale), skipping any path already resolved by a newer entry. This is mandatory as a baseline/fallback and is what Hop-and-Read (§11) relies on when no checkpoint exists.

For routine fast startup, implementations SHOULD additionally maintain an optional, periodically-generated **checkpoint**:

```json
{"ts": 1739552000, "op": "CHECKPOINT", "snapshot_path": "checkpoints/ckpt-4820000.bin", "hash": "...", "covers_up_to_line": 4820000}
```

The referenced `snapshot_path` is a binary `path → current loc` snapshot (structurally similar to `manifest.lut`, §9.2) valid as of the given line. A reader loads the latest checkpoint and only reverse-scans the (typically small) tail of new lines written after it — turning startup cost from O(full history) into O(delta since last checkpoint). Checkpoints are fully derivable from the manifest and are an optimization, not a correctness requirement; a corrupted or missing checkpoint simply falls back to §10.1's baseline scan. This pattern mirrors established practice in comparable tools (e.g. Kopia's consolidated-index epochs), not a novel mechanism.

### 10.2 Sharding / scale-out (`LINK_MANIFEST`)

STASH provides exactly **one**, fully optional, single-level-agnostic sharding primitive: `LINK_MANIFEST` (§9.1). A root manifest MAY reference any number of independent sub-manifests; each sub-manifest MAY itself contain further `LINK_MANIFEST` entries. The format imposes no hierarchy, naming convention, or "level" semantics — how sub-manifests are organized (per-tenant, per-node, per-time-window, or not at all) is entirely an operational decision made by the surrounding infrastructure, not a property of the format.

This is a deliberate simplification: established datacenter storage systems (Ceph's CRUSH placement, MinIO's tenant/namespace model) already solve placement, replication, and isolation at the infrastructure layer. STASH does not duplicate that logic — `LINK_MANIFEST` is only the pointer/verification primitive (path + hash + line count) that lets an external layer compose independently-owned manifests. Rotating to a new sub-manifest when one grows too large is an operational action (create a new file, append a `LINK_MANIFEST` entry), not a new format feature.

---

## 11. Disaster Recovery (Hop-and-Read)

If `manifest.jsonl` is lost, the archive is rebuilt by:

1. For each of the `blob_count` blob files (§2.1) — independently and optionally in parallel — reading `BLOCK_STRIDE` at a time from its start (mathematical stride, no scanning of payload data required).
2. At each block boundary, reading the 48-byte Master Trailer to get `hash_payload`, `block_type`, `data_len`.
3. For `block_type = DATA`, reading backward from the trailer into the Pre-Trailer to recover the flat list of `(path, inner_offset, inner_length, file_ver)` records for that frame.
4. For `block_type = PARITY`, recording group membership (including which blob each member was found in) for later cross-check/rebuild, not file paths.
5. Emitting one synthesized `ADD` record per recovered `(path, file_ver)`, using `[blob_id, hash_payload]` as the `loc` reference (§9.1).
6. Where the same path/version was packed redundantly across multiple identical frames (deduplicated), any one instance is sufficient to recover the mapping.

Since placement across blobs is a write-time decision (§2.1), recovery does not need to know or reconstruct the original placement policy — exhaustive per-blob scanning finds every frame regardless of which blob it landed in.

This process does not require reading or decompressing `compressed_payload` itself — only trailer and pre-trailer, which sit in the same disk region and are typically read in one sector-aligned I/O.

---

## 12. Reference Implementation (Go)

| Requirement | Package | stdlib? |
|---|---|---|
| BLAKE3 | `zeebo/blake3` or `lukechampine.com/blake3` | No |
| SHA-256 | `crypto/sha256` | Yes |
| SHA3-256 | `crypto/sha3` | Yes (as of recent Go versions) |
| Zstd / LZ4 / Brotli | `klauspost/compress` | No |
| Reed-Solomon | `klauspost/reedsolomon` | No |
| XOR parity | manual, or `crypto/subtle` primitives | Yes |
| Binary encoding | `encoding/binary` | Yes |

STASH 2.0 is **not** a zero-dependency format in its recommended configuration — this should be stated plainly in any README/marketing material rather than implied otherwise. A minimal-dependency profile is available (§5).

Recommended engineering practices for the reference implementation:
- `sync.Pool` for frame-sized buffer reuse to avoid GC pressure at petabyte-scale throughput.
- Frame writer must treat an in-progress packed frame as a staging buffer, only exposing it (and computing its hash) once sealed (§8).
- Benchmark Reed-Solomon throughput explicitly before setting it as the enterprise default — it is more CPU-intensive than hashing or compression and its SIMD path (`klauspost/reedsolomon`) should be verified on target hardware.

### 12.1 Blob Allocation (non-normative interface)

`blob_count` (§2.1) is the only blob-related fact fixed on disk. Everything about *which* blob a given frame is written to — including physical-tier awareness (e.g. preferring NVMe-backed blobs for hot data, HDD-backed blobs for cold data) — is a runtime library concern, not a format concern, and MUST NOT be encoded into the Archive Header: physical hardware changes over an archive's lifetime (drives get replaced, tiers get reorganized), while the header is immutable for the archive's life (§2).

Recommended (not mandatory) Go interface for implementations:

```go
type BlobAllocator interface {
    // SelectBlob returns which blob a new frame (or parity-group member)
    // should be written to.
    SelectBlob(ctx WriteContext) (blobID uint8, err error)
}

type WriteContext struct {
    BlobCount  uint8
    FreeSpace  map[uint8]int64 // bytes free per blob, if known
    IsParity   bool            // true when placing a parity frame
    GroupBlobs []uint8         // blobs already used by this parity group
}
```

- A default allocator (round-robin or most-free-space-first) ships with the library and requires no configuration.
- Tier-aware or priority-based placement (NVMe vs. HDD, hot vs. cold) is implemented as an alternative `BlobAllocator` supplied by the operator/application at archive-open time — entirely outside the on-disk format, freely reconfigurable without touching existing data.
- The library MUST enforce the §2.1/§7.1 parity spread rule defensively (reject/re-route a parity-frame write that would land in a blob already listed in `GroupBlobs`), rather than relying solely on the allocator to honor it.

---

## 13. Legacy v1.21 (historical reference only — not valid 2.0 syntax)

v1.21 used standalone `.sf` files (`/frames/ab/cd/abcdef....sf`), a 2-byte `'SF'` magic, a 16-bit back-offset, and an embedded free-text JSONL trailer per frame, with `op: SUB` for sub-manifest references. This was superseded in 2.0 because:

| v1.21 limitation | 2.0 fix |
|---|---|
| Millions of standalone small files on disk → filesystem metadata overhead, poor cache locality | Unified fixed-grid volume (§6) |
| 16-bit back-offset → hard ~64 KiB ceiling, incompatible with large frame classes | 48-byte fixed Master Trailer, frame-size-independent |
| Free-text JSONL trailer per frame → no O(1) mathematical seeking | Fixed-width binary Pre-Trailer + Master Trailer (§6) |
| `SUB` record loosely specified (no hash/line-count verification) | `LINK_MANIFEST` with explicit `hash_id`/`hash`/`lines` (§9) |

Do not implement `.sf` standalone files or `op: SUB` in 2.0. This section exists for migration tooling only (reading old v1.21 archives to convert them to 2.0).

---

## 14. Out of Scope for 2.0

- Encryption (non-normative guidance only — see below)
- Desktop/edge deployment profiles (smaller frame classes, lighter parity, offline-first conflict resolution — candidate for a future v2.x/v3.0 profile mechanism, not this version)
- Sub-block / content-defined-chunking deduplication (explicit non-goal, §0)
- **Tape / cold-storage tiers** — deliberately excluded, not deferred. The tape ecosystem (proprietary libraries, LTO consortium tooling, specialized hardware) is a closed, conservative market with low realistic adoption odds for a new open format; effort is better spent on disk/SSD/cloud-object-storage deployments in datacenters, which are the addressable target.

### 14.1 Encryption (non-normative)

If implemented: encrypt only `compressed_payload`; header, trailer, and pre-trailer remain in plaintext so frames stay self-describing. Compute `hash_payload` over the ciphertext when encryption is active (integrity, not secrecy, is what the hash guarantees in that mode). Store algorithm/IV/key-ID references in manifest fields, not in the fixed binary layout. No specific algorithm is mandated by this spec; implementations should use current, well-reviewed authenticated encryption (e.g., AES-GCM or a ChaCha20-Poly1305 construction) and document their own key management separately.

---

**Author:** © 2025-2026 Zbigniew Lipka  
**Full license text:** See [LICENSE](./LICENSE)