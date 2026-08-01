# 🌀 STASH — Self-describing Tagged Archive Streamable Heaps  
**Version:** 2.00 • **Enterprise-Ready Specification Draft**  

---

## 🧭 Overview

STASH is an append-only, verifiable archival format optimized for cloud-native workflows, differential sync, and long-term integrity.

Instead of bundling files into a single opaque blob (like `.zip` or `.tar.gz`), STASH splits input data into compressed frames of selected standard sizes (e.g. 4 KiB, 64 KiB, 1 MiB). Each frame is hashed (SHA-256 by default) and referenced from a flat JSONL manifest, enabling fast random access, deduplication, and content-based verification.

All frames are immutable. No data is ever overwritten — updates are expressed as new manifest entries, making STASH ideal for incremental backups, verifiable replication, and scalable archival across SSD, HDD, tape, or cold storage.

## 🆕 Version 2.0 Enhancements
To achieve enterprise-grade scale and absolute minimal I/O overhead during krizové stavy (disaster recovery), STASH 2.0 introduces three core refinements to this original foundation:

- **Fixed-Width Block Grid:** While preserving standard frame sizes, all frames within a single archive are now padded to a strictly uniform, predictable block boundary (frame_size + 48 bytes), enabling instant mathematical seeking (O(1) block striding) and eliminating lookups from scratch.
- **Frame Packing Layer:** Small files (e.g., thousands of tiny text or configuration files) are packed sequentially into a single fixed frame buffer rather than triggering wasteful padding or internal fragmentation.
- **Self-Describing Block Trailers:** Each fixed block embeds its own transaction meta-index right before a 48-byte Master Trailer, ensuring that if the global manifest is lost, a fast **Hop-and-Read Rescue** tool can skip the raw data entirely and rebuild the entire manifest.jsonl along with original file names and folder structures.

### 📏 Frame Size Selection

STASH 2.0 enforces a streamlined set of frame sizes optimized strictly for macro-aligned storage layers, high-throughput cloud streams, and predictable network seeking:
`64 KiB / 1 MiB / 4 MiB / 16 MiB`

All frames within a single archive MUST use the same size. The selected size class dictates the global layout geometry and is permanently recorded inside the Archive Header at offset 0x00 during creation.

### 🆕 2.0 Geometric Alignment Constraints
- **Deduplication vs. Throughput:** The chosen frame size determines the data aggregation window. Smaller classes (64 KiB) optimize random access performance and fine-grained content deduplication across heterogeneous datasets. Larger classes (4 MiB / 16 MiB) maximize sequential pipeline throughput and optimize network economy for cloud platforms (e.g., AWS S3) by minimizing transaction count.
- **Elimination of Dynamic Scaling:** Unlike previous iterations, STASH 2.0 forbids reader-side adaptive frame sizes or mid-stream adjustments within a single file volume. The mgrid configuration remains absolute across the entire archive string to maintain uninterrupted O(1) block-stride calculations.
- **Padding Mechanics:** If individual incoming assets or stacked data pools collected via the Frame Packing engine do not cleanly divide into the selected size class, the payload buffer is filled with deterministic zero-padding (0x00) exactly up to the frame_size threshold. The trailing byte marker is placed strictly at frame_size + 48 bytes, anchoring the mathematical alignment.

---

## 🎯 Motivation

Classic archive formats (like .zip or .tar.gz) are monolithic by design. They bundle all content into a single linear stream, making random access, diffing, or partial updates inefficient or outright impossible.

Modern data workloads — especially in cloud, archival, and compliance-focused environments — require:
- Append-only immutable structures
- Efficient incremental updates without rewriting large blobs
- Content-addressed deduplication
- Fast partial access to specific files or chunks
- Cold storage optimization across tiered physical media (SSD → HDD → MO / Tape)
- Verifiability and forensic audit support for automated compliance (GDPR, legal hold)

STASH 2.0 is designed for these realities. It serves as a programmatic building block for distributed, verifiable, and scalable archival ecosystems, guaranteeing minimal dependencies and maximum portability. By implementing an unyielding frame grid alongside an embedded meta-index layer, it mitigates cloud network cost penalties while remaining robust against global index loss.

The result is an **addressable, verifiable, and distributed archive format.**

---

⚙️ Core Principles
- All content is split into compressed frames of standard macro-aligned sizes (`64 KiB / 1 MiB / 4 MiB / 16 MiB`), packed sequentially via the library buffer to eliminate internal fragmentation
- Each frame is compressed independently, using codecs optimized for the data type (e.g., `Zstd` for binaries, `LZ4` for high-throughput pipelines, or none for pre-compressed streams)
- All frames are **immutable** and **append-only**
- The manifest is a flat JSONL file that maps files to specific frame offsets and tracks all operations (add, delete, link) as a linear log
- Data is never modified in-place — updates are expressed exclusively by appending new frames and appending transaction rows to the manifest
- Every frame block is content-addressed by its full master hash (SHA-256 or BLAKE3), enabling global storage deduplication and foolproof integrity validation
- Manifest records are optimized for reverse bottom-up scanning, allowing sub-millisecond catalog initialization by prioritizing the latest transaction states
- Metadata and data are strictly separated, allowing low-latency remote access, granular cloud stream carving, and zero-allocation parsing

**STASH 2.0** addresses these needs with:
- Immutable, fixed-width compressed frame blocks padded to strict mathematical geometric boundaries
- A flat append-only JSONL manifest accompanied by a prefix-based 256-file binary shard index layer
- Embedded per-frame block meta-indexes and 48-byte Master Trailers for zero-overhead forensic recovery
- Native support for distributed sub-manifest architecture, preventing write-lock contention across cloud clusters

The result is a **scalable, verifiable, and fault-tolerant archive format** — designed as a foundation for modern archival systems with zero-dependency parsing, efficient synchronization, and long-term structural resilience.



## 🆕 STASH 2.0 — Frame Size Class Set

STASH 2.0 establishes a finalized, strict **frame size class set**. Each archive MUST choose a single fixed frame size. This selection is stored directly within the Archive Header and encoded as a compact 8-bit byte identifier (uint8), where the byte value acts as a power-of-two multiplier yielding standard block bounds from `4 KiB` up to `256 MiB`:
`4 KiB / 8 KiB / 16 KiB / 32 KiB / 64 KiB / 128 KiB / 256 KiB / 512 KiB / 1 MiB / 2 MiB / 4 MiB / 8 MiB / 16 MiB / 32 MiB / 64 MiB / 128 MiB / 256 MiB`
This hard geometric predictability enables consistent, zero-allocation memory management, exact pipeline buffer tuning, and optimized block-level backend storage operations across cloud architectures.
The frame size configuration MUST be:
Globally fixed at archive creation time within the Archive Header at offset 0x06 — making the volume completely deterministic for downstream clients.
Strictly uniform across the entire payload — meaning reader-side adaptive frame reassembly or mid-stream sizing changes are explicitly forbidden in order to maintain O(1) mathematical block-stride calculations.
Regardless of the chosen size class, all frames remain individually addressable, immutable, and fully self-describing through their trailing structures.
⚠️ Operational Notes on Large Allocations (64 MiB to 256 MiB):
Large macro-aligned frame classes are recommended for high-bandwidth target systems supporting massive memory-mapped (mmap) storage arrays.
Ideal for enterprise-grade workloads including AI/ML training datasets, medical imaging arrays, raw 3D volumetric reconstruction streams, and large database ingestion pipelines.
Internal fragmentation for minor files within these massive blocks is entirely mitigated by the core Frame Packing aggregation engine.

---

## 🧩 File Structure

STASH archives consist of a directory containing all metadata and frame data:
```
/my-archive/
├── manifest.jsonl # Append-only JSONL log of all operations (ADD, DEL, SUB, etc.)
├── manifest.lut # Optional binary index for fast lookup (O(1))
├── frames/ # All immutable frames, sharded by hash prefix
│ ├── a1/b2/a1b2c3d4e5f6....sf
│ ├── d4/e5/d4e5f6789abc....sf
│ └── ...
└── submanifests/ # Optional sub-manifests for modular structure
├── user-data.jsonl
├── logs.jsonl
└── ...
```

### 📦 Frame Storage

- Each frame is an immutable `.sf` binary file (compressed chunk)
- Stored under `frames/[first2]/[next2]/...` based on SHA-256 prefix
- Frames end with self-describing trailer (manifest JSON + 16-bit offset + SHA-256)

### 📜 Manifest

- `manifest.jsonl` records all operations (ADD, DEL, SUB, REPL, etc.)
- Each line describes one event (append-only, line-delimited JSON)
- Can be parsed linearly or indexed via optional `manifest.lut`

### 🔁 Sub-manifests (optional)

- Nested STASH manifests (e.g. per-region, per-module, per-user)
- Referenced from main manifest via `{"op": "SUB", ...}` records
- Enable modular updates, garbage collection, and replication

This layout scales across millions of files and petabytes of data — with zero database dependencies, O(1) lookup, and graceful recovery even after partial damage.

- Each frame is a compressed binary chunk, named by its hash (`.sf` = stash frame)
- Frames are immutable and never overwritten
- The manifest stores file-to-frame mappings, size, offset, and operations (ADD, DELETE, OVERWRITE)
- Frames can be selectively moved, cached, or tiered based on usage patterns (e.g. cloud cold storage)

---

## 📦 STASH Frame Binary Layout

```text
| Offset | Size | Field               | Type       | Description                          |
|--------|------|--------------------|------------|--------------------------------------|
| 0x00   | 2    | magic              | 0x53 0x46  | Frame syncword `'SF'`                |
| 0x02   | 1    | version            | uint8      | Frame format version (e.g. 0x01)     |
| 0x03   | 1    | codec_id           | uint8      | Compression codec ID (1=LZ4, ...)    |
| 0x04   | 4    | flags              | uint32     | Reserved / future use                |
| 0x08   | 8    | uncompressed_size  | uint64     | Original size before compression     |
| 0x10   | 8    | compressed_size    | uint64     | Size of compressed payload           |
| 0x18   | 8    | timestamp          | uint64     | Unix creation time                   |
| 0x20   | ...  | compressed_payload | bytes      | Actual compressed data               |
```

---

### Manifest (Global Index)

The manifest is an append-only log (manifest.jsonl) where each line describes a single file operation (add, delete, replace).
New frames are added alongside corresponding manifest entries without modifying existing data.

```jsonl
{"ts": 1697000000, "op": "ADD", "frame": "fc31...a2", "offset": 0, "size": 1357, "path": "docs/readme.txt", "codec": "lz4"}
{"ts": 1697000123, "op": "DEL", "path": "docs/readme.txt"}
{"ts": 1697000188, "op": "ADD", "frame": "b0a1...f2", "offset": 0, "size": 1722, "path": "docs/readme.txt", "codec": "lz4"}
{"ts": 1697000222, "op": "ADD", "frame": "1cc9...7b", "offset": 0, "size": 44092, "path": "img/logo.png", "codec": "zstd"}
```

### 🔁 Versioning Example
```
v1 → frames 1–1000
v2 → frames 1001–1004 (only changed or new files)
v3 → frames 1005–1008 (further changes)
```

Each manifest entry (in `manifest.jsonl`) represents a versioned operation (`ADD`, `DEL`, `REPL`, `SUB`...).

Clients reconstruct the current state by **replaying the manifest** and resolving the latest valid entry for each path.

Old frames remain valid and deduplicated — no data is ever overwritten.

This enables:
- Efficient incremental updates (append-only writes)
- Time-based snapshots (via partial manifest replay)
- Low-bandwidth sync (only transmit new frames + manifest tail)
- Sub-manifest scoping (e.g. per user / region / module)
- Offline recovery (thanks to embedded JSON trailers in `.sf` frames)

### 🔁 Frame Trailer (Self-Describing Frame Footer)

Each `.sf` frame now embeds its own manifest record at the end of the file,  
followed by a 16-bit negative offset pointing back to the start of that JSONL entry.

This guarantees full **self-description and recoverability** even if the global manifest is lost.

```
[compressed or raw data ...]
[manifest JSONL line ...] ← e.g. {"ts":..., "op":"ADD", "path":"docs/readme.txt", ...}
[uint16 back_offset] ← number of bytes to the start of JSONL line
```

- `back_offset` is always little-endian, measured from EOF.
- The embedded JSONL line is **identical** to the one stored in `manifest.jsonl`.
- If `manifest.jsonl` is destroyed, it can be fully reconstructed by scanning all frames **backwards**.
- Frames remain immutable and independently verifiable (SHA-256 covers everything **above** the offset field).

This change makes **each frame a stand-alone verifiable record** —  
the archive can degrade gracefully even after partial data loss.

---

### ⚙️ Manifest Lookup Table (`manifest.lut`)

Large installations may optionally maintain a binary lookup table  
as a **parallel, fully derivable index** for `manifest.jsonl`.

```
/my-archive/
├── manifest.jsonl
├── manifest.lut # optional binary index
└── frames/
```

Purpose: **constant-time (O(1))** lookup of manifest records without parsing JSON.

#### 🔸 Binary Layout
| Offset | Size | Field        | Type    | Description                      |
| -----: | ---- | ------------ | ------- | -------------------------------- |
|   0x00 | 4    | magic        | char[4] | "STL1" (STASH LUT v1)            |
|   0x04 | 2    | record_size  | uint16  | fixed bytes per record (e.g. 64) |
|   0x06 | 2    | version      | uint16  | LUT format version (0x0100)      |
|   0x08 | 8    | record_count | uint64  | number of entries                |
|   0x10 | 32   | manifest_sha | bytes   | SHA-256 of manifest.jsonl        |
|   0x30 | ...  | records[]    | ...     | sequential fixed-size entries    |


#### 🔸 Record Structure (64 B)
| Offset | Size | Field        | Type   | Description                   |
| -----: | ---- | ------------ | ------ | ----------------------------- |
|   0x00 | 8    | line_no      | uint64 | line number in JSONL          |
|   0x08 | 8    | offset       | uint64 | byte offset in JSONL file     |
|   0x10 | 32   | frame_sha256 | bytes  | hash of referenced frame      |
|   0x30 | 8    | ts           | uint64 | timestamp (for range queries) |
|   0x38 | 8    | reserved     | uint64 | future use                    |


- `manifest.lut` is optional and **ephemeral** — rebuildable from `manifest.jsonl`.
- Can be **memory-mapped** (`mmap`) for O(1) access and fast scanning.
- Never modifies original STASH data — it’s a pure cache/indexing layer.

---

### 🗂️ 2️⃣ Sub-Manifests

This is a **game changer** for large, distributed archives and datacenters.

#### 🔸 Principle

Instead of one monolithic manifest pointing to all frames,  
the **root manifest** can reference **sub-manifests**, each managing a region/module/shard.

Each sub-manifest is:
- append-only
- independently verifiable
- self-contained

#### 🔸 Example Record

```json
{"ts": 1739550001, "op": "ADD", "frame": "a1b2c3...", "path": "data/image1.png", "codec": "zstd"}
{"ts": 1739550002, "op": "ADD", "frame": "d4e5f6...", "path": "data/image2.png", "codec": "zstd"}
{"ts": 1739550003, "op": "SUB", "path": "submanifests/user-data.jsonl", "frames": 248, "sha256": "aa3f...92"}
{"ts": 1739550004, "op": "SUB", "path": "submanifests/logs.jsonl", "frames": 921, "sha256": "bb2a...7d"}
```

* New op: "SUB" (or optionally "LINK") introduces a nested manifest.
* Treated like #include – the reader recursively loads referenced manifest.
* Fully supports garbage collection, modular replication, and cluster sharding.

#### 🔸 Advantages
| Feature                    | Benefit                                                               |
| -------------------------- | --------------------------------------------------------------------- |
| 🧩 **Unified format**      | A sub-manifest is just another manifest.jsonl — no new logic needed.  |
| ⚙️ **Composable**          | Root can mix normal records + `SUB` links seamlessly.                 |
| 🧭 **Distributed**         | Sub-manifests can be updated independently (e.g., logs vs images).    |
| 🧱 **Integrity preserved** | Each sub-manifest has its own SHA-256 and frame count.                |
| 🔁 **Still append-only**   | No overwrites, no dependency hell — each part evolves independently.  |
| 🧮 **O(1) lookup remains** | `manifest.lut` can include `SUB` records — same indexing, no penalty. |

#### 🔸 Summary

New record type:
```
{"op": "SUB", "path": "<submanifest_path>", "frames": <int>, "sha256": "<hash>"}
```

**Meaning:** references another manifest.jsonl which expands the archive.

Optional fields:
* `frames` – number of frames covered (for indexing, caching)
* `sha256` – full SHA-256 of sub-manifest (for verification)

## 💽 Compression Codecs

STASH supports any standard compression library.
Recommended defaults:

Codec	Speed	Ratio	Typical Use
LZ4	⚡ very fast	🔹 low	logs, binary diffs
ZSTD	⚙️ balanced	🔹 good	general-purpose
LZMA	🐢 slower	🔹 high	archival
BROTLI	🧠 slow	🔹 very high	text-heavy
STORE	–	none	already compressed data

## 🔒 Optional Crypto Extension (non-normative)

STASH deliberately keeps encryption out of its core specification.  
Implementations **MAY** introduce optional cryptographic protection for frame payloads  
or manifest signing, but these mechanisms are **implementation-specific** and must not  
alter the canonical layout of STASH frames or manifests.

The guiding principle: **integrity first, secrecy optional.**

---

### 🧩 Recommended Integration Pattern

- Encrypt only the **payload** portion of a frame;  
  the header and trailer remain intact so frames stay self-describing.  
- Store algorithm identifiers and parameters (IV, salt, key ID) either  
  in local metadata or as additional manifest fields.  
- Compute SHA-256 (or stronger) **over the ciphertext**, ensuring integrity  
  without revealing plaintext contents.
- Decryption must always yield the same uncompressed data that was originally stored  
  before compression and encryption.

---

### 🧠 Example Manifest Entries (post-quantum ciphers)

```json
{"ts":1739550005,
 "op":"ADD",
 "frame":"9fb1a6...",
 "path":"secure/data.bin",
 "codec":"zstd",
 "crypto":{
   "algorithm":"kyber-aes-gcm",
   "iv":"b64:0mN2uF9f...",
   "key_id":"urn:stash:key:001"
 }}
```

These examples reference post-quantum hybrid schemes
(e.g., **Kyber + AES-GCM, NTRU + ChaCha20-Poly1305**).
Implementations may substitute any PQC algorithm set that meets local policy.

#### 🧾 Notes

The use of encryption is optional; archives remain fully valid and readable
without crypto extensions.

Future official revisions MAY standardize field names or supported algorithms
once stable and auditable PQC practice emerges.

Always document key management and decryption workflow separately from STASH data itself.

## 🛡️ Integrity

Each `.sf` frame ends with a 32-byte SHA-256 hash that covers everything except the final hash field.

This enables:
- Independent integrity checks (without scanning full archive)
- Tamper detection and auditability
- Full recovery even without `manifest.jsonl` (thanks to embedded JSON trailer)

Hashes in the manifest or optional `manifest.lut` are used for fast lookup and verification, but are **derivable** — no external database needed.

### 🛠️ Self-Describing Resilience

Every STASH frame starts with a 2-byte syncword: `0x53 0x46` (`'SF'`).  
This makes frames trivially detectable even in raw disk editors, forensic scanners, or recovery tools.

Even without access to the manifest, any valid frame can be:

- **Located** via its magic header (`SF`)
- **Parsed** via fixed offsets (`version`, `codec_id`, `timestamp`, etc.)
- **Understood** thanks to the embedded manifest JSONL record in the trailer
- **Reconstructed** into a new manifest via full-frame scanning

This ensures that even in worst-case scenarios — lost index, corrupted directory, partial disk failure —  
**the archive can be scanned, interpreted, and rebuilt manually** with nothing more than a hex viewer.

STASH was designed not only to perform well in modern pipelines,  
but to be readable long after the tools are gone.

## 🛠️ Implementation Notes

- Each frame (`.sf`) is a standalone binary file:
  - compressed payload,
  - embedded JSONL trailer (e.g., `{"op": "ADD", ...}`),
  - 16-bit back offset,
  - 32-byte SHA-256 hash (covering all preceding data).
- Frames are named by SHA-256 hash and **optionally sharded** into directories: `/frames/ab/cd/abcdef1234....sf`
- Compression codec is per-frame (e.g., `zstd`, `lz4`, etc.).
- Manifest is an append-only `manifest.jsonl`, one line per operation (`ADD`, `DEL`, `REPL`, `SUB`, ...).
- **No frame is ever overwritten** — updates = new frames + manifest entries.
- Deleted or replaced paths are marked in the manifest, not by modifying data.
- Optional `manifest.lut` enables fast O(1) lookups for large archives.
- Sub-manifests (`SUB`) support modular and distributed archives.
- Frame IDs (if used) are implicit via line number or hash reference.

Optional tooling may include:
- Frame/manifest validators
- Garbage collection of unreachable frames
- Time-based version diffing
- Pluggable cloud/tape backends

## Author’s Note

**STASH** was created to explore what comes *after* TAR —  
a format that treats compressed data as **first-class, addressable objects**,  
not opaque blobs.

It’s intentionally simple.  
It’s meant to be **re-implemented**, **extended**, and **evolved**.

System-level behaviors such as **automated tiering**, **offline archival** (e.g. magneto-optical),  
or custom policies (e.g. retention, replication) can be implemented on top,  
using additional manifest fields like `"archived": true` or custom `"op"` types.  
The manifest is designed to accept such extensions without breaking compatibility.

## 📜 License

This specification is released under the **Zbyšek License 1.0**, which is based on the Creative Commons Attribution 4.0 International License (CC-BY 4.0), with one important exception.

You are free to:

- **Share** — copy and redistribute the material in any medium or format  
- **Adapt** — remix, transform, and build upon the material for any purpose, even commercially  

Under the following terms:

- **Attribution** — You must give appropriate credit, indicate if changes were made, and include this license.  
- **No additional restrictions** — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

### 🚫 Exception — Valve Corporation Ban

> **The Valve Corporation and any of its subsidiaries or affiliated entities are explicitly prohibited** from using, incorporating, adapting, redistributing, or otherwise exploiting this work in any form, without the author's written permission.

---

**Author:** © 2025 Zbigniew Lipka  
**Full license text:** See [LICENSE](./LICENSE)