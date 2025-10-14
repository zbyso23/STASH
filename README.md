# 🌀 STASH — Self-describing Tagged Archive Streamable Heaps  
**Version:** 1.21 • **Spec Draft**  

---

## 🧭 Overview

STASH is an append-only, verifiable archival format optimized for cloud-native workflows, differential sync, and long-term integrity.

Instead of bundling files into a single opaque blob (like `.zip` or `.tar.gz`), STASH splits input data into compressed frames of selected standard sizes (e.g. 4 KiB, 64 KiB, 1 MiB). Each frame is hashed (SHA-256) and referenced from a flat JSONL manifest, enabling fast random access, deduplication, and content-based verification.

All frames are immutable. No data is ever overwritten — updates are expressed as new manifest entries, making STASH ideal for incremental backups, verifiable replication, and scalable archival across SSD, HDD, tape, or cold storage.

### 📏 Frame Size Selection

STASH supports a predefined set of frame sizes, optimized for varying storage backends and access patterns:
`4 KiB / 16 KiB / 64 KiB / 256 KiB / 1 MiB / 8 MiB / 64 MiB / 256 MiB`

All frames within a single archive MUST use the same size. The selected size should balance compression efficiency, access granularity, and I/O performance depending on the target platform. Smaller frames favor random access and deduplication; larger frames improve compression and throughput.

---

## 🎯 Motivation

Classic archive formats (like .zip or .tar.gz) are monolithic by design. They bundle all content into a single linear stream, making random access, diffing, or partial updates inefficient or outright impossible.

Modern data workloads — especially in cloud, archival, and compliance-focused environments — require:

- Append-only immutable structures
- Efficient incremental updates (no rewriting of large blobs)
- Content-addressed deduplication
- Fast partial access to specific files or chunks
- Cold storage optimization (tiered access: SSD → HDD → MO)
- Verifiability and forensic audit support (GDPR, legal hold)

STASH is designed for these realities: to serve as a building block for distributed, verifiable, scalable archival systems, with minimal dependencies and maximum portability.

The result is an **addressable, verifiable, and distributed archive format.**

---

## ⚙️ Core Principles

- All content is split into compressed frames of standard sizes (see STASH 1.21), aligned to file boundaries where practical  
- Each frame is compressed independently, using codecs optimized for the file type (e.g. Zstd for binaries, Deflate for text)
- All frames are **immutable** and **append-only**
- The manifest is a flat JSONL file that maps files to frames and tracks all operations (add, delete, overwrite) as a linear log
- Data is never modified in-place — updates are expressed by appending new frames and manifest records
- Every frame is **content-addressed** by its hash (SHA-256 by default), enabling global deduplication and integrity checks
- Manifest records are designed for **ultra-fast parsing**, with fixed-length binary fields (TS, OP, FRAME, SIZE, OFFSET)
- Metadata and data are strictly separated, enabling selective sync, streaming, and low-latency access

**STASH 1.2** addresses these needs with:

- Immutable compressed frames with per-frame SHA-256
- A flat append-only JSONL manifest (with optional LUT index)
- Embedded per-frame manifest trailers for recovery and integrity
- Support for distributed sub-manifests and modular replication

The result is a **scalable, verifiable, and fault-tolerant archive format** — designed as a foundation for modern archival systems with zero-dependency parsing, efficient synchronization, and long-term resilience.

### 🆕 STASH 1.21 — Frame Size Class Set

STASH 1.21 introduces an explicit **frame size class set**. Each archive MUST choose a single fixed frame size from the following standard options:
`4 KiB / 16 KiB / 64 KiB / 256 KiB / 1 MiB / 8 MiB / 64 MiB / 256 MiB`

This enables consistent memory management, compression tuning, and backend storage optimization across heterogeneous environments.

Frame size MAY be:

- **Globally fixed** at archive creation time (`manifest.config.frame_size`) — suitable for deterministic archives  
- **Per-client adaptive**, if the archive permits reader-side frame reassembly or progressive access (e.g. caching layers, CDN nodes)

Regardless of adaptation, all frames remain individually addressable, immutable, and self-describing.

⚠️ Note on 256M:
* Optional in STASH 1.21, mandatory support may be introduced in future version (e.g. STASH 1.3+)
* Should only be used in archives where target systems support large memory-mapped access
* Recommended for AI datasets, medical imaging, 3D reconstruction, simulation output, etc.

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