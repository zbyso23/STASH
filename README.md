# 🌀 STASH — Self-describing Tagged Archive Streamable Heaps  
**Version:** 1.1 • **Spec Draft**  

---

## 🧭 Overview

STASH is a cloud-first archival format designed for efficient long-term storage, fast random access, and scalable differential distribution.

Unlike traditional monolithic archives (.zip, .tar.gz), STASH splits input data into fixed-size independently compressed frames (e.g. 64 KiB), which are then referenced via a JSONL manifest. Each frame is content-addressed via its hash, allowing for incremental updates, deduplication, and verification.

Frames are immutable and append-only — updates never overwrite existing data, enabling efficient synchronization, audit trails, and long-term archival strategies across different storage tiers (SSD, HDD, MO).

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

- All content is split into fixed-size frames (default: 64 KiB), aligned to file boundaries where practical
- Each frame is compressed independently, using codecs optimized for the file type (e.g. Zstd for binaries, Deflate for text)
- All frames are **immutable** and **append-only**
- The manifest is a flat JSONL file that maps files to frames and tracks all operations (add, delete, overwrite) as a linear log
- Data is never modified in-place — updates are expressed by appending new frames and manifest records
- Every frame is **content-addressed** by its hash (SHA-256 by default), enabling global deduplication and integrity checks
- Manifest records are designed for **ultra-fast parsing**, with fixed-length binary fields (TS, OP, FRAME, SIZE, OFFSET)
- Metadata and data are strictly separated, enabling selective sync, streaming, and low-latency access

---

## 🧩 File Structure

The output is a single directory containing all data and metadata:
```
/my-archive/
├── manifest.jsonl # Append-only event log in JSON Lines format
├── frames/
│ ├── a0f1c9f3...6c2f.sf # Compressed 64 KiB frame (hash-named)
│ ├── b7d2a85e...93f0.sf # ...
│ └── ...
```

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
Each manifest entry (in manifest.jsonl) represents a versioned operation (add, delete, replace).
Clients reconstruct the current state by replaying the manifest and resolving the latest valid entry for each path.
Old frames remain valid and deduplicated.

This enables:
- efficient incremental updates,
- time-based snapshots (by truncating replay),
- low-bandwidth synchronization.

## 💽 Compression Codecs

STASH supports any standard compression library.
Recommended defaults:

Codec	Speed	Ratio	Typical Use
LZ4	⚡ very fast	🔹 low	logs, binary diffs
ZSTD	⚙️ balanced	🔹 good	general-purpose
LZMA	🐢 slower	🔹 high	archival
BROTLI	🧠 slow	🔹 very high	text-heavy
STORE	–	none	already compressed data

## 🔒 Integrity

Each frame ends with a 32-byte SHA-256 hash that covers all preceding bytes of the frame (header + compressed data + metadata).

This allows:
- independent verification of each frame’s integrity,
- detection of corruption or tampering,
- validation without scanning unrelated parts of the archive.

The global manifest (stored as append-only JSONL) optionally stores these hashes for quick lookup, audit, or synchronization.

## Implementation Notes

- Each frame is stored as a standalone binary file (e.g., `frame_000001.sf`), containing a header, compressed payload, object table, and SHA-256 hash.
- Compression codecs are selectable per frame (e.g., LZ4, ZSTD, etc.).
- A frame may contain one or more files (objects) if they are small or logically grouped.
- The manifest is stored as append-only **JSONL** (`manifest.jsonl`), where each line represents a version snapshot or metadata delta.
- No existing frames are modified — all changes are **additive** (new frames + manifest updates).
- Deleted or replaced files are marked as such in the manifest.
- Frame IDs are monotonically increasing `uint64`.
- Future tooling can include:
  - validation tools (frame integrity, manifest consistency),
  - GC (garbage collection of unreachable frames),
  - content diffing between versions,
  - pluggable backends for cloud storage or offline media (e.g., SSD, tape).

## Author’s Note

**STASH** was created to explore what comes *after* TAR —  
a format that treats compressed data as **first-class, addressable objects**,  
not opaque blobs.

It’s intentionally simple.  
It’s meant to be **re-implemented**, **extended**, and **evolved**.

## 📜 License

This specification is released under the **Creative Commons Attribution 4.0 International License (CC-BY 4.0)**.

You are free to:

- **Share** — copy and redistribute the material in any medium or format  
- **Adapt** — remix, transform, and build upon the material for any purpose, even commercially  

Under the following terms:

- **Attribution** — You must give appropriate credit, provide a link to the license, and indicate if changes were made.  
- No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

**Author:** © 2025 Zbigniew Lipka  
**License text:** [CC-BY 4.0 International](https://creativecommons.org/licenses/by/4.0/)