# 🌀 STASH — Self-describing Tagged Archive Streamable Heaps  
**Version:** 1.0 • **Spec Draft**  

---

## 🧭 Overview

**STASH** is an experimental data format designed to replace traditional archive formats (`.tar`, `.zip`, `.7z`)  
with a smarter, self-describing, and versionable alternative.

Its core idea:
> *Every piece of data is stored in independent compressed frames that can be addressed, verified, and reused.*

STASH combines the simplicity of **TAR**, the performance of **Zstd/LZ4**,  
and the adaptability of **modern data systems (Parquet, IPFS)** — while staying human-readable and open.

---

## 💡 Motivation

Classic archives are monolithic.  
To extract a single file, you must decompress everything before it.  
They can’t do incremental updates, deduplication, or distributed storage efficiently.

STASH fixes that:
- Each *frame* is a self-contained unit (compressed data + metadata).
- Frames can live anywhere — locally, in the cloud, or across multiple datacenters.
- New versions are created **append-only** — no rewriting old data.
- Manifests map objects to frames → allowing instant access to any file.

The result is an **addressable, verifiable, and distributed archive format.**

---

## ⚙️ Core Principles

| Principle | Description |
|------------|-------------|
| **Self-describing** | Every frame carries its own metadata (size, codec, hash, objects). |
| **Append-only** | New data is always appended as new frames — old data stays valid. |
| **Codec-agnostic** | LZ4, Zstd, LZMA, Brotli, or even raw “store”. |
| **Predictable layout** | Frames are sequential, allowing easy diffing and streaming. |
| **Integrity built-in** | SHA-256 hash at the end of each frame ensures verification. |
| **Human-friendly manifest** | Simple JSON or CBOR file describing all frames and objects. |

---

## 🧩 File Structure

A STASH archive is composed of:

┌────────────────────────┐
│ Frame #1 │
│ Frame #2 │
│ Frame #3 │
│ ... │
│ Manifest (JSON/CBOR) │
└────────────────────────┘


Each **frame** is independently compressed and verifiable.

---

## 📦 Frame Structure (binary layout)

| Offset | Size | Field | Type | Description |
|--------:|-----:|-------|------|-------------|
| 0x00 | 2 | `magic` | `0x53 0x46` (`'SF'`) | Sync word |
| 0x02 | 1 | `version` | uint8 | Frame format version (0x01) |
| 0x03 | 1 | `codec_id` | uint8 | 1=LZ4, 2=ZSTD, 3=LZMA, 4=BROTLI, 0=STORE |
| 0x04 | 4 | `flags` | uint32 | Reserved / feature bits |
| 0x08 | 8 | `uncompressed_size` | uint64 | Size before compression |
| 0x10 | 8 | `compressed_size` | uint64 | Size after compression |
| 0x18 | 8 | `timestamp` | uint64 | Unix time (creation) |
| 0x20 | 8 | `frame_id` | uint64 | Unique sequential ID |
| 0x28 | 8 | `object_table_offset` | uint64 | Offset (from frame start) to object metadata |
| 0x30 | … | `compressed_payload` | bytes | Actual compressed data |
| ... | … | `object_table` | JSON or CBOR | Object definitions inside frame |
| ... | 32 | `frame_hash` | SHA-256 | Integrity checksum of all previous bytes |

---

### 🧾 Object Table (JSON example)

Each frame can contain one or multiple objects (files, binary blobs, JSONs, etc.)

```json
[
  {
    "name": "textures/hero.png",
    "offset": 0,
    "size": 12345,
    "hash": "a12f...f92a"
  },
  {
    "name": "data/config.json",
    "offset": 12345,
    "size": 6789,
    "hash": "b45c...7de2"
  }
]
```

### Manifest (Global Index)

The manifest lists all frames and all objects in the archive.

```json
{
  "staSH_version": 1,
  "archive_name": "assets_v1",
  "created": "2025-10-13T21:30:00Z",
  "frames": [
    {"id": 1, "hash": "aa11...", "codec": "lz4"},
    {"id": 2, "hash": "bb22...", "codec": "zstd"}
  ],
  "objects": {
    "textures/hero.png": {
      "frame": 1,
      "hash": "a12f...",
      "size": 12345
    },
    "data/config.json": {
      "frame": 2,
      "hash": "b45c...",
      "size": 6789
    }
  }
}
```

Each new version of the archive simply appends new frames and updates this manifest.

### 🔁 Versioning Example
```
v1 → frames 1–1000
v2 → frames 1–1000 + 1001–1004 (only changed files)
v3 → frames 1–1004 + 1005–1008
```

Each version’s manifest defines which frames form the complete dataset.

Old frames remain valid and deduplicated.
This enables lightweight incremental backups and data versioning.

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

Every frame ends with a 32-byte SHA-256 hash that covers the entire frame except the hash field itself.
Readers can verify frame integrity independently without scanning the entire archive.

## Implementation Notes

Chunk Size: Recommended 64 KB – 1 MB per frame.

Metadata: Stored as UTF-8 JSON (can be replaced by CBOR for binary efficiency).

Endian: Little-endian for all numeric fields.

Compatibility: Archives can be concatenated safely — readers must scan by magic 0x53 0x46.

## Example Hex Layout (minimal frame)
```
53 46 01 02 00 00 00 00 00 00 00 00 ... (header)
<compressed payload>
7B 22 6E 61 6D 65 ... 7D               (JSON object table)
<32-byte SHA-256 hash>
```

## Author’s Note

STASH was created to explore what comes after TAR —
a format that treats compressed data as first-class addressable objects,
not opaque blobs.

It’s intentionally simple.
It’s meant to be re-implemented, extended, and evolved.

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