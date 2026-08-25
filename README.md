# 🌀 STASH

**Self-describing Tagged Archive Streamable Heaps**

🌀 STASH is an open archival format designed for server, enterprise, and datacenter workloads where recovery, integrity, and predictable behavior matter more than minimizing every byte of overhead.

It stores data in immutable, grid-aligned frames distributed across one or more append-only blobs. Each frame carries enough physical and logical metadata to be discovered and reconstructed without trusting the normal manifest or derived indexes.

> **Project status:** The 🌀 STASH 2.0 Revision R7 wire-format specification is frozen. The Go reference implementation, CLI, and read-only FUSE adapter are the next development phase.

## Why 🌀 STASH exists

Many archive formats are easy to write but difficult to recover when indexes, catalogs, filenames, or surrounding metadata are damaged. 🌀 STASH treats disaster recovery as a format-level property rather than an implementation afterthought.

The format is built around four priorities:

1. **Deterministic bounded geometry** — every frame occupies a validated multiple of 4096 bytes.
2. **Self-describing recovery** — raw blobs and non-packed data frames retain the identity needed for reconstruction.
3. **Whole-frame integrity and deduplication** — hashes cover the exact stored payload representation.
4. **Enterprise throughput** — independent blob writers, parallel recovery, and indexed normal access.

🌀 STASH is intended for archival storage, verifiable replication, incremental backup, disaster recovery, and long-lived datasets. It is not intended to replace ZIP, TAR, or a general-purpose desktop filesystem.

## Core design

- Append-only writes and immutable committed frames
- Copy-on-Write updates through new frames and manifest records
- One to 255 independently writable blobs per generation
- 4096-byte physical alignment
- CRC32C-protected 64-byte self-identifying blob prefixes
- CRC32C-protected 96-byte Master Trailers
- Explicit object identity, logical offset, and logical length in non-packed DATA frames
- Self-describing parity-group membership
- PACKED frames for small objects
- Whole-frame hashing and deduplication
- Mandatory rebuildable per-blob offset indexes
- JSONL manifest with atomic multi-record transactions
- Optional authenticated encryption profile
- Crash-safe generation switching and compaction

## Two immutable frame-size modes

The archive selects one mode at creation time. The mode cannot change during the archive's lifetime.

### VARIABLE

Each frame selects its own physical size as a positive multiple of 4096 bytes, bounded by the archive's maximum frame-size class.

This mode reduces padding and write amplification for changing datasets. Recovery scans validated quantum boundaries and uses each trailer's `frame_quanta` to recover frame geometry.

### FIXED

Every frame occupies exactly `MAX_FRAME_SIZE`.

This mode restores direct slot arithmetic:

```text
frame_start(n) = 0x40 + n * MAX_FRAME_SIZE
```

It is suited to write-once or cold archives where fast, parallel disaster recovery is more important than padding efficiency.

## A blob identifies itself

Every blob starts with the following 64-byte prefix:

```text
0x00..0x2F  Archive Header   48 bytes
0x30..0x37  generation_id     8 bytes
0x38        blob_ordinal      1 byte
0x39..0x3B  reserved          3 bytes
0x3C..0x3F  prefix_crc32c     4 bytes
0x40        first frame
```

The prefix checksum covers all 64 bytes with its own field treated as zero. A detached or renamed blob can therefore identify its archive, containing generation, and ordinal without relying on its directory or filename.

## Normal access and disaster recovery

Normal reads use a mandatory per-blob offset index:

```text
hash_payload -> one or more physical frame candidates
```

This provides O(1) or O(log N) lookup without placing mutable physical offsets in the logical manifest. The index is derived state: if it is missing, stale, or corrupt, it can be rebuilt from the blobs.

Recovery deliberately has a slower but independent path:

- validate and classify blob prefixes;
- discover frames from fixed slots or 4096-byte boundaries;
- validate each Master Trailer before trusting geometry or placement;
- rebuild offset indexes;
- reconstruct non-packed objects from explicit logical ranges;
- recover parity groups from their self-described membership;
- rebuild higher-level metadata where sufficient information survives.

Encrypted archives remain physically discoverable and parity-recoverable without keys, but plaintext paths, versions, and PACKED entry maps require the appropriate key.

## Reference implementation architecture

The Go library will be the only authoritative implementation of wire parsing, validation, manifests, indexing, parity, recovery, compaction, and encryption semantics.

```text
                 +----------------------+
                 | Go 🌀 STASH library  |
                 | format + operations  |
                 +----------+-----------+
                            |
             +--------------+--------------+
             |                             |
      +------v------+               +------v------+
      |  stash CLI  |               | FUSE adapter|
      | thin client |               |  read-only  |
      +-------------+               +-------------+
```

The CLI and FUSE adapter must call the public library API. They must not implement separate wire-format parsers or recovery logic.

### Planned Go library responsibilities

- Create and open archives
- Transactional put, delete, and rename operations
- Streaming object listing
- Sequential and random object reads
- Structural and full-content verification
- Raw recovery
- Offset-index rebuilding
- Compaction and garbage collection
- Storage backend abstraction
- Key-provider integration

Wire structures and binary codecs will remain internal packages so callers cannot construct partially valid frames.

### Planned CLI surface

The reference executable will be named `stash`. Its intended command families are:

```text
stash create
stash add
stash remove
stash rename
stash extract
stash list
stash stat
stash verify
stash recover
stash index rebuild
stash compact
stash gc status
stash gc emergency-prune
stash mount
```

These commands describe the planned interface, not currently released binaries.

### Read-only FUSE profile

The official FUSE adapter is permanently read-only. A mount pins one validated generation for its lifetime and exposes a stable archive snapshot through the Go library.

All mutation attempts return `EROFS`. The adapter does not modify blobs, manifests, persistent indexes, generations, or root metadata.

## Specification

The normative format definition is:

- [`SPEC.md`](SPEC.md) — 🌀 STASH 2.0, Revision R7, wire version `0x0005`

The specification defines byte layouts, invariants, validation ordering, recovery behavior, concurrency, parity, compaction, encryption, required test vectors, and the reference product architecture.

If this README and the specification disagree, the specification wins.

## Intended repository layout

```text
.
├── README.md
├── SPEC.md
├── go.mod
├── cmd/
│   └── stash/
├── internal/
│   └── wire/
├── fuse/
├── testdata/
└── ... public library packages
```

The repository root is the Go module root. This keeps the public library, CLI, FUSE adapter, conformance tests, and specification versioned together.

The final package boundaries will be established during implementation and should follow dependency direction rather than mirror every specification section.

## Development approach

The implementation will be developed vertically, with executable conformance tests at each layer:

1. Prefix and Master Trailer codecs
2. Frame geometry and validation
3. Blob append/read paths
4. Offset indexes
5. Manifest transactions
6. Logical object reconstruction
7. PACKED frames
8. Parity
9. Compaction and generation switching
10. Encryption
11. CLI
12. Read-only FUSE adapter

The R7 required test matrix is part of the specification and is not optional implementation guidance.

## Non-goals for 🌀 STASH 2.0

- General-purpose desktop archive replacement
- Writable POSIX filesystem semantics
- Sub-block or content-defined chunking deduplication
- In-place frame mutation
- Dependence on a proprietary catalog for correctness
- Tape-specific optimization
- Mixing frame-size modes inside one archive

## Contributing

The project is entering the reference-implementation phase. Early contributions are most valuable in:

- independent review of R7 invariants;
- adversarial recovery and corruption test vectors;
- Go binary-codec and bounded-allocation review;
- parity and compaction verification;
- filesystem and object-storage backend testing;
- fuzzing and crash-injection infrastructure.

Wire-format changes require an explicit specification revision. Implementation convenience alone is not sufficient reason to weaken recovery or validation guarantees.

## License

🌀 STASH is open-source software licensed under the [MIT License](LICENSE).

**Author:** © 2025-2026 Zbigniew Lipka  
