# 🌀 STASH

**Self-describing Tagged Archive Streamable Heaps**

🌀 STASH is an open archival format designed for server, enterprise, and datacenter workloads where recovery, integrity, and predictable behavior matter more than minimizing every byte of overhead.

It stores data in immutable, grid-aligned frames distributed across one or more append-only blobs. Each frame carries enough physical and logical metadata to be discovered and reconstructed without trusting the normal manifest or derived indexes.

> **Project status:** 🌀 STASH 2.0 Revision R8, wire version `0x0006`, is **Final / Frozen**. The next milestone is the Go reference implementation and its mandatory conformance harness, not another speculative wire-format revision.

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
- CRC32C-protected self-identifying blob metadata
- CRC32C-protected 96-byte Master Trailers
- Explicit object identity, logical offset, and logical length in non-packed DATA frames
- Self-describing parity-group membership
- PACKED frames for small objects
- Whole-frame hashing and deduplication
- Mandatory rebuildable per-blob offset indexes
- JSONL manifest with atomic multi-record transactions
- Optional authenticated encryption using AES-256-GCM
- Crash-safe generation switching and compaction
- Deliberately narrow algorithm surface:
  - SHA-256 / BLAKE3 hashing
  - STORE / Zstandard compression
  - XOR / Reed-Solomon parity
  - AES-256-GCM authenticated encryption

> **Checksums and hashes detect corruption; redundancy repairs it.** CRC32C, payload hashes, and AEAD authentication detect invalid data but do not reconstruct it. Repair requires parity, another intact copy, replication, or another recovery source.

## Interoperability profiles

R8 defines three named profiles. They are presets over existing wire fields; no separate `profile_id` is stored.

| Profile | Hash | Compression | Encryption | Purpose |
|---|---|---|---|---|
| **BASELINE** | SHA-256 | STORE | none | Minimum interoperable implementation |
| **SECURE** | SHA-256 | STORE | AES-256-GCM | Conservative authenticated enterprise archival profile |
| **FAST** | BLAKE3 | ZSTD_FAST | none | Maximum practical ingest and recovery throughput |

The profiles bind only hashing, compression, and encryption. Frame-size mode, parity, PACKED frames, blob count, and maximum frame size remain orthogonal archive properties.

A minimal conformant R8 implementation must support BASELINE and must safely recognize and reject unsupported R8 features rather than misparse them.

## Compression profiles

R8 intentionally supports a small compression surface:

```text
0x00  STORE         no compression
0x01  ZSTD_FAST     Zstandard level 1
0x02  ZSTD_DEFAULT  Zstandard level 3
0x03  ZSTD_DENSE    Zstandard level 9
```

Every Zstandard payload is one independently decodable Zstandard frame. External dictionaries are not part of R8.

Equal logical input is **not** guaranteed to produce byte-identical compressed output across independent Zstandard implementations or versions. Whole-frame deduplication therefore occurs only when stored representations are actually byte-identical.

## Parity and repair

R8 defines exactly two parity mechanisms:

```text
0x00  NONE
0x01  XOR
0x02  Reed-Solomon
```

Parity groups are self-describing through `group_id` and `group_index`, and all members of one group use identical physical frame size.

CRC32C, hashes, and AEAD authentication detect corruption. XOR or Reed-Solomon parity, replication, or another intact source are the mechanisms that can repair it.

## Two immutable frame-size modes

The archive selects one mode at creation time. The mode is immutable for the entire archive lifetime.

New archives **SHOULD default to VARIABLE** unless FIXED is explicitly selected.

### VARIABLE

VARIABLE is the normal/default enterprise mode.

Each frame selects its own physical size as a positive multiple of 4096 bytes, bounded by `MAX_FRAME_SIZE`.

This mode reduces padding and write amplification for changing datasets while retaining independent quantum-boundary recovery.

### FIXED

FIXED provides deterministic direct-slot geometry and maximum recovery-scan parallelism.

Every frame occupies exactly `MAX_FRAME_SIZE`.

```text
frame_start(n) = 0x40 + n * MAX_FRAME_SIZE
```

It is suited to write-once or cold archives where direct physical arithmetic and highly parallel disaster recovery justify increased padding.

## A blob identifies itself

Each blob begins with self-identifying archive and generation metadata, including the archive identity, generation, blob ordinal, format version, and integrity protection required to classify the blob without relying on its filename or directory path.

A detached or renamed blob can therefore be associated with its archive and generation during recovery.

The exact byte layout is normative in [`SPEC.md`](SPEC.md); this README intentionally avoids duplicating wire offsets that could drift from the specification.

## Normal access and disaster recovery

Normal reads use a mandatory per-blob offset index:

```text
hash_payload -> one or more physical frame candidates
```

This provides O(1) or O(log N) lookup without placing mutable physical offsets in the logical manifest. The index is derived state: if it is missing, stale, or corrupt, it can be rebuilt from the blobs.

Recovery deliberately has a slower but independent path:

- validate and classify blob metadata;
- discover frames from fixed slots or 4096-byte boundaries;
- validate frame structure before trusting geometry or placement;
- rebuild offset indexes;
- reconstruct non-packed objects from explicit logical ranges;
- recover parity groups from their self-described membership;
- rebuild higher-level metadata where sufficient information survives.

Encrypted archives remain physically discoverable and parity-recoverable without keys, but plaintext paths, versions, and PACKED entry maps require the appropriate key.

Archive-scale recovery must be streamable and bounded. Untrusted on-disk values must never directly trigger unbounded allocation, recursion, goroutine/task creation, or uncontrolled work amplification.

## Encryption

R8 defines one authenticated-encryption algorithm:

```text
AES-256-GCM
nonce = 12 bytes
tag   = 16 bytes
```

Encrypted payloads are stored as:

```text
nonce[12] || ciphertext || tag[16]
```

R8 derives independent frame, Pre-Trailer, and manifest AEAD keys from one 32-byte archive DEK using HKDF-SHA-256 with domain-separated `info` values.

The archive DEK is immutable for the lifetime of an encrypted archive. KEK/KMS rotation may rewrap the same DEK without rewriting STASH data. Changing the DEK requires an explicit migration to a new archive.

Nonce construction is collision-free within the permitted R8 encrypted namespace. Stored nonces remain authoritative for decryption, and normal compaction copies encrypted live frames byte-for-byte.

## Reference implementation architecture

The Go library will be the authoritative implementation of wire parsing, validation, manifests, indexing, parity, recovery, compaction, and encryption semantics.

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

Recommended archive-creation surface:

```text
stash create ARCHIVE \
    --profile baseline|secure|fast \
    --mode variable|fixed \
    --max-frame-size SIZE \
    --blobs N \
    --parity none|xor|rs \
    [--parity-k K --parity-m M] \
    [--key-provider NAME]
```

Advanced creation may expose explicit `--hash` and `--codec` overrides supported by R8.

These commands describe the planned interface, not currently released binaries.

### Read-only FUSE profile

The official FUSE adapter is permanently read-only. A mount pins one validated generation for its lifetime and exposes a stable archive snapshot through the Go library.

All mutation attempts return `EROFS`. The adapter does not modify blobs, manifests, persistent indexes, generations, or root metadata.

## Specification

The normative format definition is:

- [`SPEC.md`](SPEC.md) — 🌀 STASH 2.0, **Revision R8**, wire version `0x0006`, **Final / Frozen**

The specification defines byte layouts, invariants, validation ordering, recovery behavior, concurrency, parity, compaction, encryption, resource ceilings, and the required wire-conformance test matrix.

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

1. Blob/header and Master Trailer codecs
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

The **R8 required test matrix is part of the specification and is not optional implementation guidance.**

The reference implementation must include independently constructed golden vectors, exhaustive corruption checks for fixed binary structures, decoder fuzzing, arithmetic-boundary tests, compression/parity/crypto vectors, crash injection, and raw-recovery torture tests.

Golden-vector testing must not rely solely on `Encode(x) -> Decode() -> x`; encoder output must also be compared against independently constructed exact bytes.

## R8 freeze policy

> **STASH 2.0 R8 / wire `0x0006` is frozen.**

Further wire-format revisions require evidence from the reference implementation or conformance testing, such as:

- golden-vector incompatibility;
- fuzzing findings;
- crash-injection failures;
- raw-recovery failures;
- interoperability failures;
- security analysis;
- measured performance evidence.

Speculative feature additions or implementation convenience alone are not sufficient reasons to reopen the wire format.

The next milestone is:

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

## Non-goals for 🌀 STASH 2.0

- General-purpose desktop archive replacement
- Writable POSIX filesystem semantics
- Sub-block or content-defined chunking deduplication
- In-place frame mutation
- Dependence on a proprietary catalog for correctness
- Tape-specific optimization
- Mixing frame-size modes inside one archive
- Additional compression, hash, parity, frame-mode, or encryption algorithms in R8
- IAM/RBAC or network-protocol definition
- Recovery UI or ransomware-vault protocol in the wire format

## Contributing

The project is entering the reference-implementation phase. Early contributions are most valuable in:

- adversarial review of R8 invariants;
- independently constructed wire golden vectors;
- Go binary-codec and bounded-allocation review;
- parity and compaction verification;
- filesystem and object-storage backend testing;
- fuzzing and crash-injection infrastructure;
- raw-recovery and interoperability testing.

Wire-format changes are frozen unless implementation evidence demonstrates that R8 must be reopened.

## License

🌀 STASH is open-source software licensed under the [MIT License](LICENSE).

**Author:** © 2025-2026 Zbigniew Lipka
